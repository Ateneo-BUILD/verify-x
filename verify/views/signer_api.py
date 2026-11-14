"""What the credential signer reaches on this site: /api/v1/signer/.

`report/` is what its reconciler reads: GET /api/v1/signer/report/. The
signer compares its ledger with what this app recorded and what phones
reported. Token only,
and only its SHA-256 is kept here. nginx answers 404 for /api/v1/signer/ from
outside; the reconciler calls gunicorn on 127.0.0.1 directly -- or, beside a
signer that polls, from the signer's own host over https through a proxy
that lets this path through. Nothing here decides anything: it is a
read-only account of this app's side, for a process that does not trust it.

`jobs/` and `answers/` are the job queue of a signer that dials out
(`SIGNER_QUEUE_KEY`; `accounts.signer_queue`, signer/poll.py): 404 unless the
key is set, and nothing without the signer's MAC for this site's host, its
time and an unused nonce; anything malformed is a 403 that says nothing more.
CSRF-exempt, because no browser session is involved: the MAC is the control.
Their answers are signed too, so the signer can tell this site from anything
between. A poll-mode site serves this prefix from a gunicorn pool of its own
(signer/deploy/README.md, "Poll mode"): the signer's poll and answers must
never queue behind the pages that wait for them.
"""

import hashlib
import hmac
import json
import uuid
from datetime import datetime, timezone as dt_timezone

from django.conf import settings
from django.core.exceptions import RequestDataTooBig
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_GET, require_POST

from accounts import signer_queue
from accounts.models import Device, DeviceLogEntry, IssuedCredential

#: Most answers one post may carry; the signer sends one at a time.
MAX_ANSWERS = signer_queue.MAX_JOBS

#: A report spans at most this much, whatever `since` asks for.
MAX_SPAN_SECONDS = 8 * 24 * 60 * 60


def _authorised(request) -> bool:
    expected = settings.SIGNER_REPORT_TOKEN_SHA256.strip().lower()
    header = request.META.get("HTTP_AUTHORIZATION", "")
    if not expected or not header.startswith("Bearer "):
        return False
    got = hashlib.sha256(header[len("Bearer "):].strip().encode()).hexdigest()
    return hmac.compare_digest(got, expected)


@require_GET
def report(request):
    if not settings.SIGNER_REPORT_TOKEN_SHA256:
        return JsonResponse({"error": "Not found."}, status=404)
    if not _authorised(request):
        return JsonResponse({"error": "Not authorised."}, status=403)
    now = datetime.now(dt_timezone.utc).timestamp()
    try:
        since = int(request.GET.get("since", "0"))
    except ValueError:
        return JsonResponse({"error": "since must be a unix time."}, status=400)
    # The reconciler is told where the report actually starts, so it does
    # not take a credential older than that for one never recorded.
    effective = int(max(since, now - MAX_SPAN_SECONDS))
    since = datetime.fromtimestamp(effective, dt_timezone.utc)

    credentials = [{
        "credential_id": str(row["credential_id"]),
        "state": row["state"],
        "issuer_key_id": row["issuer_key_id"],
        "organization": (str(row["organization__signing_id"])
                         if row["organization__signing_id"] else None),
    } for row in IssuedCredential.objects.filter(issued_at__gte=since).values(
        "credential_id", "state", "issuer_key_id", "organization__signing_id")]

    scans = []
    for entry in DeviceLogEntry.objects.filter(
            received_at__gte=since, event="scan", readable=True).only(
                "device_uuid", "detail"):
        detail = entry.detail or {}
        if detail.get("document") != "credential":
            continue
        scans.append({"credential_id": detail.get("credential_id"),
                      "verdict": detail.get("verdict"),
                      "issuer_key": detail.get("issuer_key"),
                      "device": str(entry.device_uuid)})

    devices = [{
        "device_id": str(row["device_id"]),
        "last_sync_at": (int(row["last_sync_at"].timestamp())
                         if row["last_sync_at"] else None),
        "issuer_chain_capable_at": (
            int(row["issuer_chain_capable_at"].timestamp())
            if row["issuer_chain_capable_at"] else None),
    } for row in Device.objects.filter(revoked_at__isnull=True).values(
        "device_id", "last_sync_at", "issuer_chain_capable_at")]

    return JsonResponse({"since": effective, "credentials": credentials,
                         "scans": scans, "devices": devices})


def _not_found():
    return JsonResponse({"error": "Not found."}, status=404)


def _refused(exc):
    return JsonResponse({"error": exc.reason}, status=exc.status)


def _signed(request, nonce, payload, status=200):
    return signer_queue.sign_response(JsonResponse(payload, status=status),
                                      request, nonce)


def _bounded(value, default, low, high):
    """A whole number from the query, held within [low, high]; None if it
    is not one."""
    try:
        number = int(value if value not in (None, "") else default)
    except (TypeError, ValueError):
        return None
    return max(low, min(high, number))


@csrf_exempt
@require_GET
def jobs(request):
    """The signer's long poll: pending jobs, claimed for it, as soon as there
    are any, or none after at most `wait` seconds (capped at
    poll.MAX_WAIT_SECONDS). At most `max` jobs -- the signer asks for as
    many as it has idle workers -- and about poll.MAX_CLAIM_BYTES of them.
    Each says how long it has left, by the database's clock: `expires_at`
    as a unix time, and `expires_in` in seconds, which the signer counts on
    its own clock from the moment this answer arrives."""
    if not signer_queue.enabled():
        return _not_found()
    try:
        nonce = signer_queue.authenticate(
            request, request.body, signer=request.GET.get("signer", ""))
    except signer_queue.Refused as exc:
        return _refused(exc)
    wait = _bounded(request.GET.get("wait"), 0, 0,
                    signer_queue.poll.MAX_WAIT_SECONDS)
    most = _bounded(request.GET.get("max"), 10, 1, signer_queue.MAX_JOBS)
    if wait is None or most is None:
        return _signed(request, nonce, {"error": "wait and max are whole "
                                                 "numbers"}, status=400)
    claimed = signer_queue.collect(most, wait)
    return _signed(request, nonce, {"jobs": [
        {"id": job_id, "request": text,
         "expires_at": int(expires_at.timestamp()), "expires_in": left}
        for job_id, text, expires_at, left in claimed]})


@csrf_exempt
@require_POST
def answers(request):
    """The signer's answers: `{"answers": [{"id": <job>, "reply": <the JSON
    text the socket would have framed>}]}`, one a post as the signer sends
    them. Each is kept once, on a job handed out and not given up on. A body
    over Django's DATA_UPLOAD_MAX_MEMORY_SIZE is a 413, which the signer
    alerts on as what it is."""
    if not signer_queue.enabled():
        return _not_found()
    try:
        body = request.body
    except RequestDataTooBig:
        return JsonResponse({"error": "too large"}, status=413)
    try:
        nonce = signer_queue.authenticate(request, body)
    except signer_queue.Refused as exc:
        return _refused(exc)
    try:
        items = json.loads(body).get("answers")
        if not isinstance(items, list) or len(items) > MAX_ANSWERS:
            raise ValueError("answers is a list")
        pairs = []
        for item in items:
            job_id, reply = item.get("id"), item.get("reply")
            if isinstance(job_id, bool) or not isinstance(job_id, int):
                raise ValueError("an id is a whole number")
            if not isinstance(json.loads(reply), dict):
                raise ValueError("a reply is a JSON object")
            pairs.append((job_id, reply))
    except (ValueError, TypeError, AttributeError):
        return _signed(request, nonce, {"error": "malformed answers"},
                       status=400)
    return _signed(request, nonce, signer_queue.accept(pairs))
