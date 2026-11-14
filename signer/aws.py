"""The ledger's way off the host: S3 Object Lock, SNS email, a heartbeat.

None of it holds key material. The signer reaches AWS with an IAM user key
only `cl03-signer` can read -- not the instance role, which the app user could
reach through IMDS. (A poll-mode signer, on a host with no app on it, may use
the instance role instead: signer/deploy/README.md, "Poll mode".) The key is
allowed `s3:PutObject`, `s3:GetObject` and
`s3:ListBucket` on the ledger prefix, `sns:Publish` on the alert topic, and
`cloudwatch:PutMetricData` in its own namespace.

**Rollback.** At start-up the signer refuses to sign while its local ledger is
behind the newest object it has shipped. A restored snapshot or an old AMI
would otherwise bring back a withdrawn key, forget which credential ids were
signed, and lift pauses.

boto3 is imported only when a real uploader is built, so neither verify's venv
nor the tests need it.
"""

from __future__ import annotations

import datetime
import json
import os
import sys

from . import ledger
# The default retention; `[runtime] ledger_retain_days` sets the site's
# (`config.runtime_retain_days`).
from .config import RETAIN_DAYS



class Rollback(RuntimeError):
    pass


def _object_key(prefix: str, first: int, last: int) -> str:
    return "%s/%012d-%012d.jsonl" % (prefix.rstrip("/"), first, last)


def _last_seq(key: str) -> int:
    return int(key.rsplit("/", 1)[-1].split("-")[1].split(".")[0])


def _first_seq(key: str) -> int:
    return int(key.rsplit("/", 1)[-1].split("-")[0])


#: What a refusal says when the local ledger is empty: a rebuilt host.
REBUILT = ("a new database on a host whose signer shipped before: "
           "`python -m signer adopt` carries the shipped ledger on "
           "(signer/deploy/README.md, \"Rebuilding the signer host\")")


class Shipper:
    def __init__(self, store, uploader, prefix: str, clock,
                 retain_days: int = RETAIN_DAYS):
        self.store = store
        self.uploader = uploader
        self.prefix = prefix
        self.clock = clock
        self.retain_days = retain_days

    def ship(self) -> int:
        """Upload every unshipped row as one object. Returns how many.

        Read under the store's lock: the one connection is shared, so a read
        beside another thread's open transaction would see rows that may yet
        roll back -- and an Object-Locked copy of a row that never existed is
        forever. The upload itself is outside the lock.
        """
        with self.store.lock:
            rows = self.store.all("SELECT * FROM ledger WHERE shipped = 0 "
                                  "ORDER BY seq")
        if not rows:
            return 0
        body = "".join(json.dumps({k: row[k] for k in row.keys()
                                   if k != "shipped"}, sort_keys=True) + "\n"
                       for row in rows)
        retain = (datetime.datetime.fromtimestamp(self.clock.now(),
                                                  datetime.timezone.utc)
                  + datetime.timedelta(days=self.retain_days))
        self.uploader.put(_object_key(self.prefix, rows[0]["seq"],
                                      rows[-1]["seq"]),
                          body.encode(), retain)
        with self.store as db:
            db.execute("UPDATE ledger SET shipped = 1 WHERE seq BETWEEN ? AND ?",
                       (rows[0]["seq"], rows[-1]["seq"]))
        return len(rows)

    def check_rollback(self) -> None:
        """Refuse a local ledger older than what has been shipped."""
        newest = self.uploader.newest(self.prefix)
        if newest is None:
            return
        key, body = newest
        try:
            last = json.loads(body.decode().strip().splitlines()[-1])
            last["seq"], last["hash"]
        except (ValueError, IndexError, KeyError, TypeError):
            # Unreadable is not "nothing shipped": refuse, with the alert,
            # rather than crash at every restart without one.
            raise Rollback("the newest shipped ledger object %s cannot be "
                           "read" % key)
        local_seq, _ = ledger.head(self.store)
        if local_seq == 0:
            raise Rollback("the local ledger is empty; %d rows were shipped "
                           "(%s). If this is %s" % (last["seq"], key, REBUILT))
        if local_seq < last["seq"]:
            raise Rollback("the local ledger ends at %d; %d was shipped "
                           "(%s). Restore the image that shipped it; on a "
                           "rebuilt host, see signer/deploy/README.md, "
                           "\"Rebuilding the signer host\""
                           % (local_seq, last["seq"], key))
        row = self.store.one("SELECT hash FROM ledger WHERE seq = ?",
                             (last["seq"],))
        if row is None or row["hash"] != last["hash"]:
            raise Rollback("row %d differs from the shipped copy" % last["seq"])


class FakeUploader:
    """In memory, for tests."""

    def __init__(self):
        self.objects = {}

    def put(self, key, body, retain_until):
        if key in self.objects:
            raise RuntimeError("Object Lock: %s exists" % key)
        self.objects[key] = body

    def newest(self, prefix):
        keys = sorted((k for k in self.objects if k.startswith(prefix)),
                      key=_last_seq)
        return (keys[-1], self.objects[keys[-1]]) if keys else None

    def keys(self, prefix):
        return sorted((k for k in self.objects if k.startswith(prefix + "/")),
                      key=_first_seq)

    def get(self, key):
        return self.objects[key]


class LocalUploader:
    """The ledger in a folder on the host, for a development site with no AWS
    (`[runtime] ledger_dir`). Each object is written once and never replaced,
    as Object Lock keeps them in S3. But the folder rides the same disk and
    images as the signer's database, so it is a copy of the ledger, not
    rollback protection: a restored image brings back both."""

    def __init__(self, directory: str):
        self.directory = directory

    def _folder(self, prefix: str) -> str:
        parts = prefix.strip("/").split("/")
        if any(p in ("", ".", "..") for p in parts):
            raise ValueError("bad ledger prefix")
        return os.path.join(self.directory, *parts)

    def put(self, key, body, retain_until):
        prefix, _, name = key.rpartition("/")
        folder = self._folder(prefix)
        os.makedirs(folder, exist_ok=True)
        # Written whole under a temporary name, then linked into place: a
        # crash part-way leaves only the temporary file, which `newest` never
        # reads, and `link` fails if the object exists, so none is replaced.
        temporary = os.path.join(folder, name + ".partial")
        final = os.path.join(folder, name)
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as handle:
            handle.write(body)
            handle.flush()
            os.fsync(handle.fileno())
        try:
            os.link(temporary, final)
        finally:
            os.unlink(temporary)
        os.chmod(final, 0o440)
        if hasattr(os, "O_DIRECTORY"):
            dir_fd = os.open(folder, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(dir_fd)
            finally:
                os.close(dir_fd)

    def newest(self, prefix):
        folder = self._folder(prefix)
        if not os.path.isdir(folder):
            return None
        names = [n for n in os.listdir(folder) if n.endswith(".jsonl")]
        if not names:
            return None
        name = max(names, key=_last_seq)
        with open(os.path.join(folder, name), "rb") as handle:
            return "%s/%s" % (prefix.rstrip("/"), name), handle.read()

    def keys(self, prefix):
        folder = self._folder(prefix)
        if not os.path.isdir(folder):
            return []
        return ["%s/%s" % (prefix.rstrip("/"), n) for n in sorted(
            (n for n in os.listdir(folder) if n.endswith(".jsonl")),
            key=_first_seq)]

    def get(self, key):
        prefix, _, name = key.rpartition("/")
        with open(os.path.join(self._folder(prefix), name), "rb") as handle:
            return handle.read()


class LogAlerts:
    """Alerts as JSON lines on stderr, which systemd keeps in the journal:
    the alert channel of a site with no SNS."""

    def __init__(self, site: str):
        self.site = site

    def __call__(self, severity, message, fields):
        print(json.dumps(dict(fields, alert=severity, site=self.site,
                              message=message), sort_keys=True, default=str),
              file=sys.stderr, flush=True)


class NoHeartbeat:
    """No CloudWatch, so nothing notices a silent signer: a development
    site only."""

    def beat(self, paused: int, failing: int = 0):
        pass


class S3Uploader:
    def __init__(self, bucket: str, region: str):
        import boto3
        self.bucket = bucket
        self.s3 = boto3.client("s3", region_name=region)

    def put(self, key, body, retain_until):
        import base64
        import hashlib
        self.s3.put_object(
            Bucket=self.bucket, Key=key, Body=body,
            ContentMD5=base64.b64encode(hashlib.md5(body).digest()).decode(),
            ObjectLockMode="COMPLIANCE",
            ObjectLockRetainUntilDate=retain_until)

    def newest(self, prefix):
        pager = self.s3.get_paginator("list_objects_v2")
        keys = [obj["Key"] for page in pager.paginate(Bucket=self.bucket,
                                                       Prefix=prefix + "/")
                for obj in page.get("Contents", [])]
        if not keys:
            return None
        key = max(keys, key=_last_seq)
        return key, self.s3.get_object(Bucket=self.bucket,
                                       Key=key)["Body"].read()

    def keys(self, prefix):
        pager = self.s3.get_paginator("list_objects_v2")
        return sorted((obj["Key"] for page in pager.paginate(
            Bucket=self.bucket, Prefix=prefix + "/")
            for obj in page.get("Contents", [])), key=_first_seq)

    def get(self, key):
        return self.s3.get_object(Bucket=self.bucket, Key=key)["Body"].read()


#: Seconds. An alert is best effort -- it is in the ledger either way -- so a
#: slow SNS gets a few seconds and one try, never a minute of retries.
SNS_CONNECT_TIMEOUT = 3
SNS_READ_TIMEOUT = 5


class SnsAlerts:
    def __init__(self, topic_arn: str, region: str, site: str):
        import boto3
        from botocore.config import Config
        self.topic = topic_arn
        self.site = site
        self.sns = boto3.client("sns", region_name=region, config=Config(
            connect_timeout=SNS_CONNECT_TIMEOUT, read_timeout=SNS_READ_TIMEOUT,
            retries={"max_attempts": 1, "mode": "standard"}))

    def __call__(self, severity, message, fields):
        self.sns.publish(TopicArn=self.topic,
                         Subject=("[%s] cl03-signer %s" % (self.site, severity))[:99],
                         Message=json.dumps(dict(fields, message=message),
                                            indent=2, default=str))


class Heartbeat:
    def __init__(self, namespace: str, region: str, site: str):
        import boto3
        self.namespace = namespace
        self.site = site
        self.cw = boto3.client("cloudwatch", region_name=region)

    def beat(self, paused: int, failing: int = 0):
        """Alive, Paused, and Failing: internal failures in a row, so an
        alarm can notice a signer that answers but refuses
        everything."""
        self.cw.put_metric_data(Namespace=self.namespace, MetricData=[
            {"MetricName": "Alive", "Value": 1.0,
             "Dimensions": [{"Name": "Site", "Value": self.site}]},
            {"MetricName": "Paused", "Value": float(paused),
             "Dimensions": [{"Name": "Site", "Value": self.site}]},
            {"MetricName": "Failing", "Value": float(failing),
             "Dimensions": [{"Name": "Site", "Value": self.site}]}])
