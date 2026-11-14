"""Fetching the portrait an eVerify answer points at.

An answer names the person's portrait by URL, `face_url`: a signed link that
expires. verify downloads it and hands the browser the bytes, never the link.
Whatever URL the answer carries is fetched FROM THIS SERVER, so an
unchecked one could make the server read any address it can reach -- the
instance metadata service, which hands out the instance role's keys, loopback
services, the private network -- and send the body on to the operator's
browser as "the face".

So nothing is fetched unless every step holds:

  * https, with the certificate checked;
  * a host name, never an address, on the default port; every address the
    name resolves to is a public one (not loopback, private, link-local,
    shared, reserved or multicast);
  * redirects followed by hand, at most MAX_REDIRECTS, each target judged by
    the same rule before anything is sent to it;
  * at most MAX_BYTES of body, read within DEADLINE seconds -- in reads of at
    most CHUNK bytes, each allowed only the time left, so a server that sends
    its body a byte at a time is cut off at the deadline rather than after a
    whole chunk;
  * bytes that ARE an image -- JPEG, PNG or WebP by their signature. The type
    the server claims is not trusted, and the data URI carries the sniffed one.

There is no host allow-list by default. Which host serves PSA's signed
portrait links is recorded nowhere this repository can see, and naming the
wrong one would drop every real portrait without a sound. The first fetch
from each host is logged, and EVERIFY_FACE_HOSTS narrows the fetch to the
hosts named once that is known.

Resolving first and connecting after leaves the usual window for a name that
resolves differently the second time. https is what closes it: an internal
service answering for an outside name would have to present a certificate
for that name, and the metadata service does not speak TLS at all.
"""

import base64
import ipaddress
import logging
import socket
import time
from urllib.parse import urljoin, urlparse

import requests
from django.conf import settings
from urllib3.exceptions import HTTPError, LocationParseError
from urllib3.util import parse_url

from .everify_address import _UNSAFE

logger = logging.getLogger(__name__)

#: A portrait is tens of kilobytes; this is far above any eVerify has sent.
MAX_BYTES = 2 * 1024 * 1024
MAX_REDIRECTS = 3
#: Per connect and per read, as `requests` counts them.
TIMEOUT = 10
#: For the whole fetch, redirects included, so a server that drips its body
#: cannot hold a verification open a read timeout at a time. A request is
#: only started inside it; connecting and reading the headers are bounded
#: by TIMEOUT each.
DEADLINE = 20
#: Bytes asked for per read. One read returns whatever one receive gives.
CHUNK = 16 * 1024

#: Hosts already logged, so each appears once per process.
_SEEN = set()


def face_hosts():
    return [host.lower() for host in getattr(settings, "EVERIFY_FACE_HOSTS", [])]


def _host(url):
    try:
        return (urlparse(url or "").hostname or "").lower()
    except ValueError:
        return ""


def _public(address):
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return False
    if ip.version == 6 and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not (ip.is_multicast or ip.is_reserved)


def _addresses(host):
    """Every address `host` resolves to, or None if it does not resolve."""
    try:
        infos = socket.getaddrinfo(host, 443, type=socket.SOCK_STREAM)
    except (OSError, UnicodeError):
        return None
    return {info[4][0] for info in infos}


def refusal(url):
    """Why `url` may not be fetched, or None if it may."""
    if not isinstance(url, str) or not url:
        return "no address"
    if _UNSAFE.search(url):
        return "characters URL parsers disagree about"
    try:
        ours, theirs = urlparse(url), parse_url(url)
        port = ours.port
    except (ValueError, LocationParseError):
        return "not a URL"
    if ours.scheme != "https" or theirs.scheme != "https":
        return "not https"
    host = (ours.hostname or "").lower()
    if not host:
        return "no host"
    try:
        ipaddress.ip_address(host)
        return "an address, not a host name"
    except ValueError:
        pass
    if (theirs.host or "").lower() != host:
        return "the two URL parsers name different hosts"
    if port not in (None, 443):
        return "not the default port"
    allowed = face_hosts()
    if allowed and host not in allowed:
        return "a host EVERIFY_FACE_HOSTS does not list"
    addresses = _addresses(host)
    if not addresses:
        return "a host that does not resolve"
    if not all(_public(address) for address in addresses):
        return "a host that resolves to a non-public address"
    return None


def _sniff(body):
    if body.startswith(b"\xff\xd8\xff"):
        return "image/jpeg"
    if body.startswith(b"\x89PNG\r\n\x1a\n"):
        return "image/png"
    if body[:4] == b"RIFF" and body[8:12] == b"WEBP":
        return "image/webp"
    return None


def _socket(response):
    """The connection's socket, to bound each read by the time left, or
    None when urllib3 does not expose it."""
    return getattr(getattr(response.raw, "connection", None), "sock", None)


def _read(response, deadline):
    """The body, or None if it is larger than MAX_BYTES or too slow."""
    declared = response.headers.get("Content-Length", "")
    if declared.isdigit() and int(declared) > MAX_BYTES:
        return None
    sock = _socket(response)
    chunks, size = [], 0
    try:
        while True:
            left = deadline - time.monotonic()
            if left <= 0:
                return None
            if sock is not None:
                sock.settimeout(min(TIMEOUT, left))
            chunk = response.raw.read1(CHUNK, decode_content=True)
            if not chunk:
                return b"".join(chunks)
            size += len(chunk)
            if size > MAX_BYTES:
                return None
            chunks.append(chunk)
    except (OSError, HTTPError):  # a read that ran out of time, or broke
        return None


def _refused(why, url):
    # The host only: the URL is a signed link to a person's photo.
    logger.warning("eVerify portrait not fetched: %s (host %r)", why, _host(url))
    return None


def data_uri(url):
    """The portrait at `url` as a data: URI, or None. Never raises: a
    portrait that cannot be fetched leaves the document without one, it does
    not cost the verification."""
    try:
        return _fetch(url)
    except Exception:
        logger.exception("eVerify portrait not fetched (host %r)", _host(url))
        return None


def _fetch(url):
    deadline = time.monotonic() + DEADLINE
    for _ in range(MAX_REDIRECTS + 1):
        why = refusal(url)
        if why:
            return _refused(why, url)
        if time.monotonic() > deadline:
            return _refused("out of time before the request", url)
        try:
            with requests.get(url, timeout=TIMEOUT, allow_redirects=False,
                              stream=True) as response:
                if response.is_redirect:
                    url = urljoin(url, response.headers["Location"])
                    continue
                if response.status_code != 200:
                    return _refused("status %d" % response.status_code, url)
                body = _read(response, deadline)
        except requests.RequestException as error:
            return _refused("connection error: %s" % type(error).__name__, url)
        if body is None:
            return _refused("larger than %d bytes or too slow" % MAX_BYTES, url)
        kind = _sniff(body)
        if kind is None:
            return _refused("not a JPEG, PNG or WebP image", url)
        host = _host(url)
        if host not in _SEEN:
            _SEEN.add(host)
            logger.info("eVerify portrait fetched from host %r", host)
        return "data:%s;base64,%s" % (kind, base64.b64encode(body).decode("ascii"))
    return _refused("more than %d redirects" % MAX_REDIRECTS, url)
