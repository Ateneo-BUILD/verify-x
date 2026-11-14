"""
Django settings for verify project.
"""

import os
from pathlib import Path

from django.core.exceptions import ImproperlyConfigured

BASE_DIR = Path(__file__).resolve().parent.parent

DEBUG = os.environ.get("DJANGO_DEBUG", "False").lower() in ("true", "1", "yes")

# The eVerify mock echoes the caller's own POST body back as a verified identity
# and logs it in, so it needs a second, deliberate opt-in on top of DEBUG. One
# stray DJANGO_DEBUG=1 must not be enough to bypass authentication.
# See _mock_login_allowed() in verify/views/everify.py.
EVERIFY_ALLOW_MOCK_LOGIN = os.environ.get(
    "EVERIFY_ALLOW_MOCK_LOGIN", "False"
).lower() in ("true", "1", "yes")

# Keep whole eVerify responses -- every field, and the face -- so the printed
# document's sizing and quality work has real data instead of a cartoon.
# TWO opt-ins on top of each other for the same reason the mock has them: this
# writes complete identity records of real people into a database that rides
# the off-site database backups, and one stray DJANGO_DEBUG=1 must not be enough to
# start it. See accounts/debug_store.py.
EVERIFY_DEBUG_CAPTURE = os.environ.get(
    "EVERIFY_DEBUG_CAPTURE", "False").lower() in ("true", "1", "yes")

# The other opt-in, for a development instance that runs without DEBUG: its
# own host name, which must also be in DJANGO_ALLOWED_HOSTS. Either this or
# DEBUG, beside EVERIFY_DEBUG_CAPTURE, opens the debug store -- so a
# workbench does not need Django's debug pages and insecure cookies to keep
# its eVerify responses. Never set it on a production server.
VERIFY_WORKBENCH = os.environ.get("VERIFY_WORKBENCH", "").strip().lower()

# The only hosts an eVerify address may name -- an organization's, Setup's
# sign-in client and the EVERIFY_BASE_URL fallback alike -- comma-separated.
# Whatever answers there decides who a verified person is, so the list is set
# here by whoever runs the server, and no page can widen it. PSA's API host by
# default; name a stub only on a test site. An empty value allows nothing:
# every lookup stops, loudly, rather than going anywhere.
EVERIFY_ALLOWED_HOSTS = [
    host.strip().lower()
    for host in os.environ.get("EVERIFY_ALLOWED_HOSTS", "ws.everify.gov.ph").split(",")
    if host.strip()]

# The hosts eVerify's portrait links may name, comma-separated. Empty by
# default, which allows any host that resolves only to public addresses: the
# portrait is fetched from this server, so loopback, the private network and
# the instance metadata service are refused whatever this says. The first
# fetch from each host is logged; name it here to narrow the fetch to it.
# See accounts/everify_face.py.
EVERIFY_FACE_HOSTS = [
    host.strip().lower()
    for host in os.environ.get("EVERIFY_FACE_HOSTS", "").split(",")
    if host.strip()]

# The single sign-on issuers Setup may choose, exactly as the provider names
# itself, comma-separated. With SSO selected, the issuer decides who signs in,
# so it is this server's to allow and no page can widen it. Empty by default:
# a site that signs in through SSO names its provider here. An issuer stored
# that is not listed counts as SSO not configured, and the login page offers
# eVerify instead.
SSO_ALLOWED_ISSUERS = [
    issuer.strip().rstrip("/")
    for issuer in os.environ.get("SSO_ALLOWED_ISSUERS", "").split(",")
    if issuer.strip()]

# How many proxies in front of the application append to X-Forwarded-For:
# the load balancer and nginx, on every deployment. The client's address --
# what the per-address limits count (accounts/throttle.py) and a refused
# sign-in records -- is the entry this many from the end, never the first,
# which the client writes itself.
VERIFY_PROXY_HOPS = int(os.environ.get("VERIFY_PROXY_HOPS", "2"))

# How long a refused sign-in takes to answer, in seconds, as (low, high).
# A National ID that names no registered operator never reaches the eVerify
# identity lookup. It still runs the real liveness check -- the two paths are
# the same UI -- and is then answered after a wait drawn from this range, so
# the outcomes are not separable with a stopwatch either. The range is what a
# real signed-out lookup measures; see REFUSAL_DELAY_SECONDS in
# verify/views/login_guard.py, which explains how to re-tune it.
EVERIFY_DECOY_DELAY_SECONDS = (2.0, 5.0)

ALLOWED_HOSTS = os.environ.get("DJANGO_ALLOWED_HOSTS", "localhost,127.0.0.1").split(",")

# The key signs every session and password-reset link, so a known key is a
# login as anybody. This repository is published, which makes any fallback a
# known key -- so a site other machines can reach REFUSES to start without
# DJANGO_SECRET_KEY rather than quietly signing with one. A checkout that
# answers only on this machine keeps a fallback, so tests, `manage.py check`
# and the measuring tools run with no setup.
_LOCAL_ONLY_HOSTS = {"localhost", "127.0.0.1", "[::1]"}
SECRET_KEY = os.environ.get("DJANGO_SECRET_KEY", "")
if not SECRET_KEY:
    if set(ALLOWED_HOSTS) - _LOCAL_ONLY_HOSTS:
        raise ImproperlyConfigured(
            "DJANGO_SECRET_KEY is not set, and DJANGO_ALLOWED_HOSTS names a "
            "host other machines can reach. Set a long random key in the "
            "instance's .env; never use a value from this repository.")
    SECRET_KEY = "django-insecure-local-only-never-on-a-reachable-host"

#: Keys `Transaction.subject_key`, the hash User Records finds a person's
#: transactions by across organizations (accounts/user_records.py). Blank
#: means SECRET_KEY is used. Whichever it is, CHANGING it orphans every key
#: already written: older rows silently stop matching anybody. Set this
#: before SECRET_KEY is ever rotated, and keep it with the site's backups.
USER_RECORDS_KEY = os.environ.get("USER_RECORDS_KEY", "")

INSTALLED_APPS = [
    "django.contrib.admin",
    "django.contrib.auth",
    "django.contrib.contenttypes",
    "django.contrib.sessions",
    "django.contrib.messages",
    "django.contrib.staticfiles",
    "accounts",
]

MIDDLEWARE = [
    "django.middleware.security.SecurityMiddleware",
    "verify.csp.ContentSecurityPolicyMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    "verify.sessions.AbsoluteSessionLifetimeMiddleware",
    "verify.sessions.RefreshSessionMiddleware",
    "django.middleware.common.CommonMiddleware",
    "django.middleware.csrf.CsrfViewMiddleware",
    "django.contrib.auth.middleware.AuthenticationMiddleware",
    "django.contrib.messages.middleware.MessageMiddleware",
    "django.middleware.clickjacking.XFrameOptionsMiddleware",
]

ROOT_URLCONF = "verify.urls"

TEMPLATES = [
    {
        "BACKEND": "django.template.backends.django.DjangoTemplates",
        "DIRS": [BASE_DIR / "templates"],
        "APP_DIRS": True,
        "OPTIONS": {
            "context_processors": [
                "django.template.context_processors.request",
                "django.contrib.auth.context_processors.auth",
                "django.contrib.messages.context_processors.messages",
                "verify.context_processors.app_version",
                "verify.context_processors.branding",
                "verify.context_processors.org_context",
                "verify.csp.nonce",
            ],
        },
    },
]

WSGI_APPLICATION = "verify.wsgi.application"

DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.sqlite3",
        "NAME": BASE_DIR / "db.sqlite3",
    }
}

AUTH_PASSWORD_VALIDATORS = [
    {"NAME": "django.contrib.auth.password_validation.UserAttributeSimilarityValidator"},
    {"NAME": "django.contrib.auth.password_validation.MinimumLengthValidator"},
    {"NAME": "django.contrib.auth.password_validation.CommonPasswordValidator"},
    {"NAME": "django.contrib.auth.password_validation.NumericPasswordValidator"},
]

LANGUAGE_CODE = "en-us"
TIME_ZONE = "Asia/Manila"
USE_I18N = True
USE_TZ = True

STATIC_URL = "/static/"
STATIC_ROOT = BASE_DIR / "staticfiles"
STATICFILES_DIRS = [BASE_DIR / "static"]

# ---------------------------------------------------------------------------
# Branding
# ---------------------------------------------------------------------------
# The deployment's own name and logos. Nothing here names any particular
# organization: with none of these set, pages are titled "Verify" and carry
# no footer. See verify/branding.py.

#: The name before the colon in every page title.
SITE_TITLE = os.environ.get("SITE_TITLE", "").strip() or "Verify"

#: Footer logos: "file|link|alt text" entries separated by ";", each file in
#: BRANDING_DIR. The link and the text are optional.
SITE_FOOTER_LOGOS = os.environ.get("SITE_FOOTER_LOGOS", "")

#: A line above the footer logos, such as "Operated by". Empty draws none.
SITE_FOOTER_LABEL = os.environ.get("SITE_FOOTER_LABEL", "")

#: The folder the footer logos are in. collectstatic copies it to
#: /static/branding/, so they are served like every other static file. It
#: lives outside the application directory, which deploy.sh rewrites.
BRANDING_DIR = os.environ.get("BRANDING_DIR", "")
if BRANDING_DIR and os.path.isdir(BRANDING_DIR):
    STATICFILES_DIRS.append(("branding", BRANDING_DIR))

# One cache-buster for every process serving these files; see
# verify/static_version.py for why it is not the start time any more.
from verify.static_version import static_version as _static_version
APP_VERSION = _static_version(STATICFILES_DIRS)

DEFAULT_AUTO_FIELD = "django.db.models.BigAutoField"

# Session timeout: 4 hours after the last request. The session is saved when
# it changes, and otherwise at most once every SESSION_REFRESH_SECONDS, by
# verify.sessions.RefreshSessionMiddleware -- not on every request, which
# rewrote the verified person's rows and face on four requests out of six.
SESSION_COOKIE_AGE = 14400
SESSION_SAVE_EVERY_REQUEST = False
SESSION_REFRESH_SECONDS = 300

# However busy it is, a sign-in ends this long after it was made: 12 hours, a
# working day and a margin (verify.sessions.AbsoluteSessionLifetimeMiddleware).
SESSION_ABSOLUTE_SECONDS = int(os.environ.get("SESSION_ABSOLUTE_SECONDS", "43200"))

# Logging
LOGGING = {
    "version": 1,
    "disable_existing_loggers": False,
    "formatters": {
        "verbose": {
            "format": "{asctime} {levelname} {name} {message}",
            "style": "{",
        },
    },
    "handlers": {
        "console": {
            "class": "logging.StreamHandler",
            "formatter": "verbose",
        },
    },
    "root": {
        "handlers": ["console"],
        "level": "INFO",
    },
}

# Always trust HTTPS origins from ALLOWED_HOSTS (a load balancer terminates TLS)
SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https")
CSRF_TRUSTED_ORIGINS = [f"https://{h.strip()}" for h in ALLOWED_HOSTS if h.strip() and h.strip() != "*"]

# Additional security settings for production
if not DEBUG:
    SESSION_COOKIE_SECURE = True
    CSRF_COOKIE_SECURE = True
    SECURE_BROWSER_XSS_FILTER = True
    SECURE_CONTENT_TYPE_NOSNIFF = True
    X_FRAME_OPTIONS = "DENY"
    # Browsers that have been here once refuse plain http for this host for a
    # year. Sent on https responses only, which is every one behind the load
    # balancer. This host only, not its siblings:
    # VERIFY_HSTS_INCLUDE_SUBDOMAINS is the owner of the domain's to set.
    SECURE_HSTS_SECONDS = int(os.environ.get("VERIFY_HSTS_SECONDS", "31536000"))
    SECURE_HSTS_INCLUDE_SUBDOMAINS = os.environ.get(
        "VERIFY_HSTS_INCLUDE_SUBDOMAINS", "False").lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Offline credentials
# ---------------------------------------------------------------------------
# The signed, encrypted credential carried in a verification document's QR.
# See accounts/credentials.py.
#
# These deliberately MIRROR the sibling OfflineVerifier deployment rather than
# being chosen independently. Two of them cannot be chosen independently at
# all:
#
#   * the ISSUER KEY is the one whose public half is already in the trust list
#     that enrolled phones carry. Sign with a different key and every
#     credential reads as `forged` until somebody registers the new one.
#   * the EPOCH POLICY numbers the audience keys. Genesis and epoch length are
#     what turn a timestamp into an epoch number, and a credential is bound to
#     the epoch it was minted in. A different genesis silently renumbers
#     everything, and a phone then reports `device_stale` for a document that
#     is perfectly good.
#
# `manage.py load_credential_keys` copies them across and refuses when they
# disagree, which is the only way this stays true after somebody edits a .env.

#: PEM holding the issuer private key. Deliberately OUTSIDE the application
#: directory: deploy.sh rsyncs with --delete, and db.sqlite3 rides the off-site
#: database backups, so neither is a place for it.
CREDENTIAL_ISSUER_KEY_PATH = os.environ.get("CREDENTIAL_ISSUER_KEY_PATH", "")

#: Names the key inside a credential, and must match the trust-list entry.
CREDENTIAL_ISSUER_KEY_ID = int(os.environ.get("CREDENTIAL_ISSUER_KEY_ID", "1"))

#: After a signer: the key file signs only once this names its key id, the
#: operator's word that the signer's last deployment key was that same key
#: (signer/deploy/README.md).
CREDENTIAL_FILE_MODE_AFTER_SIGNER = os.environ.get(
    "CREDENTIAL_FILE_MODE_AFTER_SIGNER", "")

#: The credential signer's app socket (signer/deploy/README.md). Set, and the
#: signer holds every issuer key: it signs credentials, bundles, feeds and
#: log-key statements under its own policy, and CREDENTIAL_ISSUER_KEY_PATH is
#: no longer read. Empty keeps the PEM file -- unless SIGNER_QUEUE_KEY is set.
SIGNER_SOCKET = os.environ.get("SIGNER_SOCKET", "")

#: The other way to reach a signer: it dials out. Where the app servers come
#: and go, as in an Auto Scaling group replaced at every release, the signer
#: lives on a host of its own and long-polls this site over HTTPS
#: (signer/deploy/README.md, "Poll mode"). Each request is queued as a job in
#: the database every app server shares (`accounts.signer_queue`), and the
#: signer collects it from GET /api/v1/signer/jobs/ and posts its answer to
#: POST /api/v1/signer/answers/. The answer is what the socket would have
#: said, so every caller reads it the same way.
#:
#: SIGNER_QUEUE_KEY is the key both ends sign with: 32 bytes, as 64 hex
#: characters or base64 -- the same value as the signer's credential
#: `poll-key`. Set, with SIGNER_SOCKET empty, and this site is in signer
#: mode through the queue; SIGNER_SOCKET wins when both are set. Empty, and
#: both endpoints answer 404. The key is on every app server, so anyone with
#: a copy can act as the signer from any address the proxy admits: a site in
#: this mode admits /api/v1/signer/jobs/, /api/v1/signer/answers/ and, for
#: the reconciler, /api/v1/signer/report/ only from the signer's own egress
#: addresses, and serves them from a gunicorn pool of their own. This
#: repository's own nginx answers 404 for all of /api/v1/signer/, which is
#: right for socket mode.
#: Generate one with  python -c "import secrets; print(secrets.token_hex(32))"
SIGNER_QUEUE_KEY = os.environ.get("SIGNER_QUEUE_KEY", "")
#: How long a request waits for the signer's answer before it is given up:
#: a credential then prints as the plain QR (its row kept as `unknown` if the
#: signer had collected it), and a phone's sync is refused and retried.
SIGNER_QUEUE_TIMEOUT_SECONDS = int(
    os.environ.get("SIGNER_QUEUE_TIMEOUT_SECONDS", "10"))
#: How many of one process's threads may wait for the signer at once; one
#: more waits up to a second for a place, then is refused, as a signer that
#: did not answer. It stays below gunicorn's threads a worker: the signer's
#: answer and its poll are requests too, and on a worker whose every thread
#: waited they would queue behind the waits until each timed out. It is a
#: backstop that counts only the waiting threads, never one holding the
#: signer's long poll, so a poll-mode site still serves /api/v1/signer/ from
#: a gunicorn pool of its own (signer/deploy/README.md, "Poll mode").
#:
#: The default is one fewer than GUNICORN_THREADS, else 1. The app cannot
#: read gunicorn's configuration, so GUNICORN_THREADS is how it learns the
#: threads a worker has: the site kit's deploy/gunicorn.conf.py reads the
#: same variable (2 when unset), so one value in .env sets both. A gunicorn
#: configured any other way must be told the same number here.
GUNICORN_THREADS = int(os.environ.get("GUNICORN_THREADS", "0") or 0)
SIGNER_QUEUE_MAX_WAITING = int(
    os.environ.get("SIGNER_QUEUE_MAX_WAITING", "")
    or max(1, GUNICORN_THREADS - 1))

#: SHA-256 fingerprints (hex, comma-separated) of the issuing CAs the phones
#: pin. Setup shows whether the signer's anchors match them.
CREDENTIAL_ISSUER_CA_FINGERPRINTS = [
    value.strip().lower() for value in
    os.environ.get("CREDENTIAL_ISSUER_CA_FINGERPRINTS", "").split(",")
    if value.strip()]

#: SHA-256 (hex) of the token the signer's reconciler presents to
#: /api/v1/signer/report/. Only the hash is kept here. Empty: no report.
SIGNER_REPORT_TOKEN_SHA256 = os.environ.get("SIGNER_REPORT_TOKEN_SHA256", "")

#: Epoch policy. The defaults are OfflineVerifier's shipped values; changing
#: one without changing it there orphans every credential already printed.
CREDENTIAL_GENESIS = int(os.environ.get("CREDENTIAL_GENESIS", "1750000000"))
CREDENTIAL_EPOCH_SECONDS = int(
    os.environ.get("CREDENTIAL_EPOCH_SECONDS", "2592000"))
CREDENTIAL_OVERLAP_EPOCHS = int(
    os.environ.get("CREDENTIAL_OVERLAP_EPOCHS", "3"))

#: Base64 AES key wrapping epoch private keys at rest. Epoch keys must be
#: exportable -- phones need them -- so unlike the signing key they cannot
#: simply live in a file the process never reads. Losing this orphans every
#: stored epoch key.
CREDENTIAL_EPOCH_WRAP_KEY = os.environ.get("CREDENTIAL_EPOCH_WRAP_KEY", "")

#: The longest a credential may be valid, and so the most Setup lets a site
#: choose. The validity itself is `SiteSettings.credential_validity_days`. This
#: is V in the signer's certificate rule, so it must equal the signer's
#: `credential_max_days`. A phone keeps an epoch's key until the last credential
#: minted under it expires (`credential_keys.keep_readable_until`), which is what
#: a long validity costs: more keys on every phone, for longer.
CREDENTIAL_MAX_VALIDITY_DAYS = int(
    os.environ.get("CREDENTIAL_MAX_VALIDITY_DAYS", "365"))

#: The most QR codes one document may print: the credential, its portrait and
#: every attachment part. 2, the default, is what a verify document prints -- a
#: credential and its portrait, with any attachment carried inline. 0 is no
#: cap. Issuance past it is refused, never cut short: a phone cannot tell a cap
#: from a code that was left off the page.
CREDENTIAL_MAX_QR_CODES = int(os.environ.get("CREDENTIAL_MAX_QR_CODES", "2"))
if CREDENTIAL_MAX_QR_CODES < 0 or CREDENTIAL_MAX_QR_CODES == 1:
    raise ImproperlyConfigured(
        "CREDENTIAL_MAX_QR_CODES must be 0 (no cap) or at least 2: a document "
        "with a photo prints its credential and its portrait.")

#: How long a signed revocation feed stays acceptable to a device. This is the
#: window in which a suppressed revocation could be hidden by replaying an
#: older feed, so shorter is safer -- bounded below by how often devices can
#: reasonably poll.
CREDENTIAL_REVOCATION_TTL_SECONDS = int(
    os.environ.get("CREDENTIAL_REVOCATION_TTL_SECONDS", str(24 * 60 * 60)))

#: How often the filter is rebuilt. Must stay well under the TTL above, or
#: devices would be served feeds they are about to reject.
CREDENTIAL_REVOCATION_REBUILD_SECONDS = int(
    os.environ.get("CREDENTIAL_REVOCATION_REBUILD_SECONDS", "300"))


# ---------------------------------------------------------------------------
# Verifier devices
# ---------------------------------------------------------------------------
# Pairing a phone and giving it keys. See accounts/devices.py.

#: Where the pairing QR tells the phone to connect. Empty means "whatever host
#: served the page", which is right on a LAN and right in production, and
#: wrong in exactly one case -- a browser reaching the site as localhost or
#: through a tunnel -- which the page reports rather than shipping silently.
DEVICE_PAIRING_BASE_URL = os.environ.get("DEVICE_PAIRING_BASE_URL", "")

#: How long a pairing code lives. Short on purpose: it is single-use and it is
#: displayed on a screen, so its whole job is to survive walking a phone over.
DEVICE_PAIRING_TTL_SECONDS = int(
    os.environ.get("DEVICE_PAIRING_TTL_SECONDS", "900"))

#: How long the keys handed to a device stay good before it must sync again.
#: An expired lease is not a revocation -- the phone simply has to check in.
DEVICE_LEASE_SECONDS = int(
    os.environ.get("DEVICE_LEASE_SECONDS", str(30 * 24 * 60 * 60)))

#: How long a sync challenge is accepted. Seconds, not minutes: it exists to
#: be signed and returned immediately, and a longer window is only a longer
#: window for a captured one.
DEVICE_CHALLENGE_TTL_SECONDS = int(
    os.environ.get("DEVICE_CHALLENGE_TTL_SECONDS", "120"))

#: Apple App Attest. Every pairing's attestation and every sync's assertion
#: is checked against Apple's root and recorded on the device, whatever this
#: says. On, anything but a pass is refused: the setting for a site whose
#: phones run store builds, once one of them has paired and passed, since
#: Apple attests store builds in its production environment, which no
#: development build exercises. Off -- check and record -- refuses nothing.
#: Holder phones that idmanager registers are not refused (public tier only,
#: on idmanager's signed word); idmanager pairing as a verifier by code does
#: not attest, and is refused.
DEVICE_REQUIRE_APP_ATTEST = os.environ.get(
    "DEVICE_REQUIRE_APP_ATTEST", "False").lower() in ("true", "1", "yes")

#: "<TeamID>.<BundleID>" of the app builds that pair here. Empty, nothing can
#: be attested: recorded as "not configured", and refused if required.
DEVICE_APP_ATTEST_APP_ID = os.environ.get("DEVICE_APP_ATTEST_APP_ID", "")

#: The App Attest environment the app is signed for: "production" for store
#: and beta builds, "development" for builds installed by a developer.
DEVICE_APP_ATTEST_ENVIRONMENT = os.environ.get(
    "DEVICE_APP_ATTEST_ENVIRONMENT", "production")

#: Refuse a /keys/ request signed over the bare challenge. Current builds
#: of the verifier app and idmanager sign it behind a context and say
#: "keys-context". Turn this on once no phone runs an older build,
#: idmanager's included; HOLDER_REQUIRE_CONTEXT goes with it.
DEVICE_REQUIRE_KEYS_CONTEXT = os.environ.get(
    "DEVICE_REQUIRE_KEYS_CONTEXT", "False").lower() in ("true", "1", "yes")

#: How many activity-log records one phone may have stored here in any 24
#: hours. Past it an upload stores the oldest records up to the cap and
#: acknowledges only those, and the next one is answered 429: the phone keeps
#: the rest and sends them on a later day. A record is at most
#: `device_log.MAX_RECORD_BYTES`, so this bounds the bytes too.
DEVICE_LOG_DAILY_RECORDS = int(
    os.environ.get("DEVICE_LOG_DAILY_RECORDS", "20000"))

#: How long the activity log is kept, in days from when a record arrived
#: here. `purge_device_logs` deletes what is older, run daily by the timer
#: every deploy installs (deploy/install-purge-timer.sh). 360 by default;
#: set it for the deployment. At least 1: the command refuses less.
DEVICE_LOG_RETENTION_DAYS = int(
    os.environ.get("DEVICE_LOG_RETENTION_DAYS", "360"))

# ---------------------------------------------------------------------------
# Holders registered from idmanager
# ---------------------------------------------------------------------------
# Somebody who verified THEMSELVES in idmanager -- eVerify and liveness there --
# registers their own phone here and is issued a credential, with no operator
# involved. See accounts/holders.py for why it is shaped the way it is.
#
# OFF unless both of the first two are set. What this deployment trusts is
# "idmanager signed this", so the pinned keys ARE the trust decision, and an
# empty value is the feature switched off -- the endpoint answers 404.

#: idmanager's base URL, exactly as it writes it in an assertion's `iss`.
HOLDER_ASSERTION_ISSUER = os.environ.get(
    "HOLDER_ASSERTION_ISSUER", "").strip().rstrip("/")

#: idmanager's PUBLIC signing keys, comma-separated `kid:<base64 DER SPKI>`.
#: More than one so a key can be rotated without a gap. idmanager prints the
#: line for its own key with `manage.py verify_holder_key`.
HOLDER_ASSERTION_KEYS = os.environ.get("HOLDER_ASSERTION_KEYS", "")

#: The longest an assertion may claim to live, `exp - iat`. idmanager issues
#: them for five minutes; one claiming longer is refused, not trimmed.
HOLDER_ASSERTION_MAX_LIFETIME_SECONDS = int(
    os.environ.get("HOLDER_ASSERTION_MAX_LIFETIME_SECONDS", "600"))

#: How recent the person's own eVerify + liveness check must be when the
#: phone arrives here. The check is what the credential attests, so a stale
#: one is refused rather than re-dated.
HOLDER_VERIFICATION_MAX_AGE_SECONDS = int(
    os.environ.get("HOLDER_VERIFICATION_MAX_AGE_SECONDS", "900"))

#: The issuer line a holder's credential carries -- what a verifier reads in
#: place of an organization. It says what happened, so nobody takes a
#: self-verification for one an operator ran at a counter.
HOLDER_CREDENTIAL_ISSUER_NAME = os.environ.get(
    "HOLDER_CREDENTIAL_ISSUER_NAME", "Self-verified with idmanager")

#: Refuse a holder registration or Wallet-pass request signed over the bare
#: challenge. idmanager builds that sign behind each endpoint's context say
#: "holder-context". While this or DEVICE_REQUIRE_KEYS_CONTEXT is off, a bare
#: signature an older app sent to the wrong host could be spent at /keys/ or a
#: holder endpoint while its challenge lives. Turn it on once no holder phone
#: runs an older idmanager.
HOLDER_REQUIRE_CONTEXT = os.environ.get(
    "HOLDER_REQUIRE_CONTEXT", "False").lower() in ("true", "1", "yes")

#: How long a card hand-off outlasts a browser that closed without releasing
#: it. The ordinary end is `pagehide` on the document page; this is only the
#: backstop for a lid closed mid-transaction, so it is short. It is the outer
#: bound on how long an identity sits in `card_handoffs` -- see the model.
CARD_HANDOFF_TTL_SECONDS = int(
    os.environ.get("CARD_HANDOFF_TTL_SECONDS", "300"))

#: Which encoder draws the holder's face in the portrait symbol: "webp", what
#: every verifier app in the field reads, or "avif", about 0.05 of face SSIM
#: sharper at the same bytes and readable only by an app that knows `CL03F2:`.
#: Switch it only once the verifier app AND idmanager that read the symbol
#: have shipped that -- a document printed before then shows no face on an
#: older phone. Anything else, or AVIF without the encoder, means WebP.
PORTRAIT_FORMAT = os.environ.get("PORTRAIT_FORMAT", "webp")

# ---------------------------------------------------------------------------
# Apple Wallet
# ---------------------------------------------------------------------------
# The same hand-off, offered to an iPhone as a `.pkpass` carrying the offline
# credential in its barcode and the portrait as its thumbnail.
#
# All five are required together and the feature is simply absent without
# them: `wallet_pass.configured()` is what the card page asks, and an
# unconfigured deployment never draws the button rather than drawing one that
# fails when pressed -- the shape the fingerprint reader and the credential
# mint already use.
#
# The certificate and its key are Apple's, issued against a Pass Type ID, and
# they live OUTSIDE the application directory for the reason
# CREDENTIAL_ISSUER_KEY_PATH does: deploy.sh rsyncs with --delete, and
# db.sqlite3 rides the off-site database backups, so neither is a place for a
# signing key.
WALLET_PASS_TYPE_ID = os.environ.get("WALLET_PASS_TYPE_ID", "")
WALLET_TEAM_ID = os.environ.get("WALLET_TEAM_ID", "")
WALLET_CERT_PATH = os.environ.get("WALLET_CERT_PATH", "")
WALLET_KEY_PATH = os.environ.get("WALLET_KEY_PATH", "")
#: Apple's Worldwide Developer Relations intermediate, PEM. A pass signed
#: without the chain up to it is refused on the device with no message.
WALLET_WWDR_PATH = os.environ.get("WALLET_WWDR_PATH", "")
