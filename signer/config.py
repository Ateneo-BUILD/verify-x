"""What the signer is told: validity rules, ceilings, anchors and legacy keys.

Read from a TOML file the operator owns (`signer/deploy/policy.example.toml`).
Nothing here comes from verify: a value verify could set is a value an
application compromise could set.
"""

from __future__ import annotations

import base64
from dataclasses import dataclass, field

from ovcrypto import bundle as bundle_mod

DAY = 86400

#: Contexts a ceiling or a pause can name.
CREDENTIAL = "credential"
BUNDLE = "bundle"
REVOCATION = "revocation"
LOG_KEY = "log-key"
#: verify's signed acknowledgement of a phone's log upload: one per
#: upload, signed with the key that signs statements.
LOG_ACK = "log-ack"
#: verify's signed time at a phone's sync, over the phone's own nonce: the one
#: time a phone brings its clock's mark back to.
SYNC_TIME = "sync-time"
CONTEXTS = (CREDENTIAL, BUNDLE, REVOCATION, LOG_KEY, LOG_ACK, SYNC_TIME)

#: (per minute, per hour, per day). None means no limit at that window.
DEFAULT_CEILINGS = {
    # Global per context. The bundle budget is a fleet's worth: some 400
    # phones at their own cap, so a few dozen misbehaving ones cannot use it
    # up for everybody.
    (CREDENTIAL, "*"): (60, 1200, 6000),
    (BUNDLE, "*"): (None, 3000, 20000),
    (REVOCATION, "*"): (None, 90, 1500),
    (LOG_KEY, "*"): (None, 3, 10),
    # A phone uploads at most 40 batches a day at verify's own cap of 20,000
    # records; 300 leaves room for retries, and a fleet's worth globally.
    (LOG_ACK, "*"): (None, 3000, 30000),
    # One per bundle at most, so a bundle's own ceilings.
    (SYNC_TIME, "*"): (None, 3000, 20000),
    # Per principal: at most a quarter of the global cap in every window, so
    # it takes at least four principals at their caps -- or a compromised
    # app -- to reach the global one.
    (CREDENTIAL, "organization"): (15, 300, 1500),
    (CREDENTIAL, "operator"): (10, 120, 600),
    (CREDENTIAL, "holder"): (15, 300, 1500),
    (CREDENTIAL, "holder_id"): (2, 6, 12),
    (BUNDLE, "device"): (None, 12, 48),
    (LOG_ACK, "device"): (None, 60, 300),
    (SYNC_TIME, "device"): (None, 12, 48),
}


@dataclass
class Legacy:
    """A raw key the signer does not hold, listed for credentials it signed."""
    key_id: int
    spki: bytes
    not_before: int
    not_after: int


@dataclass
class Held:
    """A raw key the signer holds and signs with, with no certificate.

    For a development site whose phones still run an app that pins only the
    raw development key (key 1, say): while it signs bundles, feeds
    and statements, those phones keep working, and keys the Organization CA
    certified reach them inside its bundles. Never on a production signer:
    store builds pin no raw key, so nothing it signed would verify there.
    """
    key_id: int
    key_file: str           # a file name in the key directory
    spki: bytes             # the key the file must hold
    not_before: int
    signing_until: int


#: The shortest lease a bundle is signed with. A lease that ends when it
#: starts is over on arrival, and continuity does not guard the sync after
#: it; one this short is a misconfiguration, not a policy.
MIN_LEASE_SECONDS = 3600


def _key_id(value) -> int:
    """A configured key's id: a u32, and never the one a bundle's chains
    digest takes (``bundle.CHAINS_DIGEST_ID``)."""
    key_id = int(value)
    if not 0 < key_id < bundle_mod.CHAINS_DIGEST_ID:
        raise ValueError("a key id is from 1 to %d, not %d"
                         % (bundle_mod.CHAINS_DIGEST_ID - 1, key_id))
    return key_id


@dataclass
class Config:
    credential_max_days: int = 365          # V
    margin_seconds: int = 30 * DAY          # M
    lease_seconds: int = 30 * DAY           # DEVICE_LEASE_SECONDS
    revocation_ttl_seconds: int = DAY
    statement_days: int = 90
    min_signing_days: int = 90              # refuse a certificate leaving less
    clock_skew_seconds: int = 300
    feed_resign_seconds: int = 3600
    feed_min_interval_seconds: int = 60
    statement_resign_seconds: int = DAY
    revocation_growth_per_call: int = 10000  # taken a call; the rest next
    revocation_alert_per_day: int = 1000     # added in a day: a high alert
    trust_list_alert_at: int = 200
    organization_leaf_days: int = 730       # what the Organization CA issues
    # The host phones pair with, which its own HTTPS certificate names. The
    # Organization CA is this site's System CA, "<site_domain> System CA",
    # and lists it; phones trust what it certifies only when it is the site
    # they paired with (signer/deploy/README.md, "The System CA's domain").
    site_domain: str = ""
    app_keys_per_day: int = 20              # keys verify may ask to be made
    # A site admin publishes an organization's key and starts it signing
    # from verify's pages, with no operator on the host. Off unless root
    # turns it on here; the deployment's own keys stay on the host either way.
    site_publishes_organization_keys: bool = False
    # Every key action from verify's pages, by one site admin, with no
    # operator here: publish and start the deployment's keys as well as
    # organizations', unsuspend a key, resume a paused context -- the global
    # credential ceiling's pause included -- and withdraw any published key
    # at once. Legacy and held keys, making a deployment key, the
    # Organization CA and removing revocations stay on the host. Off unless
    # root turns it on here; it is meant for a site whose app servers are
    # replaced at every release. What it costs: a compromised app or a
    # stolen admin session can then suspend or withdraw the deployment key
    # and stop every phone's sync, and a withdrawn key is a tombstone --
    # phones refuse every credential it ever signed, and nothing undoes
    # that. It cannot make a key, since a key still needs a
    # certificate from the PKI (signer/deploy/README.md, "Every key from the
    # site").
    site_controls_all_keys: bool = False
    anchors: list = field(default_factory=list)     # DER issuing CAs
    legacy: list = field(default_factory=list)      # [Legacy]
    held: list = field(default_factory=list)        # [Held]
    ceilings: dict = field(default_factory=lambda: dict(DEFAULT_CEILINGS))

    @property
    def credential_max_seconds(self) -> int:
        return self.credential_max_days * DAY

    def ceiling(self, context: str, principal_kind: str):
        return self.ceilings.get((context, principal_kind))


_INTEGERS = ("credential_max_days", "margin_seconds", "lease_seconds",
             "revocation_ttl_seconds", "statement_days", "min_signing_days",
             "clock_skew_seconds", "feed_resign_seconds",
             "feed_min_interval_seconds", "statement_resign_seconds",
             "revocation_growth_per_call", "revocation_alert_per_day",
             "trust_list_alert_at", "organization_leaf_days",
             "app_keys_per_day")

#: Every name policy.toml may set, by where it may be set. Anything else is
#: refused: a misspelt name would otherwise be a default nobody chose, and
#: in a ceiling an unlimited window.
TOP_LEVEL = _INTEGERS + ("site_domain", "site_publishes_organization_keys",
                         "site_controls_all_keys", "anchors", "legacy", "held",
                         "ceilings", "runtime")
#: The switches policy.toml may set, each a TOML boolean.
_SWITCHES = ("site_publishes_organization_keys", "site_controls_all_keys")
#: Read by `python -m signer` (__main__.py, startup.py), not by `load`,
#: except `transport` and `site_url`, which `load` checks (`runtime_transport`).
RUNTIME = ("site", "db", "keys", "app_socket", "admin_socket", "app_user",
           "app_group", "operators_group", "ledger_dir", "aws_region",
           "ledger_bucket", "ledger_prefix", "sns_topic", "metric_namespace",
           "ship_every_seconds", "report_url", "report_host", "transport",
           "site_url", "ledger_retain_days")
#: How verify reaches the signer: over the app socket on this host, or the
#: signer dials out to the site and long-polls it (`signer/poll.py`).
SOCKET = "socket"
POLL = "poll"
TRANSPORTS = (SOCKET, POLL)
_ENTRIES = {"legacy": ("key_id", "spki", "not_before", "not_after"),
            "held": ("key_id", "key_file", "spki", "not_before",
                     "signing_until"),
            "ceilings": ("context", "principal", "per_minute", "per_hour",
                         "per_day")}


def _refuse_unknown(names, known, where):
    unknown = sorted(set(names) - set(known))
    if unknown:
        raise ValueError("%s: %s not a setting this signer reads"
                         % (where, ", ".join(unknown)))


def load(path: str) -> Config:
    """A Config from TOML. Missing values keep their defaults; a name it
    does not know is refused."""
    import tomllib

    with open(path, "rb") as handle:
        data = tomllib.load(handle)
    if "organization_ca_name" in data:
        raise ValueError("organization_ca_name is no longer read: the "
                         "Organization CA is named after site_domain, as "
                         "\"<site_domain> System CA\"")
    _refuse_unknown(data, TOP_LEVEL, "policy.toml")
    runtime = data.get("runtime", {})
    if not isinstance(runtime, dict):
        raise ValueError("runtime is a [runtime] table")
    _refuse_unknown(runtime, RUNTIME, "[runtime]")
    runtime_transport(runtime)
    runtime_retain_days(runtime)
    for table, known in _ENTRIES.items():
        for item in data.get(table, []):
            if not isinstance(item, dict):
                raise ValueError("%s is a list of [[%s]] tables" % (table, table))
            _refuse_unknown(item, known, "[[%s]]" % table)
    cfg = Config()
    for name in _INTEGERS:
        if name in data:
            setattr(cfg, name, int(data[name]))
    if cfg.lease_seconds < MIN_LEASE_SECONDS:
        raise ValueError("lease_seconds is at least %d" % MIN_LEASE_SECONDS)
    if "site_domain" in data:
        from ovcrypto import pki
        cfg.site_domain = pki.check_site_domain(data["site_domain"])
    for name in _SWITCHES:
        if name in data:
            value = data[name]
            # A quoted "false" is a non-empty string, which bool() reads as
            # yes.
            if not isinstance(value, bool):
                raise ValueError("%s is true or false, unquoted" % name)
            setattr(cfg, name, value)
    for path_ in data.get("anchors", []):
        with open(path_, "rb") as handle:
            cfg.anchors.append(handle.read())
    for item in data.get("legacy", []):
        cfg.legacy.append(Legacy(_key_id(item["key_id"]),
                                 base64.b64decode(item["spki"]),
                                 int(item["not_before"]),
                                 int(item["not_after"])))
    for item in data.get("held", []):
        cfg.held.append(Held(_key_id(item["key_id"]), str(item["key_file"]),
                             base64.b64decode(item["spki"]),
                             int(item["not_before"]),
                             int(item["signing_until"])))
    for item in data.get("ceilings", []):
        cfg.ceilings.update([_ceiling(item)])
    return cfg


#: Hosts a poll-mode signer may reach over plain http: this machine only, for
#: a test or a tunnel. Anything else is https, so the jobs and their answers
#: are encrypted on the way, not only authenticated.
LOOPBACK_HOSTS = ("127.0.0.1", "::1", "localhost")


def runtime_transport(runtime: dict) -> str:
    """`socket` or `poll`, from the `[runtime]` table, with what poll needs
    checked: `site_url`, the site's own origin, https. Raises ValueError, as
    any other policy the signer will not start with (exit 3)."""
    import urllib.parse

    transport = runtime.get("transport", SOCKET)
    if transport not in TRANSPORTS:
        raise ValueError("[runtime] transport is %s, not %r"
                         % (" or ".join('"%s"' % t for t in TRANSPORTS),
                            transport))
    url = runtime.get("site_url")
    if transport == POLL or url is not None:
        if not isinstance(url, str) or not url:
            raise ValueError('[runtime] transport = "poll" needs site_url, '
                             'the site\'s own https origin')
        parts = urllib.parse.urlsplit(url)
        if (parts.scheme not in ("https", "http") or not parts.hostname
                or parts.path not in ("", "/") or parts.query
                or parts.fragment or parts.username or parts.password):
            raise ValueError("[runtime] site_url is an origin such as "
                             "https://verify.example.ph, not %r" % url)
        if parts.scheme == "http" and parts.hostname not in LOOPBACK_HOSTS:
            raise ValueError("[runtime] site_url is https: the jobs carry "
                             "what the signer signs")
    return transport


#: How long each shipped ledger object is kept under Object Lock, unless the
#: policy says otherwise (`[runtime] ledger_retain_days`).
RETAIN_DAYS = 400


def runtime_retain_days(runtime: dict) -> int:
    """Days each shipped ledger object is locked for: `ledger_retain_days`,
    400 by default, a whole number of at least 1. A development site may
    keep its objects a shorter time; compliance mode means nobody can
    shorten it once written. ValueError otherwise (exit 3)."""
    value = runtime.get("ledger_retain_days", RETAIN_DAYS)
    if isinstance(value, bool) or not isinstance(value, int) or value < 1:
        raise ValueError("[runtime] ledger_retain_days is a whole number of "
                         "days, at least 1, unquoted")
    return value


def _ceiling(item):
    """One [[ceilings]] entry, as ((context, principal), windows). It names
    a ceiling the signer counts, and a window it leaves out keeps the
    default. A context it does not count, and a window that is not an
    unquoted whole number, are refused when the policy is loaded."""
    pair = (item.get("context"), item.get("principal"))
    if pair not in DEFAULT_CEILINGS:
        raise ValueError("[[ceilings]]: no ceiling for context %r, principal %r; "
                         "the signer counts %s" % (pair + (", ".join(
                             sorted("%s/%s" % p for p in DEFAULT_CEILINGS)),)))
    windows = []
    for name, default in zip(("per_minute", "per_hour", "per_day"),
                             DEFAULT_CEILINGS[pair]):
        value = item.get(name, default)
        if value is not None and (isinstance(value, bool)
                                  or not isinstance(value, int) or value < 0):
            raise ValueError("[[ceilings]] %s/%s: %s is a whole number, 0 or "
                             "more, unquoted" % (pair + (name,)))
        windows.append(value)
    return pair, tuple(windows)
