# The credential signer on a verify host (stage 1)

This is how it is put on a verify instance -- or, for a site whose app
servers come and go, on a host of its own that dials out to the site ("Poll
mode", below). Nothing here is applied by Terraform or the deploy scripts;
each step is done by hand and checked.

## Before the signer protects anything: gunicorn without sudo

A host built on Amazon Linux 2023's defaults runs gunicorn as `ec2-user`,
which has passwordless sudo. An application bug is then root, and root can
read the signer's key file. The separation is worth
nothing until gunicorn runs as `verify-app`, a user without sudo:

1. `useradd --system --shell /sbin/nologin verify-app`.
2. Move the app out of `/home/ec2-user` (mode 0700) to `/srv/verify`, owned by
   `ec2-user` for deploys, group `verify-app`, mode 0750. Only `db.sqlite3`,
   its journal, the media folder and the log folder are writable by
   `verify-app`; the code is not.
3. `.env`: owner root, group `verify-app`, mode 0640.
4. Install `gunicorn-verify-app.conf` as
   `/etc/systemd/system/gunicorn.service.d/verify-app.conf`, and update the
   unit's paths.
5. Update the site's deploy scripts, and any backup of `db.sqlite3` and
   `.env`, for the new path.
6. Check: `sudo -u verify-app sudo -n true` must fail.

## Install

    sudo sh signer/deploy/install.sh verify-app     # the user gunicorn runs as

Run it from a checkout, or from `git archive <commit> signer ovcrypto`
unpacked on the host, since a deploy that leaves `deploy/` folders off the
instance leaves `signer/deploy/` off too. It needs Python 3.11 or later
and picks one (Amazon Linux 2023's `python3` is 3.9). It creates `cl03-signer`, the `cl03-operators` group, and `cl03-signer-app`, the
app socket's group, and puts the app user in it (restart gunicorn for that to
take). Then:

- `/etc/cl03-signer/policy.toml`: the anchors (the issuing CA, DER), any legacy
  keys, the AWS names under `[runtime]`.
- `/etc/cl03-signer/credstore/`: `aws-access-key-id`, `aws-secret-access-key`
  (an IAM user with `s3:PutObject`, `s3:PutObjectRetention`, `s3:GetObject`
  and `s3:ListBucket` on the ledger prefix, `sns:Publish` on the topic,
  `cloudwatch:PutMetricData` in the `CL03Signer` namespace), and
  `report-token` (`openssl rand -hex 32`; its SHA-256 goes in the site's
  `SIGNER_REPORT_TOKEN_SHA256`). Mode 0600, root. `signer/deploy/terraform/` makes the
  bucket, the topic and its email, that user and the alarms below; make the
  user's access key by hand afterwards, so it is never in Terraform state.
- Operators: `usermod -aG cl03-operators <name>`, one account each. The admin
  socket reads the group at every connection: removing somebody takes effect
  immediately, with no restart. A new member signs in again first, since the
  socket's own permissions see only the groups their login started with.
- `systemctl enable --now cl03-signer cl03-signer-reconcile.timer`.

The ledger bucket has Object Lock in compliance mode and versioning; the
alarm on the `Alive` metric treats missing data as breaching. The heartbeat
also sends `Failing`, the internal failures in a row: alarm on it above zero
for two periods, since a signer that answers but refuses everything still
beats. `cl03signer status` shows the same count under `internal_failures`, per
operation, and each failure is in the journal (a full traceback at most once
a minute). All three alarms, `Paused` too, are in `signer/deploy/terraform/`.

Running `install.sh` again updates the code and restarts a running signer.
It stages the new code beside the running copy, runs that code's `signer
check` against the live policy (a refusal changes nothing), swaps it in, and records
the commit in `/opt/cl03-signer/COMMIT` (from a checkout, or from
`signer/COMMIT`, which `git archive` fills in). A deploy of verify never
updates the signer: `cl03signer status` carries a digest of the code it runs
(`code`), Setup says in red when it differs from the site's own `signer/`
and `ovcrypto/`; a site's deploy script is the place to print a reminder.

The reconcile timer also sends the warnings before anything runs out -- a
signing key's window at 120, 90, 45 and 14 days and when it ends, the
Organization CA's last day to certify a key, the issuing CA at two years and
one -- and, once a day, a summary carrying the ledger's newest hash, a
witness to it outside this host (`signer/watch.py`). On a site with no AWS
they go to the journal: `journalctl -u cl03-signer-reconcile`.

## After editing policy.toml

    cd /opt/cl03-signer && sudo -u cl03-signer venv/bin/python -m signer check \
        --config /etc/cl03-signer/policy.toml

It loads the policy and seeds it against a read-only copy of the database in
memory, exactly as a start would, changing nothing, and says why a start
would fail.

## When it will not start

A configuration that does not load (exit 3) or a ledger the bucket is ahead
of (exit 2) stops the signer, sends one "highest" alert, and stays stopped:
the unit does not restart on either. Nothing signs and no phone syncs
meanwhile. Any other failure, such as S3 or DNS not answering yet at boot, is
retried every five seconds.

A legacy or held key whose window in `policy.toml` differs from the one it
was first given is a configuration that does not load: the registry never
takes a window from the policy after the first start. Put the window back;
end a key early with `cl03signer legacy-end` (legacy) or `retire`. An empty
database on a host whose signer shipped before is a rollback: see
"Rebuilding the signer host". Read `journalctl -u cl03-signer`, fix the
cause (the policy, or restore the right image), run the check above, then:

    sudo systemctl reset-failed cl03-signer
    sudo systemctl start cl03-signer

The alert is sent once per distinct refusal; a marker beside the database
(`start-refusal-alerted`) remembers it until a start succeeds, and is left
unwritten when the alert could not be sent.

## First key (dev)

    cl03signer keygen > key16.csr
    python manage.py make_test_pki --sign-csr key16.csr \
        --out ../.cl03-test-pki --cert-out key16.crt   # on the workstation
    cl03signer install-cert 16 key16.crt
    cl03signer publish 16          # a second operator: cl03signer confirm <n>
    cl03signer activate 16

Then set `SIGNER_SOCKET=/run/cl03-signer/app.sock` in verify's `.env` and
restart gunicorn. Close the development key's window last:
`cl03signer legacy-end 1` and a second operator's confirm.

## Switching keys

`cl03signer activate <next>` starts a published key and retires the one it
replaces. It waits for the phones (the switch gate), except for a held raw
key, which phones pin, and a deployment key when no deployment key can sign
bundles -- none is active (the very first, or one after a retirement or
withdrawal), or the active one's window has ended -- since nothing can sign
a bundle listing it first and waiting would only lengthen the outage. Every
other key, every organization key included, waits until either:

- it has been published a whole lease, or
- every phone that got a bundle within the last lease has since got one
  listing it -- counted from the signer's own ledger, and trusted only once
  the signer has signed bundles for a whole lease: before that, phones that
  synced through verify's own bundles are in no row of it.

A certified deployment key taking over from a raw one (a held key 1) also
waits for every phone that synced within a lease to run an app that follows
issuer certificates: an older app checks bundles, feeds and statements against
key 1 alone, and time does not change that. Update those phones, or unpair
them and wait out their last lease; Setup and `cl03signer status` name them.
Once a certified key signs, such a phone is cut off already, so later switches
do not wait for it. Before the first certified deployment key on a site whose
phones synced through verify's own key file, the signer cannot see them: check
Setup's phones first.

**Never retire a key before its successor is activated.** A successor
started after a retirement has no gate to pass, and phones inside a lease of
the old key's refuse its bundles and documents until that lease runs out.
`cl03signer retire` of an active key is refused while a successor waits in its
scope -- generated, certified or published: publish and activate that
instead, which retires the old key through the gate -- and otherwise needs a
second operator's confirm, saying what stops signing: for the deployment
key, every bundle, feed and statement.

## Leaving signer mode

With `SIGNER_SOCKET` removed and `CREDENTIAL_ISSUER_KEY_PATH` set back, verify
signs bundles with the file under `CREDENTIAL_ISSUER_KEY_ID`, lists every key
it mirrored, holds no private half of the signer's, and drops every withdrawn
key's tombstone. That is safe only while the signer's last deployment key was
that same file's key -- a held key 1 -- so verify mints nothing until the
`.env` says so: `CREDENTIAL_FILE_MODE_AFTER_SIGNER=<that key id>` (Setup names
it in red meanwhile). verify cannot check that word: once a certified key
has signed bundles, phones refuse the file's whatever the setting says, so do
not leave signer mode then; restore the signer instead.

## Rebuilding the signer host

A rebuilt host's empty database is refused at start (exit 2) because the
bucket is ahead of it; the refusal comes before anything is written, and the
reconcile timer refuses the same way, so the database stays empty. `adopt` makes it again from what was shipped, with the
signer stopped:

    sudo systemctl stop cl03-signer cl03-signer-reconcile.timer
    cd /opt/cl03-signer && sudo systemd-run --wait --pipe \
        -p User=cl03-signer -p WorkingDirectory=/opt/cl03-signer \
        -p LoadCredential=aws-access-key-id:/etc/cl03-signer/credstore/aws-access-key-id \
        -p LoadCredential=aws-secret-access-key:/etc/cl03-signer/credstore/aws-secret-access-key \
        venv/bin/python -m signer adopt --config /etc/cl03-signer/policy.toml

(On a site with `ledger_dir`, `sudo -u cl03-signer venv/bin/python -m signer
adopt ...` from `/opt/cl03-signer` is enough.) It checks the shipped chain from
its first row and brings back the ledger, every key and Organization CA with
their states, windows and certificates -- a withdrawn key travels as a
tombstone again -- and the credential ids already signed; key ids go on
from the highest ever named. It prints a report: `key_files` says, for every
key the registry expects this host to hold, whether its file is `present`;
a missing one cannot sign, so retire or withdraw it, or put the file back.
Not brought back: pending confirmations, pauses, and the revoked set, which
verify sends again before the next bundle. Then `systemctl start cl03-signer`.

The ledger carries every key's public half (and a `record` of each key
made before it did), so a rebuild needs nothing but the bucket.

## A development site: key 1 held, no AWS

While a development site's phones still run an app that pins only the
development key 1, a certified key 16 would cut them off: they check bundles,
revocation feeds and log-key statements against key 1 alone. So there the signer holds
key 1 and keeps signing with it (`[[held]]` in `policy.toml`); keys the
Organization CA certifies ride inside key 1's bundles, and phones with the
chain-aware app show them as certified. The old app trusts every key a key-1
bundle lists, so it verifies those documents too, as "issued by a trusted
authority".

- Install with `sudo sh signer/deploy/install.sh <gunicorn's user>`. Where
  that user has sudo, as `ec2-user` does, there is no separation; a
  development site may accept that, a production one may not.
- Copy verify's key file (`CREDENTIAL_ISSUER_KEY_PATH`) to
  `/var/lib/cl03-signer/keys/key-1.pem`, owner `cl03-signer`, mode 0600, and put
  its SPKI and IssuerKey 1's window in `[[held]]`. Every document key 1 has
  signed must fall inside that window, or the new app reads it as forged.
- `ledger_dir = "/var/lib/cl03-signer/ledger"` under `[runtime]`, and no AWS
  names: the ledger stays on the host, alerts go to the journal
  (`journalctl -u cl03-signer`), and there is no heartbeat. Install
  `local-ledger.conf` as a drop-in for both units, since the AWS credential
  files do not exist. The folder is a copy, not rollback protection.
- `systemctl enable --now cl03-signer`, then `cl03signer activate 1`. Call it
  as `sudo /usr/local/bin/cl03signer`, and give certificate files by their
  full path: the wrapper runs from `/opt/cl03-signer`.
- A second operator name for confirmations: `useradd --system
  --no-create-home --shell /sbin/nologin -G cl03-operators cl03-op`, then
  `sudo -u cl03-op /usr/local/bin/cl03signer confirm <n>`.
- The Organization CA, which is the site's System CA:
  `site_domain = "dev.verify.example.ph"` in `policy.toml` and a restart,
  then `cl03signer ca keygen` (it checks https://dev.verify.example.ph/ first),
  its request signed on the workstation by `make_test_pki --sign-csr <csr>
  --org-ca --domain dev.verify.example.ph`, then `cl03signer ca install <pem>`.
  Phones paired with that address trust what it certifies; "The System CA's
  domain", below.
- Then `SIGNER_SOCKET` in `.env`, `CREDENTIAL_ISSUER_KEY_PATH` commented out,
  and gunicorn restarted. Undo is the reverse, with
  `CREDENTIAL_FILE_MODE_AFTER_SIGNER=1` added ("Leaving signer mode"):
  verify signs with the file again, and phones notice nothing, since it is
  the same key -- while key 1 is the one the signer signs with.

- `site_publishes_organization_keys = true` in `policy.toml`, then restart
  `cl03-signer`: site admins publish and start organization keys from verify
  (below).

Key 1 leaves when every phone of the site has the chain-aware app: certify 16 and
`cl03signer activate 16` retires key 1 and destroys the signer's copy. The
gate holds 16 back while any phone that synced within a lease runs the old
app ("Switching keys"). A held key never takes over from a certified one
(`activate` refuses), because phones holding the certified key's bundle would
refuse its bundles: there is no way back to key 1 after 16.

## Publishing from the site

Off by default. With `site_publishes_organization_keys = true` in
`policy.toml` (a TOML boolean, unquoted; anything else stops the signer), a
site admin publishes an organization's certified key from its Site page and
then starts it signing, with no operator here. Only organization keys: the
deployment's own keys, withdrawals and the Organization CA stay on the host.
Each step is a ledger row naming the admin and a high alert in the journal
(or SNS). Starting a key waits, as `cl03signer activate` does, until the phones
that synced within a lease have it, an organization's first key included.

It trades the two operators' reading of a certified name for one site
admin's. Turn it on where that is an acceptable trade, as it may be on a
development site.

## Every key from the site

Off by default, and wider than the switch above. With
`site_controls_all_keys = true` in `policy.toml` (a TOML boolean, unquoted),
a site admin -- any of them, a designated one included -- does every key
action from verify's Setup page and an organization's Site page, alone, with
no operator here and no second operator's confirmation:

- publish and start the deployment's keys as well as organizations' (the
  switch gate still holds a key until the phones have it, as
  `cl03signer activate` does);
- suspend any key (as any site admin may anyway, switch or not), and
  unsuspend it;
- resume a paused context -- including the pause the global credential
  ceiling sets, which otherwise waits for an operator to look first;
- withdraw any key that was published, at once. A key never published is
  discarded instead.

Each is a ledger row naming the admin and a high alert; so is a suspension
from the site, with or without the switch. What stays on the host whatever
the switch says: legacy and held (`[[held]]`) keys, which come from this
policy; making keys for the deployment; retiring a key by hand; removing
revocations; and everything about the Organization CA.

It is meant for a site whose app servers are replaced at every release,
where nobody is on a host to run `cl03signer` in the ordinary course. What
it costs:

- an application compromise, or a stolen site admin session, can suspend or
  withdraw the deployment key, and once it is withdrawn nothing signs
  bundles, feeds or statements, so every phone's sync is refused until a
  successor is active;
- a withdrawn key is a tombstone: phones refuse every credential it ever
  signed, from the next sync on, and nothing undoes that -- every document
  it signed has to be issued again;
- it can lift the global ceiling's pause, the brake meant for exactly such a
  compromise.

It cannot forge anything: a key still needs a certificate from the PKI,
which the app cannot issue, and a key the Organization CA certifies still
needs a name no other organization holds. Keep it off anywhere else.

## Poll mode: a signer that dials out

Where verify's app servers come and go -- an Auto Scaling group whose servers
are replaced at every release -- the signer cannot live beside gunicorn. It
runs on a host of its own instead and dials out to the site: verify's servers
queue each request as a job in the database they share, and the signer
long-polls the site over HTTPS, answers each job under its unchanged policy,
and posts the answer back. Nothing connects to the signer. Socket mode is
unchanged and stays the default.

**What the signer runs.** The same code and the same answers. A job is the
frame verify would have sent on the app socket and goes to the same
dispatcher, as the app: the same operations and no others, the same
ceilings and ledger. The answer goes back as the very text the socket would
have carried. No operator command is reachable through the queue; the admin
socket stays, and operators still run `cl03signer` on the signer's host.

**The policy** (`[runtime]` in `policy.toml`):

    transport = "poll"
    site_url = "https://verify.example.ph"   # the site's own origin, https

`app_socket`, `app_user` and `app_group` are not read; `admin_socket` and
`operators_group` are. `python -m signer check` says what is missing.

**The credential.** `/etc/cl03-signer/credstore/poll-key`, root, mode 0600:
32 random bytes as 64 hex characters (`openssl rand -hex 32`), the same value
as the site's `SIGNER_QUEUE_KEY`. Install with `sudo sh
signer/deploy/install.sh --poll`: no app user is named, and `poll.conf` is
put in place as a drop-in, loading the key as the systemd credential
`poll-key`. A key that is not 32 bytes stops the signer (exit 3, one alert).

**AWS.** The ledger, alerts and heartbeat work as they do in socket mode.
Give the IAM user's key as the two credentials; or, in poll mode only, give
neither, and the signer uses boto3's own chain -- the EC2 instance role, on
a host in AWS -- with `instance-role.conf` installed as a drop-in for both
units, since the key files are not there. The role is right only on a host
where no application runs: anything on the host can ask the metadata service
for it, which is why a signer beside gunicorn refuses to start without the
IAM user's key. One credential without the other stops the signer in either
mode.

**Ledger retention.** Each object sent to the bucket is locked for
`ledger_retain_days` under `[runtime]` (400 by default, at least 1), in
compliance mode, so nobody shortens it afterwards. A development site may
choose fewer days; keep the bucket's own default retention
(`signer/deploy/terraform`, `retain_days`) the same. The value applies to
objects shipped from then on: those already in the bucket keep the date they
were written with. Editing it in `policy.toml` is the custodian's act, like
any other edit there -- root on the signer's host -- and nothing in verify
can change it.

**What the site needs.**

- `SIGNER_QUEUE_KEY` in its `.env`, the same value as `poll-key`, with
  `SIGNER_SOCKET` empty. Optional: `SIGNER_QUEUE_TIMEOUT_SECONDS` (10), how
  long a request waits for the answer.
- **A gunicorn pool of its own for `/api/v1/signer/`.** A page that needs
  the signer holds its thread while it waits, and the signer's poll and its
  answer are requests of their own. Served by the same workers, they can
  queue behind the very waits they would end -- gunicorn's gthread worker
  accepts a connection while its threads are busy and queues it -- and
  every wait then times out. Route the prefix to a separate gunicorn at the
  proxy, and size it so an answer never queues behind the signer's next
  long poll, which holds a thread for up to 25 seconds: **sync workers, 3
  or more** (a busy sync worker accepts nothing, so the answer goes to
  another), **or gthread with at least 2 threads a worker**. One gthread
  thread is not enough: the worker would accept the answer and hold it
  behind the poll.
- verify also keeps a backstop of its own, which is no substitute for that
  pool: no more than `SIGNER_QUEUE_MAX_WAITING` threads of a process wait
  for the signer at once (by default one fewer than `GUNICORN_THREADS`, or
  1); one more waits up to a second (or a tenth of its timeout) for a
  place, then is refused, as a signer that did not answer. It counts only
  those waiting threads, not one holding the signer's long poll. The app
  cannot read gunicorn's configuration: it reads `GUNICORN_THREADS` from
  `.env`. The site kit's `deploy/gunicorn.conf.py` takes its threads from
  the same variable (2 when it is unset), so one value sets both; a
  gunicorn configured any other way must be given the same number there.
  System check `accounts.W006` compares the two settings as the app reads
  them.
- **Its proxy admits `/api/v1/signer/jobs/`, `/api/v1/signer/answers/` and
  `/api/v1/signer/report/` only from the signer's own egress addresses.**
  The HMAC key is on every app server (`SIGNER_QUEUE_KEY`), so anyone
  holding a copy of it -- from a server, a backup, an image -- can act as
  the signer from any address the proxy lets through: take the jobs, and
  answer them. The address rule is what keeps such a copy useless
  elsewhere. This repository's own nginx answers 404 for all of
  `/api/v1/signer/`, which is right in socket mode and must change for
  this one.
- Every app server reads one database: the jobs and the nonces are in it,
  and every time the queue keeps is the database's own clock.
- `site_url` names the host the site serves and Django's `ALLOWED_HOSTS`
  allows: it is in every MAC.
- Both clocks right to within a minute (NTP): a request or answer more than
  60 seconds away from the other's clock is refused.
- The reconciler reads `https://<site>/api/v1/signer/report/` with its
  token, from the signer's host: leave `report_url` and `report_host` out
  and it does, or set them to say otherwise.

**On the wire.** `GET /api/v1/signer/jobs/?wait=20&max=<n>&signer=<id>`
answers at once with any jobs it can claim, or holds the request open up to
`wait` seconds (at most 25), looking every tenth of a second, and answers
as soon as one comes. The signer asks for no more jobs than it has idle
workers (four), and the site hands over at most about 2 MiB of them at once
(a bigger one alone). Each job carries the seconds it has left by the
database's clock; the signer counts them on its own clock from when the
answer arrives, and a job that runs out before a worker reaches it is
refused, `expired`, without being acted on. `POST /api/v1/signer/answers/`
carries one answer at a time, under Django's 2.5 MiB limit; an answer that
would not fit is replaced by a refusal that tells verify the request may
have been done, and alerted on as too large.

Each request and each response carries `X-CL03-Signer-Time` (ASCII digits),
`X-CL03-Signer-Nonce` and `X-CL03-Signer-MAC` (64 lowercase hex), an
HMAC-SHA256 over the method, **the site's host name** (lowercase, no port:
the host in `site_url`, and on the site the request's own host as Django
reads it, behind `ALLOWED_HOSTS`), the path with its query, the time, the
nonce and the body's SHA-256. Two sites sharing a key therefore cannot
replay into each other. A response is bound to its request's nonce.
`signer/poll.py` has the exact form. The site refuses a nonce it has seen,
on any of its servers, and anything malformed is a bare 403. Both endpoints
answer 404 while `SIGNER_QUEUE_KEY` is empty.

**What a request costs.** A healthy signer answers a job well within a
second of its creation: the poll is already open and returns within a
tenth of a second of the job's creation, and the app looks for the answer
every 20 to 100 ms (77-157 ms end to end, measured over loopback). Each
open poll holds one thread of the signer's own gunicorn pool for up to 25
seconds. A job is handed out once: if
the signer dies holding it, verify gives up after the timeout and keeps a
credential row as `unknown`, since it may have been signed. A job never
collected is withdrawn, and nothing was done. While the signer has not
polled for a minute, nothing is queued at all: documents print the plain QR
and syncs are refused at once rather than after the timeout. A page never
asks inside a database transaction: the job would be invisible to the poll.

**One signer per site.** Each poll names its signer: an id kept in the
signer's database and its host name. Setup says in red when two different
signers have polled within a few minutes -- two signers answering one site
would each keep a ledger the other does not see. Stop all but one. What it
cannot see: a copy of the signer's database running on a host with the same
host name sends the same id, so the two read as one. And it is a warning on
Setup only, for whoever opens it: no alert is sent.

**When the site does not answer**, the signer waits a second, then two, up
to a minute between tries, and alerts through its usual channel: at once
when the site refuses it (the key, the clock, `site_url`, a proxy answering
404), at once and in its own words when something is too large, after five
minutes when it is only unreachable, again every six hours while that lasts,
and once when it is back. Answers that do not get through, after three tries
each, are counted, and three in a row are an alert of their own, on the same
rules. `cl03signer status` shows all of it under `poll`: failures in a row,
answers lost, jobs that ran out, workers busy. Setup shows a signer it cannot
reach as not answering.

## The System CA's domain

`site_domain` in `policy.toml` is the host phones pair with: the address in
verify's pairing QR (`DEVICE_PAIRING_BASE_URL`, or the host the page was
served from), which its own HTTPS certificate names. A lowercase host name,
at most 54 characters; anything else stops the signer, and so does the old
`organization_ca_name`. The Organization CA is named "<site_domain> System
CA" and lists the domain, and phones paired with any other address drop the
keys it certifies (`entry_wrong_domain` in their activity log).

- `cl03signer ca keygen` refuses until `site_domain` is set, and first checks
  that `https://<site_domain>/` answers with a certificate valid for it. The
  box must reach its own public address for that.
- The PKI signs the request only for the domain it is told
  (`make_test_pki ... --org-ca --domain <site_domain>`), and checks the site
  the same way.
- `cl03signer ca install` refuses a certificate for another domain or with
  another name. Changing `site_domain` later stops Generate certificate until
  a System CA for the new domain is installed; keys already certified keep
  their chains, but phones paired with the new address drop them.

## Backups and images

Stop `cl03-signer` with gunicorn before the host is imaged: its database
comes back with the image. At start-up the signer compares its ledger with
the newest shipped object and refuses to sign if it is behind, so an older
image cannot revive a withdrawn key.

A backup of the host should copy the signer's database (`signer.db`: the
ledger and the public keys, never a private key) beside verify's.

## Response

Suspend or pause from Setup at once; withdraw on the host (two operators);
in stage 1, rebuild ("Rebuilding the signer host") and re-key through the
PKI, with documents printing the plain QR meanwhile. Once the deployment key
is withdrawn nothing signs bundles, feeds or statements until a successor is
active, so every phone's sync is refused meanwhile and a phone whose lease
ends stops verifying. The successor starts immediately, but a phone still
inside a lease of the withdrawn key's refuses it until that lease ends,
unless the successor was published before the withdrawal and the phone
already lists it.
