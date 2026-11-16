# Verify

National ID verification for counters and checkpoints. A trained operator
checks a person's Philippine National ID against the Philippine Statistics
Authority's **eVerify** service, confirms with a live face check, and prints
a verification document. The document can be validated online by scanning
its QR code, or offline with the companion verifier app, which reads its
**CL03** credential. The site and the app together, the offline verification
system, are the **CL03 implementation**.

Built by Ateneo BUILD-TRL. Version **1.5**; see [`VERSION`](VERSION).

## User manual

The **Verify Operator's Manual** covers everything an operator or
administrator needs, in five parts: Orientation, At the counter, Running an
organization, Running the installation, and Reference.

- [Operator's Manual (PDF)](docs/user-manual.pdf):
  [download](https://git.trl.ph/trl/verify-x/raw/branch/main/docs/user-manual.pdf)
- [Operator's Manual (HTML)](docs/user-manual.html), the same edition

The manual is a **draft**: check it against the running application before
relying on a detail.

## What it does

- **Operator sign-in with a National ID.** The operator enters a National ID
  and completes the real eVerify liveness check; only operators already
  registered for the installation get a session. Single sign-on (OpenID
  Connect) can be selected instead.
- **Verifying a person.** The operator scans the ID's QR code, types the
  card number, or fills in the person's details. A face check (or a
  fingerprint reader, where one is configured) confirms them, and the result
  is logged.
- **The verification document.** A one-page printout that fits A4 and
  Letter. It carries a QR code that anyone can scan to validate the record
  online, and a cut-out card with a signed, encrypted **offline credential**
  (a CL03 code) and a portrait symbol.
- **The holder's copy.** The holder can save the same card to their phone's
  photos by scanning a code on screen, or to Apple Wallet where the
  installation has a pass certificate.
- **Organizations.** One installation serves several organizations, each with
  its own members, locations, transaction types, eVerify account, choice of
  displayed and logged fields, and CSV export.
- **Offline verifier devices.** Phones running the companion app pair from
  the web, receive their keys, and poll a signed revocation list.
- **Demo Mode.** Masks names, ID numbers and faces on every page, for
  presenting with real IDs.

## Documentation

| Document | Formats |
|---|---|
| Operator's Manual | [PDF](docs/user-manual.pdf) · [HTML](docs/user-manual.html) |
| Architecture (slides) | [PDF, A4](docs/decks/verify-architecture%20-%20v1.0%20-%20A4.pdf) · [PDF, Letter](docs/decks/verify-architecture%20-%20v1.0%20-%20Letter.pdf) |
| Capabilities overview (slides) | [PDF, A4](docs/decks/verify-capabilities%20-%20v1.0%20-%20A4.pdf) · [PDF, Letter](docs/decks/verify-capabilities%20-%20v1.0%20-%20Letter.pdf) |
| Offline verification (slides) | [PDF, A4](docs/decks/verify-offline-verification%20-%20v1.0%20-%20A4.pdf) · [PDF, Letter](docs/decks/verify-offline-verification%20-%20v1.0%20-%20Letter.pdf) |
| CL03 credential QR wire format (specification) | [PDF, A4](docs/cl03-spec%20-%20v1.1%20-%20A4.pdf) · [PDF, Letter](docs/cl03-spec%20-%20v1.1%20-%20Letter.pdf) |
| Deploying on AWS | [Markdown](docs/deploy-aws.md) |

Before changing sign-in, organizations, the printed document or the
credential, read the tests that pin them in `accounts/tests.py`; their
docstrings say why each rule exists.

## Running it locally

Needs Python 3.11 or later. The stack is Django 5.2 on SQLite; production
runs gunicorn behind nginx, behind a TLS-terminating load balancer.

```bash
python -m venv venv
venv/bin/pip install -r requirements.txt        # Windows: venv\Scripts\pip
export DJANGO_DEBUG=1 DJANGO_SECRET_KEY=dev-only-not-a-secret
venv/bin/python manage.py migrate
venv/bin/python manage.py createsuperuser        # for the Django admin
venv/bin/python manage.py runserver
```

The application reads its settings from environment variables. On a server
they come from an `.env` file that `deploy/deploy.sh` writes from the
site's configuration file;
[`deploy/site.conf.example`](deploy/site.conf.example) lists every one.

Signing in to the application needs two things:

- **A registered operator.** Add an organization, the operator and their
  membership in the Django admin at `/admin/`.
- **eVerify credentials for signing in.** For the first sign-in, set
  `EVERIFY_CLIENT_ID`, `EVERIFY_CLIENT_SECRET` and `EVERIFY_PUBLIC_API_KEY`.
  After that, a site administrator can manage them on the Setup page.

Running verifications also needs each organization's own eVerify account,
entered on that organization's page. There is deliberately no fallback to
the sign-in account.

On a development machine only, `EVERIFY_ALLOW_MOCK_LOGIN=1` together with
`DJANGO_DEBUG=1` replaces eVerify with a mock that trusts whatever the
browser sends. Never set both on a server.

## Tests

```bash
venv/bin/python manage.py test accounts
```

## Deploying

**[docs/deploy-aws.md](docs/deploy-aws.md)** builds a new, independent Verify
site, from nothing to a site operators can sign in to. It shares nothing
with any other deployment: its own AWS account, network, domain, eVerify
credentials and database. All of a site's settings and secrets live in one
configuration file, kept outside this repository:

```bash
cp deploy/site.conf.example ../verify-site/site.conf    # fill it in
export VERIFY_SITE=../verify-site/site.conf
deploy/deploy.sh infra      # build the AWS resources with Terraform
deploy/deploy.sh            # deploy the application
```

| | |
|---|---|
| [`deploy/site.conf.example`](deploy/site.conf.example) | The one configuration file: AWS, domain, SSH key, eVerify credentials, Django's secrets and every optional setting |
| [`deploy/deploy.sh`](deploy/deploy.sh) | `infra` builds or changes the AWS resources; a plain run writes the server's `.env` from the configuration, copies key files, syncs the code, migrates and smoke-tests; `check`, `validate`, `ssh` and `backup` do what they say |
| [`terraform/`](terraform/) | The AWS resources: a VPC with public and private subnets and a NAT gateway, a load balancer with HTTPS, a bastion, the app server, and daily snapshots of its disk |
| [`deploy/nginx.conf.tftpl`](deploy/nginx.conf.tftpl), [`deploy/gunicorn.service.tftpl`](deploy/gunicorn.service.tftpl), [`deploy/gunicorn.conf.py`](deploy/gunicorn.conf.py) | Installed on the app server when it is built |
| [`deploy/install-purge-timer.sh`](deploy/install-purge-timer.sh), [`deploy/purge-device-logs.service.tftpl`](deploy/purge-device-logs.service.tftpl), [`deploy/purge-device-logs.timer.tftpl`](deploy/purge-device-logs.timer.tftpl) | Installed by every deploy: the daily purge of the phones' activity log, kept `DEVICE_LOG_RETENTION_DAYS` (360 unless set) |

None of it carries a deployment's settings. The tests fail if an account
id, a resource id or an address is committed to `terraform/` or `deploy/`.

A server must set its own long random `DJANGO_SECRET_KEY`. Any host other
machines can reach refuses to start without one, because a fallback written
in a published repository is a key everybody holds. The first superuser is
created only when `DJANGO_SUPERUSER_PASSWORD` is set.

## Keeping secrets out of the repository

Credentials live in environment variables and the database, never in git.
Enable the pre-push guard once per clone:

```bash
git config core.hooksPath tools/hooks
```

It refuses any push that carries a credential from your local `.env`, or
from the site configuration file `VERIFY_SITE` names, or a private key
block, and names the file without printing the value.

## Contributing

Questions, bug reports and proposals are welcome.
[CONTRIBUTING.md](CONTRIBUTING.md) says how to send one, and how a change
reaches this repository. A security flaw is reported privately, as
[SECURITY.md](SECURITY.md) describes, and not in an issue. The
[code of conduct](CODE_OF_CONDUCT.md) applies to everyone who takes part,
and [CONTRIBUTORS.md](CONTRIBUTORS.md) names those who have contributed.

## License

Copyright 2026 Ateneo de Manila University - Business Insights Laboratory for
Development - Technical Resource Lab ("Ateneo BUILD-TRL").

Licensed under the [Apache License 2.0](LICENSE). Redistributions must carry
the attribution in [`NOTICE`](NOTICE). Third-party components, the PSA and
Ateneo marks, and other exclusions are listed in
[`THIRD-PARTY-NOTICES.md`](THIRD-PARTY-NOTICES.md).
