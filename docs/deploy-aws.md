# Building a Verify site on AWS

This guide builds a new, independent Verify site in an AWS account, from
nothing to a site operators can sign in to. Everything it uses is in this
repository. Everything that belongs to your site goes in **one
configuration file** that you keep outside the repository: the AWS details,
the domain, the SSH key, the eVerify credentials and Django's secrets.
Building, deploying and every later update all read that one file.

```bash
cp deploy/site.conf.example ../verify-site/site.conf    # fill it in
export VERIFY_SITE=../verify-site/site.conf
deploy/deploy.sh infra      # build the AWS resources
deploy/deploy.sh            # deploy the application
```

## A site of its own

A site built this way shares nothing with any other deployment of Verify,
including the one its code came from. It has its own:

| | |
|---|---|
| **AWS account** | Named by `AWS_ACCOUNT_ID`. Every AWS action is checked against it, and Terraform refuses any other account |
| **AWS credentials** | In `site.conf`, or a named profile. The tools never fall back to the deploying machine's default credentials, and they ignore AWS and Terraform settings in your shell |
| **Network** | A VPC, subnets, NAT gateway, load balancer and bastion built for it alone |
| **Domain and certificate** | Your domain, and a certificate issued to it in your account |
| **eVerify credentials** | Issued by PSA to this site |
| **Database and secrets** | Its own `DJANGO_SECRET_KEY`, its own SSH key, and an empty database |
| **Name and logos** | `SITE_TITLE` and its own footer logos; none of the code's authors' |
| **Terraform state** | In the site's own folder, nowhere shared |

Nothing in this repository defaults to another deployment's values. In
particular, the application's single sign-on option names no provider until
a site administrator enters one. Offline credentials need an issuer key of
your own, and only verifier phones that trust that key can read them.

## What gets built

```
 visitors ──HTTPS──▶ load balancer ─── public subnets, two zones
                       │  TLS ends here; port 80 redirects to HTTPS
                       ▼
                     app server ────── private subnet
                       nginx :80 ─▶ gunicorn ─▶ Django + SQLite
                       outbound only, through a NAT gateway

 you ──SSH──▶ bastion ──SSH──▶ app server
```

| Part | Notes |
|---|---|
| VPC | Two public subnets for the load balancer, bastion and NAT gateway; one private subnet for the app server |
| Load balancer | HTTPS with an ACM certificate for your domain; HTTP redirects to HTTPS |
| App server | Amazon Linux 2023 in the private subnet. HTTP only from the load balancer, SSH only from the bastion. It provisions itself on first boot from the templates in `deploy/` |
| Bastion | Small server with a fixed public address. SSH only from the ranges you allow |
| Backups | Daily snapshots of the app server's disk, which holds the database, kept for 7 days by default |
| Optional | Route 53 records for the certificate and the domain, if your domain is in Route 53 |

The app server's disk is encrypted, both servers require IMDSv2, and no
secret is ever passed to Terraform. Terraform state and the servers' user
data therefore hold none.

**Cost.** At small scale, expect roughly US$100 a month in ap-southeast-1.
Most of that is the NAT gateway and the load balancer; the two servers are
a small part. Check AWS pricing for your region.

## What you need first

- **An AWS account that holds nothing else.** A new account in AWS
  Organizations is the cleanest; a standalone account works too. In it,
  create an IAM user (or a role you sign in to) for this site, allowed to
  create everything above:
  - VPC and networking
  - EC2
  - load balancers
  - ACM certificates
  - IAM roles and instance profiles (with `iam:PassRole`)
  - Data Lifecycle Manager policies
  - Route 53 records, if used

  Note the account's 12-digit id. Then either create an access key for the
  user, to put in `site.conf`, or configure an AWS CLI profile for it, such
  as one through IAM Identity Center.
- **A domain name**, and either control of its DNS or a Route 53 hosted
  zone for it.
- **eVerify API credentials from PSA, issued to this site**:
  - one client that signs operators in;
  - one per organization that runs verifications. Each organization is
    billed through its own client.

  Never reuse another deployment's client: its usage would be billed to,
  and logged against, somebody else.
- **On the machine you deploy from:**
  - Terraform 1.5 or later
  - AWS CLI v2
  - bash, ssh and rsync (Linux, macOS, or Git Bash on Windows)
  - Python 3, only to generate secrets

## 1. Make the site's folder and configuration file

The configuration file holds the site's secrets. Keep it, the SSH key and
Terraform's state together, in a private folder of their own beside your
checkout, never inside it. Back that folder up.

```bash
mkdir -p ../verify-site/keys
cp deploy/site.conf.example ../verify-site/site.conf
ssh-keygen -t ed25519 -f ../verify-site/keys/verify -C verify-deploy
```

Fill in `site.conf`. The file explains every setting. The ones a new site
needs:

| Setting | What to put |
|---|---|
| `SITE_NAME` | A short name, unique in the AWS account, such as `verify`. It names every resource, so choose it once |
| `DOMAIN` | The host name operators will use |
| `AWS_ACCOUNT_ID`, `AWS_REGION` | The site's own account, and where to build in it |
| `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY` | The site's IAM access key, or instead `AWS_PROFILE`, the name of its AWS CLI profile |
| `SSH_ALLOWED_CIDRS` | Who may reach the bastion, such as your office's public address as a /32 |
| `SSH_PUBLIC_KEY_FILE`, `SSH_PRIVATE_KEY_FILE` | The key you just made: `keys/verify.pub` and `keys/verify` |
| `DJANGO_SECRET_KEY` | The output of `python -c "import secrets; print(secrets.token_urlsafe(64))"` |
| `DJANGO_SUPERUSER_USERNAME`, `_EMAIL`, `_PASSWORD` | The account for the Django admin |
| `EVERIFY_CLIENT_ID`, `_SECRET`, `PUBLIC_API_KEY` | The sign-in client from PSA |
| `ROUTE53_ZONE_ID` | Optional. If your domain is in Route 53, DNS becomes automatic |

Write values bare: no quotes. A comment goes on a line of its own, so a
value may contain `#`. Then check the file:

```bash
export VERIFY_SITE=../verify-site/site.conf
deploy/deploy.sh validate
```

`validate` names what is missing or wrong, and lists the settings that will
go to the server. It prints names, never values.

## 2. Build the AWS resources

**With `ROUTE53_ZONE_ID` set:**

```bash
deploy/deploy.sh infra
```

The tool first confirms that the credentials belong to `AWS_ACCOUNT_ID`, and
stops if they do not. Terraform then shows its plan and asks before
creating anything. It creates the certificate's validation record and the
domain's alias record itself.

**Without Route 53**, the certificate cannot be validated until a DNS record
exists, so build in two passes:

```bash
deploy/deploy.sh infra certificate   # requests the certificate and prints a record
#   create that CNAME record in your domain's DNS, then:
deploy/deploy.sh infra               # waits for the certificate, then builds the rest
```

When it finishes, point `DOMAIN` at the load balancer with a CNAME. The
command prints the name to use; `deploy/deploy.sh infra output` shows it
again.

Instead of either, `CERTIFICATE_ARN` can name an issued ACM certificate you
already have in that region.

The app server provisions itself over the next few minutes. Its log is
`/var/log/user_data.log`. Until the first deploy the load balancer reports
it unhealthy; that is expected.

Terraform's state is written to `terraform.tfstate` in the site's folder.
Keep it there with the configuration file: it is how later runs find the
servers and change them rather than build new ones.

## 3. Deploy

```bash
deploy/deploy.sh hostkeys  # once: the servers' SSH host keys, read from AWS
deploy/deploy.sh check     # optional: reports on the server, changes nothing
deploy/deploy.sh           # deploys
```

**`hostkeys` comes first.** The deploy carries the `.env` and the key files
over SSH, so it trusts only the host keys in `known_hosts` beside
`site.conf`, under the names `bastion` and `server`. `hostkeys` reads them
from the EC2 console, which each instance writes them to at the end of its
first boot and which AWS hands back over its own authenticated API. A server
built moments ago may not have finished booting; `hostkeys` waits for it.
Keep `known_hosts` with `site.conf`.

A deploy:

1. **Writes the server's `.env` from `site.conf`.** It is installed with mode
   600, and the previous one is kept. `DJANGO_ALLOWED_HOSTS` defaults to
   `DOMAIN`, and the server's private address is added, because the load
   balancer's health checks arrive on it.
2. **Copies the key files** the configuration names, if any.
3. **Syncs the code**, installs the requirements, migrates and collects
   static files.
4. **On the first deploy**, creates the superuser and starts the
   application; afterwards, restarts it.
5. **Smoke-tests** `https://DOMAIN/health/` and `/api/lookup-data/`.

The addresses of the server and the bastion come from Terraform's state on
every run, so you never type or record one.

After the first deploy, empty `DJANGO_SUPERUSER_PASSWORD` in `site.conf`.
The next deploy then removes it from the server too.

## 4. Let operators in

Operators sign in with their National ID and a liveness check, through
eVerify. Only people already registered on the site get a session, so
registration is the step that opens it:

1. **Add the first site administrator.** At `https://<your domain>/admin/`,
   sign in as the superuser. Under **Users**, add their National ID card
   number and name, and tick **is site admin**.
2. **They sign in** at `https://<your domain>/` with their National ID.
3. **They set up each organization.** On **Site** (`/app/site/`) they create
   the organization and enter its eVerify client. An organization cannot run
   verifications without one, and it never borrows another's.
4. **They add the organization's members**, as operators or admins.

Each organization's admins then manage its locations and transaction types
themselves.

## Optional features

Each one is a few settings in `site.conf`. They are described there.

- **Your name and logos.** `SITE_TITLE` names every page. For a footer, put
  your logo files in a folder beside `site.conf`, set `BRANDING_FOLDER` to
  it, and list them in `SITE_FOOTER_LOGOS`, each with an optional link and
  alt text. The deploy copies the folder to the server, where the logos are
  served with the site's other static files. Without these settings, pages
  are titled "Verify" and have no footer: the application carries no
  organization's branding of its own.

- **Offline (CL03) credentials in the document QR.** Set `ISSUER_KEY_FILE` to the
  issuer PEM on your machine; the deploy copies it to the server. Set the
  `CREDENTIAL_*` epoch settings to match the verifier deployment whose phones
  will read the credentials. Without a key, documents print with a QR that
  holds only the transaction id.
- **Apple Wallet passes.** The two `WALLET_*` identifiers and the three
  `WALLET_*_FILE` PEMs, issued against your own Pass Type ID.
- **A pinned device-pairing address.** `DEVICE_PAIRING_BASE_URL`, if the site
  is ever reached by another name.

## Day to day

| To | Run |
|---|---|
| Deploy a change, or a changed setting | `deploy/deploy.sh` |
| See the state of the server | `deploy/deploy.sh check` |
| Open a shell on the server | `deploy/deploy.sh ssh` |
| Copy the database here | `deploy/deploy.sh backup` (into the site's `backups/` folder) |
| Put a copy back | `deploy/deploy.sh restore backups/db-....sqlite3 --confirm=DOMAIN` (see below) |
| Change the wrap key | `deploy/deploy.sh rewrap-key new-wrap.key --confirm=DOMAIN`, then deploy (see below) |
| Trust a rebuilt server's SSH host key | `deploy/deploy.sh hostkeys` |
| Change the AWS resources | Edit `site.conf`, then `deploy/deploy.sh infra` |
| Remove the site | `deploy/deploy.sh backup`, then `deploy/deploy.sh infra destroy` |

**Back up before a deploy that migrates.** The daily snapshots protect
against losing the server. A copy taken just before a risky change is what
you roll back to. Backups hold personal data: operators, ID numbers, and the
faces from refused sign-ins. Store them accordingly.

**The database is never touched by a deploy** unless you pass
`--sync-db=DOMAIN`, and that replaces it with the local `db.sqlite3`, the
way `restore` puts back a backup (below).

**Roll back** by deploying the previous release. If the release you are
leaving added migrations, do not reverse them below 0026 on a site that has
made documents or paired phones: those migrations hold keys and registries
(see "Restoring the database"). Put back the backup taken before the deploy
instead.

### Restoring the database

```bash
deploy/deploy.sh restore backups/db-20261103-210915.sqlite3 --confirm=verify.example.org
```

The file is named as `backup` named it, in the site's folder (a path from
anywhere else works too). `restore` sends it to the server, stops the
application, and puts it in place with `manage.py replace_database`, which
first copies the server's own database into `/home/ec2-user/app/backups/`
there. Then it migrates and starts the application again; a migrate that
fails is said, with the backup's name, not reported as done. `--confirm` is
the site's `DOMAIN`, typed, so a restore pointed at the wrong site does
nothing: the server's address or `localhost` will not do.

A database is more than its rows. It holds the keys every printed document
is encrypted to, and the list of phones allowed to sync. So `restore`:

- **refuses a copy whose keys the server cannot open** (one made on another
  site, under another `CREDENTIAL_EPOCH_WRAP_KEY`). In place, every phone's
  sync would fail;
- **carries the server's own keys into the copy** where the copy lacks them.
  A copy from before the current 30-day epoch began has none for it, and
  the next document would otherwise make new keys under the same epoch: the
  documents made with the old ones would never open again;
- **refuses a copy holding other keys for the same epoch**, unless you run
  `manage.py replace_database` on the server yourself with
  `--take-incoming-keys`, knowing what was made with the server's keys stops
  opening;
- **says what the copy does not have**, before anything changes:
  - phones paired since. Each one is told it is no longer registered, and
    must reset its keys and pair again;
  - documents made since. They still verify, but can no longer be revoked
    from the site;
  - revocations made since. Revoke those documents again, or phones that sync
    read them as valid.

The same holds for every way a database is swapped: `deploy --sync-db=DOMAIN`
goes through the same command, and so should a copy put back by hand.

If the current epoch's keys are gone from the database and no backup has
them (Setup says so in red, and no document is made and no phone syncs),
`manage.py remake_epoch_keys --confirm=DOMAIN` on the server accepts the
loss: new keys, and the documents made with the old ones never open again.

### Changing the wrap key

`CREDENTIAL_EPOCH_WRAP_KEY` wraps every stored epoch key and activity-log
key. To change it, say because a copy of `.env` went somewhere it should
not have, re-wrap them all under a new one. Phones notice nothing: no
public key changes, and they hold their keys wrapped to their own phone.

What it protects is the copies of the database made from then on. The
private keys themselves do not change, so the old value still opens every
copy made before: the daily snapshots, backups you downloaded, the
`db-before-replace-*` copies `restore` leaves on the server, and any backup
that went somewhere beside `.env`. If a copy of the database went with the
old `.env`, re-wrapping does not undo that.

1. Make the new key in a file only you can open, beside `site.conf`:

   ```bash
   (umask 077; python -c "import secrets; print(secrets.token_hex(32))" > new-wrap.key)
   ```

   On Windows, make it with Git Bash or Python, not PowerShell 5's `>`
   (UTF-16, which is refused), in a folder only your account can read.
2. Re-wrap on the server:

   ```bash
   deploy/deploy.sh rewrap-key new-wrap.key --confirm=DOMAIN
   ```

   That copies the key to the server, stops gunicorn, which still has the
   old key, and runs `manage.py rewrap_keys` with the server's `.env`. Every
   key is opened with the old key, checked to be the private half of its
   own public key, wrapped under the new one and opened again, in one
   transaction; one that opens with neither refuses the run, and nothing
   changes. Refused, the site serves again as it did. Re-wrapped, **gunicorn
   stays stopped**: the server's `.env` still has the old key, which opens
   none of them now. The key's copy on the server is deleted either way.
3. Put the new value in `site.conf` as `CREDENTIAL_EPOCH_WRAP_KEY` and
   deploy, which writes the server's `.env` and starts the application. The
   deploy's `migrate` and `deploy/deploy.sh check` warn (`accounts.W004`)
   if a stored key does not open with it, and Setup says so in red.
4. Only then delete `new-wrap.key`: until the site runs on the new key, that
   file is the only copy of it.

Running step 2 again finishes a run that stopped: keys already under the
new key are left as they are. If `accounts.W004` names a key after step 3,
it was made under the old key in between (a server that restarted, say):
on the server, with gunicorn stopped and `.env` loaded the way deploy.sh
loads it, `manage.py rewrap_keys --old-key-file OLD --confirm DOMAIN`
re-wraps it from the old key, the old value in a file only you can open.

**A backup made before the change** opens only with the old key, and
`restore` refuses it. Re-wrap a copy first, on any machine with this
repository and its requirements:

```bash
python manage.py rewrap_keys --database db-20260101-120000.sqlite3 \
    --old-key-file old-wrap.key --new-key-file new-wrap.key
deploy/deploy.sh restore db-20260101-120000.sqlite3 --confirm=DOMAIN
```

Each key in a file only you can open: the new one is the value in
`site.conf`. Keep the old value as long as you keep backups made under it.
Do not put the old key back in `site.conf` to restore one: `restore` would
carry this site's newer keys, under the new key, into the copy, and it
refuses that.

**A database from before the rename to CL03**. The label in each key's
wrapping changed with the format, so none of the stored keys opens on this
version, even under the right wrap key: the first deploy's `migrate` warns
(`accounts.W004`) and every sync answers 503. Straight after that deploy, on
the server, with gunicorn stopped and `.env` loaded the way deploy.sh loads
it:

```bash
python manage.py rewrap_keys --before-cl03 --confirm DOMAIN --dry-run
python manage.py rewrap_keys --before-cl03 --confirm DOMAIN
sudo systemctl start gunicorn
```

The wrap key does not change, so neither does `.env`. A backup from before
the rename needs the same before it is restored:
`python manage.py rewrap_keys --before-cl03 --database COPY`. This moves
stored keys only. Credentials issued before the rename must be issued again,
and each phone needs the new build: **send its activity log first** (Settings,
Send log: a sync does not send it), while phone and server are both on the old
version. Records still on a phone when it is updated are lost: the server
counts them unreadable, the phone deletes them with the newer records it
sends, and that phone's next record shows as a break in its chain. If an upload
holds nothing newer, 500 old records or more, Send log fails until the phone
is reset, which erases them and its attested key.

**Leftovers.** Paths excluded from the sync are also protected from its
`--delete`, and `collectstatic` never prunes. A file removed from `static/`
therefore stays on the server until you delete it by hand. `check` lists
excluded paths it finds there.

**Nothing routine replaces the app server, deliberately.** Its disk is the
database. A newer Amazon Linux image and edits to the boot script are both
ignored for the existing server. If you change `deploy/nginx.conf.tftpl` or
the gunicorn templates, `check` reports the difference; copy the rendered
file onto the server by hand.

**A second site**, such as a test copy, is a second folder with its own
`site.conf` and a different `SITE_NAME`. The two share nothing.

## A server built some other way

To deploy onto a server you built yourself, set `SERVER_IP` (and
`JUMP_HOST`, if it is reached through one) in `site.conf`, and skip
`infra`. The server must have the layout the boot script creates:

- an `ec2-user` account
- the application under `/home/ec2-user/app`
- a Python 3.11 virtualenv
- gunicorn's unit and nginx installed from `deploy/`

`hostkeys` cannot read such a server's keys from AWS, so put them in
`known_hosts` beside `site.conf` yourself: one line per key, the name
`server` (and `bastion` for `JUMP_HOST`) followed by the key as it appears in
the server's `/etc/ssh/ssh_host_*_key.pub`. Copy the keys by a channel you
trust (the provider's console, or someone at the machine), not over the
network the deploy will use.

## Troubleshooting

| Symptom | Likely cause |
|---|---|
| `infra` says the credentials belong to another account | They are not the site's. Check `AWS_ACCESS_KEY_ID` or `AWS_PROFILE` in `site.conf`; nothing was changed |
| `infra` stops at the certificate | Its DNS validation record does not exist yet. Run `infra certificate` and create the record it prints |
| `no SSH host key for the server` | `known_hosts` beside `site.conf` lacks it: `deploy/deploy.sh hostkeys` |
| ssh says `REMOTE HOST IDENTIFICATION HAS CHANGED` | The server or bastion is not the one pinned. If it was rebuilt, run `hostkeys` again; if not, stop and find out why |
| `hostkeys` says the console no longer shows the keys | The instance rebooted since it was built, and the console keeps only the latest boot. For the server, read `/etc/ssh/ssh_host_*_key.pub` through Systems Manager (Session Manager, on the AWS console) and put the keys in `known_hosts` under `server` |
| The load balancer marks the server unhealthy after a deploy | `deploy.sh check`. Usually gunicorn failed to start; on the server, `journalctl -u gunicorn` |
| The smoke test cannot reach the site | `DOMAIN` is not yet pointed at the load balancer, or the DNS change has not spread |
| The site will not start: `DJANGO_SECRET_KEY is not set` | `DJANGO_SECRET_KEY` is empty in `site.conf` |
| Device pairing QR codes say `http://` | Something replaced `X-Forwarded-Proto` between the load balancer and Django. `check` shows whether nginx's configuration differs from `deploy/` |
| eVerify answers 401 `Unauthenticated.` | The client id or secret is wrong |
| eVerify answers 401 `Unauthorized.` | The credentials are right, but the client is not entitled to that endpoint. That is a matter for PSA |
| A real person's sign-in says "No matching record" | They are not registered on the site, or are registered with a different ID number |
