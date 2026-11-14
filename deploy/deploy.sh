#!/bin/bash
# Build and deploy one Verify site from its configuration file.
#
#   deploy/deploy.sh [--config SITE.conf] [COMMAND]
#
#   infra [apply|plan|destroy|output|certificate]
#             build or change the site's AWS resources with Terraform
#   deploy    (the default) install the settings, the key files and the code
#   check     report on the server; change nothing
#   validate  check the configuration file; connect to nothing
#   ssh       open a shell on the server, through the bastion
#   backup    copy a consistent snapshot of the database to this machine
#   restore FILE --confirm=HOST
#             put FILE in place of the server's database, backing that up
#   rewrap-key FILE --confirm=HOST
#             re-wrap the server's stored keys under the wrap key in FILE
#             (manage.py rewrap_keys); gunicorn stays stopped until a deploy
#             brings that key
#   hostkeys  read the bastion's and the server's SSH host keys from AWS
#             into known_hosts beside the configuration file
#
# SITE.conf is deploy/site.conf.example filled in, and kept OUTSIDE this
# repository: it holds the site's secrets. Name it with --config, or once
# per shell with `export VERIFY_SITE=path/to/site.conf`.
#
# deploy:
#   1. writes the server's .env from the configuration file and installs it
#      (mode 600, the previous one kept), and copies the key files it names;
#   2. syncs the code, installs requirements, migrates, collects static
#      files and restarts gunicorn. On a server's first deploy it starts
#      gunicorn instead, and creates the first superuser. It installs, or
#      brings up to date, the daily purge of the phones' activity log
#      (install-purge-timer.sh);
#   3. smoke-tests /health/ and /api/lookup-data/ through the load balancer.
#   The database is never copied unless --sync-db=HOST names the site, and
#   that REPLACES the server's database with the local db.sqlite3, the way
#   `restore` does with a backup: gunicorn stopped, the server's database
#   backed up on the server first, a copy refused whose keys the server
#   cannot open (manage.py replace_database).
#
# SSH trusts only the host keys in known_hosts beside the configuration file,
# which `hostkeys` reads from AWS (an instance prints them at first boot);
# a server built some other way gets them put there by hand.
#
# The server's and the bastion's addresses come from the Terraform state
# beside the configuration file, read on every run, so no address is ever
# written down. A server built some other way is named with SERVER_IP and
# JUMP_HOST in the configuration file.

set -euo pipefail

DEPLOY_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$DEPLOY_DIR")"
TF_DIR="$PROJECT_DIR/terraform"

# --- What the configuration file may hold -------------------------------------
#
# Three kinds of key, and every other key is refused. APP_KEYS is exactly the
# set the application reads from its environment; accounts/tests.py fails if
# the two ever differ.

INFRA_KEYS="SITE_NAME DOMAIN AWS_ACCOUNT_ID AWS_REGION AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY AWS_PROFILE SSH_ALLOWED_CIDRS SSH_PUBLIC_KEY_FILE
ROUTE53_ZONE_ID CERTIFICATE_ARN INSTANCE_TYPE BASTION_INSTANCE_TYPE VPC_CIDR
ROOT_VOLUME_GB SNAPSHOT_RETENTION_DAYS"

DEPLOY_KEYS="SSH_PRIVATE_KEY_FILE SERVER_IP JUMP_HOST REMOTE_USER APP_DIR
REMOTE_SECRETS_DIR ISSUER_KEY_FILE WALLET_CERT_FILE WALLET_KEY_FILE
WALLET_WWDR_FILE BRANDING_FOLDER"

APP_KEYS="DJANGO_SECRET_KEY DJANGO_ALLOWED_HOSTS DJANGO_DEBUG
DJANGO_SUPERUSER_USERNAME DJANGO_SUPERUSER_EMAIL DJANGO_SUPERUSER_PASSWORD
EVERIFY_CLIENT_ID EVERIFY_CLIENT_SECRET EVERIFY_PUBLIC_API_KEY EVERIFY_BASE_URL
EVERIFY_ALLOWED_HOSTS EVERIFY_FACE_HOSTS SSO_ALLOWED_ISSUERS VERIFY_PROXY_HOPS
SESSION_ABSOLUTE_SECONDS VERIFY_HSTS_SECONDS VERIFY_HSTS_INCLUDE_SUBDOMAINS
EVERIFY_ALLOW_MOCK_LOGIN EVERIFY_DEBUG_CAPTURE VERIFY_WORKBENCH VERIFY_DEFAULT_ORG_NAME
CREDENTIAL_ISSUER_KEY_PATH CREDENTIAL_ISSUER_KEY_ID SIGNER_SOCKET
SIGNER_QUEUE_KEY SIGNER_QUEUE_TIMEOUT_SECONDS SIGNER_QUEUE_MAX_WAITING
GUNICORN_THREADS
CREDENTIAL_ISSUER_CA_FINGERPRINTS SIGNER_REPORT_TOKEN_SHA256 CREDENTIAL_GENESIS
CREDENTIAL_EPOCH_SECONDS CREDENTIAL_OVERLAP_EPOCHS CREDENTIAL_EPOCH_WRAP_KEY
CREDENTIAL_FILE_MODE_AFTER_SIGNER
CREDENTIAL_MAX_VALIDITY_DAYS CREDENTIAL_MAX_QR_CODES CREDENTIAL_REVOCATION_TTL_SECONDS
CREDENTIAL_REVOCATION_REBUILD_SECONDS DEVICE_PAIRING_BASE_URL
DEVICE_PAIRING_TTL_SECONDS DEVICE_LEASE_SECONDS DEVICE_CHALLENGE_TTL_SECONDS
DEVICE_REQUIRE_APP_ATTEST DEVICE_APP_ATTEST_APP_ID DEVICE_APP_ATTEST_ENVIRONMENT
DEVICE_REQUIRE_KEYS_CONTEXT DEVICE_LOG_DAILY_RECORDS DEVICE_LOG_RETENTION_DAYS
CARD_HANDOFF_TTL_SECONDS
PORTRAIT_FORMAT
WALLET_PASS_TYPE_ID
WALLET_TEAM_ID WALLET_CERT_PATH WALLET_KEY_PATH WALLET_WWDR_PATH SITE_TITLE
SITE_FOOTER_LABEL SITE_FOOTER_LOGOS BRANDING_DIR HOLDER_ASSERTION_ISSUER
HOLDER_ASSERTION_KEYS HOLDER_ASSERTION_MAX_LIFETIME_SECONDS
HOLDER_VERIFICATION_MAX_AGE_SECONDS HOLDER_CREDENTIAL_ISSUER_NAME HOLDER_REQUIRE_CONTEXT
USER_RECORDS_KEY"

# Key files on this machine, the server setting each one feeds, and the name
# it is given in REMOTE_SECRETS_DIR.
SECRET_FILES="ISSUER_KEY_FILE:CREDENTIAL_ISSUER_KEY_PATH:verify-issuer.pem
WALLET_CERT_FILE:WALLET_CERT_PATH:wallet-cert.pem
WALLET_KEY_FILE:WALLET_KEY_PATH:wallet-key.pem
WALLET_WWDR_FILE:WALLET_WWDR_PATH:wallet-wwdr.pem"

PATH_KEYS="SSH_PUBLIC_KEY_FILE SSH_PRIVATE_KEY_FILE ISSUER_KEY_FILE
WALLET_CERT_FILE WALLET_KEY_FILE WALLET_WWDR_FILE BRANDING_FOLDER"

# What stays OFF the server. rsync does not read .gitignore, so this list is
# the whole of what keeps a file out of the application directory.
#
# demo/ holds synthetic CSVs shaped exactly like an organization's transaction
# export. Nothing serves them and nobody real is in them, but a file of names
# and National ID numbers in the application directory of a production box is
# a thing somebody has to stop and rule out.
#
# dbbackup/ and backups/ are the sharpest of these. They are where database
# backups are pulled down to, so they hold whole databases: real operators,
# both of their National ID numbers, the transaction log, refused sign-ins
# with their faces. Being in .gitignore keeps them out of git and does
# nothing at all here.
# secrets/, *.pem and *.key are the same shape: key files belong in
# REMOTE_SECRETS_DIR, outside the code directory, never synced with it.
#
# Excluding a path also protects it from --delete, so adding an exclusion
# does not remove what earlier deploys already copied. `check` lists any such
# leftovers; delete them on the server by hand.
EXCLUDES=(
    '.git'
    'venv'
    '*.pyc'
    '__pycache__'
    '.env'
    '.env.*'
    'staticfiles/'
    'deploy/'
    'terraform/'
    'site/'
    'references/'
    'demo/'
    'dbbackup/'
    'backups/'
    '.vscode/'
    'secrets/'
    '*.pem'
    '*.key'
    'db.sqlite3'
)

die() { echo "deploy: $*" >&2; exit 1; }
warn() { echo "deploy: WARNING: $*" >&2; }
usage() {
    sed -n '2,/^$/s/^# \{0,1\}//p' "$0"
    exit "${1:-2}"
}
# True when the whole of $1 matches the extended regular expression $2.
fits() { printf '%s\n' "$1" | grep -qxE -- "$2"; }
is_true() {
    case "$(printf '%s' "$1" | tr 'A-Z' 'a-z')" in
        true|1|yes) return 0 ;;
    esac
    return 1
}
trim() {
    local s="$1"
    s="${s#"${s%%[![:space:]]*}"}"
    s="${s%"${s##*[![:space:]]}"}"
    printf '%s' "$s"
}
in_list() { case " $(echo $2) " in *" $1 "*) return 0 ;; esac; return 1; }
# Git Bash on Windows: rsync reads "C:" as a host name, so every local path
# handed to it is converted to /c/... first; Terraform, a Windows program,
# is handed C:/... instead.
to_unix() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -u "$1"; else printf '%s' "$1"; fi
}
native() {
    if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi
}

TMPFILES=()
cleanup() {
    if [ "${#TMPFILES[@]}" -gt 0 ]; then rm -f "${TMPFILES[@]}"; fi
}
trap cleanup EXIT

# --- Arguments ----------------------------------------------------------------

CONFIG="${VERIFY_SITE:-}" COMMAND="" SUBCOMMAND="" SYNC_HOST="" CONFIRM=""
while [ $# -gt 0 ]; do
    case "$1" in
        --config) [ $# -ge 2 ] || die "--config needs a file"; CONFIG="$2"; shift 2 ;;
        # Named, not a switch: replacing a server's database has to say
        # which site's.
        --sync-db=?*) SYNC_HOST="${1#--sync-db=}"; shift ;;
        --sync-db|--sync-db=) die "--sync-db replaces the server's database: name the site, --sync-db=HOST (its DOMAIN)" ;;
        --confirm=?*) CONFIRM="${1#--confirm=}"; shift ;;
        -h|--help) usage 0 ;;
        -*) echo "deploy: unknown option $1" >&2; usage ;;
        *)
            if [ -z "$COMMAND" ]; then COMMAND="$1"
            elif [ -z "$SUBCOMMAND" ]; then SUBCOMMAND="$1"
            else usage; fi
            shift ;;
    esac
done
COMMAND="${COMMAND:-deploy}"
case "$COMMAND" in
    infra|deploy|check|validate|ssh|backup|restore|rewrap-key|hostkeys) ;;
    *) echo "deploy: unknown command $COMMAND" >&2; usage ;;
esac
[ -z "$SYNC_HOST" ] || [ "$COMMAND" = deploy ] || die "--sync-db goes with deploy"
[ -n "$CONFIG" ] || die "name the site's configuration file with --config, or export VERIFY_SITE"

# --- The configuration file -------------------------------------------------------
#
# Parsed, never sourced: it is data, and a stray line in it must not run as a
# command on the operator's machine. Every key starts empty, so a setting
# that happens to be in the operator's own shell never reaches the server.
#
# The same goes for AWS and Terraform. A site has an AWS account of its own,
# and its access comes from this file and nowhere else: credentials, a
# profile or a region in the operator's shell may belong to another
# deployment entirely, and so may TF_VAR_* or TF_CLI_ARGS*, which would
# quietly add variables or flags to every Terraform run.

unset AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_SECURITY_TOKEN \
    AWS_PROFILE AWS_DEFAULT_PROFILE AWS_REGION AWS_DEFAULT_REGION \
    AWS_CONFIG_FILE AWS_SHARED_CREDENTIALS_FILE AWS_ROLE_ARN \
    AWS_ROLE_SESSION_NAME AWS_WEB_IDENTITY_TOKEN_FILE TF_WORKSPACE TF_DATA_DIR
for var in $(compgen -e | grep -E '^(TF_VAR_|TF_CLI_ARGS)' || true); do
    unset "$var"
done

for key in $INFRA_KEYS $DEPLOY_KEYS $APP_KEYS; do
    printf -v "$key" '%s' ''
done

CONFIG="$(to_unix "$CONFIG")"
[ -f "$CONFIG" ] || die "no such configuration file: $CONFIG"
SITE_DIR="$(cd "$(dirname "$CONFIG")" && pwd)"
lineno=0
while IFS= read -r line || [ -n "$line" ]; do
    lineno=$((lineno + 1))
    line="$(trim "${line%$'\r'}")"
    case "$line" in ''|\#*) continue ;; esac
    case "$line" in *=*) ;; *) die "$CONFIG:$lineno: expected KEY=value" ;; esac
    key="$(trim "${line%%=*}")"
    value="$(trim "${line#*=}")"
    case "$value" in \"*|\'*) die "$CONFIG:$lineno: $key is quoted; write the value bare" ;; esac
    if ! fits "$key" '[A-Z][A-Z0-9_]*' || ! in_list "$key" "$INFRA_KEYS $DEPLOY_KEYS $APP_KEYS"; then
        die "$CONFIG:$lineno: unknown key $key"
    fi
    if [ -n "$value" ] && in_list "$key" "$PATH_KEYS"; then
        value="$(to_unix "$value")"
        case "$value" in /*) ;; *) value="$SITE_DIR/$value" ;; esac
    fi
    printf -v "$key" '%s' "$value"
done < "$CONFIG"

REMOTE_USER="${REMOTE_USER:-ec2-user}"
APP_DIR="${APP_DIR:-/home/$REMOTE_USER/app}"
REMOTE_SECRETS_DIR="${REMOTE_SECRETS_DIR:-/home/$REMOTE_USER/secrets}"
DJANGO_ALLOWED_HOSTS="${DJANGO_ALLOWED_HOSTS:-$DOMAIN}"
SITE_URL=""
[ -z "$DOMAIN" ] || SITE_URL="https://$DOMAIN"
# The SSH host keys this site trusts (see "SSH host keys" below).
KNOWN_HOSTS="$SITE_DIR/known_hosts"

plain_path() { fits "$1" '/[A-Za-z0-9._/-]+' && case "$1" in *..*) false ;; *) true ;; esac; }

# The database a deploy or a restore puts in place, and the site it names.
INCOMING=""
if [ "$COMMAND" = restore ]; then
    [ -n "$SUBCOMMAND" ] || die "restore needs the database file to put in place"
    INCOMING="$(to_unix "$SUBCOMMAND")"
    # As given, or in the site's folder, where `backup` puts its copies.
    case "$INCOMING" in
        /*) ;;
        *) [ -f "$INCOMING" ] || INCOMING="$SITE_DIR/$INCOMING" ;;
    esac
    [ -f "$INCOMING" ] || die "no such file: $SUBCOMMAND"
    [ -n "$CONFIRM" ] || die "restore replaces the server's database: name the site, --confirm=HOST (its DOMAIN)"
    SYNC_HOST="$CONFIRM"
fi
# The new wrap key `rewrap-key` sends, found the same way, and the site it names.
KEY_FILE=""
if [ "$COMMAND" = rewrap-key ]; then
    [ -n "$SUBCOMMAND" ] || die "rewrap-key needs the file that holds the new wrap key"
    KEY_FILE="$(to_unix "$SUBCOMMAND")"
    case "$KEY_FILE" in
        /*) ;;
        *) [ -f "$KEY_FILE" ] || KEY_FILE="$SITE_DIR/$KEY_FILE" ;;
    esac
    [ -f "$KEY_FILE" ] || die "no such file: $SUBCOMMAND"
    [ -n "$CONFIRM" ] || die "rewrap-key changes every stored key on the server: name the site, --confirm=HOST (its DOMAIN)"
    SYNC_HOST="$CONFIRM"
fi
if [ -n "$SYNC_HOST" ]; then
    # A host name: the server's address and localhost name no site.
    ! printf '%s\n' "$SYNC_HOST" | grep -qixE '[0-9.:]+|localhost|\*|\..*' \
        || die "name the site by its host name, its DOMAIN, not $SYNC_HOST; nothing was changed"
    in_list "$(printf '%s' "$SYNC_HOST" | tr 'A-Z' 'a-z')" \
            "$(printf '%s' "$DJANGO_ALLOWED_HOSTS" | tr 'A-Z,' 'a-z ')" \
        || die "$SYNC_HOST is not this site (DOMAIN and DJANGO_ALLOWED_HOSTS in $(basename "$CONFIG")); nothing was changed"
fi
if [ "$COMMAND" = deploy ] && [ -n "$SYNC_HOST" ]; then
    INCOMING="$PROJECT_DIR/db.sqlite3"
    [ -f "$INCOMING" ] || die "--sync-db: there is no db.sqlite3 in $PROJECT_DIR to send"
fi
fits "$REMOTE_USER" '[a-z_][a-z0-9_-]*' || die "REMOTE_USER is not a plain user name"
plain_path "$APP_DIR" || die "APP_DIR must be an absolute path of plain characters"
plain_path "$REMOTE_SECRETS_DIR" || die "REMOTE_SECRETS_DIR must be an absolute path of plain characters"
case "$REMOTE_SECRETS_DIR/" in
    "$APP_DIR/verify/"*) die "REMOTE_SECRETS_DIR is inside the code directory, which every deploy rewrites" ;;
esac

# --- Checks ---------------------------------------------------------------------
#
# Name keys, never values: this output lands in terminals and CI logs.

PROBLEMS=0
problem() { echo "  $*" >&2; PROBLEMS=$((PROBLEMS + 1)); }
need() {
    local key
    for key in "$@"; do [ -n "${!key}" ] || problem "$key: missing or empty"; done
}

check_infra_settings() {
    need SITE_NAME DOMAIN AWS_ACCOUNT_ID AWS_REGION SSH_ALLOWED_CIDRS SSH_PUBLIC_KEY_FILE
    [ -z "$SITE_NAME" ] || fits "$SITE_NAME" '[a-z][a-z0-9-]{1,23}' \
        || problem "SITE_NAME: 2 to 24 lower-case letters, digits and hyphens, starting with a letter"
    [ -z "$AWS_ACCOUNT_ID" ] || fits "$AWS_ACCOUNT_ID" '[0-9]{12}' \
        || problem "AWS_ACCOUNT_ID: the account's 12-digit id"
    [ -z "$SSH_PUBLIC_KEY_FILE" ] || [ -f "$SSH_PUBLIC_KEY_FILE" ] \
        || problem "SSH_PUBLIC_KEY_FILE: no such file"
    # The site's own credentials, one way or the other. With neither, the AWS
    # tools would fall back to this machine's default credentials -- which
    # may well belong to another deployment's account.
    if [ -n "$AWS_ACCESS_KEY_ID$AWS_SECRET_ACCESS_KEY" ]; then
        need AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
        [ -z "$AWS_PROFILE" ] || problem "AWS_PROFILE: set the access keys or a profile, not both"
    elif [ -z "$AWS_PROFILE" ]; then
        problem "AWS credentials: set AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY, or AWS_PROFILE. Without them this machine's default credentials would be used, and they may belong to another account"
    fi
}

# The site's AWS access, exported for the AWS CLI and Terraform only. With
# access keys, the machine's own AWS configuration files are hidden as well,
# so nothing in a default profile can mix in.
aws_access() {
    export AWS_REGION AWS_DEFAULT_REGION="$AWS_REGION"
    if [ -n "$AWS_ACCESS_KEY_ID" ]; then
        export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY
        : > "$SITE_DIR/.aws-empty"
        export AWS_CONFIG_FILE="$(native "$SITE_DIR/.aws-empty")"
        export AWS_SHARED_CREDENTIALS_FILE="$(native "$SITE_DIR/.aws-empty")"
    else
        export AWS_PROFILE
    fi
}

# Refuse to go on unless the credentials belong to the site's own account.
# Terraform checks again (allowed_account_ids); this says so before it starts.
check_account() {
    local actual
    command -v aws >/dev/null 2>&1 || die "needs the AWS CLI"
    actual="$(MSYS_NO_PATHCONV=1 aws sts get-caller-identity --query Account --output text | tr -d '\r')" \
        || die "AWS refused these credentials; nothing was changed"
    [ "$actual" = "$AWS_ACCOUNT_ID" ] \
        || die "these credentials belong to AWS account $actual, not this site's AWS_ACCOUNT_ID $AWS_ACCOUNT_ID; nothing was changed"
    echo "=== AWS account $actual, region $AWS_REGION ==="
}

check_server_settings() {
    local key value entry file setting
    need DJANGO_SECRET_KEY DJANGO_ALLOWED_HOSTS SSH_PRIVATE_KEY_FILE
    [ -z "$DJANGO_SECRET_KEY" ] || [ "${#DJANGO_SECRET_KEY}" -ge 50 ] \
        || warn "DJANGO_SECRET_KEY is ${#DJANGO_SECRET_KEY} characters; Django recommends at least 50"
    [ -z "$SSH_PRIVATE_KEY_FILE" ] || [ -f "$SSH_PRIVATE_KEY_FILE" ] \
        || problem "SSH_PRIVATE_KEY_FILE: no such file"
    if is_true "$DJANGO_DEBUG"; then
        is_true "$EVERIFY_ALLOW_MOCK_LOGIN" \
            && problem "DJANGO_DEBUG and EVERIFY_ALLOW_MOCK_LOGIN are both on: anybody could sign in as anybody"
        warn "DJANGO_DEBUG is on; a server should not run with it"
    fi
    [ -z "$VERIFY_WORKBENCH" ] \
        || warn "VERIFY_WORKBENCH is set: with EVERIFY_DEBUG_CAPTURE, this server keeps whole eVerify responses. A development server only"
    [ -n "$EVERIFY_CLIENT_ID" ] \
        || warn "EVERIFY_CLIENT_ID is empty: operators can sign in only once a site administrator saves a client on the Setup page"
    # An issuer key with no epoch wrap key mints nothing: every document
    # would print the plain QR.
    if [ -n "$SIGNER_SOCKET$SIGNER_QUEUE_KEY$ISSUER_KEY_FILE$CREDENTIAL_ISSUER_KEY_PATH" ] \
            && [ -z "$CREDENTIAL_EPOCH_WRAP_KEY" ]; then
        problem "CREDENTIAL_EPOCH_WRAP_KEY is empty, but an issuer key is set (SIGNER_SOCKET, SIGNER_QUEUE_KEY, ISSUER_KEY_FILE or CREDENTIAL_ISSUER_KEY_PATH): no document would carry a credential"
    fi
    for entry in $SECRET_FILES; do
        file="${entry%%:*}"; setting="${entry#*:}"; setting="${setting%%:*}"
        if [ -n "${!file}" ]; then
            [ -f "${!file}" ] || problem "$file: no such file"
            [ -z "${!setting}" ] || problem "$setting: set $file or $setting, not both"
        fi
    done
    # Footer logos: files in the site's branding folder, named the way the
    # application accepts them (verify/branding.py drops anything else).
    if [ -n "$BRANDING_FOLDER" ]; then
        [ -d "$BRANDING_FOLDER" ] || problem "BRANDING_FOLDER: no such folder"
        [ -z "$BRANDING_DIR" ] || problem "BRANDING_DIR: set BRANDING_FOLDER or BRANDING_DIR, not both"
    fi
    if [ -n "$SITE_FOOTER_LOGOS" ]; then
        [ -n "$BRANDING_FOLDER$BRANDING_DIR" ] \
            || problem "SITE_FOOTER_LOGOS: set BRANDING_FOLDER to the folder the logos are in"
        local logo name logos
        IFS=';' read -r -a logos <<< "$SITE_FOOTER_LOGOS"
        for logo in ${logos[@]+"${logos[@]}"}; do
            name="$(trim "${logo%%|*}")"
            [ -n "$name" ] || continue
            fits "$name" '[A-Za-z0-9][A-Za-z0-9._-]*\.([Pp][Nn][Gg]|[Jj][Pp][Ee]?[Gg]|[Gg][Ii][Ff]|[Ww][Ee][Bb][Pp])' \
                || problem "SITE_FOOTER_LOGOS: $name is not a plain PNG, JPEG, GIF or WebP file name"
            [ -z "$BRANDING_FOLDER" ] || [ -f "$BRANDING_FOLDER/$name" ] \
                || problem "SITE_FOOTER_LOGOS: $name is not in BRANDING_FOLDER"
        done
    fi
    for key in $APP_KEYS; do
        value="${!key}"
        [ -n "$value" ] || continue
        case "$value" in *\\*) warn "$key contains a backslash, which systemd may read differently" ;; esac
        case "$key" in
            *_PATH|*_DIR)
                case "$value" in
                    /*) ;;
                    *) problem "$key: not an absolute path on the server" ;;
                esac
                case "$value" in
                    "$APP_DIR/verify/"*) problem "$key: inside the code directory, which every deploy rewrites" ;;
                esac ;;
        esac
    done
}

# The server's .env, written from the configuration file. Only the
# application's own settings go in, and only those with a value: an empty
# one keeps the application's default.
render_env() {
    local key value entry file setting name
    echo "# Written by deploy/deploy.sh from the site's configuration file."
    echo "# Change the setting there and deploy again; edits here are replaced."
    for key in $APP_KEYS; do
        value="${!key}"
        for entry in $SECRET_FILES; do
            file="${entry%%:*}"; setting="${entry#*:}"; name="${setting#*:}"; setting="${setting%%:*}"
            if [ "$key" = "$setting" ] && [ -n "${!file}" ]; then
                value="$REMOTE_SECRETS_DIR/$name"
            fi
        done
        if [ "$key" = BRANDING_DIR ] && [ -n "$BRANDING_FOLDER" ]; then
            value="$APP_DIR/branding"
        fi
        [ -z "$value" ] || printf '%s=%s\n' "$key" "$value"
    done
}

# --- Terraform ---------------------------------------------------------------------
#
# The state lives beside the configuration file, never in this repository,
# and so does Terraform's working directory, so two sites cannot mix.

tf() {
    MSYS_NO_PATHCONV=1 TF_DATA_DIR="$(native "$SITE_DIR/.terraform")" \
        terraform -chdir="$(native "$TF_DIR")" "$@"
}
tf_init() {
    command -v terraform >/dev/null 2>&1 || die "needs Terraform 1.5 or later"
    tf init -input=false -reconfigure \
        -backend-config="path=$(native "$SITE_DIR/terraform.tfstate")" >/dev/null \
        || die "terraform init failed"
}
tf_inputs() {
    local cidr list=""
    export TF_VAR_aws_account_id="$AWS_ACCOUNT_ID"
    export TF_VAR_aws_region="$AWS_REGION"
    export TF_VAR_site_name="$SITE_NAME"
    export TF_VAR_domain_name="$DOMAIN"
    export TF_VAR_ssh_public_key="$(tr -d '\r\n' < "$SSH_PUBLIC_KEY_FILE")"
    for cidr in $(echo "$SSH_ALLOWED_CIDRS" | tr ',' ' '); do
        list="$list${list:+,}\"$cidr\""
    done
    export TF_VAR_ssh_allowed_cidrs="[$list]"
    [ -z "$ROUTE53_ZONE_ID" ] || export TF_VAR_route53_zone_id="$ROUTE53_ZONE_ID"
    [ -z "$CERTIFICATE_ARN" ] || export TF_VAR_certificate_arn="$CERTIFICATE_ARN"
    [ -z "$INSTANCE_TYPE" ] || export TF_VAR_instance_type="$INSTANCE_TYPE"
    [ -z "$BASTION_INSTANCE_TYPE" ] || export TF_VAR_bastion_instance_type="$BASTION_INSTANCE_TYPE"
    [ -z "$VPC_CIDR" ] || export TF_VAR_vpc_cidr="$VPC_CIDR"
    [ -z "$ROOT_VOLUME_GB" ] || export TF_VAR_root_volume_gb="$ROOT_VOLUME_GB"
    [ -z "$SNAPSHOT_RETENTION_DAYS" ] || export TF_VAR_snapshot_retention_days="$SNAPSHOT_RETENTION_DAYS"
}

# --- validate -------------------------------------------------------------------------

if [ "$COMMAND" = validate ]; then
    # A server built some other way needs no AWS settings.
    [ -n "$SERVER_IP" ] || check_infra_settings
    check_server_settings
    [ "$PROBLEMS" -eq 0 ] || die "$CONFIG: $PROBLEMS problem(s)"
    echo "$CONFIG: ok"
    echo "  AWS and Terraform: $(for k in $INFRA_KEYS; do [ -z "${!k}" ] || printf '%s ' "$k"; done)"
    echo "  server .env:      $(render_env | sed -n 's/^\([A-Z][A-Z0-9_]*\)=.*/\1/p' | tr '\n' ' ')"
    for entry in $SECRET_FILES; do
        file="${entry%%:*}"; name="${entry##*:}"
        [ -z "${!file}" ] || echo "  key file:         $file -> $REMOTE_SECRETS_DIR/$name"
    done
    exit 0
fi

# --- infra ------------------------------------------------------------------------------

if [ "$COMMAND" = infra ]; then
    check_infra_settings
    [ "$PROBLEMS" -eq 0 ] || die "$CONFIG: $PROBLEMS problem(s); nothing was changed"
    aws_access
    check_account
    tf_init
    tf_inputs
    case "${SUBCOMMAND:-apply}" in
        plan) tf plan -input=false ;;
        apply)
            tf apply
            echo "=== Built. The load balancer is $(tf output -raw alb_dns_name) ==="
            [ -n "$ROUTE53_ZONE_ID" ] || echo "    Point $DOMAIN at it with a CNAME, then: deploy/deploy.sh hostkeys, deploy/deploy.sh deploy"
            [ -z "$ROUTE53_ZONE_ID" ] || echo "    Next: deploy/deploy.sh hostkeys, then deploy/deploy.sh deploy"
            ;;
        destroy)
            echo "deploy: this deletes the server and its database. Take a backup first: deploy/deploy.sh backup" >&2
            tf destroy ;;
        output) tf output ;;
        certificate)
            [ -z "$CERTIFICATE_ARN" ] || die "CERTIFICATE_ARN is set: there is no certificate to request"
            tf apply -target=aws_acm_certificate.app
            echo "=== Create this record in the DNS for $DOMAIN, then: deploy/deploy.sh infra ==="
            tf output acm_validation_records ;;
        *) die "unknown infra command ${SUBCOMMAND}" ;;
    esac
    exit 0
fi

# --- SSH host keys -------------------------------------------------------------------------
#
# Only the keys in this file are trusted, under the names `bastion` and
# `server`: trusting whatever key answered would send the .env and the
# key files to it. An instance's first boot prints its keys to the EC2
# console, which AWS hands back over its own authenticated API:
# `hostkeys` reads them from there.

if [ "$COMMAND" = hostkeys ]; then
    [ -f "$SITE_DIR/terraform.tfstate" ] \
        || die "hostkeys reads the instances built by infra; for a server built some other way, put its keys in $KNOWN_HOSTS by hand (docs/deploy-aws.md)"
    check_infra_settings
    [ "$PROBLEMS" -eq 0 ] || die "$CONFIG: $PROBLEMS problem(s); nothing was changed"
    aws_access
    check_account
    tf_init
    pin() {
        local name="$1" id="$2" keys="" tries=0
        fits "$id" 'i-[0-9a-f]+' || die "Terraform knows no $name instance: run deploy/deploy.sh infra first"
        while :; do
            keys="$(MSYS_NO_PATHCONV=1 aws ec2 get-console-output --instance-id "$id" --output text 2>/dev/null \
                | tr -d '\r' \
                | sed -n '/^-----BEGIN SSH HOST KEY KEYS-----$/,/^-----END SSH HOST KEY KEYS-----$/p' \
                | grep -E '^(ssh-ed25519|ecdsa-sha2-nistp256|ssh-rsa) ' || true)"
            [ -z "$keys" ] || break
            tries=$((tries + 1))
            # A server just built prints them at the end of its first boot.
            [ "$tries" -lt 20 ] || die "the $name ($id) has not shown its host keys on the EC2 console; if it rebooted since it was built, the console no longer holds them (docs/deploy-aws.md, Troubleshooting)"
            echo "    waiting for the $name to finish booting"
            sleep 30
        done
        touch "$KNOWN_HOSTS"
        grep -v "^$name " "$KNOWN_HOSTS" > "$KNOWN_HOSTS.new" || true
        printf '%s\n' "$keys" | awk -v name="$name" '{ print name " " $1 " " $2 }' >> "$KNOWN_HOSTS.new"
        mv "$KNOWN_HOSTS.new" "$KNOWN_HOSTS"
        grep "^$name " "$KNOWN_HOSTS" > "$KNOWN_HOSTS.show"
        echo "    $name ($id):"
        ssh-keygen -lf "$KNOWN_HOSTS.show" | sed 's/^/        /'
        rm -f "$KNOWN_HOSTS.show"
    }
    echo "=== Reading the SSH host keys from AWS into $KNOWN_HOSTS ==="
    pin bastion "$(tf output -raw bastion_instance_id | tr -d '\r')"
    pin server "$(tf output -raw server_instance_id | tr -d '\r')"
    exit 0
fi

# --- Which server ---------------------------------------------------------------------------

if [ -z "$SERVER_IP" ]; then
    [ -f "$SITE_DIR/terraform.tfstate" ] \
        || die "no Terraform state beside $CONFIG: run deploy/deploy.sh infra first, or set SERVER_IP"
    tf_init
    SERVER_IP="$(tf output -raw server_private_ip | tr -d '\r')"
    [ -n "$JUMP_HOST" ] || JUMP_HOST="$(tf output -raw bastion_public_ip | tr -d '\r')"
fi
fits "$SERVER_IP" '[A-Za-z0-9.:-]+' || die "SERVER_IP is not an address"
[ -z "$JUMP_HOST" ] || fits "$JUMP_HOST" '[A-Za-z0-9.:-]+' || die "JUMP_HOST is not an address"
if [ "$COMMAND" = deploy ]; then
    check_server_settings
else
    need SSH_PRIVATE_KEY_FILE
    [ -z "$SSH_PRIVATE_KEY_FILE" ] || [ -f "$SSH_PRIVATE_KEY_FILE" ] || problem "SSH_PRIVATE_KEY_FILE: no such file"
fi
[ "$PROBLEMS" -eq 0 ] || die "$CONFIG: $PROBLEMS problem(s); nothing was changed"

# --- SSH host keys: only these are trusted (hostkeys, above) -------------------------------

for name in server ${JUMP_HOST:+bastion}; do
    ssh-keygen -F "$name" -f "$KNOWN_HOSTS" >/dev/null 2>&1 \
        || die "no SSH host key for the $name in $KNOWN_HOSTS: run deploy/deploy.sh hostkeys, which reads it from AWS (a server built some other way: docs/deploy-aws.md)"
done

# --- SSH ------------------------------------------------------------------------------------
#
# The key is copied to a private temp file because NTFS mounts ignore chmod
# and ssh refuses a key others can read. With a bastion, the identity is
# named under BOTH hosts: `ssh -J` would not pass it to the first hop.

KEY_COPY="$(mktemp /tmp/deploy_key_XXXXXX)"
SSH_CONFIG="$(mktemp /tmp/deploy_ssh_config_XXXXXX)"
TMPFILES+=("$KEY_COPY" "$SSH_CONFIG")
cp "$SSH_PRIVATE_KEY_FILE" "$KEY_COPY"
chmod 600 "$KEY_COPY"

{
    if [ -n "$JUMP_HOST" ]; then
        printf 'Host jump\n    HostName %s\n    User %s\n    IdentityFile %s\n' "$JUMP_HOST" "$REMOTE_USER" "$KEY_COPY"
        printf '    HostKeyAlias bastion\n    UserKnownHostsFile "%s"\n' "$KNOWN_HOSTS"
        printf '    GlobalKnownHostsFile /dev/null\n    StrictHostKeyChecking yes\n'
        printf '    ConnectTimeout 60\n    LogLevel ERROR\n\n'
    fi
    printf 'Host target\n    HostName %s\n    User %s\n    IdentityFile %s\n' "$SERVER_IP" "$REMOTE_USER" "$KEY_COPY"
    printf '    HostKeyAlias server\n    UserKnownHostsFile "%s"\n' "$KNOWN_HOSTS"
    printf '    GlobalKnownHostsFile /dev/null\n    StrictHostKeyChecking yes\n'
    printf '    ConnectTimeout 60\n    LogLevel ERROR\n'
    [ -z "$JUMP_HOST" ] || printf '    ProxyJump jump\n'
} > "$SSH_CONFIG"

SSH_OPTS="-F $SSH_CONFIG"
REMOTE_ENV="APP_DIR=$(printf %q "$APP_DIR") REMOTE_SECRETS_DIR=$(printf %q "$REMOTE_SECRETS_DIR")"
VIA="${JUMP_HOST:+ (via $JUMP_HOST)}"

if [ "$COMMAND" = ssh ]; then
    # Not exec: the trap still has to delete the key's temp copy afterwards.
    status=0
    ssh $SSH_OPTS -t target || status=$?
    exit "$status"
fi

smoke_test() {
    [ -n "$SITE_URL" ] || return 0
    command -v curl >/dev/null 2>&1 || { warn "curl not found; no smoke test"; return 0; }
    echo "--- Smoke test: $SITE_URL ---"
    local code="" tries=0
    # A first deploy has to pass the load balancer's health checks before the
    # site answers at all, which takes a minute.
    while :; do
        code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$SITE_URL/health/" || true)"
        [ "$code" = 200 ] && break
        tries=$((tries + 1))
        [ "$tries" -lt 12 ] || break
        sleep 10
    done
    if [ "$code" = 200 ]; then echo "    ok    /health/ answers 200"; else warn "/health/ answers $code, not 200 (is $DOMAIN pointed at the load balancer yet?)"; fi
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 20 "$SITE_URL/api/lookup-data/" || true)"
    if [ "$code" = 403 ]; then echo "    ok    /api/lookup-data/ answers 403 signed out"; else warn "/api/lookup-data/ answers $code, not 403"; fi
    echo "    Then sign in as a real operator: a genuine sign-in is the only proof that sign-in works."
}

# --- backup ----------------------------------------------------------------------------------

if [ "$COMMAND" = backup ]; then
    stamp="$(date +%Y%m%d-%H%M%S)"
    remote_dir="$(dirname "$APP_DIR")/backups"
    echo "=== Backing up the database on $SERVER_IP$VIA ==="
    remote_sum="$(ssh $SSH_OPTS target "$REMOTE_ENV DEST=$(printf %q "$remote_dir/db-$stamp.sqlite3") bash -s" <<'REMOTE'
set -euo pipefail
mkdir -p "$(dirname "$DEST")"
chmod 700 "$(dirname "$DEST")"
# sqlite's online backup: consistent even while the site is writing.
"$APP_DIR/venv/bin/python" - "$APP_DIR/verify/db.sqlite3" "$DEST" <<'PY'
import sqlite3, sys
source, copy = sqlite3.connect(sys.argv[1]), sqlite3.connect(sys.argv[2])
with copy:
    source.backup(copy)
copy.close()
source.close()
PY
chmod 600 "$DEST"
sha256sum "$DEST" | cut -c1-64
REMOTE
)"
    mkdir -p "$SITE_DIR/backups"
    rsync -p --chmod=F600 -e "ssh $SSH_OPTS" "target:$remote_dir/db-$stamp.sqlite3" "$SITE_DIR/backups/"
    local_sum="$(sha256sum "$SITE_DIR/backups/db-$stamp.sqlite3" | cut -c1-64)"
    [ "$local_sum" = "$remote_sum" ] || die "the copy does not match the server's; it is left on the server at $remote_dir"
    ssh $SSH_OPTS target "rm -f $(printf %q "$remote_dir/db-$stamp.sqlite3")"
    echo "=== $SITE_DIR/backups/db-$stamp.sqlite3 (sha256 $local_sum) ==="
    echo "    It holds personal data -- operators, ID numbers, faces from refused sign-ins. Store it accordingly."
    exit 0
fi

# --- restore: a database put in place of the server's ------------------------------------------

# Sends $INCOMING beside the server's database. replace_remote_db (in the
# remote steps) puts it in place.
send_incoming() {
    echo "--- Sending $(basename "$INCOMING") to replace $SYNC_HOST's database ---"
    rsync -p --chmod=F600 -e "ssh $SSH_OPTS" "$INCOMING" "target:$APP_DIR/db.sqlite3.incoming"
}

if [ "$COMMAND" = restore ]; then
    echo "=== Restoring $SYNC_HOST's database on $SERVER_IP$VIA from $(basename "$INCOMING") ==="
    send_incoming
    status=0
    ssh $SSH_OPTS target "$REMOTE_ENV SYNC_HOST=$(printf %q "$SYNC_HOST") bash -s" <<'REMOTE' || status=$?
set -uo pipefail
# However this ends, the copy sent is gone and the site serves again.
finish() {
    rm -f "$APP_DIR/db.sqlite3.incoming" "$APP_DIR/db.sqlite3.incoming-wal" \
        "$APP_DIR/db.sqlite3.incoming-shm"
    sudo systemctl start gunicorn
}
trap finish EXIT
cd "$APP_DIR/verify"
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
    key=${line%%=*} value=${line#*=}
    [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
    export "$key=$value"
done < "$APP_DIR/.env"
sudo systemctl stop gunicorn
"$APP_DIR/venv/bin/python" manage.py replace_database "$APP_DIR/db.sqlite3.incoming" \
    --confirm "$SYNC_HOST" || exit 3
# Replaced: an older copy needs the code's migrations before it serves.
"$APP_DIR/venv/bin/python" manage.py migrate --noinput || exit 4
exit 0
REMOTE
    case "$status" in
        0) ;;
        3) die "the database was not replaced (see above); the server serves the one it had" ;;
        4) die "the database was replaced, but migrate failed (see above): the server runs on it unmigrated. The one it replaced is in the backup named above" ;;
        *) die "the restore stopped (status $status); see above" ;;
    esac
    smoke_test
    echo "=== Done. Phones paired since the copy was made must reset and pair again (see above) ==="
    exit 0
fi

# --- rewrap-key: every stored key under a new wrap key ----------------------------------------

if [ "$COMMAND" = rewrap-key ]; then
    echo "=== Re-wrapping $SYNC_HOST's stored keys on $SERVER_IP$VIA under the key in $(basename "$KEY_FILE") ==="
    rsync -p --chmod=F600 -e "ssh $SSH_OPTS" "$KEY_FILE" "target:$APP_DIR/new-wrap.key"
    status=0
    ssh $SSH_OPTS target "$REMOTE_ENV SYNC_HOST=$(printf %q "$SYNC_HOST") bash -s" <<'REMOTE' || status=$?
set -uo pipefail
# The key's copy goes however this ends. gunicorn serves again only if
# nothing was re-wrapped: after a re-wrap the .env here still holds the old
# key, which opens none of the keys, and a gunicorn running on it would make
# its next keys under it. The deploy that brings the new key starts it.
REWRAPPED=""
finish() {
    rm -f "$APP_DIR/new-wrap.key"
    [ -n "$REWRAPPED" ] || sudo systemctl start gunicorn
}
trap finish EXIT
cd "$APP_DIR/verify"
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
    key=${line%%=*} value=${line#*=}
    [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
    export "$key=$value"
done < "$APP_DIR/.env"
sudo systemctl stop gunicorn
"$APP_DIR/venv/bin/python" manage.py rewrap_keys --new-key-file "$APP_DIR/new-wrap.key" \
    --confirm "$SYNC_HOST" || exit 3
REWRAPPED=1
exit 0
REMOTE
    case "$status" in
        0) ;;
        3) die "nothing was re-wrapped (see above); the server serves as it did" ;;
        *) die "the re-wrap stopped (status $status); see above. If it never ran, the key's copy may still be on the server as $APP_DIR/new-wrap.key: delete it" ;;
    esac
    echo "=== Re-wrapped. gunicorn is stopped: the server's .env still holds the old key ==="
    echo "    Next: put the new key in $(basename "$CONFIG") as CREDENTIAL_EPOCH_WRAP_KEY, and deploy."
    echo "    Keep $(basename "$KEY_FILE") until that deploy is done and Setup shows no key in red."
    exit 0
fi

# --- check: report, change nothing --------------------------------------------------------------

if [ "$COMMAND" = check ]; then
    # The installed configuration is compared with deploy/ rendered for this
    # layout, ignoring comments, blank lines and line endings.
    render() { sed -e "s|\${app_dir}|$APP_DIR|g" -e "s|\${app_user}|$REMOTE_USER|g" "$1"; }
    digest() { tr -d '\r' | grep -vE '^[[:space:]]*(#|$)' | sed 's/[[:space:]]*$//' | sha256sum | cut -c1-64; }
    NGINX_SHA="$(render "$DEPLOY_DIR/nginx.conf.tftpl" | digest)"
    UNIT_SHA="$(render "$DEPLOY_DIR/gunicorn.service.tftpl" | digest)"
    GCONF_SHA="$(digest < "$DEPLOY_DIR/gunicorn.conf.py")"
    LEFTOVERS=""
    for e in "${EXCLUDES[@]}"; do
        case "$e" in *'*'*|.env|.env.*|db.sqlite3|staticfiles/|__pycache__) continue ;; esac
        LEFTOVERS="$LEFTOVERS ${e%/}"
    done

    echo "=== Checking $SERVER_IP$VIA; nothing will be changed ==="
    status=0
    ssh $SSH_OPTS target "$REMOTE_ENV NGINX_SHA=$NGINX_SHA UNIT_SHA=$UNIT_SHA GCONF_SHA=$GCONF_SHA LEFTOVERS='$LEFTOVERS' bash -s" <<'REMOTE' || status=$?
set -uo pipefail
FAILURES=0 WARNINGS=0
ok()   { printf '    ok    %s\n' "$*"; }
warn() { printf '    WARN  %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '    FAIL  %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
IP=$(hostname -I | awk '{print $1}')

echo "--- Server"
echo "    $(hostname), $IP, $(. /etc/os-release && echo "$PRETTY_NAME")"
df -h / | awk 'NR==2 {print "    " $4 " free of " $2 " on /"}'
[ ! -f /var/log/user_data.log ] || tail -n 1 /var/log/user_data.log | sed 's/^/    boot script: /'

echo "--- Application directory $APP_DIR"
if [ -d "$APP_DIR" ]; then ok "exists"; else fail "missing: the boot script has not finished, or APP_DIR is wrong"; fi
if [ -x "$APP_DIR/venv/bin/python" ]; then
    ok "virtualenv, $("$APP_DIR/venv/bin/python" --version 2>&1)"
else
    fail "no virtualenv at $APP_DIR/venv"
fi
if [ -f "$APP_DIR/verify/manage.py" ]; then ok "code present"; else warn "no code yet: the next deploy brings it"; fi
[ ! -f "$APP_DIR/.first_deploy" ] || warn "first deploy pending: the next deploy starts gunicorn"

echo "--- $APP_DIR/.env (key names only)"
ENV="$APP_DIR/.env"
if [ -f "$ENV" ]; then
    mode=$(stat -c %a "$ENV")
    if [ "$mode" = 600 ]; then ok "mode 600"; else warn "mode $mode; should be 600"; fi
    for k in DJANGO_SECRET_KEY DJANGO_ALLOWED_HOSTS; do
        if grep -qE "^$k=.+" "$ENV"; then ok "$k set"; else fail "$k missing or empty"; fi
    done
    for k in EVERIFY_CLIENT_ID EVERIFY_CLIENT_SECRET EVERIFY_PUBLIC_API_KEY; do
        if grep -qE "^$k=.+" "$ENV"; then ok "$k set"; else warn "$k not set: sign-in needs a client saved on the Setup page"; fi
    done
    if grep -E '^DJANGO_ALLOWED_HOSTS=' "$ENV" | grep -qE "[=,]$IP(,|\$)"; then
        ok "DJANGO_ALLOWED_HOSTS names this server's address"
    else
        fail "DJANGO_ALLOWED_HOSTS lacks $IP: the load balancer's health checks will be refused"
    fi
    ! grep -qiE '^DJANGO_DEBUG=(true|1|yes)[[:space:]]*$' "$ENV" || warn "DJANGO_DEBUG is on"
    while IFS= read -r line || [ -n "$line" ]; do
        line=${line%$'\r'}
        [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
        key=${line%%=*} value=${line#*=}
        [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
        k=$key v=$value
        case "$k" in *_PATH) ;; *) continue ;; esac
        [ -n "$v" ] || continue
        case "$v" in "$APP_DIR/verify/"*) fail "$k points inside the code directory, which every deploy rewrites"; continue ;; esac
        if [ -r "$v" ]; then
            m=$(stat -c %a "$v")
            if [ "$m" = 600 ] || [ "$m" = 400 ]; then ok "$k: file present, mode $m"; else warn "$k: file mode $m; should be 600"; fi
        else
            fail "$k names a file that is not there"
        fi
    done < "$ENV"
else
    warn "no .env yet: the next deploy writes it"
fi

echo "--- Services"
if systemctl is-enabled --quiet gunicorn 2>/dev/null; then ok "gunicorn enabled"; else fail "gunicorn not enabled"; fi
if systemctl is-active --quiet gunicorn; then
    ok "gunicorn running"
elif [ -f "$APP_DIR/.first_deploy" ]; then
    ok "gunicorn stopped, as it should be before the first deploy"
else
    fail "gunicorn not running"
fi
if systemctl is-active --quiet nginx; then ok "nginx running"; else fail "nginx not running"; fi
# The activity log's retention. Every deploy installs the timer and
# replaces units that differ, so this checks only its state.
if systemctl is-enabled --quiet purge-device-logs.timer 2>/dev/null \
        && systemctl is-active --quiet purge-device-logs.timer; then
    ok "purge-device-logs.timer on; next run $(systemctl show -p NextElapseUSecRealtime --value purge-device-logs.timer)"
    purge_user=$(systemctl show -p User --value purge-device-logs.service)
    gunicorn_user=$(systemctl show -p User --value gunicorn.service)
    if [ "$purge_user" = "$gunicorn_user" ]; then
        ok "the purge runs as gunicorn does ($purge_user)"
    else
        warn "the purge runs as '$purge_user', gunicorn as '$gunicorn_user': deploy again"
    fi
    if systemctl is-failed --quiet purge-device-logs.service; then
        fail "the last purge failed: journalctl -u purge-device-logs"
    fi
else
    warn "purge-device-logs.timer is not on: the activity log is never aged out until a deploy installs it"
fi
if sudo -n nginx -t >/dev/null 2>&1; then ok "nginx configuration parses"; else fail "nginx -t fails"; fi
# 127.0.0.1, not localhost: localhost resolves to ::1 first, where the
# distribution's stock server block listens and answers 404.
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H 'Host: localhost' http://127.0.0.1/health/ || true)
if [ "$code" = 200 ]; then ok "/health/ answers 200 on the server"; else warn "/health/ answers $code on the server"; fi

echo "--- Migrations"
if [ -f "$APP_DIR/verify/manage.py" ] && [ -f "$ENV" ]; then
    (
        cd "$APP_DIR/verify"
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line%$'\r'}
            [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
            key=${line%%=*} value=${line#*=}
            [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
            export "$key=$value"
        done < "$ENV"
        "$APP_DIR/venv/bin/python" manage.py showmigrations accounts 2>&1 | tail -n 3 | sed 's/^/    /'
        pending=$("$APP_DIR/venv/bin/python" manage.py showmigrations --plan 2>/dev/null | grep -c '^\[ \]' || true)
        echo "    $pending unapplied by the code now on the server (a deploy applies the new code's)"
    )
else
    echo "    (no code or no .env yet)"
fi

echo "--- Stored keys"
if [ -f "$APP_DIR/verify/manage.py" ] && [ -f "$ENV" ]; then
    # accounts.W004: keys the wrap key in .env does not open, say after a
    # re-wrap deployed with the wrong value. /health/ cannot tell.
    keys_status=0
    keys=$(
        cd "$APP_DIR/verify"
        while IFS= read -r line || [ -n "$line" ]; do
            line=${line%$'\r'}
            [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
            key=${line%%=*} value=${line#*=}
            [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
            export "$key=$value"
        done < "$ENV"
        "$APP_DIR/venv/bin/python" manage.py check --database default --tag database 2>&1
    ) || keys_status=$?
    if printf '%s\n' "$keys" | grep -q 'accounts\.W004'; then
        warn "$(printf '%s\n' "$keys" | grep 'accounts\.W004' | head -n 1 | sed 's/^[^(]*//')"
    elif [ "$keys_status" = 0 ]; then
        ok "every stored key opens with CREDENTIAL_EPOCH_WRAP_KEY"
    else
        warn "manage.py check --database default failed (status $keys_status)"
    fi
else
    echo "    (no code or no .env yet)"
fi

echo "--- Configuration from deploy/ (comments and blank lines ignored)"
compare() {
    local file="$1" expected="$2" source="$3" actual
    if [ ! -f "$file" ]; then fail "$file missing"; return; fi
    actual=$(tr -d '\r' < "$file" | grep -vE '^[[:space:]]*(#|$)' | sed 's/[[:space:]]*$//' | sha256sum | cut -c1-64)
    if [ "$actual" = "$expected" ]; then
        ok "$file matches deploy/$source"
    else
        warn "$file differs from deploy/$source: installed from an older copy, or edited on the server"
    fi
}
compare /etc/nginx/conf.d/verify.conf "$NGINX_SHA" nginx.conf.tftpl
compare /etc/systemd/system/gunicorn.service "$UNIT_SHA" gunicorn.service.tftpl
compare "$APP_DIR/gunicorn.conf.py" "$GCONF_SHA" gunicorn.conf.py

echo "--- Excluded paths an earlier deploy left in $APP_DIR/verify"
found=0
for p in $LEFTOVERS; do
    if [ -e "$APP_DIR/verify/$p" ]; then
        warn "$APP_DIR/verify/$p exists. An exclusion also protects a path from --delete; remove it by hand"
        found=1
    fi
done
[ "$found" = 1 ] || ok "none"

echo "=== $FAILURES failure(s), $WARNINGS warning(s) ==="
[ "$FAILURES" -eq 0 ]
REMOTE
    smoke_test
    exit "$status"
fi

# --- deploy -----------------------------------------------------------------------------------

echo "=== Deploying $SITE_NAME to $SERVER_IP$VIA ==="
echo "    Local project: $PROJECT_DIR"

echo "--- Writing the server's .env from $(basename "$CONFIG") ---"
ENV_COPY="$(mktemp /tmp/deploy_env_XXXXXX)"
TMPFILES+=("$ENV_COPY")
chmod 600 "$ENV_COPY"
render_env > "$ENV_COPY"
rsync -p --chmod=F600 -e "ssh $SSH_OPTS" "$ENV_COPY" "target:$APP_DIR/.env.incoming"
ssh $SSH_OPTS target "$REMOTE_ENV bash -s" <<'REMOTE'
set -euo pipefail
cd "$APP_DIR"
# The load balancer's health checks arrive on the private address, which
# nobody writing the configuration file can know in advance.
ip=$(hostname -I | awk '{print $1}')
hosts=$(sed -n 's/^DJANGO_ALLOWED_HOSTS=//p' .env.incoming | tail -n 1)
for h in "$ip" localhost; do
    case ",$hosts," in *",$h,"*) ;; *) hosts="$hosts,$h" ;; esac
done
sed -i "s|^DJANGO_ALLOWED_HOSTS=.*|DJANGO_ALLOWED_HOSTS=$hosts|" .env.incoming
if [ -f .env ] && ! cmp -s .env .env.incoming; then
    cp -p .env ".env.previous-$(date +%Y%m%d-%H%M%S)"
    # Keep the five most recent.
    ls -1t .env.previous-* 2>/dev/null | tail -n +6 | xargs -r rm -f --
fi
chmod 600 .env.incoming
mv .env.incoming .env
echo "    installed; DJANGO_ALLOWED_HOSTS also names $ip and localhost"
REMOTE

copied=0
for entry in $SECRET_FILES; do
    file="${entry%%:*}"; name="${entry##*:}"
    [ -n "${!file}" ] || continue
    if [ "$copied" = 0 ]; then
        echo "--- Copying key files to $REMOTE_SECRETS_DIR (mode 600) ---"
        ssh $SSH_OPTS target "mkdir -p $(printf %q "$REMOTE_SECRETS_DIR") && chmod 700 $(printf %q "$REMOTE_SECRETS_DIR")"
        copied=1
    fi
    rsync -p --chmod=F600 -e "ssh $SSH_OPTS" "${!file}" "target:$REMOTE_SECRETS_DIR/$name"
    echo "    $file -> $REMOTE_SECRETS_DIR/$name"
done

# Beside the code, never inside it (every deploy rewrites that), and before
# collectstatic, which publishes it under /static/branding/.
if [ -n "$BRANDING_FOLDER" ]; then
    echo "--- Copying the branding folder to $APP_DIR/branding ---"
    rsync -rtp --delete --chmod=D755,F644 -e "ssh $SSH_OPTS" \
        "$BRANDING_FOLDER/" "target:$APP_DIR/branding/"
fi

echo "--- Syncing project files ---"
RSYNC_EXCLUDES=()
for e in "${EXCLUDES[@]}"; do RSYNC_EXCLUDES+=(--exclude "$e"); done
rsync -avz --delete -e "ssh $SSH_OPTS" "${RSYNC_EXCLUDES[@]}" \
    "$PROJECT_DIR/" "target:$APP_DIR/verify/"

if [ -n "$SYNC_HOST" ]; then
    send_incoming
else
    echo "--- Database left alone (--sync-db=HOST replaces it) ---"
fi

rsync -avz -e "ssh $SSH_OPTS" "$PROJECT_DIR/requirements.txt" "target:$APP_DIR/requirements.txt"

# The activity log's daily purge, beside the code, which leaves deploy/ out;
# the remote setup below installs it.
rsync -tp --chmod=F644 -e "ssh $SSH_OPTS" "$DEPLOY_DIR/install-purge-timer.sh" \
    "$DEPLOY_DIR/purge-device-logs.service.tftpl" \
    "$DEPLOY_DIR/purge-device-logs.timer.tftpl" "target:$APP_DIR/units/"

echo "--- Running remote setup ---"
ssh $SSH_OPTS target "$REMOTE_ENV SYNC_HOST=$(printf %q "$SYNC_HOST") bash -s" <<'REMOTE'
set -euo pipefail

cd "$APP_DIR"
source venv/bin/activate

# However this script ends: a database sent to replace the server's is
# gone, and a gunicorn stopped for the swap serves again, so a failed
# migrate does not leave the site down.
START_GUNICORN=""
finish() {
    rm -f "$APP_DIR/db.sqlite3.incoming" "$APP_DIR/db.sqlite3.incoming-wal" \
        "$APP_DIR/db.sqlite3.incoming-shm"
    if [ -n "$START_GUNICORN" ]; then sudo systemctl start gunicorn; fi
}
trap finish EXIT

# Load the .env into this shell. Read, never sourced: a value with a shell
# character in it must not run, and a syntax error must not print the line.
# Read as gunicorn's systemd EnvironmentFile= reads the KEY=value lines a
# .env holds, so what runs here sees the values the site does: split at
# the first '=' only (a base64 value ends in '=' and must keep it), one
# pair of quotes taken off, a CR at a line's end dropped, a line with no
# key skipped, a last line without a newline read. Not systemd's trimming
# of spaces or its escapes, which no value the kit writes needs.
while IFS= read -r line || [ -n "$line" ]; do
    line=${line%$'\r'}
    [[ "$line" == [!=]*=* && "$line" != \#* && "$line" != \;* ]] || continue
    key=${line%%=*} value=${line#*=}
    [[ "$value" == \"*\" || "$value" == \'*\' ]] && value=${value:1:${#value}-2}
    export "$key=$value"
done < "$APP_DIR/.env"

pip install -r requirements.txt

cd verify

# The swap, after the code that does it and before migrate: the copy may be
# older. Refused, the server's database is untouched and the deploy finishes
# on it, and says so at the end.
SYNC_REFUSED=""
if [ -n "$SYNC_HOST" ]; then
    echo "--- Replacing the database (gunicorn stopped meanwhile) ---"
    # Stopped whatever systemd says it is doing: a unit waiting to restart
    # after a failure is not "active", and would come back mid-swap.
    sudo systemctl stop gunicorn
    [ -f "$APP_DIR/.first_deploy" ] || START_GUNICORN=1
    python manage.py replace_database "$APP_DIR/db.sqlite3.incoming" \
        --confirm "$SYNC_HOST" || SYNC_REFUSED=1
fi

python manage.py migrate --noinput
python manage.py collectstatic --noinput

# First deploy: create superuser and start gunicorn
if [ -f "$APP_DIR/.first_deploy" ]; then
    echo "--- First deploy detected ---"

    python manage.py shell -c "
from django.contrib.auth import get_user_model
User = get_user_model()
if not User.objects.filter(is_superuser=True).exists():
    import os
    username = os.environ.get('DJANGO_SUPERUSER_USERNAME', 'admin')
    email = os.environ.get('DJANGO_SUPERUSER_EMAIL', 'admin@verify.local')
    # No default: a password typed into a published script is everybody's.
    password = os.environ.get('DJANGO_SUPERUSER_PASSWORD')
    if password:
        User.objects.create_superuser(username, email, password)
        print(f'Superuser {username} created.')
    else:
        print('DJANGO_SUPERUSER_PASSWORD is not set; no superuser created. '
              'Run manage.py createsuperuser on the instance.')
else:
    print('Superuser already exists in transferred database, skipping.')
"

    sudo systemctl start gunicorn
    rm -f "$APP_DIR/.first_deploy"
    echo "--- First deploy complete ---"
else
    sudo systemctl restart gunicorn
fi

# Refuse to reload a configuration that does not parse: a broken nginx takes
# the site down, and the health check would blame the application.
sudo nginx -t
sudo systemctl reload nginx

# The activity log's daily purge, as gunicorn's user: installed, or brought
# up to date, on every deploy. A failure is said at the end, once the steps
# after this one have run.
PURGE_FAILED=""
sudo bash "$APP_DIR/units/install-purge-timer.sh" "$APP_DIR" "$APP_DIR/units" \
    || PURGE_FAILED=1

FAILED=""
if [ -n "$SYNC_REFUSED" ]; then
    echo "!!! The code is deployed, but the database was NOT replaced: see above." >&2
    FAILED=1
fi
if [ -n "$PURGE_FAILED" ]; then
    echo "!!! The code is deployed, but the activity log's purge was not installed: see above." >&2
    FAILED=1
fi
[ -z "$FAILED" ] || exit 1
echo "=== Deploy complete ==="
REMOTE

smoke_test
echo "=== Done. $SITE_NAME deployed to $SERVER_IP ==="
