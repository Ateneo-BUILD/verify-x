# Security

Verify handles National ID data and signs credentials that other people rely
on, so please report a security flaw privately, and not in a public issue.

## What to report here

A weakness in what this repository holds: the application, the signer, the
credential code in `ovcrypto/`, or the site kit in `deploy/` and
`terraform/`. For example, a way to sign in or act as someone else, to read
another organization's records, to make a site issue or accept a credential
it should refuse, or to reach a secret.

The current release is the one that is maintained ([`VERSION`](VERSION)).
Say which release you tested.

## How to report

1. Where this repository is on GitHub, use **Report a vulnerability** on its
   [Security tab](https://github.com/Ateneo-BUILD/verify-x/security/advisories/new).
   The report is private to the maintainers.
2. If you cannot use that, write to rlozada@ateneo.edu.

Say what an attacker needs and what they gain, and give the steps that show
it. Use invented data: never send a real person's details, the number or
code of a real ID, or a live credential.

Test against a site of your own, which the [README](README.md) says how to
run, and not against a site other people depend on.

## What happens next

We read every report, confirm that we have received it, and tell you what we
conclude. A confirmed flaw is corrected in a new release. With your
agreement, you are named in [CONTRIBUTORS.md](CONTRIBUTORS.md).

Please give us time to correct it, and to tell those who run Verify sites,
before you publish.

## What belongs elsewhere

- **A site that runs Verify.** A flaw in how one site is set up or run goes
  to the organization that operates it.
- **The CL03 format.** A flaw in the credential format itself, and not in
  this code, goes to the
  [CL03 specification](https://github.com/Ateneo-BUILD/CL03/security/policy).
- **eVerify and the National ID.** Those are the Philippine Statistics
  Authority's services.

If you cannot tell where a flaw belongs, report it here, privately, and we
will pass it on.
