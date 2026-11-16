# Privacy

This page describes how Verify handles personal information. It covers the software published in this repository. It is not the privacy notice of any site that runs Verify.

## Who is responsible

Ateneo de Manila University, through the Business Insights Laboratory for Development and its Technical Resource Lab (Ateneo BUILD-TRL), publishes the software.

Each organization that deploys Verify decides what personal information it collects and why. That organization is the personal information controller under Republic Act 10173, the Data Privacy Act of 2012, and must publish its own privacy notice to the people it verifies.

## Laws the software is designed to support

- Republic Act 10173, the Data Privacy Act of 2012, its implementing rules, and National Privacy Commission issuances
- Republic Act 11055, the Philippine Identification System Act, and its implementing rules

## What personal information the software handles

When an operator verifies a Philippine National ID, Verify receives the person's details from the Philippine Statistics Authority's eVerify service.

On by default, the minimum needed to identify the person:

- full name
- PhilSys Card Number and Digital National ID number
- birth date, and the age worked out from it
- permanent and present address
- face photograph (shown, never logged)

Off by default, until a site administrator switches them on for an organization: suffix, sex, place of birth, marital status, blood type, address parts, email, mobile number and residency status.

Operators sign in with their own National ID through eVerify, or through an OpenID Connect provider chosen by the deployment.

## How the software limits and protects it

- **Field choice.** Each organization chooses which fields are shown on screen, which are logged, and which are printed.
- **Two-tier encryption.** The offline credential (CL03) is encrypted in two tiers with X25519, HKDF-SHA256 and AES-256-GCM. A device that holds only the public-tier key can confirm a document is genuine without reading the holder's details.
- **Signatures and expiry.** Every credential is signed and carries validity dates. A verifier trusts nothing it decrypts until the signature checks.
- **Paired devices.** Verifier phones pair with one organization, receive time-limited keys, and check a signed revocation list.
- **Demo Mode.** Masks names, ID numbers and faces on every page when the system is shown to an audience.
- **Retention of phone activity logs.** Purged daily after 360 days, unless the deployment sets a different period.
- **Separate accounts.** Each organization verifies through its own eVerify account. There is no shared fallback account.
- **No secrets in the code.** Credentials live in environment variables and the database. A pre-push hook blocks credentials and private keys from the repository.

Retention of verification records, access by staff, and disclosure to third parties are set by each deploying organization and stated in its own privacy notice.

## Contact

To report a security problem, follow SECURITY.md. For other questions about the software, open an issue in this repository or contact Ateneo BUILD-TRL through https://trl.ph.
