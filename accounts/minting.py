"""Minting one credential and recording it, in the order a signer needs.

A credential that exists in the world and not in `IssuedCredential` cannot be
revoked, and a signer's reconciler treats one it signed but cannot find here
as signed by something else. So the row comes first:

1. choose the credential id, the epoch and the signing key, once;
2. write the row as PENDING;
3. ask for the signature;
4. mark the row SIGNED.

A failure that certainly produced no signature deletes the row, so a failed
mint leaves nothing behind. A failure after the request may
have reached a signer -- a reply lost to a timeout -- marks it UNKNOWN
instead: the credential may exist, and the row is what lets it be found. A
failure after a signer HAS signed -- the QR not fitting the stamp, say --
keeps the row as SIGNED: the signer's ledger has it, and a missing row would
read to the reconciler as a credential signed for somebody else.

With a signer (`SIGNER_SOCKET`), the key is the organization's own when it has
one, and the credential then names the organization as its certificate does.
The key id is inside the signed bytes, so a key switched between choosing and
signing is answered with `KeyChanged`; the mint is run again, once, with the
key the signer named.

Callers keep their own rule that minting never loses the verification: they
catch whatever this raises and print the plain QR.
"""

from __future__ import annotations

import logging
import uuid

from accounts import credential_keys, credentials, signer_client
from accounts.models import IssuedCredential

logger = logging.getLogger(__name__)


class _Watched:
    """A signer that remembers whether it returned a signature."""

    def __init__(self, inner):
        self.inner = inner
        self.key_id = inner.key_id
        self.sig_alg = inner.sig_alg
        self.signed = False

    def sign(self, message: bytes) -> bytes:
        sig = self.inner.sign(message)
        self.signed = True
        return sig


def _signer_for(organization, *, operator, holder, holder_id="", key_id=None,
                force=False):
    """(signer, certified name or None) for this mint."""
    if not credential_keys.signer_mode():
        return credential_keys.signer(), None
    signing_id = getattr(organization, "signing_id", None)
    chosen, certified = signer_client.signing_key(signing_id, force=force)
    return signer_client.CredentialSigner(
        key_id or chosen, organization=signing_id, operator=operator,
        holder=holder, holder_id=holder_id), certified


def mint_recorded(rows, *, transaction, organization, issued_at, expires_at,
                  claims_organization=None, signer=None, issuer_name=None,
                  operator="", holder=False, holder_id="",
                  **mint_kwargs) -> dict:
    """Mint one credential for `transaction`, recorded before it is signed.

    `organization` is the row the record belongs to (None for a holder's
    self-verification); `claims_organization` is what the credential names,
    when that differs. `operator`, `holder` and `holder_id` (a stable,
    pseudonymous id for the one person) tell a signer whose ceiling the
    credential counts against. Everything else is passed to `credentials.mint`.
    """
    certified = None
    if signer is None:
        signer, certified = _signer_for(organization, operator=operator,
                                        holder=holder, holder_id=holder_id)
    epoch_keys = credential_keys.issuing_keys()
    credential_id = uuid.uuid4()

    record = IssuedCredential.objects.create(
        credential_id=credential_id,
        transaction=transaction,
        organization=organization,
        document_uuid=transaction.transaction_id,
        epoch=epoch_keys.epoch,
        # The key chosen here is the key that signs: read once, never again.
        issuer_key_id=signer.key_id,
        issued_at=issued_at,
        expires_at=expires_at,
        state=IssuedCredential.STATE_PENDING)
    # Before it is signed, as the row is: a credential that exists must be one a
    # phone can be given the key to. One that then fails to sign leaves the keys
    # on phones a little longer, which costs nothing it was not going to.
    credential_keys.keep_readable_until(epoch_keys.epoch, expires_at)

    watched = []

    def attempt(signer, certified):
        signer = _Watched(signer)
        watched.append(signer)
        return credentials.mint(
            rows,
            organization=(claims_organization if claims_organization is not None
                          else organization),
            document_uuid=transaction.transaction_id,
            epoch_keys=epoch_keys,
            signer=signer,
            issued_at=issued_at,
            expires_at=expires_at,
            credential_id=credential_id,
            # An organization key signs only the name its certificate holds.
            issuer_name=certified if certified else issuer_name,
            **mint_kwargs)

    try:
        try:
            minted = attempt(signer, certified)
        except signer_client.KeyChanged as exc:
            signer, certified = _signer_for(organization, operator=operator,
                                            holder=holder, holder_id=holder_id,
                                            key_id=exc.key_id, force=True)
            record.issuer_key_id = signer.key_id
            record.save(update_fields=["issuer_key_id"])
            minted = attempt(signer, certified)
    except Exception as exc:
        if credential_keys.signer_mode() and any(w.signed for w in watched):
            # Signed, and not printed: the row stays, as what it is.
            record.state = IssuedCredential.STATE_SIGNED
            record.save(update_fields=["state"])
        elif getattr(exc, "reply_lost", False):
            record.state = IssuedCredential.STATE_UNKNOWN
            record.save(update_fields=["state"])
        else:
            record.delete()
        raise

    try:
        record.state = IssuedCredential.STATE_SIGNED
        record.save(update_fields=["state"])
    except Exception:
        # The credential exists and the row does too, so it can still be
        # revoked; only its state is behind. Not a reason to lose the QR.
        logger.exception("credential %s signed but not marked signed",
                         credential_id)
    return minted
