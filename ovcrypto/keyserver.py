"""Epoch key lifecycle and per-device bundle assembly.

Three independent clocks run in this system and conflating any two of them is
the classic way a design like this fails. They are named separately here on
purpose:

1. **Credential expiry** -- ``expiresAt`` inside the signed claims. The only one
   that answers "is this document still valid". Not this module's concern.
2. **Epoch validity** -- how long a decryption key is used for new issuance
   (``epoch_seconds``), and how many past epochs a device keeps
   (``overlap_epochs``). This governs whether a device *can read* a credential,
   which is a statement about the device, never about the document.
3. **Device lease** -- ``lease_seconds``, how long a device may keep verifying
   before it must sync. This is what actually enforces "keys expire" and what
   cuts off a lost or decommissioned device.

The overlap window is the security-critical setting and the one most likely to
be raised carelessly. It is *exactly* how long a revoked device keeps working
after revocation, and how stale its revocation filter may be. Raising it to
cover a longer offline period is a direct trade against both.
"""

from __future__ import annotations

import os
import time
from dataclasses import dataclass, field

from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)

from . import bundle, issuer, kdf

DAY = 86400


@dataclass
class Policy:
    """Tunable because the required offline window varies by deployment."""

    genesis: int                      # unix time of epoch 0
    epoch_seconds: int = 30 * DAY     # how long an epoch is used for issuance
    overlap_epochs: int = 3           # past epochs a device retains
    lease_seconds: int = 30 * DAY     # max time offline before a sync is required

    def __post_init__(self):
        if self.epoch_seconds < DAY:
            raise ValueError("epoch_seconds must be at least one day")
        if self.overlap_epochs < 0:
            raise ValueError("overlap_epochs must not be negative")

    def epoch_at(self, when: int) -> int:
        if when < self.genesis:
            raise ValueError("timestamp precedes genesis")
        return (when - self.genesis) // self.epoch_seconds

    def epoch_start(self, epoch: int) -> int:
        return self.genesis + epoch * self.epoch_seconds

    def epoch_end(self, epoch: int) -> int:
        return self.epoch_start(epoch + 1)

    def readable_epochs(self, when: int) -> list:
        """Epochs a device synced at ``when`` should hold.

        Current plus ``overlap_epochs`` past ones, so credentials printed under
        a previous key still open. Without this, every rotation would silently
        brick the back-catalogue.
        """
        current = self.epoch_at(when)
        return list(range(max(0, current - self.overlap_epochs), current + 1))

    @property
    def max_offline_days(self) -> float:
        """How long a credential stays readable by an already-synced device."""
        return (self.overlap_epochs + 1) * self.epoch_seconds / DAY


@dataclass
class EpochKeyPair:
    """One epoch's X25519 key pair for one tier. Private half is wrapped at rest."""
    epoch: int
    tier: int
    private_key: X25519PrivateKey
    not_before: int
    not_after: int

    @property
    def public_key(self) -> X25519PublicKey:
        return self.private_key.public_key()


class KeyServer:
    """In-memory epoch key store.

    The Django layer persists the same material (private halves envelope-encrypted
    under a key the PKCS#11 token protects); this class holds the lifecycle logic
    so it can be tested without a database.
    """

    def __init__(self, policy: Policy, signer, wrapper=None):
        self.policy = policy
        self.signer = signer
        self.wrapper = wrapper
        self._keys = {}

    # -- epoch keys -------------------------------------------------------

    def key_for(self, epoch: int, tier: int) -> EpochKeyPair:
        """Fetch or lazily create the key pair for an (epoch, tier)."""
        entry = self._keys.get((epoch, tier))
        if entry is None:
            entry = EpochKeyPair(
                epoch, tier, X25519PrivateKey.generate(),
                self.policy.epoch_start(epoch),
                # Outlives its issuance window by the overlap, since devices
                # must still be able to read what was issued under it.
                self.policy.epoch_end(epoch)
                + self.policy.overlap_epochs * self.policy.epoch_seconds)
            self._keys[(epoch, tier)] = entry
        return entry

    def issuing_keys(self, when: int = None) -> issuer.EpochPublicKeys:
        """Public keys the printing system encrypts to right now."""
        when = int(time.time()) if when is None else when
        epoch = self.policy.epoch_at(when)
        return issuer.EpochPublicKeys(
            epoch,
            self.key_for(epoch, bundle.TIER_PUBLIC).public_key,
            self.key_for(epoch, bundle.TIER_RESTRICTED).public_key)

    # -- bundles ----------------------------------------------------------

    def build_bundle(self, *, device_id: bytes,
                     device_se_public_key: ec.EllipticCurvePublicKey,
                     restricted_tier: bool, trust_entries: list,
                     revocation_blob: bytes = b"", when: int = None) -> bundle.Bundle:
        """Assemble and sign the bundle for one device.

        ``restricted_tier`` is the entitlement decision and it is made here, on
        the server, per device. A public-tier device is simply never sent the
        restricted key, so it cannot read that section at all -- the separation
        is cryptographic, not a UI toggle.
        """
        when = int(time.time()) if when is None else when
        tiers = [bundle.TIER_PUBLIC]
        if restricted_tier:
            tiers.append(bundle.TIER_RESTRICTED)

        wrapped = []
        for epoch in self.policy.readable_epochs(when):
            for tier in tiers:
                kp = self.key_for(epoch, tier)
                wrapped.append(bundle.WrappedEpochKey(
                    epoch=epoch, tier=tier,
                    not_before=kp.not_before, not_after=kp.not_after,
                    wrapped=bundle.apple_ecies_encrypt(
                        device_se_public_key, kdf.private_bytes(kp.private_key))))

        b = bundle.Bundle(
            device_id=device_id, issued_at=when, not_before=when,
            not_after=when + self.policy.lease_seconds,
            epoch_keys=wrapped, trust=trust_entries,
            revocation=revocation_blob)
        return b.sign(self.signer)
