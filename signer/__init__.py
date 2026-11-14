"""The credential signer: the only process that holds an issuer key.

verify asks for signatures (over a UNIX socket, or through the poll queue)
and never sees a key. Each request is parsed and checked against a policy
before anything is signed, so an application compromise can ask for
well-formed protocol messages within its ceilings -- and nothing else.

Django-free on purpose: it runs as its own user (`cl03-signer`) from a
root-owned tree, and must not import the application it does not trust.

    clock      the time, injectable for tests
    config     ceilings, validity, anchors, legacy keys
    store      one SQLite database: registry, ledger, cache, counters
    keys       private keys (a file in stage 1; PKCS#11 later)
    messages   parsing what verify sends; the signed layouts
    registry   key state, windows, trust lists, the switch gate
    ceilings   per-principal and global rate limits, and pauses
    ledger     the hash-chained record of every signature and key event
    service    the operations: app-side (reduce only) and admin-side
"""
