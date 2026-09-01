# probes/

Standalone reproductions of the four halt-release races closed on 2026-09-01.
Each forces the vulnerable interleaving deterministically with a blocking gate —
no scheduler luck, no thread-count lottery.

    python3 probes/race_demo.py            # races 1 and 2 (halt state)
    python3 probes/probe_identity_policy.py # race 3 (identity policy) + controls
    python3 probes/probe_stale_authority.py # race 4 (authorisation wiring)

On the current tree all four print refusals. They are kept because a passing test
tells you the guard fires; these tell you what it fires *against*, and they can be
pointed at any future tree to check the property still holds after a refactor.

`probe_identity_policy.py` runs its controls first — it establishes that
LABEL_ONLY permits the principal and REGISTERED refuses it — so the race result
means something rather than being asserted.

They mutate process-global identity policy. Run them on their own, not inside
another suite.
