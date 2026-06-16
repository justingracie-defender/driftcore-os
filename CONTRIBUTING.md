# Contributing to DriftCore OS

Thank you for being here. This project exists because someone needs
to show what responsible, human-centred AI looks like in practice.
Every contribution to that goal matters.

## The Core Principle

Safety first. Everything else is secondary.

If a contribution adds capability without maintaining or improving
the safety guarantees, it is not ready. Capability and safety
are not opposites — but when they conflict, safety wins.

## What We Welcome

- New safety modules with tests
- Improvements to existing modules
- Bug fixes with test coverage
- Documentation updates that reflect code changes
- Research integrations (new alignment research that improves detection)
- Backend adapters (new storage, embedding, or model integrations)
- Translations of the plain language guide

## What We Do Not Accept

- Changes that weaken invariants
- Mode switching that bypasses human authority
- Storage changes that remove tamper detection
- Audit chain modifications that allow silent changes
- Anything that reduces the family's control over the system

## Before You Contribute

1. Read CONSTITUTION.md — understand the invariants
2. Read CLAUDE.md — understand the operating principles
3. Read the relevant module — understand what you are changing
4. Run all tests — `python test_*.py` — confirm nothing breaks
5. Write tests for what you add — untested safety is claimed safety

## Test Coverage

Every safety guarantee must have a test that verifies it works
AND a test that verifies it catches failure. The success case
is not enough. The failure case is where safety is proven.

Current: 343 tests across 9 modules. Every contribution should
maintain or increase this number.

## Updating Documents

If your contribution changes how a module works, update the
relevant document in /docs. The documents must reflect what
the code actually does. Drift between code and documentation
is its own kind of safety failure.

## The Standard

Ask yourself: would a family trust this change with their
medical information, their children, their home?

If yes — welcome.
If not sure — ask.
If no — rethink.

## Contact

Justin Gracie
justin.gracie@gmail.com
https://github.com/justingracie-defender/driftcore-os

For the future. For the kids.
