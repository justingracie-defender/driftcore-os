# Contributing to DriftCore

Thank you for wanting to make AI safety belong to everyone.

## The Ground Rules

By contributing, you agree to:

1. **License your contributions** under the DriftCore Safety
   Copyleft License (see LICENSE), including its patent grant.

2. **Never weaken an invariant.** Pull requests that remove,
   weaken, or circumvent any Safety Invariant will be rejected
   regardless of technical merit. You may propose ADDING
   invariants — strengthening is always welcome.

3. **Preserve legibility.** DriftCore's plain-language
   explanations are a feature, not decoration. New modules
   should include explanations that a non-engineer can read.
   If your code can't be explained simply, it probably
   shouldn't be in a safety system.

4. **Warnings stay loud.** Safety events must narrate visibly.
   Silent failure modes will be rejected.

## What We Need Most

- **Real hardware testing** — GPIO, MQTT, Modbus, CAN, ROS2
  integrations tested on physical hardware
- **LLM adapters** — connecting the abduction engine and
  sycophancy detector to real models
- **Formal verification** — proving invariant enforcement
- **Translations** — the Fable glossary and explanations
  in more languages
- **Red team scenarios** — new attack patterns for the
  simulation suite
- **Legal review** — open source + AI ethics attorneys

## Process

1. Open an issue describing what you want to change and why
2. For invariant-adjacent code, expect extra scrutiny — that's
   the system working as designed
3. All changes must pass the existing demo suite (`python main.py`)
4. New safety features need new demos showing them firing

## The Spirit

This project exists because safety infrastructure should not
be a luxury good. Contribute in that spirit: build for the
small robotics shop, the school, the developing-world factory —
the people who can't afford a safety team.
