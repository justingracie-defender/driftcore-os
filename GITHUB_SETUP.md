# Pushing DriftCore to GitHub

## One-time setup

1. Create a new repository at https://github.com/new
   - Name: `driftcore-os` (or your choice)
   - Public (this project belongs to everyone)
   - Do NOT initialize with README/license — we have our own

2. On your machine, from inside this folder:

```bash
git init
git add .
git commit -m "DriftCore OS v3.1 — initial public release

- Immutable invariants (InvariantGuard) + Constitution
- Three-mode cognition (Truth/Creative/Discovery)
- Sycophancy detection + Bayesian uncertainty
- Hardware safety interlocks (GPIO/MQTT/Modbus/CAN/ROS2)
- Fable transparency layer with loud warnings
- Apache License 2.0"

git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/driftcore-os.git
git push -u origin main
```

## Recommended repo settings after push

- **About section**: "Open-source AI safety middleware. Immutable
  invariants, human oversight enforcement, plain-language transparency.
  Safety infrastructure that belongs to everyone."
- **Topics**: `ai-safety`, `robotics`, `human-in-the-loop`,
  `open-source`, `safety-critical`, `transparency`
- **Branch protection on main**: require pull request reviews —
  you are the human merge authority. AIs propose, you decide.
- Enable **Issues** and **Discussions** for community input.

## Suggested first issues to open (community starters)

1. "LLM adapter for abduction engine (v3.2)" — good first issue
2. "Test GPIO integration on real Raspberry Pi hardware"
3. "Review Apache-2.0 adoption and safety-intent wording"
4. "Translate CONSTITUTION.md" — one issue per language
5. "New red team scenarios wanted"

## A note on the license

The repository is licensed under the Apache License 2.0. The complete
canonical text is in `LICENSE`, attribution is in `NOTICE`, and the project's
non-binding safety and naming policy is in `SAFETY_INTENT.md`. The latter does
not add conditions to the Apache license grant.
