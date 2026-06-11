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
- Safety Copyleft License (draft — pending legal review)"

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
3. "Legal review of Safety Copyleft License — seeking OSS/AI attorneys"
4. "Translate CONSTITUTION.md" — one issue per language
5. "New red team scenarios wanted"

## A note on the license

LICENSE is a DRAFT. Before promoting the project widely, get it
reviewed — Software Freedom Conservancy (sfconservancy.org) and the
RAIL initiative (licenses.ai) are good starting points. The key legal
question to ask: *"Can invariant preservation survive as a license
condition rather than a contract term?"*
