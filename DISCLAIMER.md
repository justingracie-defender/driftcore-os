# DISCLAIMER

## Read This Before Using DriftCore

**DriftCore is a safety framework. It is not certified safety equipment.**

### What this means in plain language:

1. **This software has NOT been certified** under any functional safety
   standard (IEC 61508, ISO 13849, ISO 26262, UL, CE, or any other).
   It is open source research and engineering work.

2. **Never rely on DriftCore alone for life-safety functions.**
   If failure of your system could hurt someone, you MUST use
   certified hardware interlocks (certified safety relays,
   emergency stops, physical fuses) as the primary protection.
   DriftCore is an additional layer — never the only layer.

3. **The hardware integration code contains stubs.** The files in
   `driftcore/hardware/` show how to connect real sensors and relays,
   but the shipped code simulates these connections. Deploying to
   real hardware requires a qualified engineer and proper testing.

4. **Test your shutdown path before going live.** Trigger every
   sensor. Watch every relay open. If the emergency stop doesn't
   work in testing, it won't work in an emergency.

5. **The license is a draft.** The LICENSE file has not been
   reviewed by an attorney. Have it professionally reviewed
   before relying on its protections.

6. **No warranty.** The software is provided as-is. The authors
   and contributors accept no liability for any damages arising
   from its use. See LICENSE Sections 6 and 7.

### The honest framing:

DriftCore exists to make AI systems safer and more transparent.
But software safety is a process, not a product. Using DriftCore
does not make a dangerous system safe. It gives you tools —
drift detection, human oversight enforcement, audit trails,
hardware interlock architecture — that make safety achievable
when used correctly, tested thoroughly, and combined with
certified hardware protections.

**If someone's life depends on it, get it certified and get it
reviewed by qualified professionals. No exceptions.**
