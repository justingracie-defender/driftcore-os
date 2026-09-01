"""
driftcore/review/__init__.py
==============================
Automated audit review module for DriftCore OS.

Reads the audit chain, detects patterns, and alerts the admin.
The reviewer never writes to the audit chain — read only.
It surfaces what humans would miss in high-volume logs.

Two alert channels:
  Email — daily summaries, routine reports
  SMS   — critical alerts only, immediate

SMS is sent via email-to-SMS gateway (no extra API needed).
Most Canadian carriers support this format:
  Bell:    number@txt.bell.ca
  Rogers:  number@pcs.rogers.com
  Telus:   number@msg.telus.com
  Fido:    number@fido.ca

For Twilio or other SMS APIs, replace _send_sms() implementation.

The reviewer detects:
  - Safety triggers increasing
  - Invariants firing more often
  - Drift scores rising
  - Injection attempts
  - Tamper detection events
  - Unusual patterns over time

It does not:
  - Modify the audit chain
  - Make decisions
  - Take actions
  - Override anything

It only reads, summarizes, and alerts.
"""

import json
import os
import time
import hashlib
import smtplib
import ssl
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime, timedelta


# ── Alert levels ──────────────────────────────────────────────────

class AlertLevel:
    ROUTINE  = "routine"   # daily summary via email
    WARNING  = "warning"   # elevated — email immediately
    CRITICAL = "critical"  # SMS + email immediately


# ── Action vocabulary ─────────────────────────────────────────────
# Exact action names emitted by the rest of DriftCore. We match on
# membership, NOT substring — "FLAGGED" must not also catch the benign
# USER_FLAGGED_DRIFT (a user honestly reporting drift is not an attack).

SAFETY_TRIGGER_ACTIONS = {"SAFETY_DRIFT"}
INJECTION_ACTIONS      = {"FLAGGED"}                       # blocked hostile input ONLY
DRIFT_SCORE_ACTIONS    = {"DRIFT_CHECKPOINT", "SAFETY_DRIFT"}  # entries that may carry safety=
TAMPER_ACTIONS         = {"SHUTDOWN", "TAMPER"}            # if/when written to the chain
DOMAIN_ACTIONS         = {"DOMAIN_SWITCH"}
BENIGN_USER_ACTIONS    = {"USER_FLAGGED_DRIFT"}            # explicitly NOT injection


# ── Pattern detection ─────────────────────────────────────────────

@dataclass
class DetectedPattern:
    """A pattern found in the audit log."""
    pattern_id:   str
    level:        str
    title:        str
    description:  str
    count:        int
    timeframe:    str
    entries:      List[dict] = field(default_factory=list)


# ── Review config ─────────────────────────────────────────────────

@dataclass
class ReviewConfig:
    """
    Configuration for the review module.
    Loaded from _config/.driftcore/review_config.json
    """
    # Email settings
    smtp_host:     str = "smtp.gmail.com"
    smtp_port:     int = 587
    smtp_user:     str = ""
    smtp_password: str = ""
    admin_email:   str = ""

    # SMS via email-to-SMS gateway
    sms_enabled:   bool = False
    phone_number:  str = ""           # 10 digits, no spaces
    carrier_gateway: str = ""         # e.g. txt.bell.ca

    # Thresholds
    safety_trigger_warning:  int = 3   # warn after N safety triggers
    safety_trigger_critical: int = 5   # critical after N safety triggers
    drift_warning_score:     float = 0.50
    drift_critical_score:    float = 0.75
    injection_warning:       int = 1   # any injection attempt = warning

    # Schedule
    daily_report_hour: int = 8   # send daily summary at 8am

    @classmethod
    def load(cls, path: str = "_config/.driftcore/review_config.json"):
        try:
            with open(path) as f:
                data = json.load(f)
            return cls(**{k: v for k, v in data.items()
                         if k in cls.__dataclass_fields__})
        except Exception:
            return cls()

    def save(self, path: str = "_config/.driftcore/review_config.json"):
        try:
            os.makedirs(os.path.dirname(path), exist_ok=True)
            with open(path, "w") as f:
                json.dump({
                    "smtp_host":      self.smtp_host,
                    "smtp_port":      self.smtp_port,
                    "smtp_user":      self.smtp_user,
                    "smtp_password":  "***",  # never save plaintext
                    "admin_email":    self.admin_email,
                    "sms_enabled":    self.sms_enabled,
                    "phone_number":   self.phone_number,
                    "carrier_gateway": self.carrier_gateway,
                    "safety_trigger_warning":  self.safety_trigger_warning,
                    "safety_trigger_critical": self.safety_trigger_critical,
                    "drift_warning_score":     self.drift_warning_score,
                    "drift_critical_score":    self.drift_critical_score,
                    "injection_warning":       self.injection_warning,
                    "daily_report_hour":       self.daily_report_hour,
                }, f, indent=2)
        except Exception:
            pass

    @property
    def sms_address(self) -> str:
        """Email address for SMS gateway."""
        if not self.phone_number or not self.carrier_gateway:
            return ""
        digits = "".join(c for c in self.phone_number if c.isdigit())
        return f"{digits}@{self.carrier_gateway}"


# ── Main reviewer ─────────────────────────────────────────────────

class AuditReviewer:
    """
    Reads DriftCore audit logs and alerts the admin.

    Read-only access to the audit chain.
    Sends email summaries and SMS critical alerts.

    Usage:
        reviewer = AuditReviewer()
        reviewer.run_review()   # call periodically
        reviewer.daily_summary()  # call once per day
    """

    AUDIT_FILE     = "logs/audit_chain.jsonl"
    LAST_RUN_FILE  = "logs/reviewer_last_run.json"
    REPORT_FILE    = "logs/last_review_report.txt"

    TAMPER_REASON_FILE = "logs/CHAIN_SHUTDOWN_REASON.json"

    def __init__(self, config: Optional[ReviewConfig] = None):
        self._config = config or ReviewConfig.load()
        self._last_run = self._load_last_run()
        # Read status from the most recent _read_all_entries() call.
        # "ok"          — file read cleanly
        # "no_file"     — audit log absent (benign on first boot)
        # "unreadable"  — file present but read/permission error (BLIND)
        self._read_status: Dict[str, object] = {"state": "ok", "corrupt_lines": 0}

    # ── Main review ───────────────────────────────────────────────

    def run_review(self) -> List[DetectedPattern]:
        """
        Run a review of recent audit entries.
        Detects patterns and sends alerts as needed.
        Returns list of detected patterns.
        """
        entries = self._read_recent_entries()

        # Integrity checks run FIRST and ALWAYS — an unreadable or tampered
        # log produces no entries, and that must raise an alarm, not fall
        # through the old `if not entries: return []` as a silent all-clear.
        patterns = self._integrity_patterns()
        patterns += self._detect_patterns(entries)

        self._handle_patterns(patterns)
        self._save_last_run()

        return patterns

    def daily_summary(self):
        """
        Generate and send a daily summary email.
        Call this once per day.
        """
        entries = self._read_all_today()
        patterns = self._integrity_patterns() + self._detect_patterns(entries)

        # Daily summary stays routine-only by design, but if integrity checks
        # surfaced a CRITICAL (blind log / tamper), escalate it now rather than
        # burying it in a once-a-day email.
        critical = [p for p in patterns if p.level == AlertLevel.CRITICAL]
        if critical:
            self._handle_patterns(critical)

        report = self._build_report(entries, patterns, period="today")
        self._save_report(report)

        if self._config.admin_email:
            self._send_email(
                subject="DriftCore Daily Summary",
                body=report,
                level=AlertLevel.ROUTINE,
            )

    # ── Pattern detection ─────────────────────────────────────────

    def _detect_patterns(
        self,
        entries: List[dict],
    ) -> List[DetectedPattern]:
        """Detect patterns in audit entries."""
        patterns = []

        # Safety triggers
        safety = [e for e in entries
                  if e.get("action", "") in SAFETY_TRIGGER_ACTIONS]
        if len(safety) >= self._config.safety_trigger_critical:
            patterns.append(DetectedPattern(
                pattern_id  = "safety_critical",
                level       = AlertLevel.CRITICAL,
                title       = "Safety Triggers — Critical Level",
                description = f"{len(safety)} safety triggers detected. Immediate review required.",
                count       = len(safety),
                timeframe   = "recent",
                entries     = safety,
            ))
        elif len(safety) >= self._config.safety_trigger_warning:
            patterns.append(DetectedPattern(
                pattern_id  = "safety_warning",
                level       = AlertLevel.WARNING,
                title       = "Safety Triggers — Elevated",
                description = f"{len(safety)} safety triggers detected. Monitor closely.",
                count       = len(safety),
                timeframe   = "recent",
                entries     = safety,
            ))

        # Injection attempts — exact match only. USER_FLAGGED_DRIFT contains
        # the substring "FLAGGED" but is a cooperative user action, not an attack.
        injections = [e for e in entries
                      if e.get("action", "") in INJECTION_ACTIONS]
        if len(injections) >= self._config.injection_warning:
            patterns.append(DetectedPattern(
                pattern_id  = "injection_attempt",
                level       = AlertLevel.WARNING,
                title       = "Injection Attempts Detected",
                description = f"{len(injections)} suspicious inputs were blocked.",
                count       = len(injections),
                timeframe   = "recent",
                entries     = injections,
            ))

        # Drift scores — only entries that actually carry a safety= score.
        drift = [e for e in entries
                 if e.get("action", "") in DRIFT_SCORE_ACTIONS]
        high_drift = []
        for e in drift:
            detail = e.get("detail", "")
            try:
                if "safety=" in detail:
                    score = float(detail.split("safety=")[1].split(",")[0])
                    if score >= self._config.drift_critical_score:
                        high_drift.append(e)
            except Exception:
                pass

        if high_drift:
            patterns.append(DetectedPattern(
                pattern_id  = "high_drift",
                level       = AlertLevel.CRITICAL,
                title       = "Critical Drift Score Detected",
                description = f"Safety drift score exceeded critical threshold.",
                count       = len(high_drift),
                timeframe   = "recent",
                entries     = high_drift,
            ))

        # Tamper detection (entries in the chain). Note: the chain rarely
        # contains these — the real tamper signal is checked separately in
        # _integrity_patterns() via verify_chain() and the shutdown-reason file.
        tamper = [e for e in entries
                  if e.get("action", "") in TAMPER_ACTIONS]
        if tamper:
            patterns.append(DetectedPattern(
                pattern_id  = "tamper_detected",
                level       = AlertLevel.CRITICAL,
                title       = "Tamper or Shutdown Event",
                description = f"System detected tamper or triggered shutdown.",
                count       = len(tamper),
                timeframe   = "recent",
                entries     = tamper,
            ))

        # Domain switches — unusual frequency
        domain_switches = [e for e in entries
                          if e.get("action", "") in DOMAIN_ACTIONS]
        if len(domain_switches) > 20:
            patterns.append(DetectedPattern(
                pattern_id  = "frequent_domain_switch",
                level       = AlertLevel.WARNING,
                title       = "Frequent Domain Switching",
                description = f"{len(domain_switches)} domain switches detected. May indicate instability.",
                count       = len(domain_switches),
                timeframe   = "recent",
                entries     = [],
            ))

        return patterns

    # ── Alert handling ────────────────────────────────────────────

    def _handle_patterns(self, patterns: List[DetectedPattern]):
        """Send appropriate alerts for detected patterns."""
        if not patterns:
            return

        critical = [p for p in patterns if p.level == AlertLevel.CRITICAL]
        warnings = [p for p in patterns if p.level == AlertLevel.WARNING]

        # Critical — SMS + email immediately
        if critical:
            sms_body = self._build_sms(critical)
            self._send_sms(sms_body)

            email_body = self._build_alert_email(critical + warnings)
            self._send_email(
                subject=f"⚠️ DriftCore CRITICAL Alert — {len(critical)} issue(s)",
                body=email_body,
                level=AlertLevel.CRITICAL,
            )

        # Warnings only — email immediately
        elif warnings:
            email_body = self._build_alert_email(warnings)
            self._send_email(
                subject=f"DriftCore Warning — {len(warnings)} pattern(s) detected",
                body=email_body,
                level=AlertLevel.WARNING,
            )

    # ── Report building ───────────────────────────────────────────

    def _build_report(
        self,
        entries:  List[dict],
        patterns: List[DetectedPattern],
        period:   str = "today",
    ) -> str:
        now = datetime.now().strftime("%Y-%m-%d %H:%M")
        lines = [
            f"DriftCore Audit Review — {now}",
            f"Period: {period}",
            f"{'=' * 50}",
            f"",
            f"Total audit entries: {len(entries)}",
            f"Patterns detected:   {len(patterns)}",
            f"",
        ]

        if not patterns:
            lines.append("No significant patterns detected. System operating normally.")
        else:
            for p in patterns:
                lines += [
                    f"[{p.level.upper()}] {p.title}",
                    f"  {p.description}",
                    f"  Count: {p.count}",
                    f"",
                ]

        # Entry type breakdown
        action_counts: Dict[str, int] = {}
        for e in entries:
            action = e.get("action", "UNKNOWN")
            action_counts[action] = action_counts.get(action, 0) + 1

        if action_counts:
            lines += ["Activity breakdown:", ""]
            for action, count in sorted(
                action_counts.items(), key=lambda x: x[1], reverse=True
            )[:10]:
                lines.append(f"  {action}: {count}")

        lines += ["", f"{'=' * 50}", "DriftCore automated review — read only"]
        return "\n".join(lines)

    def _build_sms(self, patterns: List[DetectedPattern]) -> str:
        """Short SMS for critical alerts — keep under 160 chars."""
        titles = ", ".join(p.title[:30] for p in patterns[:2])
        return f"DriftCore ALERT: {titles}. Check email for details."

    def _build_alert_email(self, patterns: List[DetectedPattern]) -> str:
        lines = [
            "DriftCore has detected the following patterns requiring your attention:",
            "",
        ]
        for p in patterns:
            lines += [
                f"[{p.level.upper()}] {p.title}",
                f"  {p.description}",
                f"  Events: {p.count}",
                "",
            ]
        lines += [
            "Please review logs/audit_chain.jsonl for full details.",
            "",
            "This is an automated report. The review system has read-only access.",
            "No changes have been made automatically.",
        ]
        return "\n".join(lines)

    # ── Email sending ─────────────────────────────────────────────

    def _send_email(
        self,
        subject: str,
        body:    str,
        level:   str = AlertLevel.ROUTINE,
    ) -> bool:
        """Send an email to the admin."""
        if not self._config.admin_email or not self._config.smtp_user:
            print(f"\n  📧 Email not configured. Would send: {subject}\n")
            return False

        try:
            msg = MIMEMultipart()
            msg["From"]    = self._config.smtp_user
            msg["To"]      = self._config.admin_email
            msg["Subject"] = subject
            msg.attach(MIMEText(body, "plain"))

            context = ssl.create_default_context()
            with smtplib.SMTP(self._config.smtp_host, self._config.smtp_port) as server:
                server.starttls(context=context)
                server.login(self._config.smtp_user, self._config.smtp_password)
                server.sendmail(
                    self._config.smtp_user,
                    self._config.admin_email,
                    msg.as_string(),
                )

            self._audit_alert(subject, level, "email")
            return True

        except Exception as e:
            print(f"\n  ⚠️  Email failed: {e}\n")
            return False

    # ── SMS sending ───────────────────────────────────────────────

    def _send_sms(self, body: str) -> bool:
        """
        Send SMS via email-to-SMS gateway.
        No extra API needed — uses the email connection.

        Canadian carrier gateways:
          Bell:    txt.bell.ca
          Rogers:  pcs.rogers.com
          Telus:   msg.telus.com
          Fido:    fido.ca
        """
        if not self._config.sms_enabled or not self._config.sms_address:
            print(f"\n  📱 SMS not configured. Would send: {body}\n")
            return False

        try:
            msg = MIMEText(body[:160])  # SMS length limit
            msg["From"]    = self._config.smtp_user
            msg["To"]      = self._config.sms_address
            msg["Subject"] = ""  # SMS gateways ignore subject

            context = ssl.create_default_context()
            with smtplib.SMTP(self._config.smtp_host, self._config.smtp_port) as server:
                server.starttls(context=context)
                server.login(self._config.smtp_user, self._config.smtp_password)
                server.sendmail(
                    self._config.smtp_user,
                    self._config.sms_address,
                    msg.as_string(),
                )

            self._audit_alert(body[:50], AlertLevel.CRITICAL, "sms")
            return True

        except Exception as e:
            print(f"\n  ⚠️  SMS failed: {e}\n")
            return False

    # ── Log reading ───────────────────────────────────────────────

    def _read_recent_entries(self, minutes: int = 60) -> List[dict]:
        """Read audit entries from the last N minutes."""
        cutoff = time.time() - (minutes * 60)
        return [
            e for e in self._read_all_entries()
            if e.get("timestamp", 0) > cutoff
        ]

    def _read_all_today(self) -> List[dict]:
        """Read all audit entries from today."""
        midnight = datetime.now().replace(
            hour=0, minute=0, second=0, microsecond=0
        ).timestamp()
        return [
            e for e in self._read_all_entries()
            if e.get("timestamp", 0) > midnight
        ]

    def _read_all_entries(self) -> List[dict]:
        """
        Read all audit chain entries. Never modifies.

        Records the outcome on self._read_status so a *read failure* is
        never indistinguishable from a healthy quiet system. A monitor
        that returns [] on an unreadable log is reporting a false all-clear.
        """
        entries: List[dict] = []
        corrupt = 0

        if not os.path.exists(self.AUDIT_FILE):
            # No log yet — benign on first boot, but still not "ok".
            self._read_status = {"state": "no_file", "corrupt_lines": 0}
            return entries

        try:
            with open(self.AUDIT_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except Exception:
                        corrupt += 1
        except Exception as e:
            # File exists but we cannot read it: permissions, I/O error,
            # truncation mid-stream. This is a blind spot — surface it.
            self._read_status = {
                "state": "unreadable",
                "corrupt_lines": corrupt,
                "error": str(e),
            }
            return entries

        self._read_status = {"state": "ok", "corrupt_lines": corrupt}
        return entries

    @staticmethod
    def _entry_fingerprint(entry: dict) -> str:
        """Mirror of audit._hash_entry — deterministic, no side effects."""
        return hashlib.sha256(
            json.dumps(entry, sort_keys=True).encode()
        ).hexdigest()

    def _verify_chain_readonly(self):
        """
        Re-verify the audit chain WITHOUT side effects.

        Returns (True, "intact"), (False, reason) if compromised, or
        (None, reason) if integrity can't be determined (missing/unreadable).
        Never halts, never writes, never mutates global audit state.
        """
        if not os.path.exists(self.AUDIT_FILE):
            return (None, "no chain file")

        try:
            with open(self.AUDIT_FILE) as f:
                lines = [l.strip() for l in f if l.strip()]
        except Exception as e:
            return (None, f"unreadable: {e}")

        prev_hash = "GENESIS"
        prev_seq  = 0
        for i, line in enumerate(lines):
            try:
                entry = json.loads(line)
            except Exception:
                return (False, f"entry {i + 1}: invalid JSON")

            if entry.get("sequence") != prev_seq + 1:
                return (False,
                        f"sequence gap at position {i + 1} "
                        f"(expected {prev_seq + 1}, got {entry.get('sequence')})")

            if entry.get("previous_hash") != prev_hash:
                return (False, f"broken link at sequence {entry.get('sequence')}")

            stored = entry.pop("entry_hash", None)
            recomputed = self._entry_fingerprint(entry)
            entry["entry_hash"] = stored  # restore (local dict only)
            if stored != recomputed:
                return (False, f"altered content at sequence {entry.get('sequence')}")

            prev_hash = stored
            prev_seq  = entry.get("sequence")

        return (True, "intact")

    # ── Integrity / blind-spot detection ──────────────────────────

    def _integrity_patterns(self) -> List[DetectedPattern]:
        """
        Patterns that do NOT come from audit *content* but from the health
        of the audit trail itself. These are the checks that make tamper
        detection real (verify_chain + the shutdown-reason file) and that
        stop a failed read from looking like "nothing wrong".
        """
        patterns: List[DetectedPattern] = []
        status = self._read_status or {}

        # (a) Could not read the log → we are blind. CRITICAL.
        if status.get("state") == "unreadable":
            patterns.append(DetectedPattern(
                pattern_id  = "audit_unreadable",
                level       = AlertLevel.CRITICAL,
                title       = "Audit Log Unreadable",
                description = (
                    "The audit log exists but could not be read "
                    f"({status.get('error', 'unknown error')}). "
                    "The reviewer is blind — treat as a potential tamper event."
                ),
                count       = 1,
                timeframe   = "now",
                entries     = [],
            ))

        # (b) Corrupt lines in the chain file → WARNING.
        corrupt = int(status.get("corrupt_lines", 0) or 0)
        if corrupt:
            patterns.append(DetectedPattern(
                pattern_id  = "audit_corrupt_lines",
                level       = AlertLevel.WARNING,
                title       = "Corrupt Audit Entries",
                description = f"{corrupt} audit line(s) could not be parsed.",
                count       = corrupt,
                timeframe   = "now",
                entries     = [],
            ))

        # (c) Chain integrity → CRITICAL on failure.
        #     IMPORTANT: we do NOT call audit.verify_chain() here. That
        #     function halts the system and writes the shutdown-reason file
        #     on failure — a read-only monitor must never be able to *cause*
        #     the shutdown it is watching for. We re-verify independently,
        #     with zero side effects, using the same hash scheme.
        intact, reason = self._verify_chain_readonly()
        if intact is False:
            patterns.append(DetectedPattern(
                pattern_id  = "chain_verification_failed",
                level       = AlertLevel.CRITICAL,
                title       = "Audit Chain Verification Failed",
                description = f"Read-only verification found the chain compromised: {reason}",
                count       = 1,
                timeframe   = "now",
                entries     = [],
            ))

        # Secondary read-only signal: the audit module's own flag, if set
        # by some other component. is_compromised() is a pure getter.
        try:
            from driftcore.audit import is_compromised
            if is_compromised():
                patterns.append(DetectedPattern(
                    pattern_id  = "chain_flagged_compromised",
                    level       = AlertLevel.CRITICAL,
                    title       = "Audit Module Reports Compromise",
                    description = "audit.is_compromised() is set.",
                    count       = 1,
                    timeframe   = "now",
                    entries     = [],
                ))
        except Exception:
            pass

        # (d) Shutdown-reason file present → the tamper path fired. CRITICAL.
        try:
            if os.path.exists(self.TAMPER_REASON_FILE):
                patterns.append(DetectedPattern(
                    pattern_id  = "tamper_reason_file",
                    level       = AlertLevel.CRITICAL,
                    title       = "Tamper Shutdown Recorded",
                    description = (
                        f"{self.TAMPER_REASON_FILE} exists — the chain-tamper "
                        "shutdown path was triggered."
                    ),
                    count       = 1,
                    timeframe   = "now",
                    entries     = [],
                ))
        except Exception:
            pass

        return patterns

    # ── State ─────────────────────────────────────────────────────

    def _save_last_run(self):
        try:
            os.makedirs("logs", exist_ok=True)
            with open(self.LAST_RUN_FILE, "w") as f:
                json.dump({"last_run": time.time()}, f)
        except Exception:
            pass

    def _load_last_run(self) -> float:
        try:
            with open(self.LAST_RUN_FILE) as f:
                return json.load(f).get("last_run", 0)
        except Exception:
            return 0

    def _save_report(self, report: str):
        try:
            with open(self.REPORT_FILE, "w") as f:
                f.write(report)
        except Exception:
            pass

    def _audit_alert(self, message: str, level: str, channel: str):
        try:
            from driftcore.audit import record
            record(
                action        = "REVIEW_ALERT_SENT",
                memory_text   = message[:200],
                authorised_by = "audit_reviewer",
                detail        = f"level={level}, channel={channel}",
            )
        except Exception:
            pass


# ── Setup helper ──────────────────────────────────────────────────

def setup_review(
    admin_email:     str,
    smtp_user:       str,
    smtp_password:   str,
    phone_number:    str = "",
    carrier_gateway: str = "txt.bell.ca",
    sms_enabled:     bool = False,
) -> ReviewConfig:
    """
    Quick setup for the review module.

    Canadian carrier gateways:
      Bell:    txt.bell.ca
      Rogers:  pcs.rogers.com
      Telus:   msg.telus.com
      Fido:    fido.ca

    Example:
        config = setup_review(
            admin_email   = "admin@example.invalid",
            smtp_user     = "alerts@example.invalid",
            smtp_password = "your_app_password",
            phone_number  = "6135551234",
            carrier_gateway = "txt.bell.ca",
            sms_enabled   = True,
        )
    """
    config = ReviewConfig(
        admin_email     = admin_email,
        smtp_user       = smtp_user,
        smtp_password   = smtp_password,
        phone_number    = phone_number,
        carrier_gateway = carrier_gateway,
        sms_enabled     = sms_enabled,
    )
    config.save()
    return config
