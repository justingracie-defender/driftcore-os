# SPDX-License-Identifier: Apache-2.0
"""CLAIM refusal-data-is-not-echoed: at the actuation broker's socket boundary,
refusal details, extra fields and unknown error names are replaced by a finite
public vocabulary before transmission.

HONEST LIMITS
Authorized successful result payloads are outside this projection's privacy
contract. Their adapters and information-flow gates govern what may be returned.
Public status codes and observable allow/deny behavior remain visible by design.
"""

# Codes are the existing wire API. Only their explanations are replaced; no
# exception text, configured target, threshold, expected signature, or callback
# name is interpolated into an agent-facing explanation.
_GROUPS = (
    (("no_grant", "malformed_grant", "grant_rejected", "no_human_attestation",
      "malformed_attestation", "human_approval_rejected", "no_intent_decision",
      "malformed_intent_decision", "intent_decision_rejected"),
     "Authorization is missing, invalid or no longer current. Request fresh approval for this action.",
     "NOT_STARTED"),
    (("egress_no_destination", "egress_declaration_mismatch", "egress_block_undeclared",
      "egress_block_malformed", "egress_block_private"),
     "External access is not authorized. Request approval or use an already permitted alternative.",
     "NOT_STARTED"),
    (("effect_block", "effect_block_undeclared"),
     "This action is not permitted. Choose a permitted action or ask the operator for guidance.",
     "NOT_STARTED"),
    (("effect_hold_for_review", "blast_radius_review_required", "ledger_refused"),
     "This action requires operator review. Stop this request and seek guidance.",
     "NOT_STARTED"),
    (("halted", "breached"),
     "Operations are stopped. Await authorized operator recovery; do not attempt to resume them.",
     "NOT_STARTED"),
    (("peer_uid_rejected", "unknown_op", "unknown_actuator", "unbindable_parameters"),
     "This request is not accepted. Check the published interface or contact the operator.",
     "NOT_STARTED"),
    (("isolation_unattested", "halt_check_failed", "halt_misconfigured", "posture_misconfigured",
      "posture_unavailable", "effect_block_error", "blast_radius_error", "registry_error",
      "egress_error", "egress_unconfigured", "declaration_unreadable", "envelope_error", "envelope_changed",
      "intent_ledger_unconfigured", "human_approval_unconfigured", "ledger_error",
      "evidence_unavailable"),
     "Required safety checks are unavailable or have changed. Wait for the operator to resolve this.",
     "NOT_STARTED"),
    (("unknown_physical_state", "actuator_timeout", "actuator_failed", "broker_error", "bad_request"),
     "Completion is uncertain. Do not retry automatically; ask the operator to establish the actual outcome.",
     "UNKNOWN"),
    (("execution_mismatch",),
     "The actuator reported an unexpected outcome. Do not retry; ask the operator to reconcile the result.",
     "MISMATCH"),
)
_REFUSALS = {code: (message, status) for codes, message, status in _GROUPS for code in codes}


def agent_response(response):
    """CLAIM uncertain-is-not-clean-refusal: the public response projection keeps
    uncertain/mismatched completion after possible execution or an unknown error,
    and marks automatic retry unsafe.
    """
    if type(response) is not dict:
        response = {}
    if response.get("ok") is True:
        public = {"ok": True, "result": response.get("result")}
        confirmed = response.get("execution_confirmed")
        public["execution_confirmed"] = confirmed if type(confirmed) is bool else None
        if "warning" in response:
            public["warning"] = "The action ran, but its return value was unavailable. Do not retry it."
        return public
    code = response.get("error")
    if type(code) is not str or code not in _REFUSALS:
        code = "broker_error"
    message, status = _REFUSALS[code]
    return {"ok": False, "error": code, "error_code": code.upper(),
            "detail": message, "effect_status": status, "retry_safe": False}
