"""
Security & Access Layer
-------------------------
Minimal RBAC enforcement for the prototype. In a production build this
would sit behind organizational SSO/PKI; here it models the same
control points: role hierarchy + per-function minimum-role tagging,
enforced BEFORE a built-in is allowed to execute.

Role hierarchy (low -> high):
    TIER1_TRIAGE < TIER2_ANALYST < LEAD_INVESTIGATOR < ADMIN

ADMIN deliberately cannot run investigative built-ins (separation of
duties) -- it can only manage roles / verify audit logs, which is out
of scope for this prototype's runtime but modeled by ROLE_RANK.
"""

from __future__ import annotations
from typing import Dict


ROLE_RANK = {
    "TIER1_TRIAGE": 1,
    "TIER2_ANALYST": 2,
    "LEAD_INVESTIGATOR": 3,
    "ADMIN": 4,
}

# Added: optional alternate role names, mapped onto the existing rank
# system. These are purely additive -- the four canonical names above
# still work exactly as before (self.role always stores one of them
# after normalization), so nothing that already checks against
# ROLE_RANK or reads .role changes behavior for existing callers.
# "Reviewer" is intentionally mapped at the same rank as "Analyst"
# (read/analyze but not sign/export), matching the request's own
# description of a Reviewer's permissions.
ROLE_ALIASES = {
    "VIEWER": "TIER1_TRIAGE",
    "ANALYST": "TIER2_ANALYST",
    "REVIEWER": "TIER2_ANALYST",
    "INVESTIGATOR": "LEAD_INVESTIGATOR",
    "ADMINISTRATOR": "ADMIN",
}


class AuthorizationError(Exception):
    pass


class SecurityContext:
    def __init__(self, investigator: str, role: str, case_id: str):
        canonical = ROLE_ALIASES.get(role.upper(), role)
        if canonical not in ROLE_RANK:
            raise ValueError(
                f"Unknown role: {role} (expected one of {sorted(ROLE_RANK)} "
                f"or an alias {sorted(ROLE_ALIASES)})"
            )
        self.investigator = investigator
        self.role = canonical
        self.case_id = case_id

    def require(self, min_role: str, function_name: str):
        if ROLE_RANK[self.role] < ROLE_RANK[min_role]:
            raise AuthorizationError(
                f"Role '{self.role}' may not call '{function_name}' "
                f"(requires at least '{min_role}')."
            )
