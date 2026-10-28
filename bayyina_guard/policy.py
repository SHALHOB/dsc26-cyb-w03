"""Document access policy for Bayyina. Rules: README.md, "What to build", part 2."""
from __future__ import annotations

from dataclasses import dataclass, field
"""Authorization policy for Bayyina Guard."""



@dataclass(frozen=True)
class User:
    id: str
    role: str                       # partner | associate | paralegal | client | auditor
    client_id: str | None = None    # for client users: which Bayyina client they belong to
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False               # this session passed MFA


@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal"  # "normal" or "restricted"
    legal_hold: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


# Roles → actions they may perform at most.
_ROLE_ACTIONS: dict[str, frozenset[str]] = {
    "partner":   frozenset({"read", "comment", "upload_version", "delete", "share_external"}),
    "associate": frozenset({"read", "comment", "upload_version"}),
    "paralegal": frozenset({"read", "upload_version"}),
    "client":    frozenset({"read", "comment"}),
    "auditor":   frozenset(),  # auditors read the audit log — a different system
}

_ALL_ACTIONS = frozenset({"read", "comment", "upload_version", "delete", "share_external"})


def _deny(reason: str) -> Decision:
    return Decision(False, reason)


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    # 1. unauthenticated
    if user is None or not user.id:
        return _deny("unauthenticated")

    # 2. unknown_action
    if action not in _ALL_ACTIONS:
        return _deny("unknown_action")

    # 3. unknown_role
    if user.role not in _ROLE_ACTIONS:
        return _deny("unknown_role")

    # 4. legal_hold
    if action == "delete" and doc.legal_hold:
        return _deny("legal_hold")

    # 5. role_not_permitted
    if action not in _ROLE_ACTIONS[user.role]:
        return _deny("role_not_permitted")

    # 6. tenant_mismatch
    if user.role == "client":
        if user.client_id is None or user.client_id != doc.client_id:
            return _deny("tenant_mismatch")

    # 7. not_assigned
    if user.role in ("associate", "paralegal"):
        if doc.matter_id not in user.matters:
            return _deny("not_assigned")

    # 8. restricted
    if user.role in ("client", "paralegal") and doc.confidentiality != "normal":
        return _deny("restricted")

    # 9. mfa_required
    if (doc.confidentiality != "normal" or action == "share_external") and not user.mfa:
        return _deny("mfa_required")

    return Decision(True, "ok")


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    return [doc for doc in docs if authorize(user, "read", doc).allowed]


@dataclass(frozen=True)
class User:
    id: str
    role: str                       # partner | associate | paralegal | client | auditor
    client_id: str | None = None    # for client users: which Bayyina client they belong to
    matters: frozenset[str] = field(default_factory=frozenset)
    mfa: bool = False               # this session passed MFA


@dataclass(frozen=True)
class Document:
    id: str
    client_id: str
    matter_id: str
    confidentiality: str = "normal" # "normal" or "restricted"
    legal_hold: bool = False


@dataclass(frozen=True)
class Decision:
    allowed: bool
    reason: str


def authorize(user: User | None, action: str, doc: Document) -> Decision:
    """Evaluate the nine rules in order and return the first denial, else Decision(True, "ok")."""
    raise NotImplementedError


def visible_documents(user: User | None, docs: list[Document]) -> list[Document]:
    """The documents `user` may read, in their original order."""
    raise NotImplementedError
