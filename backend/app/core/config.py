"""
AEGIX (SOC-AI Assistant) — Central Configuration & Security Policy Constants
File path in repository: backend/app/core/config.py

Implements the architectural parameters, trust-zone boundaries, and security
controls specified in Chapter 3 (NFR-01 to NFR-05) and Chapter 4 (Sections 4.1 to 4.6).
All secrets are loaded strictly from environment variables at startup (Section 4.5.5, T7).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Final


# =============================================================================
# 1. Core Enumerations for Roles, Tools, and Permissions (Table 4-2 & Table 4-8)
# =============================================================================

class UserRole(str, Enum):
    """System roles enforced by Auth & RBAC (Section 4.5.3, Table 4-8)."""
    VIEWER = "VIEWER"
    ANALYST = "ANALYST"
    APPROVER = "APPROVER"
    ADMIN = "ADMIN"


class AgentToolName(str, Enum):
    """Authorized tools exposed to the LangChain agent via Tool Gateway (Table 4-2)."""
    HUNT_THREATS = "hunt_threats"
    WAZUH_ALERTS = "wazuh_alerts"
    WAZUH_AGENT_INFO = "wazuh_agent_info"
    VIRUSTOTAL_LOOKUP = "virustotal_lookup"
    PROPOSE_ACTION = "propose_action"
    GENERATE_REPORT = "generate_report"


class SystemPermission(str, Enum):
    """Granular backend permissions mapped in Table 4-8."""
    READ_INVESTIGATIONS = "read_investigations"
    CREATE_INVESTIGATIONS = "create_investigations"
    CHAT = "chat"
    RUN_HUNTS = "run_hunts"
    GENERATE_REPORTS = "generate_reports"
    PROPOSE_ACTION = "propose_action"
    APPROVE_ACTION = "approve_action"
    READ_AUDIT_LOG = "read_audit_log"
    MANAGE_USERS = "manage_users"


# Role-to-Permission Matrix (Table 4-8, Section 4.5.3)
# Note: ADMIN manages users and verifies the audit log but cannot chat or approve actions.
ROLE_PERMISSIONS: Final[dict[UserRole, frozenset[SystemPermission]]] = {
    UserRole.VIEWER: frozenset({
        SystemPermission.READ_INVESTIGATIONS,
    }),
    UserRole.ANALYST: frozenset({
        SystemPermission.READ_INVESTIGATIONS,
        SystemPermission.CREATE_INVESTIGATIONS,
        SystemPermission.CHAT,
        SystemPermission.RUN_HUNTS,
        SystemPermission.GENERATE_REPORTS,
        SystemPermission.PROPOSE_ACTION,
    }),
    UserRole.APPROVER: frozenset({
        SystemPermission.READ_INVESTIGATIONS,
        SystemPermission.CREATE_INVESTIGATIONS,
        SystemPermission.CHAT,
        SystemPermission.RUN_HUNTS,
        SystemPermission.GENERATE_REPORTS,
        SystemPermission.PROPOSE_ACTION,
        SystemPermission.APPROVE_ACTION,
    }),
    UserRole.ADMIN: frozenset({
        SystemPermission.READ_INVESTIGATIONS,
        SystemPermission.READ_AUDIT_LOG,
        SystemPermission.MANAGE_USERS,
    }),
}

# Role-to-Allowed-Tools Matrix enforced by ToolGateway.invoke() (Section 4.4.1)
ROLE_ALLOWED_TOOLS: Final[dict[UserRole, frozenset[AgentToolName]]] = {
    UserRole.VIEWER: frozenset(),
    UserRole.ADMIN: frozenset(),
    UserRole.ANALYST: frozenset({
        AgentToolName.HUNT_THREATS,
        AgentToolName.WAZUH_ALERTS,
        AgentToolName.WAZUH_AGENT_INFO,
        AgentToolName.VIRUSTOTAL_LOOKUP,
        AgentToolName.PROPOSE_ACTION,
        AgentToolName.GENERATE_REPORT,
    }),
    UserRole.APPROVER: frozenset({
        AgentToolName.HUNT_THREATS,
        AgentToolName.WAZUH_ALERTS,
        AgentToolName.WAZUH_AGENT_INFO,
        AgentToolName.VIRUSTOTAL_LOOKUP,
        AgentToolName.PROPOSE_ACTION,
        AgentToolName.GENERATE_REPORT,
    }),
}


# =============================================================================
# 2. Fixed Design Constants & Security Bounds (Chapter 4, Sections 4.4 & 4.5)
# =============================================================================

# --- Section 4.4.1: Agent Loop Bounds ---
AGENT_MAX_STEPS: Final[int] = 6  # Maximum tool calls per analyst message
TOOL_DEFAULT_TIMEOUT_SEC: Final[int] = 30  # Default timeout for external tool calls
TOOL_RATE_LIMIT_PER_MIN: Final[int] = 20  # Per-user, per-tool rate limit per minute

# --- Section 4.4.2 & 4.5.4: Case-State & Observation Bounds (Threat T1 & T9) ---
CASE_STATE_MAX_CHARS: Final[int] = 4000  # Deterministic case-state cap (oldest dropped first)
OBSERVATION_MAX_CHARS: Final[int] = 4000  # Untrusted tool observation cap sent to LLM
EVIDENCE_RAW_REF_MAX_CHARS: Final[int] = 2000  # Truncated JSON cap for EVIDENCE.raw_ref (Appendix A)

# --- Section 4.4.3 & Table 4-6: SPL Validator Checks (C1 to C6) ---
SPL_MAX_LENGTH: Final[int] = 2000  # Check C1: Maximum query length in characters
SPL_FORBIDDEN_OUTSIDE_QUOTES: Final[tuple[str, ...]] = ("[", "]", "`")  # Check C1: No subsearches/macros

# Check C2: Strict command allow-list (anything else is denied by default, Decision D3)
SPL_ALLOWED_COMMANDS: Final[frozenset[str]] = frozenset({
    "search",
    "where",
    "eval",
    "rex",
    "stats",
    "chart",
    "timechart",
    "top",
    "rare",
    "dedup",
    "sort",
    "head",
    "tail",
    "table",
    "fields",
    "rename",
    "bin",
})

# Check C5: Time window bounds (earliest/latest in query text are rejected)
SPL_FORBIDDEN_TIME_KEYWORDS: Final[tuple[str, ...]] = ("earliest", "latest")
SPL_DEFAULT_WINDOW_HOURS: Final[int] = 24  # Default 24 hours
SPL_MAX_WINDOW_DAYS: Final[int] = 7  # Maximum 7 days (168 hours)
SPL_MAX_WINDOW_HOURS: Final[int] = SPL_MAX_WINDOW_DAYS * 24

# Check C6 & Search Execution Bounds (Table 4-6)
SPL_PARSER_TIMEOUT_SEC: Final[int] = 5  # Splunk parser dry-run timeout
SPL_JOB_MAX_COUNT: Final[int] = 500  # Maximum rows returned per search job
SPL_JOB_MAX_TIME_SEC: Final[int] = 60  # Maximum runtime for a Splunk search job

# --- Section 4.4.4: Human-in-the-Loop (HITL) Approval Service (Gates G1 to G4) ---
APPROVAL_TTL_SECONDS: Final[int] = 300  # Gate G2: Proposal expires after 300 seconds (5 min)
ACTION_HASH_DISPLAY_CHARS: Final[int] = 8  # Screen S4 shows first 8 chars of action_hash
ALLOWED_ACTION_TYPES: Final[frozenset[str]] = frozenset({
    "ISOLATE_ENDPOINT",
    "RELEASE_ENDPOINT",
})

# --- Section 4.5.2: Authentication, JWT, and Account Lockout (Threat T6, Decision D9) ---
PASSWORD_HASH_SCHEME: Final[str] = "argon2id"  # OWASP choice [37]
MAX_FAILED_LOGIN_ATTEMPTS: Final[int] = 5  # Lock account after 5 consecutive failures
ACCOUNT_LOCKOUT_MINUTES: Final[int] = 15  # Lock duration in minutes
ACCESS_TOKEN_EXPIRE_MINUTES: Final[int] = 15  # Short-lived JWT kept in browser memory
REFRESH_TOKEN_EXPIRE_HOURS: Final[int] = 8  # Revocable session stored as hash in SESSIONS
JWT_ALGORITHM: Final[str] = "HS256"

# --- Section 4.2.3: Audit Log Hash Chain ---
AUDIT_GENESIS_PREV_HASH: Final[str] = "0" * 64  # Initial prev_hash for the first AUDIT_LOG row


# =============================================================================
# 3. Runtime Environment Settings Object (Section 4.5.5 & Table 4-9)
# =============================================================================

def _parse_csv_env(env_key: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = os.getenv(env_key, "").strip()
    if not raw:
        return default
    return tuple(item.strip() for item in raw.split(",") if item.strip())


def _parse_bool_env(env_key: str, default: bool) -> bool:
    raw = os.getenv(env_key)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class Settings:
    """
    Centralized runtime configuration loaded from environment variables.
    Secrets are never hardcoded or logged (NFR-02, Section 4.5.5).
    """

    # Application & CORS (Section 4.5.2)
    app_name: str = "AEGIX (SOC-AI Assistant)"
    environment: str = field(default_factory=lambda: os.getenv("AEGIX_ENV", "lab"))
    frontend_origin: str = field(
        default_factory=lambda: os.getenv("FRONTEND_ORIGIN", "http://localhost:5173")
    )
    use_mock_integrations: bool = field(
        default_factory=lambda: _parse_bool_env("USE_MOCK_INTEGRATIONS", False)
    )

    # Database (Section 4.2, Decision D7)
    # Uses SQLite by default; switchable to PostgreSQL via DATABASE_URL
    database_url: str = field(
        default_factory=lambda: os.getenv("DATABASE_URL", "sqlite:///./aegix.db")
    )
    sqlite_enforce_foreign_keys: bool = True

    # File paths for Field Catalogue (Check C4) and PDF Reports (FR-08)
    field_catalogue_path: Path = field(
        default_factory=lambda: Path(
            os.getenv("FIELD_CATALOGUE_PATH", "backend/data/field_catalogue.json")
        )
    )
    reports_output_dir: Path = field(
        default_factory=lambda: Path(os.getenv("REPORTS_OUTPUT_DIR", "backend/reports"))
    )

    # Check C3: Allowed Splunk indexes in the laboratory
    spl_allowed_indexes: tuple[str, ...] = field(
        default_factory=lambda: _parse_csv_env(
            "SPL_ALLOWED_INDEXES",
            ("main", "windows", "sysmon", "wazuh", "network", "security"),
        )
    )

    # Authentication Secret (Section 4.5.2)
    jwt_secret_key: str = field(
        default_factory=lambda: os.getenv("JWT_SECRET_KEY", "CHANGE_ME_IN_LAB_ENV_ONLY")
    )

    # Account 1: LLM Provider API (Table 4-9 — Inference only, replaceable provider)
    llm_provider: str = field(default_factory=lambda: os.getenv("LLM_PROVIDER", "openai"))
    llm_model: str = field(default_factory=lambda: os.getenv("LLM_MODEL", "gpt-4o-mini"))
    llm_api_key: str = field(default_factory=lambda: os.getenv("LLM_API_KEY", ""))
    llm_temperature: float = field(
        default_factory=lambda: float(os.getenv("LLM_TEMPERATURE", "0.0"))
    )
    llm_timeout_sec: int = field(
        default_factory=lambda: int(os.getenv("LLM_TIMEOUT_SEC", "30"))
    )

    # Account 2: Splunk Read-Only Account (Table 4-9 — Search only, used by Splunk Tool)
    splunk_host: str = field(default_factory=lambda: os.getenv("SPLUNK_HOST", "https://localhost:8089"))
    splunk_read_token: str = field(default_factory=lambda: os.getenv("SPLUNK_READ_TOKEN", ""))
    splunk_read_username: str = field(default_factory=lambda: os.getenv("SPLUNK_READ_USER", ""))
    splunk_read_password: str = field(default_factory=lambda: os.getenv("SPLUNK_READ_PASS", ""))
    splunk_verify_ssl: bool = field(
        default_factory=lambda: _parse_bool_env("SPLUNK_VERIFY_SSL", False)
    )

    # Account 3: Wazuh Read Account (Table 4-9 — Read alerts & agent info only)
    wazuh_api_url: str = field(
        default_factory=lambda: os.getenv("WAZUH_API_URL", "https://localhost:55000")
    )
    wazuh_read_username: str = field(default_factory=lambda: os.getenv("WAZUH_READ_USER", ""))
    wazuh_read_password: str = field(default_factory=lambda: os.getenv("WAZUH_READ_PASS", ""))
    wazuh_verify_ssl: bool = field(
        default_factory=lambda: _parse_bool_env("WAZUH_VERIFY_SSL", False)
    )

    # Account 4: Wazuh Action Account (Table 4-9 — Separate account used ONLY by Action Executor)
    wazuh_action_username: str = field(default_factory=lambda: os.getenv("WAZUH_ACTION_USER", ""))
    wazuh_action_password: str = field(default_factory=lambda: os.getenv("WAZUH_ACTION_PASS", ""))
    # Decision D10: "custom_script" (custom active-response isolation) or "firewall_drop"
    wazuh_isolation_mode: str = field(
        default_factory=lambda: os.getenv("WAZUH_ISOLATION_MODE", "custom_script")
    )
    wazuh_isolate_command: str = field(
        default_factory=lambda: os.getenv("WAZUH_ISOLATE_COMMAND", "isolate-endpoint")
    )
    wazuh_release_command: str = field(
        default_factory=lambda: os.getenv("WAZUH_RELEASE_COMMAND", "release-endpoint")
    )

    # Account 5: VirusTotal API Key (Table 4-9 — Indicator lookups only; never uploads files)
    virustotal_api_key: str = field(default_factory=lambda: os.getenv("VIRUSTOTAL_API_KEY", ""))
    virustotal_base_url: str = field(
        default_factory=lambda: os.getenv(
            "VIRUSTOTAL_BASE_URL", "https://www.virustotal.com/api/v3"
        )
    )
    virustotal_rate_limit_per_min: int = field(
        default_factory=lambda: int(os.getenv("VIRUSTOTAL_RATE_LIMIT_PER_MIN", "4"))
    )

    def get_known_secrets(self) -> tuple[str, ...]:
        """
        Returns non-empty secret values so the logging filter and observation
        masker can strip them if they ever appear in text (Section 4.5.5, T7).
        """
        candidates = (
            self.jwt_secret_key,
            self.llm_api_key,
            self.splunk_read_token,
            self.splunk_read_password,
            self.wazuh_read_password,
            self.wazuh_action_password,
            self.virustotal_api_key,
        )
        return tuple(
            s for s in candidates
            if s and len(s) >= 8 and s != "CHANGE_ME_IN_LAB_ENV_ONLY"
        )


def has_permission(role: UserRole, permission: SystemPermission) -> bool:
    """Checks whether a given role holds the requested permission (Table 4-8)."""
    return permission in ROLE_PERMISSIONS.get(role, frozenset())


def is_tool_allowed_for_role(role: UserRole, tool_name: AgentToolName) -> bool:
    """Checks whether a given role may invoke the specified agent tool (Section 4.4.1)."""
    return tool_name in ROLE_ALLOWED_TOOLS.get(role, frozenset())


# Singleton settings instance imported across all backend modules
settings = Settings()