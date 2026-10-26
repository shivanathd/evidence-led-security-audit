"""Shared, dependency-free text scanners used by the bundled scripts.

Pattern-based detection has false negatives and false positives. A clean scan
means "no listed pattern matched", never "no secret or private data present".
Callers must never print matched values; use ``redact`` or report the pattern
name and location only.
"""

import ipaddress
import re

# Secret-shaped patterns. Names are stable identifiers used in reports.
SECRET_PATTERNS = [
    ("aws_access_key_id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("github_fine_grained_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{40,}\b")),
    ("slack_token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}\b")),
    # Whole block, header to end marker; an unterminated block runs to the end
    # of the text so a truncated key body is never left behind.
    ("private_key_block", re.compile(
        r"-----BEGIN ((?:[A-Z0-9]+ )*PRIVATE KEY(?: BLOCK)?)-----.*?(?:-----END \1-----|\Z)", re.DOTALL)),
    ("jwt_like", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("stripe_live_key", re.compile(r"\b[rs]k_live_[0-9A-Za-z]{16,}\b")),
    ("generic_sk_key", re.compile(r"\bsk-[A-Za-z0-9_-]{32,}\b")),
    # Any URL userinfo (user, user:, user:pw of any length) is treated as sensitive.
    ("url_userinfo", re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s/?#@'\"<>]*@")),
    ("assigned_secret", re.compile(
        r"(?i)\b[a-z0-9_]*?(?:password|passwd|secret|api[_-]?key|app[_-]?key|private[_-]?key|access[_-]?key|"
        r"token|client[_-]?secret)\b[\"']?\s*[:=]\s*[\"']?([^\s\"'#,;]{8,})")),
]

# Values that look like placeholders rather than real secrets.
_PLACEHOLDER = re.compile(
    r"(?i)^(?:\$\{?[A-Z0-9_]+\}?|<[^>]*>|\{\{.*\}\}|\[redacted.*|redacted|changeme|example\S*|"
    r"placeholder\S*|dummy\S*|x{6,}|\*{4,}|null|none|true|false|os\.environ.*|process\.env.*|getenv.*)$")


def find_secrets(text):
    """Return a sorted list of (pattern_name, start, end) without values."""
    hits = []
    for name, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            if name == "assigned_secret" and _PLACEHOLDER.match(m.group(1)):
                continue
            hits.append((name, m.start(), m.end()))
    hits.sort(key=lambda h: (h[1], h[0]))
    return hits


def redact(text):
    """Replace every secret-shaped match with a typed redaction marker."""
    hits = find_secrets(text)
    if not hits:
        return text
    out, pos = [], 0
    for name, start, end in hits:
        if start < pos:  # overlapping match: extend the current redaction
            pos = max(pos, end)
            continue
        out.append(text[pos:start])
        out.append("[REDACTED:%s]" % name)
        pos = end
    out.append(text[pos:])
    return "".join(out)


def line_of(text, index):
    return text.count("\n", 0, index) + 1


# ---------------------------------------------------------------- public leaks
RESERVED_SUFFIXES = (".invalid", ".example", ".test", ".localhost")
RESERVED_HOSTS = {"example.com", "example.net", "example.org", "localhost", "example.invalid"}
# Reviewed public reference hosts. Change only by code review; never derive
# this list from report or package content.
REVIEWED_PUBLIC_HOSTS = frozenset({
    "github.com", "www.php.net", "php.net", "www.cve.org", "cve.org", "osv.dev", "google.github.io",
    "trivy.dev", "agentskills.io", "opensource.org", "json-schema.org", "nvd.nist.gov", "www.first.org",
    "blog.railway.com", "status.railway.com",  # cited by profiles/railway-2026-10-21.md
    "skills.sh", "img.shields.io",  # README badges
    "blog.mozilla.org", "bugzilla.mozilla.org", "emudhra.com", "emudhra.we-have-a-problem.com",  # emudhra profile
    "support.apple.com",  # cited by profiles/emudhra-2026-10-17.md
    "nodejs.org",  # cited by profiles/brotli-2026-10-21.md
    "istio.io",  # cited by profiles/brotli-2026-10-21.md
    "docs.litellm.ai",  # cited by profiles/litellm-2026-10-21.md
    "pillow.readthedocs.io",  # cited by profiles/brotli-2026-10-21.md
    "tailworm.com",  # cited by profiles/mesh-vpn-ssh-2026-10-25.md
    "tailscale.com",  # Tailscale SSH, policy, lock and security bulletins
    "lightning.ai",  # cited by profiles/lightning-ai-2026-10-16.md
    "unit42.paloaltonetworks.com",  # Unit 42 PHP2Shell retraction note
})
_URL = re.compile(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://(?:[^\s/@'\"]*@)?([A-Za-z0-9][A-Za-z0-9.-]*)")
_EMAIL = re.compile(r"\b[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)\b")
_BARE_HOST = re.compile(
    r"(?<![@/\w.-])((?:[a-z0-9-]+\.)+(?:com|net|org|io|dev|ai|co|app|cloud|xyz|me|info|biz|us|uk|in|de|eu|tech|site))\b",
    re.IGNORECASE)
_IPV4 = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
_ACCOUNT_ID = re.compile(r"(?<!\d)\d{12}(?!\d)")
_DOC_NETS = [ipaddress.ip_network(n) for n in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "127.0.0.0/8", "0.0.0.0/32")]


def is_reserved_host(host):
    host = host.lower().rstrip(".")
    if host in RESERVED_HOSTS:
        return True
    if host.endswith(RESERVED_SUFFIXES):
        return True
    return any(host.endswith("." + h) for h in ("example.com", "example.net", "example.org"))


def _host_allowed(host, allowed_hosts):
    host = host.lower().rstrip(".")
    return is_reserved_host(host) or host in allowed_hosts


def find_public_leaks(text, allowed_hosts=frozenset(), denylist=()):
    """Return (kind, start, end, detail) for content unsafe in a public package.

    ``detail`` is a fixed category description and never contains matched
    text, so diagnostics cannot disclose the host, address or term they flag.
    Denylist terms are reported by index only.
    """
    allowed = {h.lower() for h in allowed_hosts}
    hits = []
    for m in _URL.finditer(text):
        host = m.group(1)
        if not _host_allowed(host, allowed):
            hits.append(("non_reserved_url_host", m.start(), m.end(), "URL host outside reserved and reviewed hosts"))
    for m in _EMAIL.finditer(text):
        if not is_reserved_host(m.group(1)):
            hits.append(("email_address", m.start(), m.end(), "email at non-reserved domain"))
    for m in _BARE_HOST.finditer(text):
        host = m.group(1)
        if not _host_allowed(host, allowed):
            hits.append(("non_reserved_hostname", m.start(), m.end(), "hostname outside reserved and reviewed hosts"))
    for m in _IPV4.finditer(text):
        try:
            ip = ipaddress.ip_address(m.group(0))
        except ValueError:
            continue
        if not any(ip in n for n in _DOC_NETS):
            hits.append(("ip_address", m.start(), m.end(), "non-documentation IPv4"))
    for m in _ACCOUNT_ID.finditer(text):
        hits.append(("account_id_like", m.start(), m.end(), "12-digit identifier"))
    lowered = text.lower()
    for idx, term in enumerate(denylist):
        term = term.strip().lower()
        if not term:
            continue
        start = lowered.find(term)
        while start != -1:
            hits.append(("denylisted_term", start, start + len(term), "denylist entry #%d" % (idx + 1)))
            start = lowered.find(term, start + 1)
    hits.sort(key=lambda h: (h[1], h[0]))
    return hits


def diagnostic_text(value):
    """Value-free diagnostic text, not general-purpose de-identification."""
    text = redact(str(value))
    text = re.sub(r"\b[a-zA-Z][a-zA-Z0-9+.-]*://[^\s<>\"']+", "[REDACTED:url]", text)
    hits = find_public_leaks(text, allowed_hosts=())
    out, pos = [], 0
    for kind, start, end, _detail in hits:
        if start < pos:
            pos = max(pos, end)
            continue
        out.extend((text[pos:start], "[REDACTED:%s]" % kind))
        pos = end
    out.append(text[pos:])
    return re.sub(r"[\x00-\x1f\x7f\u202a-\u202e\u2066-\u2069]",
                  lambda m: "\\u%04x" % ord(m.group(0)), "".join(out))


def policy_summaries(records):
    """Keep policy text local; diagnostics carry only ordinal IDs."""
    return [{"override_id": "HOST-%03d" % (i + 1), "requires_human_signoff": True}
            for i, _record in enumerate(records)]


# ------------------------------------------------------- reviewed host policy
_HOSTNAME = re.compile(r"(?=.{1,253}\Z)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\Z")


def parse_host_policy(doc):
    """Validate a human-reviewed host-override policy document.

    Shape: {"approved_by_role": str, "hosts": [{"host": str, "rationale": str}]}
    Hosts must be exact lowercase DNS names (no wildcards, ports, paths or
    userinfo). Returns (frozenset_of_hosts, records); raises ValueError.
    The records are echoed in tool output so an override is never silent.
    """
    if not isinstance(doc, dict) or set(doc) != {"approved_by_role", "hosts"}:
        raise ValueError("host policy must be an object with exactly approved_by_role and hosts")
    role = doc["approved_by_role"]
    if not isinstance(role, str) or len(role.strip()) < 3:
        raise ValueError("host policy needs a named human approver role")
    if re.search(r"\b(model|llm|assistant|subagent|agent|bot|automated|automation|self)\b", role, re.I):
        raise ValueError("host policy cannot be approved by a machine or self-approval role")
    if not isinstance(doc["hosts"], list) or not doc["hosts"]:
        raise ValueError("host policy hosts must be a non-empty list")
    hosts, records = set(), []
    for i, entry in enumerate(doc["hosts"]):
        if not isinstance(entry, dict) or set(entry) != {"host", "rationale"}:
            raise ValueError("hosts[%d] must have exactly host and rationale" % i)
        host, why = entry["host"], entry["rationale"]
        if not isinstance(host, str) or not _HOSTNAME.match(host):
            raise ValueError("hosts[%d].host is not an exact lowercase hostname" % i)
        if not isinstance(why, str) or len(why.strip()) < 10:
            raise ValueError("hosts[%d].rationale must explain the approval" % i)
        if host in hosts:
            raise ValueError("hosts[%d].host is duplicated" % i)
        hosts.add(host)
        records.append({"host": host, "rationale": why.strip(), "approved_by_role": role.strip()})
    return frozenset(hosts), records
