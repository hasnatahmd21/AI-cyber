from ai_cyber.crypto_integrity import Integrity, StaticKeyProvider
from ai_cyber.audit_telemetry import AuditLog
from ai_cyber.trust_authority import TrustAuthority
from ai_cyber.runtime import build_system

KEY = StaticKeyProvider({"default": b"k" * 32})


def trust():
    t = TrustAuthority(Integrity(KEY), AuditLog())
    t.grant("alice", "read", "/docs/")
    t.grant("alice", "write", "/docs/")
    t.grant("alice", "delete", "/docs/")
    return t


def system(**cfg):
    s = build_system(cfg, key_provider=KEY)
    s.trust.grant("alice", "read", "/docs/"); s.trust.grant("alice", "write", "/docs/")
    s.trust.grant("alice", "delete", "/docs/"); s.trust.grant("bob", "read", "/docs/")
    return s
