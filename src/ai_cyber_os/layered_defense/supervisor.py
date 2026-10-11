"""Continuous fail-closed supervisor for the active layered defence runtime.

The supervisor is intended to live for the lifetime of the operational UI or be run
as a separate service. It verifies the same signed source baseline used by the CLI,
keeps the IT-Tech network and authority engines alive, checks integrity periodically,
and denies UI-triggered HYDRA runs unless the resident monitor remains healthy.
"""
from __future__ import annotations

import datetime
import json
import os
import threading
import time
from typing import Any, Optional

from .audit_store import save
from .audit_telemetry import AuditLog
from .contracts import Decision, Request
from .crypto_integrity import Integrity, KeyProvider
from .integrity_gate import check, check_file
from .keystore import DefaultKeyProvider
from .runtime import StartupError, System, build_system

PACKAGE_REL = os.path.join("src", "ai_cyber_os")
IT_TECH_REL = "IT_tech__MERGED_ALL_FIXES_APPLIED.py"


class SupervisorStartupError(StartupError):
    """Raised when the always-on defence service cannot start safely."""


def _utc_now() -> str:
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


class DefenceSupervisor:
    """Resident integrity and IT-Tech network/authority monitor.

    Startup does not create or re-sign baselines. Operators must first review the
    source and initialize baselines explicitly through the secured CLI.
    """

    def __init__(
        self,
        root: str,
        *,
        interval_s: float = 2.0,
        key_provider: Optional[KeyProvider] = None,
    ) -> None:
        if isinstance(interval_s, bool) or not isinstance(interval_s, (int, float)):
            raise ValueError("monitor interval must be numeric")
        if not 0.25 <= float(interval_s) <= 60.0:
            raise ValueError("monitor interval must be between 0.25 and 60 seconds")
        self.root = os.path.realpath(root)
        self.interval_s = float(interval_s)
        self.state_dir = os.path.join(self.root, ".ai_cyber")
        self.target = os.path.join(self.root, PACKAGE_REL)
        self.it_tech_path = os.path.join(self.root, IT_TECH_REL)
        self.baseline_path = os.path.join(self.state_dir, "hydra_baseline.json")
        self.it_tech_baseline_path = os.path.join(self.state_dir, "it_tech_baseline.json")
        self.latch_path = os.path.join(self.state_dir, "defence_latch.json")
        # A separate signed fallback keeps restart enforcement durable if the primary
        # latch path fails for a path-specific or transient filesystem reason.
        self.fallback_latch_path = os.path.join(self.state_dir, "defence_latch_fallback.json")
        self.key_provider = key_provider or DefaultKeyProvider(self.state_dir)
        self.integrity = Integrity(self.key_provider)

        self._system: Optional[System] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._request_lock = threading.Lock()
        self._latch_lock = threading.Lock()
        self._audit_save_lock = threading.Lock()
        self._failed_latched = False
        # True only after a signed primary or fallback marker write returned and
        # the marker was still present. A mere path-exists check is insufficient.
        self._durable_latch_confirmed = False
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        self.audit_path = os.path.join(self.state_dir, "audit", f"supervisor-{timestamp}.jsonl")
        self._status: dict[str, Any] = {
            "service": "ai-cyber-defence-supervisor",
            "active": False,
            "ready": False,
            "status": "stopped",
            "interval_seconds": self.interval_s,
            "started_at": None,
            "last_check_at": None,
            "checks": {},
            "reason": "not started",
        }

    def _set_status(self, **fields: Any) -> None:
        with self._lock:
            self._status.update(fields)

    def snapshot(self) -> dict[str, Any]:
        with self._lock:
            return json.loads(json.dumps(self._status, default=str))

    def _verify_source_assets(self) -> tuple[bool, str, dict[str, bool]]:
        if os.path.islink(self.state_dir):
            return False, "security state directory is a symlink; refusing to trust local state", {
                "hydra_source_integrity": False,
                "it_tech_source_integrity": False,
            }
        if not os.path.isfile(self.baseline_path) or not os.path.isfile(self.it_tech_baseline_path):
            return False, "signed source baseline missing; explicit reviewed rebaseline required", {
                "hydra_source_integrity": False,
                "it_tech_source_integrity": False,
            }
        hydra = check(self.target, self.baseline_path, self.integrity)
        it_tech = check_file(self.it_tech_path, self.it_tech_baseline_path, self.integrity)
        checks = {
            "hydra_source_integrity": bool(hydra.ok),
            "it_tech_source_integrity": bool(it_tech.ok),
        }
        if not hydra.ok:
            return False, "HYDRA source integrity: " + hydra.reason, checks
        if not it_tech.ok:
            return False, "IT-Tech source integrity: " + it_tech.reason, checks
        return True, "signed source baselines verified", checks

    def _persistent_latch_reason(self) -> Optional[str]:
        # Do not follow the runtime-state directory even when no latch is present.
        # Both the primary and fallback markers are restart-enforced.
        if os.path.islink(self.state_dir):
            return "security state directory is a symlink; refusing to trust local state"
        for latch_path in (self.latch_path, self.fallback_latch_path):
            if not os.path.lexists(latch_path):
                continue
            label = os.path.basename(latch_path)
            if os.path.islink(latch_path):
                return f"persistent defence latch {label} is a symlink; operator review required"
            try:
                with open(latch_path, encoding="utf-8") as stream:
                    envelope = json.load(stream)
                document = envelope["document"]
                signature = envelope["signature"]
                if not isinstance(document, dict) or not isinstance(signature, str):
                    return f"persistent defence latch {label} schema invalid; explicit review required"
                canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
                if not self.integrity.verify(canonical, signature):
                    return f"persistent defence latch {label} signature invalid; explicit review required"
                if document.get("status") != "blocked":
                    return f"persistent defence latch {label} status invalid; explicit review required"
                detail = str(document.get("reason", "unspecified incident"))
                return (
                    f"persistent defence incident latch ({label}) is active: " + detail
                    + "; inspect signed audit records, remediate, then clear explicitly"
                )
            except Exception as exc:
                return f"persistent defence latch {label} unreadable ({type(exc).__name__}); explicit review required"
        return None

    def _write_persistent_latch(self, reason: str, checks: dict[str, bool]) -> None:
        self._write_persistent_latch_to(self.latch_path, reason, checks)

    def _write_persistent_latch_to(
        self, latch_path: str, reason: str, checks: dict[str, bool]
    ) -> None:
        """Atomically write a signed incident marker at the requested path."""
        os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        if os.path.islink(self.state_dir) or os.path.islink(latch_path):
            raise SupervisorStartupError("refusing to write through a symlinked defence latch path")
        if os.path.exists(latch_path):
            # A prior attempt may have linked the complete file but failed while
            # fsyncing the directory. Re-sync both file and parent before confirming
            # durability on a retry.
            flags = os.O_RDONLY
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            marker_fd = os.open(latch_path, flags)
            try:
                os.fsync(marker_fd)
            finally:
                os.close(marker_fd)
            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            directory_fd = os.open(self.state_dir, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
            return
        document = {
            "status": "blocked",
            "detected_at": _utc_now(),
            "reason": str(reason)[:1200],
            "checks": {str(key): bool(value) for key, value in checks.items()},
        }
        canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
        envelope = {
            "document": document,
            "signature": self.integrity.sign(canonical),
        }
        temporary = (
            latch_path + f".{os.getpid()}.{threading.get_ident()}.tmp"
        )
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        fd = os.open(temporary, flags, 0o600)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as stream:
                json.dump(envelope, stream, sort_keys=True, indent=2)
                stream.flush()
                os.fsync(stream.fileno())
            # Atomic link installation does not overwrite another incident marker.
            try:
                os.link(temporary, latch_path)
            except FileExistsError:
                # A concurrent writer installed this marker. Confirm its contents
                # and directory entry are flushed before returning success.
                marker_flags = os.O_RDONLY
                if hasattr(os, "O_NOFOLLOW"):
                    marker_flags |= os.O_NOFOLLOW
                marker_fd = os.open(latch_path, marker_flags)
                try:
                    os.fsync(marker_fd)
                finally:
                    os.close(marker_fd)
            directory_flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                directory_flags |= os.O_DIRECTORY
            directory_fd = os.open(self.state_dir, directory_flags)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        finally:
            try:
                os.unlink(temporary)
            except FileNotFoundError:
                pass

    def _request(self, request_id: str, payload: str, *, source: str = "external") -> Request:
        if self._system is None:
            raise SupervisorStartupError("defence supervisor system is unavailable")
        token = self._system.trust.issue_token("hydra-runtime")
        return Request(
            request_id=request_id,
            principal="hydra-runtime",
            action="read",
            resource="hydra:run",
            payload=payload,
            credentials=token,
            source=source,
            attributes={},
        )

    def start(self) -> "DefenceSupervisor":
        with self._lock:
            if self._status["active"]:
                return self

        ok, reason, checks = self._verify_source_assets()
        if not ok:
            self._set_status(
                active=False, ready=False, status="blocked", reason=reason,
                last_check_at=_utc_now(), checks=checks,
            )
            raise SupervisorStartupError(reason)
        latch_reason = self._persistent_latch_reason()
        if latch_reason:
            self._set_status(
                active=False, ready=False, status="blocked", reason=latch_reason,
                last_check_at=_utc_now(), checks={**checks, "persistent_latch": False},
            )
            raise SupervisorStartupError(latch_reason)

        try:
            self._system = build_system(
                config={
                    "it_tech_source": self.it_tech_path,
                    "package_baseline_path": self.baseline_path,
                    "it_tech_baseline_path": self.it_tech_baseline_path,
                    # The source verifier above has just validated both signatures.
                    "it_tech_integrity_verified": True,
                },
                key_provider=self.key_provider,
            )
            self._system.trust.grant("hydra-runtime", "read", "hydra:")
            # Startup is fail-closed: no service is marked healthy until a genuine
            # end-to-end barrier/L1/L2/L3 request has returned ALLOW.
            result = self._system.orchestrator.handle(
                self._request("supervisor-startup", "continuous-defence-startup-check")
            )
            if result.decision is not Decision.ALLOW:
                raise SupervisorStartupError(
                    f"startup defence pipeline denied: {result.decision.value}: {result.reason}"
                )

            network_gate = getattr(self._system.orchestrator.l2, "it_tech_network", None)
            authority_gate = getattr(self._system.orchestrator.l3, "it_tech_gate", None)
            if network_gate is None or authority_gate is None:
                raise SupervisorStartupError("required IT-Tech network or authority gate is not wired")
            network_ok, network_reason = network_gate.health_check()
            if not network_ok:
                raise SupervisorStartupError(network_reason)
            authority_ok, authority_reason = authority_gate.health_check()
            if not authority_ok:
                raise SupervisorStartupError(authority_reason)
        except Exception:
            system, self._system = self._system, None
            if system is not None:
                try:
                    system.shutdown()
                    save(system.audit, self.audit_path, integrity=self.integrity)
                except Exception:
                    pass
            raise

        checks.update({
            "barrier_and_three_layers": True,
            "it_tech_network_engine": True,
            "it_tech_authority_engine": True,
            "audit_chain": bool(self._system.audit.self_verify()),
        })
        if not checks["audit_chain"]:
            system, self._system = self._system, None
            if system is not None:
                system.shutdown()
            raise SupervisorStartupError("audit chain failed startup verification")

        self._set_status(
            active=True, ready=True, status="healthy",
            started_at=_utc_now(), last_check_at=_utc_now(),
            checks=checks, reason="continuous IT-Tech defence active",
        )
        self._thread = threading.Thread(
            target=self._monitor_loop,
            name="ai-cyber-defence-supervisor",
            daemon=True,
        )
        self._thread.start()
        return self

    def authorize_hydra(self, phase: str, hardening: bool = False) -> tuple[bool, str, dict[str, Any]]:
        """Apply the resident, stateful defence gate before the secured CLI is invoked."""
        if not isinstance(phase, str) or not phase:
            return False, "invalid HYDRA phase selector", {}
        with self._request_lock:
            state = self.snapshot()
            if not state.get("active") or not state.get("ready") or state.get("status") != "healthy":
                return False, "resident defence monitor is not healthy; HYDRA blocked", state

            ok, reason, checks = self._verify_source_assets()
            if not ok:
                self._latch_failure(reason, checks)
                return False, reason, self.snapshot()
            latch_reason = self._persistent_latch_reason()
            if latch_reason:
                self._latch_failure(latch_reason, {"persistent_latch": False})
                return False, latch_reason, self.snapshot()

            try:
                if self._system is None:
                    raise SupervisorStartupError("defence supervisor system is unavailable")
                result = self._system.orchestrator.handle(
                    self._request(
                        f"ui-hydra-{time.time_ns()}",
                        f"phase={phase}; hardening={bool(hardening)}",
                        source="external",
                    )
                )
                self._system.audit.record(
                    "supervisor_hydra_gate",
                    decision=result.decision.value,
                    reason=result.reason,
                    trace=list(result.trace),
                    phase=phase,
                )
                if result.decision is not Decision.ALLOW:
                    reason = (
                        f"resident defence denied HYDRA: {result.decision.value}: {result.reason}"
                    )
                    evidence = {
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "trace": list(result.trace),
                    }
                    # A failed decision at the final control point is an incident,
                    # not just a UI error. Latch it durably so a fresh CLI/service
                    # process cannot regain an ALLOW decision after restart.
                    self._latch_failure(
                        reason,
                        {
                            "layered_defence_allowed": False,
                            "barrier_and_layers": False,
                            "decision_blocked": result.decision is Decision.BLOCK,
                            "decision_quarantined": result.decision is Decision.QUARANTINE,
                            "decision_error": result.decision is Decision.ERROR,
                        },
                    )
                    return False, reason, evidence
                return True, "resident IT-Tech layered defence allowed request", {
                    "decision": result.decision.value,
                    "trace": list(result.trace),
                }
            except Exception as exc:
                reason = f"resident defence failed closed: {type(exc).__name__}: {exc}"
                self._latch_failure(reason, {"resident_defence": False})
                return False, reason, self.snapshot()

    def _latch_marker_present(self) -> bool:
        return any(
            os.path.lexists(path) and not os.path.islink(path)
            for path in (self.latch_path, self.fallback_latch_path)
        )

    def _persist_incident_latch(
        self, reason: str, checks: dict[str, bool]
    ) -> tuple[bool, str]:
        """Persist a signed primary/fallback marker and report only confirmed writes."""
        if self._durable_latch_confirmed and self._latch_marker_present():
            return True, reason

        final_reason = reason
        primary_error: Exception | None = None
        try:
            self._write_persistent_latch(reason, checks)
        except Exception as exc:
            primary_error = exc
        else:
            if os.path.lexists(self.latch_path) and not os.path.islink(self.latch_path):
                self._durable_latch_confirmed = True
                return True, final_reason
            primary_error = SupervisorStartupError(
                "primary latch writer returned without a usable marker"
            )

        try:
            self._write_persistent_latch_to(self.fallback_latch_path, reason, checks)
        except Exception as fallback_error:
            final_reason = (
                f"{reason}; primary latch write failed: {type(primary_error).__name__}; "
                f"fallback latch write failed: {type(fallback_error).__name__}"
            )
        else:
            if (
                os.path.lexists(self.fallback_latch_path)
                and not os.path.islink(self.fallback_latch_path)
            ):
                self._durable_latch_confirmed = True
                final_reason = (
                    f"{reason}; primary latch write failed: {type(primary_error).__name__}; "
                    "signed fallback latch persisted"
                )
                return True, final_reason
            final_reason = (
                f"{reason}; primary latch write failed: {type(primary_error).__name__}; "
                "fallback latch writer returned without a usable marker"
            )

        self._durable_latch_confirmed = False
        return False, final_reason

    def _latch_failure(
        self, reason: str, checks: dict[str, bool], *, persist_audit: bool = True
    ) -> None:
        # Readiness is withdrawn before disk or audit I/O. Do not publish the terminal
        # blocked state until a signed marker write and its fsync sequence succeeded.
        with self._latch_lock:
            with self._lock:
                first_failure = not self._failed_latched
                self._failed_latched = True
                self._status.update(
                    active=True, ready=False, status="blocking", reason=reason,
                    last_check_at=_utc_now(), checks={**self._status.get("checks", {}), **checks},
                )

            was_durable = self._durable_latch_confirmed
            latch_persisted, final_reason = self._persist_incident_latch(reason, checks)
            if not latch_persisted:
                final_reason = (
                    f"{final_reason}; no durable incident latch could be confirmed; service "
                    "remains unready and fail-closed in this process, but restart persistence "
                    "is unavailable until storage is repaired"
                )

            newly_durable = not was_durable and latch_persisted
            if (first_failure or newly_durable) and self._system is not None:
                event = "supervisor_fail_closed" if first_failure else "supervisor_latch_persistence_recovered"
                try:
                    self._system.audit.record(
                        event, reason=final_reason, checks=checks,
                        durable_latch=bool(latch_persisted),
                    )
                except Exception as exc:
                    final_reason = f"{final_reason}; audit append failed: {type(exc).__name__}"
                if persist_audit:
                    self._persist_audit(latch_on_failure=False)
                    audit_status = self.snapshot()
                    audit_reason = str(audit_status.get("reason", "")).lower()
                    if "audit persistence failed" in audit_reason:
                        final_reason = f"{final_reason}; {audit_status['reason']}"

            # A previous failed write is retried by the monitor loop. A file merely
            # left behind by an exception is not counted as durable until fsync works.
            self._set_status(
                active=True,
                ready=False,
                status="blocked" if latch_persisted else "blocking",
                reason=final_reason,
                last_check_at=_utc_now(),
                checks={**self.snapshot().get("checks", {}), **checks,
                        "persistent_latch": bool(latch_persisted)},
            )

    def _monitor_loop(self) -> None:
        last_audit_save = time.monotonic()
        while not self._stop.wait(self.interval_s):
            ok, reason, checks = self._verify_source_assets()
            persistent_reason = self._persistent_latch_reason()
            if persistent_reason and not self._failed_latched:
                self._latch_failure(persistent_reason, {"persistent_latch": False})
            elif not ok:
                self._latch_failure(reason, checks)
            elif not self._failed_latched and self._system is not None:
                try:
                    network_gate = getattr(self._system.orchestrator.l2, "it_tech_network", None)
                    authority_gate = getattr(self._system.orchestrator.l3, "it_tech_gate", None)
                    if network_gate is None or authority_gate is None:
                        raise SupervisorStartupError("IT-Tech network/authority gate disappeared")
                    network_ok, network_reason = network_gate.health_check()
                    authority_ok, authority_reason = authority_gate.health_check()
                    checks.update({
                        "it_tech_network_engine": bool(network_ok),
                        "it_tech_authority_engine": bool(authority_ok),
                        "audit_chain": bool(self._system.audit.self_verify()),
                    })
                    if not network_ok:
                        self._latch_failure(network_reason, checks)
                    elif not authority_ok:
                        self._latch_failure(authority_reason, checks)
                    elif not checks["audit_chain"] or self._system.audit.health_errors:
                        self._latch_failure("audit chain/telemetry health check failed", checks)
                    else:
                        self._set_status(
                            active=True, ready=True, status="healthy",
                            last_check_at=_utc_now(), checks=checks,
                            reason="continuous IT-Tech defence active",
                        )
                except Exception as exc:
                    self._latch_failure(
                        f"continuous monitor failed closed: {type(exc).__name__}: {exc}",
                        {**checks, "monitor": False},
                    )
            else:
                if self._failed_latched:
                    # Retry persistence after a transient filesystem failure, and
                    # recreate the marker if external tampering removed it in-process.
                    if not self._durable_latch_confirmed or not self._latch_marker_present():
                        self._durable_latch_confirmed = False
                        current = self.snapshot()
                        self._latch_failure(
                            str(current.get("reason", "previous defence incident")),
                            current.get("checks", {}),
                        )
                    else:
                        self._set_status(
                            active=True, ready=False, status="blocked",
                            last_check_at=_utc_now(),
                        )
                else:
                    self._set_status(active=True, ready=False, status="blocked", last_check_at=_utc_now())

            if time.monotonic() - last_audit_save >= 30.0:
                self._persist_audit()
                last_audit_save = time.monotonic()

    def _persist_audit(self, *, latch_on_failure: bool = True) -> None:
        system = self._system
        if system is None:
            return
        try:
            with self._audit_save_lock:
                save(system.audit, self.audit_path, integrity=self.integrity)
        except Exception as exc:
            reason = f"audit persistence failed: {type(exc).__name__}"
            if latch_on_failure:
                # A write failure is itself a defence incident. The nested path
                # persists a signed latch but deliberately does not recurse into
                # another audit save attempt.
                self._latch_failure(
                    reason,
                    {"audit_persistence": False},
                    persist_audit=False,
                )
            else:
                self._set_status(ready=False, status="blocked", reason=reason)

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(2.0, self.interval_s + 1.0))
        system, self._system = self._system, None
        if system is not None:
            try:
                system.shutdown()
            finally:
                try:
                    with self._audit_save_lock:
                        save(system.audit, self.audit_path, integrity=self.integrity)
                except Exception as exc:
                    self._latch_failure(
                        f"audit persistence failed during shutdown: {type(exc).__name__}",
                        {"audit_persistence": False},
                        persist_audit=False,
                    )
        current = self.snapshot()
        durable_latch = self._durable_latch_confirmed and self._latch_marker_present()
        self._set_status(
            active=False, ready=False,
            status=(
                "blocked" if self._failed_latched and durable_latch
                else "blocking" if self._failed_latched
                else "stopped"
            ),
            reason=current.get("reason") if self._failed_latched else "stopped by operator",
            last_check_at=_utc_now(),
        )


def clear_defence_latch(root: str, reason: str) -> tuple[bool, str]:
    """Clear persisted incident markers only after clean signed-source verification.

    Every marker is audited before removal. If final audit persistence fails, removed
    marker bytes are restored so an incomplete recovery cannot reopen the service.
    """
    root = os.path.realpath(root)
    state_dir = os.path.join(root, ".ai_cyber")
    target = os.path.join(root, PACKAGE_REL)
    it_tech_path = os.path.join(root, IT_TECH_REL)
    baseline_path = os.path.join(state_dir, "hydra_baseline.json")
    it_baseline_path = os.path.join(state_dir, "it_tech_baseline.json")
    latch_paths = [
        os.path.join(state_dir, "defence_latch.json"),
        os.path.join(state_dir, "defence_latch_fallback.json"),
    ]

    if not isinstance(reason, str) or not reason.strip() or len(reason.strip()) > 512:
        return False, "a non-empty operator review reason of at most 512 characters is required"
    if os.path.islink(state_dir):
        return False, "security state directory is a symlink; refusing latch clear"
    if not os.path.isfile(baseline_path) or not os.path.isfile(it_baseline_path):
        return False, "cannot clear latch without both signed source baselines"

    provider = DefaultKeyProvider(state_dir)
    integrity = Integrity(provider)
    hydra = check(target, baseline_path, integrity)
    if not hydra.ok:
        return False, "cannot clear latch; HYDRA source integrity: " + hydra.reason
    it_tech = check_file(it_tech_path, it_baseline_path, integrity)
    if not it_tech.ok:
        return False, "cannot clear latch; IT-Tech source integrity: " + it_tech.reason

    existing = [path for path in latch_paths if os.path.lexists(path)]
    if not existing:
        return True, "no persisted defence latch is present; signed source baselines are clean"
    if any(os.path.islink(path) for path in existing):
        return False, "persistent defence latch is a symlink; refusing to follow or remove it"

    prior_bytes: dict[str, bytes] = {}
    prior_metadata: list[dict[str, Any]] = []
    removed: list[str] = []
    try:
        for path in existing:
            with open(path, "rb") as stream:
                payload = stream.read()
            prior_bytes[path] = payload
            valid = False
            prior_reason = "unreadable or invalid prior latch"
            try:
                envelope = json.loads(payload.decode("utf-8"))
                document = envelope["document"]
                signature = envelope["signature"]
                canonical = json.dumps(document, sort_keys=True, separators=(",", ":")).encode("utf-8")
                valid = isinstance(document, dict) and isinstance(signature, str) and integrity.verify(canonical, signature)
                if valid:
                    prior_reason = str(document.get("reason", "unspecified incident"))
            except Exception:
                valid = False
            prior_metadata.append({
                "path": os.path.basename(path),
                "previous_latch_valid": valid,
                "previous_latch_reason": prior_reason,
            })

        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%dT%H%M%S.%fZ")
        audit_path = os.path.join(state_dir, "audit", f"supervisor-latch-clear-{timestamp}.jsonl")
        audit = AuditLog()
        audit.record(
            "defence_latch_clear_requested",
            operator_reason=reason.strip(),
            latches=prior_metadata,
            hydra_source_integrity=True,
            it_tech_source_integrity=True,
        )
        save(audit, audit_path, integrity=integrity)

        for path in existing:
            os.remove(path)
            removed.append(path)
        audit.record(
            "defence_latch_cleared",
            operator_reason=reason.strip(),
            cleared_latches=[os.path.basename(path) for path in removed],
        )
        save(audit, audit_path, integrity=integrity)
        return True, "all persistent defence latches cleared after signed source-integrity verification; restart the service"
    except Exception as exc:
        # If final audit persistence fails after a marker was removed, restore its
        # exact prior bytes; the runtime remains closed until audited recovery succeeds.
        for path in removed:
            try:
                if not os.path.lexists(path) and path in prior_bytes:
                    temporary = path + ".restore.tmp"
                    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
                    if hasattr(os, "O_NOFOLLOW"):
                        flags |= os.O_NOFOLLOW
                    fd = os.open(temporary, flags, 0o600)
                    with os.fdopen(fd, "wb") as stream:
                        stream.write(prior_bytes[path])
                        stream.flush()
                        os.fsync(stream.fileno())
                    os.replace(temporary, path)
            except Exception:
                pass
        return False, f"latch clear failed closed: {type(exc).__name__}"
