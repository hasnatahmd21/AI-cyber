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
        self.key_provider = key_provider or DefaultKeyProvider(self.state_dir)
        self.integrity = Integrity(self.key_provider)

        self._system: Optional[System] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._lock = threading.RLock()
        self._request_lock = threading.Lock()
        self._audit_save_lock = threading.Lock()
        self._failed_latched = False
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

        try:
            self._system = build_system(
                config={"it_tech_source": self.it_tech_path},
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
            authority_ok, authority_reason = authority_gate.authorize(
                self._request("supervisor-authority-startup", "continuous-authority-check")
            )
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
                    return False, f"resident defence denied HYDRA: {result.decision.value}: {result.reason}", {
                        "decision": result.decision.value,
                        "reason": result.reason,
                        "trace": list(result.trace),
                    }
                return True, "resident IT-Tech layered defence allowed request", {
                    "decision": result.decision.value,
                    "trace": list(result.trace),
                }
            except Exception as exc:
                reason = f"resident defence failed closed: {type(exc).__name__}: {exc}"
                self._latch_failure(reason, {"resident_defence": False})
                return False, reason, self.snapshot()

    def _latch_failure(self, reason: str, checks: dict[str, bool]) -> None:
        with self._lock:
            self._failed_latched = True
            self._status.update(
                active=True, ready=False, status="blocked", reason=reason,
                last_check_at=_utc_now(), checks={**self._status.get("checks", {}), **checks},
            )
        if self._system is not None:
            self._system.audit.record("supervisor_fail_closed", reason=reason, checks=checks)
            self._persist_audit()

    def _monitor_loop(self) -> None:
        last_audit_save = time.monotonic()
        while not self._stop.wait(self.interval_s):
            ok, reason, checks = self._verify_source_assets()
            if not ok:
                self._latch_failure(reason, checks)
            elif not self._failed_latched and self._system is not None:
                try:
                    network_gate = getattr(self._system.orchestrator.l2, "it_tech_network", None)
                    authority_gate = getattr(self._system.orchestrator.l3, "it_tech_gate", None)
                    if network_gate is None or authority_gate is None:
                        raise SupervisorStartupError("IT-Tech network/authority gate disappeared")
                    network_ok, network_reason = network_gate.health_check()
                    authority_ok, authority_reason = authority_gate.authorize(
                        self._request(
                            f"supervisor-authority-{time.time_ns()}",
                            "continuous-authority-health-check",
                        )
                    )
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
                self._set_status(active=True, ready=False, status="blocked", last_check_at=_utc_now())

            if time.monotonic() - last_audit_save >= 30.0:
                self._persist_audit()
                last_audit_save = time.monotonic()

    def _persist_audit(self) -> None:
        system = self._system
        if system is None:
            return
        try:
            with self._audit_save_lock:
                save(system.audit, self.audit_path, integrity=self.integrity)
        except Exception as exc:
            self._set_status(
                ready=False, status="blocked",
                reason=f"audit persistence failed: {type(exc).__name__}",
            )

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None and self._thread is not threading.current_thread():
            self._thread.join(timeout=max(2.0, self.interval_s + 1.0))
        system, self._system = self._system, None
        if system is not None:
            try:
                system.shutdown()
            finally:
                self._persist_audit()
        current = self.snapshot()
        self._set_status(
            active=False, ready=False,
            status="blocked" if self._failed_latched else "stopped",
            reason=current.get("reason") if self._failed_latched else "stopped by operator",
            last_check_at=_utc_now(),
        )
