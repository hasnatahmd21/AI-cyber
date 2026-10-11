"""
HYDRA POST-CORE — PHASE 10: HARDWARE / FIRMWARE / BOOT TRUST
================================================================
Single-file delivery. Contains:

  * Conceptual HYDRA contracts (Protocols only)
  * Trust-anchor model (root of trust)
  * Firmware component model (signature, version, digest, drift)
  * Boot-chain graph (UEFI → bootloader → kernel → initrd → runtime)
  * Per-stage measurement verification (PCR-style)
  * Attestation model (quote, nonce, PCRs, signature validity, freshness)
  * TEE state model (SGX / SEV / TDX / TrustZone / None)
  * Hardware identity model (endorsement key, cert chain, device match)
  * Continuous platform trust state
  * Trust propagation forward from anchor through boot chain
  * Break detection:
      - trust-anchor missing
      - firmware drift
      - firmware signature invalid
      - secure-boot disabled
      - boot-chain break
      - boot-measurement mismatch
      - attestation stale
      - attestation invalid
      - TEE compromised
      - hardware-identity mismatch
  * Continuity analysis with intrinsic risk
  * Explicit trust-label transitions
  * Machine-checkable hardware/boot invariants
  * In-memory + SQLite stores
  * Phase-10 engine facade
  * Full test suite + manual runner

This is NEW hardware/firmware/boot trust-state technology. It is not a
firmware scanner, not a TPM driver, not a boot attestation tool — it
is continuous platform trust state.

Run tests:
    python hydra_phase10_hardware_firmware_boot_trust.py
    pytest hydra_phase10_hardware_firmware_boot_trust.py -q
"""
from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from enum import Enum
from typing import (
    Any,
    Callable,
    Dict,
    FrozenSet,
    Iterable,
    List,
    Mapping,
    Optional,
    Protocol,
    Tuple,
)

# =============================================================================
# SECTION 1 — CONTRACTS
# =============================================================================


class Clock(Protocol):
    def now(self) -> datetime: ...


class IdProvider(Protocol):
    def new_id(self, prefix: str = "") -> str: ...


class EvidenceEmitter(Protocol):
    def emit(self, evidence: Mapping[str, Any]) -> None: ...


class ProvenanceRecorder(Protocol):
    def record(self, *, subject_id: str, action: str, at: datetime,
               details: Mapping[str, Any]) -> None: ...


class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None: ...


# =============================================================================
# SECTION 2 — DOMAIN
# =============================================================================


class BootStage(str, Enum):
    UEFI_FIRMWARE = "uefi_firmware"
    UEFI_DRIVER = "uefi_driver"
    BOOTLOADER = "bootloader"
    KERNEL = "kernel"
    INITRD = "initrd"
    HYPERVISOR = "hypervisor"
    RUNTIME = "runtime"


_BOOT_ORDER: Mapping[BootStage, int] = {
    BootStage.UEFI_FIRMWARE: 0,
    BootStage.UEFI_DRIVER: 1,
    BootStage.BOOTLOADER: 2,
    BootStage.KERNEL: 3,
    BootStage.INITRD: 4,
    BootStage.HYPERVISOR: 5,
    BootStage.RUNTIME: 6,
}


def boot_order(stage: BootStage) -> int:
    return _BOOT_ORDER[stage]


class FirmwareKind(str, Enum):
    BIOS = "bios"
    UEFI = "uefi"
    BMC = "bmc"
    NIC_FIRMWARE = "nic_firmware"
    MANAGEMENT_ENGINE = "management_engine"
    STORAGE_FIRMWARE = "storage_firmware"
    SECURE_BOOT_KEYS = "secure_boot_keys"
    OPTION_ROM = "option_rom"


class HardwareKind(str, Enum):
    CPU = "cpu"
    TPM = "tpm"
    HSM = "hsm"
    SECURE_ELEMENT = "secure_element"
    BASEBOARD_MANAGEMENT_CONTROLLER = "bmc"
    NIC = "nic"
    STORAGE_CONTROLLER = "storage_controller"
    ACCELERATOR = "accelerator"


class TeeKind(str, Enum):
    NONE = "none"
    INTEL_SGX = "intel_sgx"
    AMD_SEV = "amd_sev"
    INTEL_TDX = "intel_tdx"
    ARM_TRUSTZONE = "arm_trustzone"
    ARM_CONFIDENTIAL_COMPUTE = "arm_cca"


class TrustLabel(str, Enum):
    UNKNOWN = "unknown"
    OBSERVED = "observed"
    TRUSTED = "trusted"
    DEGRADED = "degraded"
    SUSPICIOUS = "suspicious"
    COMPROMISED = "compromised"
    QUARANTINED = "quarantined"


_LABEL_SEVERITY: Mapping[TrustLabel, int] = {
    TrustLabel.UNKNOWN: 0,
    TrustLabel.OBSERVED: 1,
    TrustLabel.TRUSTED: 1,
    TrustLabel.DEGRADED: 2,
    TrustLabel.SUSPICIOUS: 3,
    TrustLabel.COMPROMISED: 4,
    TrustLabel.QUARANTINED: 5,
}


def label_severity(label: TrustLabel) -> int:
    return _LABEL_SEVERITY[label]


def worse_of(a: TrustLabel, b: TrustLabel) -> TrustLabel:
    return a if label_severity(a) >= label_severity(b) else b


def is_untrusted(label: TrustLabel) -> bool:
    return label in (
        TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    )


class HardwareBreakKind(str, Enum):
    NONE = "none"
    TRUST_ANCHOR_MISSING = "trust_anchor_missing"
    FIRMWARE_DRIFT = "firmware_drift"
    FIRMWARE_SIGNATURE_INVALID = "firmware_signature_invalid"
    SECURE_BOOT_DISABLED = "secure_boot_disabled"
    BOOT_CHAIN_BREAK = "boot_chain_break"
    BOOT_MEASUREMENT_MISMATCH = "boot_measurement_mismatch"
    ATTESTATION_STALE = "attestation_stale"
    ATTESTATION_INVALID = "attestation_invalid"
    TEE_COMPROMISED = "tee_compromised"
    HARDWARE_IDENTITY_MISMATCH = "hardware_identity_mismatch"


@dataclass(frozen=True)
class Evidence:
    evidence_id: str
    source: str
    confidence: float
    observed_at: datetime
    payload: Mapping[str, Any]

    def __post_init__(self) -> None:
        if not self.evidence_id:
            raise ValueError("evidence_id is required")
        if not self.source:
            raise ValueError("source is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


# =============================================================================
# SECTION 3 — HARDWARE SECURITY SUB-MODELS
# =============================================================================


@dataclass(frozen=True)
class TrustAnchor:
    """Root of trust for a platform (TPM EK, hardware root, etc.)."""
    anchor_id: str
    kind: HardwareKind
    digest: str
    verified: bool = True
    certificate_chain_valid: bool = True

    def __post_init__(self) -> None:
        if not self.anchor_id:
            raise ValueError("anchor_id is required")
        if not self.digest:
            raise ValueError("digest is required")


@dataclass(frozen=True)
class FirmwareComponent:
    component_id: str
    kind: FirmwareKind
    version: str
    digest: str
    expected_version: Optional[str] = None
    expected_digest: Optional[str] = None
    signed: bool = True
    signature_verified: bool = True
    secure_boot_required: bool = False

    def __post_init__(self) -> None:
        if not self.component_id:
            raise ValueError("component_id is required")
        if not self.version:
            raise ValueError("version is required")
        if not self.digest:
            raise ValueError("digest is required")

    @property
    def drifted(self) -> bool:
        if self.expected_digest is not None and self.digest != self.expected_digest:
            return True
        if self.expected_version is not None and self.version != self.expected_version:
            return True
        return False

    def dangerous_score(self) -> float:
        s = 0.0
        if not self.signed:
            s += 0.30
        if self.signed and not self.signature_verified:
            s += 0.40
        if self.drifted:
            s += 0.25
        if self.secure_boot_required and not (self.signed and self.signature_verified):
            s += 0.20
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class BootStageMeasurement:
    stage: BootStage
    digest: str
    expected_digest: Optional[str]
    measured_at: datetime
    signer_verified: bool = True

    def __post_init__(self) -> None:
        if not self.digest:
            raise ValueError("digest is required")
        if self.measured_at.tzinfo is None:
            raise ValueError("measured_at must be timezone-aware")

    @property
    def matches_expected(self) -> bool:
        if self.expected_digest is None:
            return True
        return self.digest == self.expected_digest


@dataclass(frozen=True)
class Attestation:
    attestation_id: str
    platform_id: str
    nonce: str
    pcr_digest: str
    signature_valid: bool
    fresh: bool
    signed_at: datetime
    verifier_id: str
    evidence: Evidence

    def __post_init__(self) -> None:
        if not self.attestation_id:
            raise ValueError("attestation_id is required")
        if not self.platform_id:
            raise ValueError("platform_id is required")
        if not self.nonce:
            raise ValueError("nonce is required")
        if not self.pcr_digest:
            raise ValueError("pcr_digest is required")
        if not self.verifier_id:
            raise ValueError("verifier_id is required")
        if self.signed_at.tzinfo is None:
            raise ValueError("signed_at must be timezone-aware")


@dataclass(frozen=True)
class TeeState:
    kind: TeeKind
    enabled: bool = True
    attestation_valid: bool = True
    sealed_data_available: bool = True
    debug_mode: bool = False
    microcode_version: Optional[str] = None

    def dangerous_score(self) -> float:
        s = 0.0
        if self.kind is not TeeKind.NONE and not self.enabled:
            s += 0.30
        if self.kind is not TeeKind.NONE and not self.attestation_valid:
            s += 0.40
        if self.debug_mode:
            s += 0.30
        return max(0.0, min(1.0, s))


@dataclass(frozen=True)
class HardwareIdentity:
    device_id: str
    hardware_kind: HardwareKind
    endorsement_key_id: str
    cert_chain_valid: bool
    matches_expected: bool
    observed_at: datetime

    def __post_init__(self) -> None:
        if not self.device_id:
            raise ValueError("device_id is required")
        if not self.endorsement_key_id:
            raise ValueError("endorsement_key_id is required")
        if self.observed_at.tzinfo is None:
            raise ValueError("observed_at must be timezone-aware")


# =============================================================================
# SECTION 4 — PLATFORM
# =============================================================================


@dataclass(frozen=True)
class Platform:
    platform_id: str
    tenant_id: str
    criticality: float
    trust_anchor: Optional[TrustAnchor]
    firmware: FrozenSet[FirmwareComponent]
    boot_measurements: Tuple[BootStageMeasurement, ...]
    tee: TeeState
    hardware_identities: Tuple[HardwareIdentity, ...]

    def __post_init__(self) -> None:
        if not self.platform_id:
            raise ValueError("platform_id is required")
        if not self.tenant_id:
            raise ValueError("tenant_id is required")
        if not 0.0 <= self.criticality <= 1.0:
            raise ValueError("criticality must be within [0,1]")

        # Boot measurements must be in strictly increasing stage order
        prev_order = -1
        for m in self.boot_measurements:
            o = boot_order(m.stage)
            if o <= prev_order:
                raise ValueError(
                    "boot measurements must be in increasing stage order"
                )
            prev_order = o

    def intrinsic_risk(self) -> float:
        s = 0.0
        for f in self.firmware:
            s = max(s, f.dangerous_score())
        s = max(s, self.tee.dangerous_score())
        return s


# =============================================================================
# SECTION 5 — TRUST STATE
# =============================================================================


NEUTRAL_SCORE = 0.5


@dataclass(frozen=True)
class TrustSignal:
    signal_id: str
    weight: float
    polarity: float
    at: datetime
    evidence: Evidence

    def __post_init__(self) -> None:
        if not 0.0 <= self.weight <= 1.0:
            raise ValueError("weight must be within [0,1]")
        if not -1.0 <= self.polarity <= 1.0:
            raise ValueError("polarity must be within [-1,1]")
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


@dataclass(frozen=True)
class TrustState:
    score: float
    confidence: float
    basis: Tuple[TrustSignal, ...]
    updated_at: datetime

    def __post_init__(self) -> None:
        if not 0.0 <= self.score <= 1.0:
            raise ValueError("score must be within [0,1]")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("confidence must be within [0,1]")
        if self.updated_at.tzinfo is None:
            raise ValueError("updated_at must be timezone-aware")


def neutral_trust(at: datetime) -> TrustState:
    return TrustState(score=NEUTRAL_SCORE, confidence=0.0,
                      basis=(), updated_at=at)


def combine_trust(signals: Iterable[TrustSignal], at: datetime) -> TrustState:
    basis = tuple(sorted(signals, key=lambda s: s.at))
    if not basis:
        return neutral_trust(at)
    num = 0.0
    den = 0.0
    for s in basis:
        num += s.weight * s.polarity
        den += s.weight
    if den <= 0.0:
        return neutral_trust(at)
    raw = num / den
    score = max(0.0, min(1.0, (raw + 1.0) / 2.0))
    confidence = den / (den + 2.0)
    return TrustState(score=score, confidence=confidence,
                      basis=basis, updated_at=at)


def derive_label(trust: TrustState) -> TrustLabel:
    if trust.confidence < 0.4:
        return TrustLabel.UNKNOWN
    s = trust.score
    if s < 0.30:
        return TrustLabel.SUSPICIOUS
    if s < 0.55:
        return TrustLabel.DEGRADED
    if s < 0.85:
        return TrustLabel.OBSERVED
    return TrustLabel.TRUSTED


# =============================================================================
# SECTION 6 — BREAK DETECTORS
# =============================================================================


@dataclass(frozen=True)
class HardwareBreakFinding:
    kind: HardwareBreakKind
    platform_id: str
    subject_id: str
    detail: str
    severity: int
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")


def detect_trust_anchor_missing(
    platform: Platform, *, at: datetime,
) -> Optional[HardwareBreakFinding]:
    if platform.trust_anchor is None:
        return HardwareBreakFinding(
            kind=HardwareBreakKind.TRUST_ANCHOR_MISSING,
            platform_id=platform.platform_id,
            subject_id=platform.platform_id,
            detail=f"platform {platform.platform_id} has no trust anchor",
            severity=5,
            at=at,
        )
    if not platform.trust_anchor.verified \
       or not platform.trust_anchor.certificate_chain_valid:
        return HardwareBreakFinding(
            kind=HardwareBreakKind.TRUST_ANCHOR_MISSING,
            platform_id=platform.platform_id,
            subject_id=platform.trust_anchor.anchor_id,
            detail=(
                f"trust anchor {platform.trust_anchor.anchor_id} "
                f"unverified or cert chain invalid"
            ),
            severity=5,
            at=at,
        )
    return None


def detect_firmware_drift(
    component: FirmwareComponent,
    *,
    platform_id: str,
    at: datetime,
) -> Optional[HardwareBreakFinding]:
    if not component.drifted:
        return None
    return HardwareBreakFinding(
        kind=HardwareBreakKind.FIRMWARE_DRIFT,
        platform_id=platform_id,
        subject_id=component.component_id,
        detail=(
            f"firmware {component.component_id} drifted: version "
            f"{component.version} (expected {component.expected_version}), "
            f"digest {component.digest[:12]}… "
            f"(expected {(component.expected_digest or 'n/a')[:12]}…)"
        ),
        severity=4,
        at=at,
    )


def detect_firmware_signature_invalid(
    component: FirmwareComponent,
    *,
    platform_id: str,
    at: datetime,
) -> Optional[HardwareBreakFinding]:
    if component.signed and component.signature_verified:
        return None
    return HardwareBreakFinding(
        kind=HardwareBreakKind.FIRMWARE_SIGNATURE_INVALID,
        platform_id=platform_id,
        subject_id=component.component_id,
        detail=(
            f"firmware {component.component_id} signature invalid "
            f"(signed={component.signed}, verified={component.signature_verified})"
        ),
        severity=5,
        at=at,
    )


def detect_secure_boot_disabled(
    firmware: Iterable[FirmwareComponent],
    *,
    secure_boot_enabled: bool,
    platform_id: str,
    at: datetime,
) -> Optional[HardwareBreakFinding]:
    requires = [f for f in firmware if f.secure_boot_required]
    if requires and not secure_boot_enabled:
        return HardwareBreakFinding(
            kind=HardwareBreakKind.SECURE_BOOT_DISABLED,
            platform_id=platform_id,
            subject_id=platform_id,
            detail=(
                f"platform {platform_id} has {len(requires)} firmware "
                f"component(s) requiring secure boot, but secure boot is off"
            ),
            severity=4,
            at=at,
        )
    return None


def detect_boot_chain_break(
    measurements: Tuple[BootStageMeasurement, ...],
    *,
    platform_id: str,
    required_stages: FrozenSet[BootStage],
    at: datetime,
) -> Tuple[HardwareBreakFinding, ...]:
    out: List[HardwareBreakFinding] = []
    present = {m.stage for m in measurements}
    missing = required_stages - present
    for stage in sorted(missing, key=boot_order):
        out.append(HardwareBreakFinding(
            kind=HardwareBreakKind.BOOT_CHAIN_BREAK,
            platform_id=platform_id,
            subject_id=stage.value,
            detail=(
                f"required boot stage {stage.value} has no measurement"
            ),
            severity=4,
            at=at,
        ))
    return tuple(out)


def detect_boot_measurement_mismatch(
    measurements: Tuple[BootStageMeasurement, ...],
    *,
    platform_id: str,
    at: datetime,
) -> Tuple[HardwareBreakFinding, ...]:
    out: List[HardwareBreakFinding] = []
    for m in measurements:
        if not m.matches_expected:
            out.append(HardwareBreakFinding(
                kind=HardwareBreakKind.BOOT_MEASUREMENT_MISMATCH,
                platform_id=platform_id,
                subject_id=m.stage.value,
                detail=(
                    f"stage {m.stage.value} digest {m.digest[:12]}… "
                    f"!= expected {(m.expected_digest or '')[:12]}…"
                ),
                severity=5,
                at=at,
            ))
        if not m.signer_verified:
            out.append(HardwareBreakFinding(
                kind=HardwareBreakKind.BOOT_CHAIN_BREAK,
                platform_id=platform_id,
                subject_id=m.stage.value,
                detail=(
                    f"stage {m.stage.value} signer not verified"
                ),
                severity=4,
                at=at,
            ))
    return tuple(out)


def detect_attestation_invalid(
    attestations: Iterable[Attestation],
    *,
    platform_id: str,
    at: datetime,
) -> Tuple[HardwareBreakFinding, ...]:
    out: List[HardwareBreakFinding] = []
    for a in attestations:
        if a.platform_id != platform_id:
            continue
        if not a.signature_valid:
            out.append(HardwareBreakFinding(
                kind=HardwareBreakKind.ATTESTATION_INVALID,
                platform_id=platform_id,
                subject_id=a.attestation_id,
                detail=(
                    f"attestation {a.attestation_id} signature invalid"
                ),
                severity=5,
                at=at,
            ))
    return tuple(out)


def detect_attestation_stale(
    attestations: Iterable[Attestation],
    *,
    platform_id: str,
    max_age_seconds: int,
    at: datetime,
) -> Optional[HardwareBreakFinding]:
    applicable = [a for a in attestations if a.platform_id == platform_id]
    if not applicable:
        return None
    for a in applicable:
        if a.fresh and (at - a.signed_at).total_seconds() <= max_age_seconds:
            return None
    worst = max(applicable, key=lambda a: a.signed_at)
    return HardwareBreakFinding(
        kind=HardwareBreakKind.ATTESTATION_STALE,
        platform_id=platform_id,
        subject_id=worst.attestation_id,
        detail=(
            f"no fresh attestation for platform {platform_id} "
            f"(latest signed {worst.signed_at.isoformat()})"
        ),
        severity=3,
        at=at,
    )


def detect_tee_compromised(
    tee: TeeState, *, platform_id: str, at: datetime,
) -> Tuple[HardwareBreakFinding, ...]:
    out: List[HardwareBreakFinding] = []
    if tee.kind is TeeKind.NONE:
        return ()
    if not tee.enabled:
        out.append(HardwareBreakFinding(
            kind=HardwareBreakKind.TEE_COMPROMISED,
            platform_id=platform_id,
            subject_id=platform_id,
            detail=f"TEE {tee.kind.value} is disabled",
            severity=4,
            at=at,
        ))
    if not tee.attestation_valid:
        out.append(HardwareBreakFinding(
            kind=HardwareBreakKind.TEE_COMPROMISED,
            platform_id=platform_id,
            subject_id=platform_id,
            detail=f"TEE {tee.kind.value} attestation invalid",
            severity=5,
            at=at,
        ))
    if tee.debug_mode:
        out.append(HardwareBreakFinding(
            kind=HardwareBreakKind.TEE_COMPROMISED,
            platform_id=platform_id,
            subject_id=platform_id,
            detail=f"TEE {tee.kind.value} is in debug mode",
            severity=5,
            at=at,
        ))
    return tuple(out)


def detect_hardware_identity_mismatch(
    identities: Iterable[HardwareIdentity],
    *,
    platform_id: str,
    at: datetime,
) -> Tuple[HardwareBreakFinding, ...]:
    out: List[HardwareBreakFinding] = []
    for i in identities:
        if not i.matches_expected:
            out.append(HardwareBreakFinding(
                kind=HardwareBreakKind.HARDWARE_IDENTITY_MISMATCH,
                platform_id=platform_id,
                subject_id=i.device_id,
                detail=(
                    f"hardware {i.device_id} does not match expected"
                ),
                severity=5,
                at=at,
            ))
        if not i.cert_chain_valid:
            out.append(HardwareBreakFinding(
                kind=HardwareBreakKind.HARDWARE_IDENTITY_MISMATCH,
                platform_id=platform_id,
                subject_id=i.device_id,
                detail=(
                    f"hardware {i.device_id} certificate chain invalid"
                ),
                severity=4,
                at=at,
            ))
    return tuple(out)


# =============================================================================
# SECTION 7 — CONTINUITY ANALYSIS
# =============================================================================


@dataclass(frozen=True)
class PlatformContinuityResult:
    platform_id: str
    label: TrustLabel
    trust: TrustState
    continuity: float
    findings: Tuple[HardwareBreakFinding, ...]
    rationale: str
    at: datetime

    def __post_init__(self) -> None:
        if self.at.tzinfo is None:
            raise ValueError("at must be timezone-aware")
        if not 0.0 <= self.continuity <= 1.0:
            raise ValueError("continuity must be within [0,1]")


def effective_platform_continuity(
    *,
    anchor_trust: float,
    stage_scores: Iterable[float],
    intrinsic_risk: float,
    findings: Iterable[HardwareBreakFinding],
) -> float:
    base = max(0.0, min(1.0, anchor_trust))
    for s in stage_scores:
        if not 0.0 <= s <= 1.0:
            raise ValueError("stage score must be within [0,1]")
        base *= 0.5 + 0.5 * s
    base *= (1.0 - 0.5 * max(0.0, min(1.0, intrinsic_risk)))
    penalty = 0.0
    for f in findings:
        penalty += 0.05 * f.severity
    return max(0.0, min(1.0, base - penalty))


def _stage_scores(
    measurements: Tuple[BootStageMeasurement, ...],
) -> Tuple[float, ...]:
    scores: List[float] = []
    for m in measurements:
        s = 1.0
        if not m.matches_expected:
            s -= 0.7
        if not m.signer_verified:
            s -= 0.3
        scores.append(max(0.0, min(1.0, s)))
    return tuple(scores)


def analyse_platform_continuity(
    platform: Platform,
    *,
    signals: Iterable[TrustSignal],
    findings: Tuple[HardwareBreakFinding, ...],
    at: datetime,
) -> PlatformContinuityResult:
    observed = combine_trust(signals, at)

    if platform.trust_anchor is None:
        anchor_trust = 0.0
    elif not platform.trust_anchor.verified \
         or not platform.trust_anchor.certificate_chain_valid:
        anchor_trust = 0.2
    else:
        anchor_trust = 1.0

    scores = _stage_scores(platform.boot_measurements)
    intrinsic = platform.intrinsic_risk()

    continuity = effective_platform_continuity(
        anchor_trust=anchor_trust,
        stage_scores=scores,
        intrinsic_risk=intrinsic,
        findings=findings,
    )

    # Blend observed signals with structural continuity; give structure
    # the stronger vote (hardware trust is mostly structural).
    if observed.confidence > 0.0:
        blended = 0.3 * observed.score + 0.7 * continuity
    else:
        blended = continuity

    provisional = TrustState(
        score=blended, confidence=max(0.9, observed.confidence),
        basis=observed.basis, updated_at=at,
    )
    label = derive_label(provisional)

    for f in findings:
        if f.severity >= 5:
            label = worse_of(label, TrustLabel.COMPROMISED)
        elif f.severity >= 4:
            label = worse_of(label, TrustLabel.SUSPICIOUS)
        elif f.severity >= 3:
            label = worse_of(label, TrustLabel.DEGRADED)

    rationale = (
        f"platform {platform.platform_id} continuity {continuity:.2f}, "
        f"anchor_trust {anchor_trust:.2f}, intrinsic risk {intrinsic:.2f}, "
        f"{len(findings)} finding(s)"
    )

    return PlatformContinuityResult(
        platform_id=platform.platform_id,
        label=label,
        trust=TrustState(
            score=blended, confidence=max(0.9, observed.confidence),
            basis=observed.basis, updated_at=at,
        ),
        continuity=continuity,
        findings=findings,
        rationale=rationale,
        at=at,
    )


# =============================================================================
# SECTION 8 — TRANSITIONS
# =============================================================================


class TransitionOutcome(str, Enum):
    ALLOWED = "allowed"
    REJECTED_INVALID = "rejected_invalid"
    REQUIRES_VERIFICATION = "requires_verification"


_ALLOWED_LABEL_EDGES: Mapping[TrustLabel, FrozenSet[TrustLabel]] = {
    TrustLabel.UNKNOWN: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.TRUSTED, TrustLabel.COMPROMISED,
        TrustLabel.QUARANTINED,
    }),
    TrustLabel.OBSERVED: frozenset({
        TrustLabel.TRUSTED, TrustLabel.DEGRADED,
        TrustLabel.SUSPICIOUS, TrustLabel.COMPROMISED,
    }),
    TrustLabel.TRUSTED: frozenset({
        TrustLabel.DEGRADED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.DEGRADED: frozenset({
        TrustLabel.OBSERVED, TrustLabel.SUSPICIOUS,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.SUSPICIOUS: frozenset({
        TrustLabel.OBSERVED, TrustLabel.DEGRADED,
        TrustLabel.COMPROMISED, TrustLabel.QUARANTINED,
    }),
    TrustLabel.COMPROMISED: frozenset({TrustLabel.QUARANTINED}),
    TrustLabel.QUARANTINED: frozenset({TrustLabel.OBSERVED}),
}


@dataclass(frozen=True)
class TransitionRequest:
    entity_id: str
    from_label: TrustLabel
    to_label: TrustLabel
    reason: str
    verified: bool


@dataclass(frozen=True)
class TransitionDecision:
    outcome: TransitionOutcome
    rationale: str


def evaluate_transition(req: TransitionRequest) -> TransitionDecision:
    if not req.reason:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID, "reason is required"
        )
    if req.from_label is req.to_label:
        return TransitionDecision(TransitionOutcome.ALLOWED, "no-op")
    permitted = _ALLOWED_LABEL_EDGES.get(req.from_label, frozenset())
    if req.to_label not in permitted:
        return TransitionDecision(
            TransitionOutcome.REJECTED_INVALID,
            f"{req.from_label.value} -> {req.to_label.value} not permitted",
        )
    going_better = label_severity(req.to_label) < label_severity(req.from_label)
    reaching_trust_from_unknown = (
        req.from_label is TrustLabel.UNKNOWN
        and req.to_label is TrustLabel.TRUSTED
    )
    if (going_better or reaching_trust_from_unknown) and not req.verified:
        return TransitionDecision(
            TransitionOutcome.REQUIRES_VERIFICATION,
            "recovery transitions require verification",
        )
    return TransitionDecision(TransitionOutcome.ALLOWED, "permitted")


# =============================================================================
# SECTION 9 — INVARIANTS
# =============================================================================


class InvariantSeverity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(frozen=True)
class PlatformSnapshot:
    platform: Platform
    label: TrustLabel
    continuity: float
    findings: Tuple[HardwareBreakFinding, ...]


@dataclass(frozen=True)
class HardwareSnapshot:
    platforms: Mapping[str, PlatformSnapshot]
    attestations: Mapping[str, Tuple[Attestation, ...]]
    secure_boot_enabled: Mapping[str, bool]


@dataclass(frozen=True)
class InvariantViolation:
    invariant_id: str
    severity: InvariantSeverity
    subject_id: str
    detail: str


@dataclass(frozen=True)
class HardwareInvariant:
    invariant_id: str
    severity: InvariantSeverity
    predicate: Callable[[HardwareSnapshot], Tuple[InvariantViolation, ...]]
    description: str


def _inv_trusted_requires_anchor(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        if s.platform.trust_anchor is None:
            out.append(InvariantViolation(
                invariant_id="hw.trusted_requires_anchor",
                severity=InvariantSeverity.CRITICAL,
                subject_id=pid,
                detail=f"platform {pid} is TRUSTED without a trust anchor",
            ))
    return tuple(out)


def _inv_trusted_requires_signed_firmware(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        for f in s.platform.firmware:
            if not f.signed or not f.signature_verified:
                out.append(InvariantViolation(
                    invariant_id="hw.trusted_requires_signed_firmware",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=pid,
                    detail=(
                        f"platform {pid} TRUSTED but firmware "
                        f"{f.component_id} is unsigned or unverified"
                    ),
                ))
                break
    return tuple(out)


def _inv_trusted_requires_boot_chain_intact(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        for m in s.platform.boot_measurements:
            if not m.matches_expected or not m.signer_verified:
                out.append(InvariantViolation(
                    invariant_id="hw.trusted_requires_boot_chain_intact",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=pid,
                    detail=(
                        f"platform {pid} TRUSTED but boot stage "
                        f"{m.stage.value} measurement/signature invalid"
                    ),
                ))
                break
    return tuple(out)


def _inv_trusted_requires_fresh_attestation(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        atts = snap.attestations.get(pid, ())
        if not atts or not any(a.signature_valid and a.fresh for a in atts):
            out.append(InvariantViolation(
                invariant_id="hw.trusted_requires_fresh_attestation",
                severity=InvariantSeverity.HIGH,
                subject_id=pid,
                detail=(
                    f"platform {pid} TRUSTED without fresh valid attestation"
                ),
            ))
    return tuple(out)


def _inv_trusted_requires_tee_valid(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        tee = s.platform.tee
        if tee.kind is TeeKind.NONE:
            continue
        if not tee.enabled or not tee.attestation_valid or tee.debug_mode:
            out.append(InvariantViolation(
                invariant_id="hw.trusted_requires_tee_valid",
                severity=InvariantSeverity.CRITICAL,
                subject_id=pid,
                detail=(
                    f"platform {pid} TRUSTED but TEE {tee.kind.value} is "
                    f"in a bad state (enabled={tee.enabled}, "
                    f"attestation_valid={tee.attestation_valid}, "
                    f"debug={tee.debug_mode})"
                ),
            ))
    return tuple(out)


def _inv_high_criticality_requires_secure_boot(
    snap: HardwareSnapshot,
    *,
    threshold: float = 0.7,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.platform.criticality < threshold:
            continue
        if not snap.secure_boot_enabled.get(pid, False):
            out.append(InvariantViolation(
                invariant_id="hw.high_criticality_requires_secure_boot",
                severity=InvariantSeverity.HIGH,
                subject_id=pid,
                detail=(
                    f"high-criticality platform {pid} "
                    f"(crit={s.platform.criticality:.2f}) has secure boot off"
                ),
            ))
    return tuple(out)


def _inv_no_trusted_with_identity_mismatch(
    snap: HardwareSnapshot,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for pid, s in snap.platforms.items():
        if s.label is not TrustLabel.TRUSTED:
            continue
        for i in s.platform.hardware_identities:
            if not i.matches_expected or not i.cert_chain_valid:
                out.append(InvariantViolation(
                    invariant_id="hw.no_trusted_with_identity_mismatch",
                    severity=InvariantSeverity.CRITICAL,
                    subject_id=pid,
                    detail=(
                        f"platform {pid} TRUSTED but hardware "
                        f"{i.device_id} identity mismatch/cert invalid"
                    ),
                ))
                break
    return tuple(out)


DEFAULT_INVARIANTS: Tuple[HardwareInvariant, ...] = (
    HardwareInvariant(
        invariant_id="hw.trusted_requires_anchor",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_requires_anchor,
        description="TRUSTED platform must have a trust anchor.",
    ),
    HardwareInvariant(
        invariant_id="hw.trusted_requires_signed_firmware",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_requires_signed_firmware,
        description="TRUSTED platform must have signed verified firmware.",
    ),
    HardwareInvariant(
        invariant_id="hw.trusted_requires_boot_chain_intact",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_requires_boot_chain_intact,
        description="TRUSTED platform must have intact boot measurements.",
    ),
    HardwareInvariant(
        invariant_id="hw.trusted_requires_fresh_attestation",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_trusted_requires_fresh_attestation,
        description="TRUSTED platform must have a fresh valid attestation.",
    ),
    HardwareInvariant(
        invariant_id="hw.trusted_requires_tee_valid",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_trusted_requires_tee_valid,
        description="TRUSTED platform must have TEE in a valid state.",
    ),
    HardwareInvariant(
        invariant_id="hw.high_criticality_requires_secure_boot",
        severity=InvariantSeverity.HIGH,
        predicate=_inv_high_criticality_requires_secure_boot,
        description="High-criticality platforms must have secure boot enabled.",
    ),
    HardwareInvariant(
        invariant_id="hw.no_trusted_with_identity_mismatch",
        severity=InvariantSeverity.CRITICAL,
        predicate=_inv_no_trusted_with_identity_mismatch,
        description="TRUSTED platform must have valid hardware identity.",
    ),
)


def check_invariants(
    snap: HardwareSnapshot,
    invariants: Iterable[HardwareInvariant] = DEFAULT_INVARIANTS,
) -> Tuple[InvariantViolation, ...]:
    out: List[InvariantViolation] = []
    for inv in invariants:
        out.extend(inv.predicate(snap))
    return tuple(out)


# =============================================================================
# SECTION 10 — STORES
# =============================================================================


@dataclass(frozen=True)
class PlatformStateRecord:
    platform_id: str
    label: TrustLabel
    continuity: float
    findings_count: int
    updated_at: datetime


class HardwareStateStore(Protocol):
    def get(self, platform_id: str) -> Optional[PlatformStateRecord]: ...
    def put(self, record: PlatformStateRecord) -> None: ...
    def all(self) -> Tuple[PlatformStateRecord, ...]: ...
    def put_attestation(self, att: Attestation) -> None: ...
    def all_attestations(self) -> Tuple[Attestation, ...]: ...


class InMemoryHardwareStore:
    def __init__(self) -> None:
        self._state: Dict[str, PlatformStateRecord] = {}
        self._atts: Dict[str, Attestation] = {}

    def get(self, platform_id: str) -> Optional[PlatformStateRecord]:
        return self._state.get(platform_id)

    def put(self, record: PlatformStateRecord) -> None:
        existing = self._state.get(record.platform_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._state[record.platform_id] = record

    def all(self) -> Tuple[PlatformStateRecord, ...]:
        return tuple(self._state.values())

    def put_attestation(self, att: Attestation) -> None:
        existing = self._atts.get(att.attestation_id)
        if existing is not None and existing.signed_at > att.signed_at:
            raise ValueError(
                "refusing to overwrite newer attestation with older one"
            )
        self._atts[att.attestation_id] = att

    def all_attestations(self) -> Tuple[Attestation, ...]:
        return tuple(self._atts.values())


class SqliteHardwareStore:
    def __init__(self, path: str) -> None:
        self._conn = sqlite3.connect(path)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hw_platform_state (
                platform_id TEXT PRIMARY KEY,
                label TEXT NOT NULL,
                continuity REAL NOT NULL,
                findings_count INTEGER NOT NULL,
                updated_at TEXT NOT NULL
            )
            """
        )
        self._conn.execute(
            """
            CREATE TABLE IF NOT EXISTS hw_attestations (
                attestation_id TEXT PRIMARY KEY,
                platform_id TEXT NOT NULL,
                payload_json TEXT NOT NULL
            )
            """
        )
        self._conn.commit()

    def get(self, platform_id: str) -> Optional[PlatformStateRecord]:
        row = self._conn.execute(
            "SELECT label, continuity, findings_count, updated_at "
            "FROM hw_platform_state WHERE platform_id = ?",
            (platform_id,),
        ).fetchone()
        if row is None:
            return None
        return PlatformStateRecord(
            platform_id=platform_id,
            label=TrustLabel(row[0]),
            continuity=float(row[1]),
            findings_count=int(row[2]),
            updated_at=datetime.fromisoformat(row[3]),
        )

    def put(self, record: PlatformStateRecord) -> None:
        existing = self.get(record.platform_id)
        if existing is not None and existing.updated_at > record.updated_at:
            raise ValueError("refusing to overwrite newer state with older record")
        self._conn.execute(
            """
            INSERT INTO hw_platform_state
              (platform_id, label, continuity, findings_count, updated_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(platform_id) DO UPDATE SET
              label=excluded.label,
              continuity=excluded.continuity,
              findings_count=excluded.findings_count,
              updated_at=excluded.updated_at
            """,
            (record.platform_id, record.label.value, record.continuity,
             record.findings_count, record.updated_at.isoformat()),
        )
        self._conn.commit()

    def all(self) -> Tuple[PlatformStateRecord, ...]:
        rows = self._conn.execute(
            "SELECT platform_id FROM hw_platform_state"
        ).fetchall()
        return tuple(
            r for r in (self.get(x[0]) for x in rows) if r is not None
        )

    def put_attestation(self, att: Attestation) -> None:
        payload = {
            "attestation_id": att.attestation_id,
            "platform_id": att.platform_id,
            "nonce": att.nonce,
            "pcr_digest": att.pcr_digest,
            "signature_valid": att.signature_valid,
            "fresh": att.fresh,
            "signed_at": att.signed_at.isoformat(),
            "verifier_id": att.verifier_id,
            "evidence_id": att.evidence.evidence_id,
            "evidence_source": att.evidence.source,
            "evidence_confidence": att.evidence.confidence,
            "evidence_observed_at": att.evidence.observed_at.isoformat(),
        }
        self._conn.execute(
            "INSERT OR REPLACE INTO hw_attestations "
            "(attestation_id, platform_id, payload_json) VALUES (?, ?, ?)",
            (att.attestation_id, att.platform_id,
             json.dumps(payload, sort_keys=True)),
        )
        self._conn.commit()

    def get_attestation(self, attestation_id: str) -> Optional[Attestation]:
        row = self._conn.execute(
            "SELECT payload_json FROM hw_attestations "
            "WHERE attestation_id = ?",
            (attestation_id,),
        ).fetchone()
        if row is None:
            return None
        p = json.loads(row[0])
        return Attestation(
            attestation_id=p["attestation_id"],
            platform_id=p["platform_id"],
            nonce=p["nonce"],
            pcr_digest=p["pcr_digest"],
            signature_valid=p["signature_valid"],
            fresh=p["fresh"],
            signed_at=datetime.fromisoformat(p["signed_at"]),
            verifier_id=p["verifier_id"],
            evidence=Evidence(
                evidence_id=p["evidence_id"],
                source=p["evidence_source"],
                confidence=float(p["evidence_confidence"]),
                observed_at=datetime.fromisoformat(p["evidence_observed_at"]),
                payload={},
            ),
        )

    def all_attestations(self) -> Tuple[Attestation, ...]:
        rows = self._conn.execute(
            "SELECT attestation_id FROM hw_attestations"
        ).fetchall()
        out: List[Attestation] = []
        for r in rows:
            a = self.get_attestation(r[0])
            if a is not None:
                out.append(a)
        return tuple(out)


# =============================================================================
# SECTION 11 — ENGINE
# =============================================================================


class HardwareBootTrustEngine:
    """Continuous hardware / firmware / boot trust-state engine."""

    def __init__(
        self, *, store: Optional[HardwareStateStore] = None,
    ) -> None:
        self._store: HardwareStateStore = store or InMemoryHardwareStore()
        self._platforms: Dict[str, Platform] = {}
        self._signals: Dict[str, List[TrustSignal]] = {}
        self._attestations: Dict[str, List[Attestation]] = {}
        self._secure_boot_enabled: Dict[str, bool] = {}
        self._required_stages: Dict[str, FrozenSet[BootStage]] = {}
        self._labels: Dict[str, TrustLabel] = {}
        self._continuity: Dict[str, PlatformContinuityResult] = {}
        self._findings: Dict[str, List[HardwareBreakFinding]] = {}
        self._violations: Tuple[InvariantViolation, ...] = ()

        # Policy: defaults for all platforms
        self._default_required_stages: FrozenSet[BootStage] = frozenset({
            BootStage.UEFI_FIRMWARE,
            BootStage.BOOTLOADER,
            BootStage.KERNEL,
        })
        self._attestation_max_age_seconds: int = 3600
        self._high_criticality_threshold: float = 0.7

    # ---- registration ----------------------------------------------------

    def register_platform(
        self, platform: Platform, *,
        secure_boot_enabled: bool = False,
        required_stages: Optional[FrozenSet[BootStage]] = None,
    ) -> None:
        if platform.platform_id in self._platforms:
            raise ValueError(
                f"platform {platform.platform_id} already registered"
            )
        self._platforms[platform.platform_id] = platform
        self._secure_boot_enabled[platform.platform_id] = secure_boot_enabled
        self._required_stages[platform.platform_id] = (
            required_stages if required_stages is not None
            else self._default_required_stages
        )
        self._findings[platform.platform_id] = []

    def add_attestation(self, attestation: Attestation) -> None:
        if attestation.platform_id not in self._platforms:
            raise KeyError(
                f"attestation platform {attestation.platform_id} not "
                f"registered"
            )
        self._attestations.setdefault(
            attestation.platform_id, []
        ).append(attestation)
        if isinstance(self._store, SqliteHardwareStore):
            self._store.put_attestation(attestation)

    def observe_signal(self, platform_id: str, signal: TrustSignal) -> None:
        if platform_id not in self._platforms:
            raise KeyError(f"unknown platform {platform_id}")
        if signal.at.tzinfo is None:
            raise ValueError("signal.at must be timezone-aware")
        self._signals.setdefault(platform_id, []).append(signal)

    def set_secure_boot(self, platform_id: str, enabled: bool) -> None:
        if platform_id not in self._platforms:
            raise KeyError(f"unknown platform {platform_id}")
        self._secure_boot_enabled[platform_id] = enabled

    def set_required_stages(
        self, platform_id: str, stages: FrozenSet[BootStage],
    ) -> None:
        if platform_id not in self._platforms:
            raise KeyError(f"unknown platform {platform_id}")
        self._required_stages[platform_id] = stages

    def set_attestation_max_age(self, seconds: int) -> None:
        if seconds <= 0:
            raise ValueError("attestation max age must be positive")
        self._attestation_max_age_seconds = seconds

    def set_high_criticality_threshold(self, threshold: float) -> None:
        if not 0.0 <= threshold <= 1.0:
            raise ValueError("threshold must be within [0,1]")
        self._high_criticality_threshold = threshold

    # ---- recompute -------------------------------------------------------

    def recompute(self, *, at: datetime) -> Tuple[PlatformStateRecord, ...]:
        if at.tzinfo is None:
            raise ValueError("at must be timezone-aware")

        records: List[PlatformStateRecord] = []

        for pid, platform in self._platforms.items():
            findings: List[HardwareBreakFinding] = []

            fa = detect_trust_anchor_missing(platform, at=at)
            if fa is not None:
                findings.append(fa)

            for f in platform.firmware:
                fd = detect_firmware_drift(f, platform_id=pid, at=at)
                if fd is not None:
                    findings.append(fd)
                fs = detect_firmware_signature_invalid(
                    f, platform_id=pid, at=at,
                )
                if fs is not None:
                    findings.append(fs)

            sb = detect_secure_boot_disabled(
                platform.firmware,
                secure_boot_enabled=self._secure_boot_enabled.get(pid, False),
                platform_id=pid, at=at,
            )
            if sb is not None:
                findings.append(sb)

            findings.extend(detect_boot_chain_break(
                platform.boot_measurements, platform_id=pid,
                required_stages=self._required_stages[pid], at=at,
            ))
            findings.extend(detect_boot_measurement_mismatch(
                platform.boot_measurements, platform_id=pid, at=at,
            ))

            atts = tuple(self._attestations.get(pid, ()))
            findings.extend(detect_attestation_invalid(
                atts, platform_id=pid, at=at,
            ))
            astale = detect_attestation_stale(
                atts, platform_id=pid,
                max_age_seconds=self._attestation_max_age_seconds, at=at,
            )
            if astale is not None:
                findings.append(astale)

            findings.extend(detect_tee_compromised(
                platform.tee, platform_id=pid, at=at,
            ))
            findings.extend(detect_hardware_identity_mismatch(
                platform.hardware_identities, platform_id=pid, at=at,
            ))

            self._findings[pid] = findings

            result = analyse_platform_continuity(
                platform,
                signals=self._signals.get(pid, []),
                findings=tuple(findings),
                at=at,
            )
            self._continuity[pid] = result

            previous = self._labels.get(pid, TrustLabel.UNKNOWN)
            if previous is not result.label:
                verified = (
                    result.continuity >= 0.6
                    and not is_untrusted(result.label)
                )
                decision = evaluate_transition(TransitionRequest(
                    entity_id=pid, from_label=previous,
                    to_label=result.label, reason="recompute",
                    verified=verified,
                ))
                if decision.outcome in (
                    TransitionOutcome.REJECTED_INVALID,
                    TransitionOutcome.REQUIRES_VERIFICATION,
                ):
                    result = PlatformContinuityResult(
                        platform_id=result.platform_id,
                        label=previous,
                        trust=result.trust,
                        continuity=result.continuity,
                        findings=result.findings,
                        rationale=result.rationale + " | transition held",
                        at=result.at,
                    )

            self._labels[pid] = result.label

            rec = PlatformStateRecord(
                platform_id=pid, label=result.label,
                continuity=result.continuity,
                findings_count=len(result.findings),
                updated_at=at,
            )
            self._store.put(rec)
            records.append(rec)

        self._violations = check_invariants(self.snapshot())
        return tuple(records)

    # ---- queries ---------------------------------------------------------

    def label(self, platform_id: str) -> Optional[TrustLabel]:
        return self._labels.get(platform_id)

    def continuity(self, platform_id: str) -> Optional[PlatformContinuityResult]:
        return self._continuity.get(platform_id)

    def state(self, platform_id: str) -> Optional[PlatformStateRecord]:
        return self._store.get(platform_id)

    def findings(self, platform_id: str) -> Tuple[HardwareBreakFinding, ...]:
        return tuple(self._findings.get(platform_id, ()))

    def violations(self) -> Tuple[InvariantViolation, ...]:
        return self._violations

    def snapshot(self) -> HardwareSnapshot:
        platforms: Dict[str, PlatformSnapshot] = {}
        for pid, p in self._platforms.items():
            rec = self._store.get(pid)
            if rec is None:
                continue
            platforms[pid] = PlatformSnapshot(
                platform=p, label=rec.label, continuity=rec.continuity,
                findings=tuple(self._findings.get(pid, ())),
            )
        attestations_map = {
            pid: tuple(lst) for pid, lst in self._attestations.items()
        }
        return HardwareSnapshot(
            platforms=platforms,
            attestations=attestations_map,
            secure_boot_enabled=dict(self._secure_boot_enabled),
        )


# =============================================================================
# SECTION 12 — TESTS
# =============================================================================


def _t0() -> datetime:
    from datetime import timezone
    return datetime(2026, 1, 1, tzinfo=timezone.utc)


def _ev(at: datetime, conf: float = 0.9) -> Evidence:
    return Evidence(evidence_id="e", source="test", confidence=conf,
                    observed_at=at, payload={})


def _pos(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    t = at or _t0()
    return TrustSignal(sid, 1.0, 1.0, t, _ev(t))


def _neg(sid: str = "s", at: Optional[datetime] = None) -> TrustSignal:
    t = at or _t0()
    return TrustSignal(sid, 1.0, -1.0, t, _ev(t))


def _anchor(aid: str = "anchor") -> TrustAnchor:
    return TrustAnchor(
        anchor_id=aid, kind=HardwareKind.TPM, digest="d-anchor",
        verified=True, certificate_chain_valid=True,
    )


def _fw(
    cid: str, *, kind: FirmwareKind = FirmwareKind.UEFI,
    version: str = "1.0", digest: str = "d",
    exp_version: Optional[str] = None,
    exp_digest: Optional[str] = None,
    signed: bool = True, sig_ok: bool = True,
    requires_secure_boot: bool = False,
) -> FirmwareComponent:
    return FirmwareComponent(
        component_id=cid, kind=kind, version=version, digest=digest,
        expected_version=exp_version, expected_digest=exp_digest,
        signed=signed, signature_verified=sig_ok,
        secure_boot_required=requires_secure_boot,
    )


def _measurement(
    stage: BootStage, *, digest: str = "d",
    expected: Optional[str] = None,
    at: Optional[datetime] = None,
    signer_verified: bool = True,
) -> BootStageMeasurement:
    return BootStageMeasurement(
        stage=stage, digest=digest, expected_digest=expected,
        measured_at=at or _t0(), signer_verified=signer_verified,
    )


def _att(
    aid: str, pid: str, *, sig_valid: bool = True, fresh: bool = True,
    at: Optional[datetime] = None,
) -> Attestation:
    t = at or _t0()
    return Attestation(
        attestation_id=aid, platform_id=pid, nonce="n1",
        pcr_digest="pcr", signature_valid=sig_valid, fresh=fresh,
        signed_at=t, verifier_id="verifier", evidence=_ev(t),
    )


def _tee(kind: TeeKind = TeeKind.INTEL_SGX,
         enabled: bool = True, att_valid: bool = True,
         debug: bool = False) -> TeeState:
    return TeeState(
        kind=kind, enabled=enabled, attestation_valid=att_valid,
        sealed_data_available=True, debug_mode=debug,
    )


def _hwid(
    did: str = "hw", *, kind: HardwareKind = HardwareKind.CPU,
    matches: bool = True, cert_ok: bool = True,
) -> HardwareIdentity:
    return HardwareIdentity(
        device_id=did, hardware_kind=kind,
        endorsement_key_id=f"ek-{did}", cert_chain_valid=cert_ok,
        matches_expected=matches, observed_at=_t0(),
    )


def _platform(
    pid: str = "p1", *, criticality: float = 0.5,
    anchor: Optional[TrustAnchor] = None,
    firmware: Iterable[FirmwareComponent] = (),
    measurements: Iterable[BootStageMeasurement] = (),
    tee: Optional[TeeState] = None,
    hwids: Iterable[HardwareIdentity] = (),
) -> Platform:
    return Platform(
        platform_id=pid, tenant_id="t1", criticality=criticality,
        trust_anchor=anchor if anchor is not None else _anchor(),
        firmware=frozenset(firmware),
        boot_measurements=tuple(measurements),
        tee=tee if tee is not None else TeeState(kind=TeeKind.NONE),
        hardware_identities=tuple(hwids),
    )


def _secure_platform() -> Platform:
    return _platform(
        "p1", criticality=0.8,
        anchor=_anchor(),
        firmware=(
            _fw("uefi", version="1.0", digest="d-u",
                exp_version="1.0", exp_digest="d-u"),
            _fw("bootloader", kind=FirmwareKind.UEFI, version="2.0",
                digest="d-b", exp_version="2.0", exp_digest="d-b"),
        ),
        measurements=(
            _measurement(BootStage.UEFI_FIRMWARE, digest="m1",
                         expected="m1"),
            _measurement(BootStage.BOOTLOADER, digest="m2", expected="m2"),
            _measurement(BootStage.KERNEL, digest="m3", expected="m3"),
        ),
        tee=_tee(TeeKind.INTEL_SGX),
        hwids=(_hwid("cpu"),),
    )


# ---- domain tests ---------------------------------------------------------

def test_boot_order_monotonic() -> None:
    assert boot_order(BootStage.UEFI_FIRMWARE) < boot_order(BootStage.KERNEL)
    assert boot_order(BootStage.KERNEL) < boot_order(BootStage.RUNTIME)


def test_platform_requires_id() -> None:
    try:
        Platform(
            platform_id="", tenant_id="t", criticality=0.5,
            trust_anchor=None, firmware=frozenset(),
            boot_measurements=(), tee=TeeState(kind=TeeKind.NONE),
            hardware_identities=(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_platform_rejects_out_of_order_measurements() -> None:
    try:
        Platform(
            platform_id="p", tenant_id="t", criticality=0.5,
            trust_anchor=None, firmware=frozenset(),
            boot_measurements=(
                _measurement(BootStage.KERNEL),
                _measurement(BootStage.UEFI_FIRMWARE),
            ),
            tee=TeeState(kind=TeeKind.NONE), hardware_identities=(),
        )
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_firmware_component_drift_detected() -> None:
    f = _fw("uefi", version="2.0", digest="dA", exp_version="1.0",
            exp_digest="dB")
    assert f.drifted


def test_firmware_component_no_drift() -> None:
    f = _fw("uefi", version="1.0", digest="d", exp_version="1.0",
            exp_digest="d")
    assert not f.drifted


def test_firmware_unsigned_dangerous() -> None:
    f = _fw("uefi", signed=False)
    assert f.dangerous_score() >= 0.3


def test_measurement_matches_expected() -> None:
    m = _measurement(BootStage.KERNEL, digest="a", expected="a")
    assert m.matches_expected


def test_measurement_mismatch() -> None:
    m = _measurement(BootStage.KERNEL, digest="a", expected="b")
    assert not m.matches_expected


# ---- trust tests ----------------------------------------------------------

def test_combine_trust_empty_neutral() -> None:
    st = combine_trust([], _t0())
    assert st.score == NEUTRAL_SCORE and st.confidence == 0.0


def test_combine_trust_positive() -> None:
    assert combine_trust([_pos()], _t0()).score == 1.0


def test_combine_trust_negative() -> None:
    assert combine_trust([_neg()], _t0()).score == 0.0


def test_derive_label_unknown() -> None:
    st = TrustState(0.9, 0.1, (), _t0())
    assert derive_label(st) is TrustLabel.UNKNOWN


# ---- break detectors ------------------------------------------------------

def test_detect_trust_anchor_missing() -> None:
    p = _platform(anchor=None)
    # Note: _platform substitutes _anchor() when anchor=None, so test
    # the detector directly against a Platform with anchor=None.
    p = Platform(
        platform_id="p", tenant_id="t", criticality=0.5,
        trust_anchor=None, firmware=frozenset(),
        boot_measurements=(), tee=TeeState(kind=TeeKind.NONE),
        hardware_identities=(),
    )
    f = detect_trust_anchor_missing(p, at=_t0())
    assert f is not None and f.kind is HardwareBreakKind.TRUST_ANCHOR_MISSING


def test_detect_trust_anchor_unverified() -> None:
    a = TrustAnchor(anchor_id="a", kind=HardwareKind.TPM, digest="d",
                    verified=False)
    p = Platform(
        platform_id="p", tenant_id="t", criticality=0.5,
        trust_anchor=a, firmware=frozenset(),
        boot_measurements=(), tee=TeeState(kind=TeeKind.NONE),
        hardware_identities=(),
    )
    f = detect_trust_anchor_missing(p, at=_t0())
    assert f is not None and f.kind is HardwareBreakKind.TRUST_ANCHOR_MISSING


def test_detect_firmware_drift() -> None:
    f = _fw("uefi", version="2.0", digest="dA", exp_version="1.0",
            exp_digest="dB")
    finding = detect_firmware_drift(f, platform_id="p", at=_t0())
    assert finding is not None and finding.kind is HardwareBreakKind.FIRMWARE_DRIFT


def test_detect_firmware_signature_invalid() -> None:
    f = _fw("uefi", signed=False)
    finding = detect_firmware_signature_invalid(f, platform_id="p", at=_t0())
    assert finding is not None
    assert finding.kind is HardwareBreakKind.FIRMWARE_SIGNATURE_INVALID


def test_detect_secure_boot_disabled() -> None:
    f = _fw("uefi", requires_secure_boot=True)
    finding = detect_secure_boot_disabled(
        (f,), secure_boot_enabled=False, platform_id="p", at=_t0(),
    )
    assert finding is not None
    assert finding.kind is HardwareBreakKind.SECURE_BOOT_DISABLED


def test_detect_secure_boot_not_required() -> None:
    f = _fw("uefi", requires_secure_boot=False)
    finding = detect_secure_boot_disabled(
        (f,), secure_boot_enabled=False, platform_id="p", at=_t0(),
    )
    assert finding is None


def test_detect_boot_chain_break() -> None:
    measurements = (
        _measurement(BootStage.UEFI_FIRMWARE),
        _measurement(BootStage.KERNEL),
    )
    findings = detect_boot_chain_break(
        measurements, platform_id="p",
        required_stages=frozenset({
            BootStage.UEFI_FIRMWARE, BootStage.BOOTLOADER,
            BootStage.KERNEL,
        }),
        at=_t0(),
    )
    assert len(findings) == 1
    assert findings[0].kind is HardwareBreakKind.BOOT_CHAIN_BREAK
    assert "bootloader" in findings[0].detail


def test_detect_boot_measurement_mismatch() -> None:
    measurements = (
        _measurement(BootStage.KERNEL, digest="a", expected="b"),
    )
    findings = detect_boot_measurement_mismatch(
        measurements, platform_id="p", at=_t0(),
    )
    assert len(findings) == 1
    assert findings[0].kind is HardwareBreakKind.BOOT_MEASUREMENT_MISMATCH
    assert findings[0].severity == 5


def test_detect_boot_measurement_signer_unverified() -> None:
    measurements = (
        _measurement(BootStage.KERNEL, digest="a", expected="a",
                     signer_verified=False),
    )
    findings = detect_boot_measurement_mismatch(
        measurements, platform_id="p", at=_t0(),
    )
    assert any(f.kind is HardwareBreakKind.BOOT_CHAIN_BREAK
               for f in findings)


def test_detect_attestation_invalid() -> None:
    atts = [_att("a1", "p", sig_valid=False)]
    findings = detect_attestation_invalid(atts, platform_id="p", at=_t0())
    assert findings and findings[0].kind is HardwareBreakKind.ATTESTATION_INVALID


def test_detect_attestation_stale() -> None:
    old = _t0() - timedelta(hours=5)
    atts = [_att("a1", "p", fresh=False, at=old)]
    f = detect_attestation_stale(
        atts, platform_id="p", max_age_seconds=3600, at=_t0(),
    )
    assert f is not None and f.kind is HardwareBreakKind.ATTESTATION_STALE


def test_detect_attestation_fresh_returns_none() -> None:
    atts = [_att("a1", "p", fresh=True)]
    f = detect_attestation_stale(
        atts, platform_id="p", max_age_seconds=3600, at=_t0(),
    )
    assert f is None


def test_detect_tee_compromised_disabled() -> None:
    tee = _tee(TeeKind.INTEL_SGX, enabled=False)
    findings = detect_tee_compromised(tee, platform_id="p", at=_t0())
    assert any(f.kind is HardwareBreakKind.TEE_COMPROMISED for f in findings)


def test_detect_tee_compromised_debug_mode() -> None:
    tee = _tee(TeeKind.INTEL_SGX, debug=True)
    findings = detect_tee_compromised(tee, platform_id="p", at=_t0())
    assert any(f.severity == 5 for f in findings)


def test_detect_tee_none_returns_empty() -> None:
    tee = TeeState(kind=TeeKind.NONE)
    assert detect_tee_compromised(tee, platform_id="p", at=_t0()) == ()


def test_detect_hardware_identity_mismatch() -> None:
    ids = [_hwid("cpu", matches=False)]
    findings = detect_hardware_identity_mismatch(
        ids, platform_id="p", at=_t0(),
    )
    assert any(f.kind is HardwareBreakKind.HARDWARE_IDENTITY_MISMATCH
               for f in findings)


def test_detect_hardware_identity_cert_invalid() -> None:
    ids = [_hwid("cpu", cert_ok=False)]
    findings = detect_hardware_identity_mismatch(
        ids, platform_id="p", at=_t0(),
    )
    assert len(findings) == 1 and findings[0].severity == 4


# ---- continuity -----------------------------------------------------------

def test_effective_continuity_no_penalty() -> None:
    c = effective_platform_continuity(
        anchor_trust=1.0, stage_scores=[1.0, 1.0],
        intrinsic_risk=0.0, findings=[],
    )
    assert abs(c - 1.0) < 1e-9


def test_effective_continuity_low_stage_score_halves() -> None:
    c = effective_platform_continuity(
        anchor_trust=1.0, stage_scores=[0.0], intrinsic_risk=0.0,
        findings=[],
    )
    assert abs(c - 0.5) < 1e-9


def test_effective_continuity_intrinsic_risk_reduces() -> None:
    c = effective_platform_continuity(
        anchor_trust=1.0, stage_scores=[], intrinsic_risk=1.0, findings=[],
    )
    assert c <= 0.5 + 1e-9


def test_effective_continuity_findings_penalize() -> None:
    f = HardwareBreakFinding(
        kind=HardwareBreakKind.FIRMWARE_DRIFT,
        platform_id="p", subject_id="x", detail="d", severity=4, at=_t0(),
    )
    c = effective_platform_continuity(
        anchor_trust=1.0, stage_scores=[], intrinsic_risk=0.0,
        findings=[f],
    )
    assert c < 1.0


# ---- transition tests -----------------------------------------------------

def test_transition_compromise_to_trusted_rejected() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="p", from_label=TrustLabel.COMPROMISED,
        to_label=TrustLabel.TRUSTED, reason="x", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


def test_transition_quarantine_recovery_requires_verification() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="p", from_label=TrustLabel.QUARANTINED,
        to_label=TrustLabel.OBSERVED, reason="x", verified=False,
    ))
    assert d.outcome is TransitionOutcome.REQUIRES_VERIFICATION


def test_transition_reason_required() -> None:
    d = evaluate_transition(TransitionRequest(
        entity_id="p", from_label=TrustLabel.OBSERVED,
        to_label=TrustLabel.TRUSTED, reason="", verified=True,
    ))
    assert d.outcome is TransitionOutcome.REJECTED_INVALID


# ---- engine integration ---------------------------------------------------

def test_engine_secure_platform_ok() -> None:
    eng = HardwareBootTrustEngine()
    eng.register_platform(_secure_platform(), secure_boot_enabled=True)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    eng.observe_signal("p1", _pos())
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.platform_id == "p1")
    assert rec.label in (TrustLabel.TRUSTED, TrustLabel.OBSERVED)


def test_engine_firmware_drift_degrades() -> None:
    eng = HardwareBootTrustEngine()
    p = _platform(
        "p1", criticality=0.5,
        firmware=(_fw("uefi", version="2.0", digest="dNEW",
                      exp_version="1.0", exp_digest="dOLD"),),
        measurements=(
            _measurement(BootStage.UEFI_FIRMWARE),
            _measurement(BootStage.BOOTLOADER),
            _measurement(BootStage.KERNEL),
        ),
    )
    eng.register_platform(p)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.platform_id == "p1")
    assert label_severity(rec.label) >= label_severity(TrustLabel.SUSPICIOUS)


def test_engine_missing_anchor_compromised() -> None:
    eng = HardwareBootTrustEngine()
    p = Platform(
        platform_id="p1", tenant_id="t", criticality=0.5,
        trust_anchor=None, firmware=frozenset(),
        boot_measurements=(
            _measurement(BootStage.UEFI_FIRMWARE),
            _measurement(BootStage.BOOTLOADER),
            _measurement(BootStage.KERNEL),
        ),
        tee=TeeState(kind=TeeKind.NONE), hardware_identities=(),
    )
    eng.register_platform(p)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.platform_id == "p1")
    assert label_severity(rec.label) >= label_severity(TrustLabel.COMPROMISED)


def test_engine_invariant_high_crit_requires_secure_boot() -> None:
    eng = HardwareBootTrustEngine()
    p = _secure_platform()   # criticality 0.8
    eng.register_platform(p, secure_boot_enabled=False)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    eng.observe_signal("p1", _pos())
    eng.recompute(at=_t0())
    # Either the platform isn't TRUSTED, or invariant fires.
    label = eng.label("p1")
    v = eng.violations()
    assert label is not TrustLabel.TRUSTED or any(
        x.invariant_id == "hw.high_criticality_requires_secure_boot"
        for x in v
    )


def test_engine_invariant_trusted_without_attestation() -> None:
    eng = HardwareBootTrustEngine()
    eng.register_platform(_secure_platform(), secure_boot_enabled=True)
    eng.observe_signal("p1", _pos())
    records = eng.recompute(at=_t0())
    rec = next(r for r in records if r.platform_id == "p1")
    if rec.label is TrustLabel.TRUSTED:
        assert any(
            v.invariant_id == "hw.trusted_requires_fresh_attestation"
            for v in eng.violations()
        )
    else:
        # Defence in depth: without attestation it should not be TRUSTED.
        assert rec.label is not TrustLabel.TRUSTED


def test_engine_invariant_trusted_with_compromised_tee() -> None:
    eng = HardwareBootTrustEngine()
    p = _platform(
        "p1", criticality=0.5,
        firmware=(_fw("uefi", version="1.0", digest="dU",
                      exp_version="1.0", exp_digest="dU"),),
        measurements=(
            _measurement(BootStage.UEFI_FIRMWARE),
            _measurement(BootStage.BOOTLOADER),
            _measurement(BootStage.KERNEL),
        ),
        tee=_tee(TeeKind.INTEL_SGX, debug=True),
    )
    eng.register_platform(p)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    eng.observe_signal("p1", _pos())
    eng.recompute(at=_t0())
    v = eng.violations()
    assert any(x.invariant_id == "hw.trusted_requires_tee_valid" for x in v) \
        or eng.label("p1") is not TrustLabel.TRUSTED


def test_engine_unregister_attestation_unknown_platform_rejected() -> None:
    eng = HardwareBootTrustEngine()
    try:
        eng.add_attestation(_att("a1", "missing"))
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_observe_signal_unknown_platform_rejected() -> None:
    eng = HardwareBootTrustEngine()
    try:
        eng.observe_signal("missing", _pos())
    except KeyError:
        return
    raise AssertionError("expected KeyError")


def test_engine_duplicate_platform_rejected() -> None:
    eng = HardwareBootTrustEngine()
    eng.register_platform(_secure_platform())
    try:
        eng.register_platform(_secure_platform())
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_engine_required_stage_breakdown_flagged() -> None:
    eng = HardwareBootTrustEngine()
    p = _platform(
        "p1", criticality=0.5,
        firmware=(_fw("uefi", version="1.0", digest="dU",
                      exp_version="1.0", exp_digest="dU"),),
        measurements=(
            # only UEFI, missing bootloader & kernel
            _measurement(BootStage.UEFI_FIRMWARE),
        ),
    )
    eng.register_platform(p)
    eng.add_attestation(_att("a1", "p1", fresh=True))
    eng.recompute(at=_t0())
    v = eng.violations()
    # Either the platform isn't TRUSTED or invariant fires.
    assert eng.label("p1") is not TrustLabel.TRUSTED or any(
        x.invariant_id == "hw.trusted_requires_boot_chain_intact"
        for x in v
    )


# ---- store tests ----------------------------------------------------------

def test_in_memory_store_rejects_stale() -> None:
    s = InMemoryHardwareStore()
    t = _t0()
    s.put(PlatformStateRecord("p", TrustLabel.TRUSTED, 0.9, 0, t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put(PlatformStateRecord("p", TrustLabel.UNKNOWN, 0.5, 0, earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_in_memory_attestation_store_rejects_stale() -> None:
    s = InMemoryHardwareStore()
    t = _t0()
    s.put_attestation(_att("a1", "p", at=t))
    earlier = t.replace(year=t.year - 1)
    try:
        s.put_attestation(_att("a1", "p", at=earlier))
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def test_sqlite_store_platform_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "hw.db")
    store = SqliteHardwareStore(db)
    t = _t0()
    store.put(PlatformStateRecord("p1", TrustLabel.TRUSTED, 0.9, 0, t))
    got = store.get("p1")
    assert got is not None and got.label is TrustLabel.TRUSTED


def test_sqlite_store_attestation_roundtrip() -> None:
    import tempfile
    import os
    tmp = tempfile.mkdtemp()
    db = os.path.join(tmp, "hw.db")
    store = SqliteHardwareStore(db)
    att = _att("a1", "p1", sig_valid=True, fresh=True)
    store.put_attestation(att)
    got = store.get_attestation("a1")
    assert got is not None and got.platform_id == "p1"
    assert got.signature_valid is True


# =============================================================================
# SECTION 13 — MANUAL RUNNER
# =============================================================================


def _run_all_tests() -> Tuple[int, int]:
    import traceback
    g = globals()
    tests = sorted(
        (name, fn) for name, fn in g.items()
        if name.startswith("test_") and callable(fn)
    )
    passed = 0
    failed = 0
    for name, fn in tests:
        try:
            fn()
        except Exception:
            failed += 1
            print(f"[FAIL] {name}")
            traceback.print_exc()
        else:
            passed += 1
            print(f"[ OK ] {name}")
    return passed, failed


if __name__ == "__main__":
    passed, failed = _run_all_tests()
    print(f"\n{passed} passed, {failed} failed")
    if failed:
        raise SystemExit(1)
