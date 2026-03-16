"""
claudedeck.proof — Proof bundle generation and verification.

A proof bundle is a self-contained package that proves:
1. A specific prompt produced a specific response
2. Specific artifacts were produced in that session
3. The record is part of an internally consistent hash chain
4. The chain head was anchored at a specific time (via Sigstore/OTS)

The bundle contains:
- The full chain (hashes only — safe to publish)
- The disclosed entries' plaintext (researcher chooses what to reveal)
- Artifact files (or their hashes if files are large)
- External anchor references (Sigstore log index, OTS proof file)
"""

import json
import hashlib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .core import (
    Chain, ChainRecord, ArtifactRef, ToolInteraction,
    sha256_hex, canonical_json, GENESIS_HASH,
)


@dataclass
class DisclosedToolInteraction:
    """Plaintext tool input/result disclosed in a proof bundle."""
    tool_name: str
    tool_use_id: str
    input: dict       # raw input parameters
    result: str       # raw result content

    def to_dict(self) -> dict:
        return {
            "tool_name": self.tool_name,
            "tool_use_id": self.tool_use_id,
            "input": self.input,
            "result": self.result,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "DisclosedToolInteraction":
        return cls(
            tool_name=d["tool_name"],
            tool_use_id=d["tool_use_id"],
            input=d.get("input", {}),
            result=d.get("result", ""),
        )


@dataclass
class DisclosedTurn:
    """A single turn being disclosed in a proof bundle."""
    seq: int
    prompt: str
    response: str
    artifacts: dict[str, str]  # filename -> content (text) or hash (binary)
    tool_interactions: list[DisclosedToolInteraction] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = {
            "seq": self.seq,
            "prompt": self.prompt,
            "response": self.response,
            "artifacts": self.artifacts,
        }
        if self.tool_interactions:
            d["tool_interactions"] = [ti.to_dict() for ti in self.tool_interactions]
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "DisclosedTurn":
        return cls(
            seq=d["seq"],
            prompt=d["prompt"],
            response=d["response"],
            artifacts=d.get("artifacts", {}),
            tool_interactions=[
                DisclosedToolInteraction.from_dict(ti)
                for ti in d.get("tool_interactions", [])
            ],
        )


@dataclass
class AnchorRef:
    """Reference to an external timestamp anchor."""
    anchor_type: str  # "local", "sigstore", "ots"
    chain_head_hash: str
    reference: str  # Rekor log index, OTS proof path, etc.
    timestamp: Optional[str] = None
    proof_data: Optional[str] = None  # base64-encoded proof (for OTS)

    def to_dict(self) -> dict:
        d = {
            "anchor_type": self.anchor_type,
            "chain_head_hash": self.chain_head_hash,
            "reference": self.reference,
            "timestamp": self.timestamp,
        }
        if self.proof_data is not None:
            d["proof_data"] = self.proof_data
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "AnchorRef":
        return cls(
            anchor_type=d["anchor_type"],
            chain_head_hash=d["chain_head_hash"],
            reference=d["reference"],
            timestamp=d.get("timestamp"),
            proof_data=d.get("proof_data"),
        )


@dataclass
class ProofBundle:
    """A self-contained, verifiable proof of AI interaction provenance."""
    version: str = "0.1.0"
    chain_records: list[dict] = field(default_factory=list)
    disclosed_turns: list[DisclosedTurn] = field(default_factory=list)
    anchors: list[AnchorRef] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)  # researcher name, purpose, etc.

    def to_dict(self) -> dict:
        return {
            "version": self.version,
            "chain_records": self.chain_records,
            "disclosed_turns": [t.to_dict() for t in self.disclosed_turns],
            "anchors": [a.to_dict() for a in self.anchors],
            "metadata": self.metadata,
        }

    def save(self, path: str | Path):
        from .core import atomic_write
        atomic_write(path, json.dumps(self.to_dict(), indent=2, sort_keys=True))

    @classmethod
    def load(cls, path: str | Path) -> "ProofBundle":
        with open(path) as f:
            d = json.load(f)
        bundle = cls(
            version=d["version"],
            chain_records=d["chain_records"],
            disclosed_turns=[DisclosedTurn.from_dict(t) for t in d["disclosed_turns"]],
            anchors=[AnchorRef.from_dict(a) for a in d.get("anchors", [])],
            metadata=d.get("metadata", {}),
        )
        return bundle


# ---------------------------------------------------------------------------
# Bundle creation
# ---------------------------------------------------------------------------

def create_proof_bundle(
    chain: Chain,
    vault,  # Vault instance (import avoided for stdlib-only verify path)
    disclose_seqs: list[int],
    anchors: list[AnchorRef] | None = None,
    metadata: dict | None = None,
) -> ProofBundle:
    """Create a proof bundle disclosing specific turns from a session.

    Args:
        chain: The full session chain.
        vault: Vault containing plaintext for disclosed entries.
        disclose_seqs: Sequence numbers of turns to disclose.
        anchors: External anchor references (Sigstore, OTS, etc.)
        metadata: Optional researcher metadata (name, ORCID, purpose, etc.)
    """
    disclosed = []
    for seq in disclose_seqs:
        entry = vault.retrieve(seq)
        if entry is None:
            raise ValueError(f"Sequence {seq} not found in vault")
        tool_interactions = [
            DisclosedToolInteraction.from_dict(ti)
            for ti in entry.get("tool_interactions", [])
        ]
        disclosed.append(DisclosedTurn(
            seq=seq,
            prompt=entry["prompt"],
            response=entry["response"],
            artifacts=entry.get("artifacts", {}),
            tool_interactions=tool_interactions,
        ))

    return ProofBundle(
        chain_records=[rec.to_dict() for rec in chain.records],
        disclosed_turns=disclosed,
        anchors=anchors or [],
        metadata=metadata or {},
    )


# ---------------------------------------------------------------------------
# Bundle verification (stdlib only — no external dependencies)
# ---------------------------------------------------------------------------

@dataclass
class VerificationResult:
    """Result of verifying a proof bundle."""
    is_valid: bool
    checks: list[dict]  # {"check": str, "passed": bool, "detail": str}

    @property
    def trust_level(self) -> str:
        """Classify the trust level based on anchor presence.

        Returns:
            "anchored" — at least one external anchor (sigstore/ots)
            "local_only" — only local anchors (no third-party attestation)
            "unanchored" — no anchors at all (trivially forgeable)
        """
        anchor_checks = [
            c for c in self.checks
            if c["check"].startswith("anchor_") and c["check"] not in ("anchor_note", "anchors")
        ]
        if not anchor_checks:
            return "unanchored"
        anchor_types = set()
        for c in anchor_checks:
            # check name is "anchor_{type}"
            atype = c["check"].split("_", 1)[1]
            anchor_types.add(atype)
        if anchor_types - {"local"}:
            return "anchored"
        return "local_only"

    def summary(self) -> str:
        lines = []
        for c in self.checks:
            icon = "PASS" if c["passed"] else "FAIL"
            lines.append(f"  [{icon}] {c['check']}: {c['detail']}")
        status = "VALID" if self.is_valid else "INVALID"
        trust = self.trust_level.upper()
        return f"Proof bundle verification: {status} [{trust}]\n" + "\n".join(lines)


def verify_proof_bundle(
    bundle: ProofBundle,
    require_anchor: bool = False,
) -> VerificationResult:
    """Verify a proof bundle's integrity.

    Checks performed:
    1. Chain internal consistency (hashes and linkage)
    2. Disclosed content matches chain hashes
    3. Artifact hashes match chain records
    4. Anchor references are present (actual anchor verification
       requires external tools — Sigstore/OTS CLI)

    Args:
        bundle: The proof bundle to verify.
        require_anchor: If True, verification fails when no external
            anchors are present. Default False for backward compatibility.
    """
    checks = []

    # --- Check 1: Chain integrity ---
    records = [ChainRecord.from_dict(d) for d in bundle.chain_records]
    chain_ok = True
    for i, rec in enumerate(records):
        expected_hash = rec.compute_hash()
        if rec.record_hash != expected_hash:
            chain_ok = False
            checks.append({
                "check": f"chain_record_{i}_hash",
                "passed": False,
                "detail": f"Hash mismatch at seq {rec.seq}",
            })
        if i == 0 and rec.prev_hash != GENESIS_HASH:
            chain_ok = False
            checks.append({
                "check": "chain_genesis",
                "passed": False,
                "detail": "First record prev_hash is not GENESIS",
            })
        elif i > 0 and rec.prev_hash != records[i - 1].record_hash:
            chain_ok = False
            checks.append({
                "check": f"chain_link_{i}",
                "passed": False,
                "detail": f"Broken link between records {i-1} and {i}",
            })

    if chain_ok:
        checks.append({
            "check": "chain_integrity",
            "passed": True,
            "detail": f"All {len(records)} records internally consistent and linked",
        })

    # --- Check 2: Disclosed content matches chain hashes ---
    record_by_seq = {r.seq: r for r in records}
    for turn in bundle.disclosed_turns:
        rec = record_by_seq.get(turn.seq)
        if rec is None:
            checks.append({
                "check": f"disclosed_turn_{turn.seq}",
                "passed": False,
                "detail": f"No chain record for disclosed seq {turn.seq}",
            })
            continue

        prompt_hash = sha256_hex(turn.prompt.encode("utf-8"))
        response_hash = sha256_hex(turn.response.encode("utf-8"))

        prompt_ok = prompt_hash == rec.turn.prompt_hash
        response_ok = response_hash == rec.turn.response_hash

        checks.append({
            "check": f"prompt_hash_seq_{turn.seq}",
            "passed": prompt_ok,
            "detail": "Prompt matches chain" if prompt_ok else "PROMPT HASH MISMATCH",
        })
        checks.append({
            "check": f"response_hash_seq_{turn.seq}",
            "passed": response_ok,
            "detail": "Response matches chain" if response_ok else "RESPONSE HASH MISMATCH",
        })

    # --- Check 2b: Tool interaction verification ---
    for turn in bundle.disclosed_turns:
        rec = record_by_seq.get(turn.seq)
        if rec is None or not turn.tool_interactions:
            continue
        chain_interactions = {
            ti.tool_use_id: ti
            for ti in rec.turn.tool_interactions
        }
        for dti in turn.tool_interactions:
            chain_ti = chain_interactions.get(dti.tool_use_id)
            if chain_ti is None:
                checks.append({
                    "check": f"tool_input_seq_{turn.seq}_{dti.tool_use_id}",
                    "passed": False,
                    "detail": f"Tool interaction '{dti.tool_use_id}' not in chain record",
                })
                continue
            # Verify input hash
            input_hash = sha256_hex(canonical_json(dti.input))
            input_ok = input_hash == chain_ti.input_hash
            checks.append({
                "check": f"tool_input_seq_{turn.seq}_{dti.tool_use_id}",
                "passed": input_ok,
                "detail": (
                    f"Tool input for {dti.tool_name} matches chain"
                    if input_ok else
                    f"TOOL INPUT HASH MISMATCH for {dti.tool_name}"
                ),
            })
            # Verify result hash
            result_hash = sha256_hex(dti.result.encode("utf-8"))
            result_ok = result_hash == chain_ti.result_hash
            checks.append({
                "check": f"tool_result_seq_{turn.seq}_{dti.tool_use_id}",
                "passed": result_ok,
                "detail": (
                    f"Tool result for {dti.tool_name} matches chain"
                    if result_ok else
                    f"TOOL RESULT HASH MISMATCH for {dti.tool_name}"
                ),
            })

    # --- Check 3: Artifact verification ---
    for turn in bundle.disclosed_turns:
        rec = record_by_seq.get(turn.seq)
        if rec is None:
            continue
        artifact_hashes = {a.filename: a.sha256 for a in rec.turn.artifacts}
        for filename, content in turn.artifacts.items():
            expected = artifact_hashes.get(filename)
            if expected is None:
                checks.append({
                    "check": f"artifact_{turn.seq}_{filename}",
                    "passed": False,
                    "detail": f"Artifact '{filename}' not in chain record",
                })
                continue
            actual = sha256_hex(content.encode("utf-8"))
            ok = actual == expected
            checks.append({
                "check": f"artifact_{turn.seq}_{filename}",
                "passed": ok,
                "detail": f"Artifact matches chain" if ok else "ARTIFACT HASH MISMATCH",
            })

    # --- Check 4: Anchor references present ---
    if bundle.anchors:
        for anchor in bundle.anchors:
            head_hash = records[-1].record_hash if records else ""
            hash_ok = anchor.chain_head_hash == head_hash
            checks.append({
                "check": f"anchor_{anchor.anchor_type}",
                "passed": hash_ok,
                "detail": (
                    f"Anchor references chain head ({anchor.reference})"
                    if hash_ok else
                    "Anchor hash doesn't match chain head"
                ),
            })
        checks.append({
            "check": "anchor_note",
            "passed": True,
            "detail": "External anchor verification requires Sigstore/OTS CLI tools",
        })
    else:
        if require_anchor:
            checks.append({
                "check": "anchors",
                "passed": False,
                "detail": "WARNING: No external anchors — bundle is trivially forgeable. "
                          "Anyone can fabricate a valid-looking chain without anchors.",
            })
        else:
            checks.append({
                "check": "anchors",
                "passed": True,
                "detail": "WARNING: UNANCHORED — no external anchors present. "
                          "Chain is self-consistent but could have been fabricated. "
                          "Use 'claudedeck anchor' to add external timestamp proof.",
            })

    is_valid = all(c["passed"] for c in checks)
    return VerificationResult(is_valid=is_valid, checks=checks)
