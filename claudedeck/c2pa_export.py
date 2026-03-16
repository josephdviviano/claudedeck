"""
claudedeck.c2pa_export — C2PA-compatible manifest generation.

Generates signed C2PA manifests for proof bundles, enabling
interoperability with the Content Provenance ecosystem (Adobe, Google,
Microsoft, OpenAI).

The output is a signed PNG file with the C2PA manifest embedded. This
carrier PNG sits alongside the proof bundle JSON and can be verified
by any C2PA-compatible tool.

Requires the optional `c2pa` dependency:
    pip install -e ".[c2pa]"
"""

import datetime
import json
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .proof import ProofBundle


# ---------------------------------------------------------------------------
# Certificate generation (self-signed CA + leaf for local signing)
# ---------------------------------------------------------------------------

def _generate_cert_chain() -> tuple[bytes, bytes]:
    """Generate a self-signed CA + leaf certificate chain for C2PA signing.

    Returns (cert_chain_pem, private_key_pem) where cert_chain_pem contains
    the leaf cert followed by the CA cert.

    Requires the `cryptography` package.
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID

    now = datetime.datetime.now(datetime.timezone.utc)

    # Root CA
    ca_key = ec.generate_private_key(ec.SECP256R1())
    ca_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ClaudeDeck"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ClaudeDeck Root CA"),
    ])
    ca_cert = (
        x509.CertificateBuilder()
        .subject_name(ca_name)
        .issuer_name(ca_name)
        .public_key(ca_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 10))
        .add_extension(
            x509.BasicConstraints(ca=True, path_length=0), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=True,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    # Leaf signing cert — C2PA requires EKU with emailProtection
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf_name = x509.Name([
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ClaudeDeck"),
        x509.NameAttribute(NameOID.COMMON_NAME, "ClaudeDeck Session Signer"),
    ])
    leaf_cert = (
        x509.CertificateBuilder()
        .subject_name(leaf_name)
        .issuer_name(ca_name)
        .public_key(leaf_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(days=1))
        .not_valid_after(now + datetime.timedelta(days=365 * 5))
        .add_extension(
            x509.BasicConstraints(ca=False, path_length=None), critical=True
        )
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.EMAIL_PROTECTION]),
            critical=True,
        )
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_subject_key_identifier(
                ca_cert.extensions.get_extension_for_class(
                    x509.SubjectKeyIdentifier
                ).value
            ),
            critical=False,
        )
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(leaf_key.public_key()),
            critical=False,
        )
        .sign(ca_key, hashes.SHA256())
    )

    cert_chain_pem = (
        leaf_cert.public_bytes(serialization.Encoding.PEM)
        + ca_cert.public_bytes(serialization.Encoding.PEM)
    )
    private_key_pem = leaf_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    return cert_chain_pem, private_key_pem


# ---------------------------------------------------------------------------
# C2PA manifest construction
# ---------------------------------------------------------------------------

def _build_manifest_json(bundle: ProofBundle) -> dict:
    """Build a C2PA manifest definition from a proof bundle.

    Maps claudedeck concepts to C2PA assertions:
    - stds.schema-org.CreativeWork: authorship metadata
    - c2pa.actions: chain provenance actions
    - org.claudedeck.chain: chain head hash, record count, anchors
    """
    chain_records = bundle.chain_records
    head_hash = chain_records[-1]["record_hash"] if chain_records else ""
    num_turns = len(chain_records)
    # Use comma-separated string to avoid CBOR encoding issues with lists
    disclosed_seqs = ",".join(str(t.seq) for t in bundle.disclosed_turns)

    actions = []
    for rec in chain_records:
        action = {
            "action": "c2pa.created" if rec["seq"] == 0 else "c2pa.edited",
            "when": rec["timestamp"],
            "softwareAgent": {
                "name": "claudedeck",
                "version": bundle.version,
            },
        }
        if rec["turn"].get("model"):
            action["softwareAgent"]["model"] = rec["turn"]["model"]
        actions.append(action)

    assertions = [
        {
            "label": "stds.schema-org.CreativeWork",
            "data": {
                "@context": "https://schema.org",
                "@type": "CreativeWork",
                "author": [
                    {
                        "@type": "Organization",
                        "name": "claudedeck",
                    }
                ],
            },
        },
        {
            "label": "c2pa.actions",
            "data": {"actions": actions},
        },
        {
            "label": "org.claudedeck.chain",
            "data": {
                "chain_head_hash": head_hash,
                "num_records": str(num_turns),
                "disclosed_sequences": disclosed_seqs,
                "anchors": json.dumps(
                    [a.to_dict() for a in bundle.anchors],
                    sort_keys=True,
                ),
            },
        },
    ]

    if bundle.metadata:
        # Embed metadata as a JSON string inside the chain assertion
        # to avoid CBOR schema validation issues with custom assertions
        assertions[-1]["data"]["metadata"] = json.dumps(
            bundle.metadata, sort_keys=True
        )

    return {
        "claim_generator": f"claudedeck/{bundle.version}",
        "title": "claudedeck proof bundle",
        "assertions": assertions,
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

@dataclass
class C2paExportResult:
    """Result of a C2PA manifest export."""
    success: bool
    manifest_path: Optional[str] = None
    error: Optional[str] = None


def export_c2pa_manifest(
    bundle: ProofBundle,
    proof_bundle_path: str | Path,
    output_path: str | Path | None = None,
    cert_chain_pem: bytes | None = None,
    private_key_pem: bytes | None = None,
    ta_url: str | None = None,
) -> C2paExportResult:
    """Export a C2PA manifest as a signed PNG carrier file.

    The output PNG contains the C2PA manifest with claudedeck chain
    metadata embedded. It can be verified by any C2PA-compatible tool.

    Args:
        bundle: The proof bundle to create a manifest for.
        proof_bundle_path: Path to the saved proof bundle JSON file.
        output_path: Where to write the signed PNG with embedded manifest.
            Defaults to proof_bundle_path with .c2pa.png extension.
        cert_chain_pem: PEM-encoded certificate chain (leaf + CA).
            If None, generates a self-signed chain.
        private_key_pem: PEM-encoded private key for the leaf cert.
            Required if cert_chain_pem is provided.
        ta_url: Timestamp authority URL for RFC 3161 timestamps.
            Defaults to DigiCert's public TSA.

    Returns:
        C2paExportResult with the output path on success.
    """
    try:
        import c2pa
    except ImportError:
        return C2paExportResult(
            success=False,
            error="c2pa-python not installed. Install with: pip install 'claudedeck[c2pa]'",
        )

    proof_bundle_path = Path(proof_bundle_path)
    if output_path is None:
        output_path = proof_bundle_path.with_suffix(".c2pa.png")
    else:
        output_path = Path(output_path)

    # Generate or use provided certs
    if cert_chain_pem is None:
        cert_chain_pem, private_key_pem = _generate_cert_chain()
    elif private_key_pem is None:
        return C2paExportResult(
            success=False,
            error="private_key_pem required when cert_chain_pem is provided",
        )

    manifest_def = _build_manifest_json(bundle)

    # ta_url is required by c2pa-python; default to DigiCert's public TSA
    effective_ta_url = ta_url or "http://timestamp.digicert.com"
    signer_info = c2pa.C2paSignerInfo(
        alg=c2pa.C2paSigningAlg.ES256,
        sign_cert=cert_chain_pem,
        private_key=private_key_pem,
        ta_url=effective_ta_url,
    )
    signer = c2pa.Signer.from_info(signer_info)

    builder = c2pa.Builder(manifest_def)
    carrier_png = _make_minimal_png()

    src_path = None
    try:
        with tempfile.NamedTemporaryFile(
            suffix=".png", delete=False
        ) as src_f:
            src_f.write(carrier_png)
            src_path = src_f.name

        builder.sign_file(src_path, str(output_path), signer)

        return C2paExportResult(
            success=True,
            manifest_path=str(output_path),
        )
    except Exception as e:
        return C2paExportResult(success=False, error=str(e))
    finally:
        import os

        if src_path:
            try:
                os.unlink(src_path)
            except OSError:
                pass


def read_c2pa_manifest(manifest_path: str | Path) -> dict | None:
    """Read and parse a C2PA manifest store from a signed file.

    Args:
        manifest_path: Path to a signed PNG with embedded C2PA manifest.

    Returns:
        Parsed manifest store as a dict, or None if c2pa is not available.
    """
    try:
        import c2pa
    except ImportError:
        return None

    reader = c2pa.Reader("image/png", open(str(manifest_path), "rb"))
    return json.loads(reader.json())


def verify_c2pa_manifest(
    manifest_path: str | Path,
    expected_chain_head: str | None = None,
) -> tuple[bool, str]:
    """Verify a C2PA manifest and optionally check the chain head hash.

    Args:
        manifest_path: Path to a signed PNG with embedded C2PA manifest.
        expected_chain_head: If provided, verify the chain head hash matches.

    Returns:
        (success, detail) tuple.
    """
    try:
        import c2pa
    except ImportError:
        return False, "c2pa-python not installed"

    try:
        reader = c2pa.Reader("image/png", open(str(manifest_path), "rb"))
    except Exception as e:
        return False, f"Failed to read manifest: {e}"

    store = json.loads(reader.json())

    # Check C2PA validation status
    validation_status = store.get("validation_status", [])
    errors = [
        v for v in validation_status
        if "error" in v.get("code", "").lower()
    ]
    if errors:
        error_codes = [e.get("code", "unknown") for e in errors]
        return False, f"Validation errors: {', '.join(error_codes)}"

    if expected_chain_head:
        chain_data = _extract_chain_assertion(store)
        if chain_data is None:
            return False, "No org.claudedeck.chain assertion found"

        actual_head = chain_data.get("chain_head_hash", "")
        if actual_head != expected_chain_head:
            return False, (
                f"Chain head mismatch: manifest has {actual_head[:16]}..., "
                f"expected {expected_chain_head[:16]}..."
            )

    return True, "C2PA manifest valid"


def _extract_chain_assertion(store: dict) -> dict | None:
    """Extract the org.claudedeck.chain assertion data from a manifest store."""
    active_label = store.get("active_manifest")
    if not active_label:
        return None

    manifests = store.get("manifests", {})
    active = manifests.get(active_label, {})

    for a in active.get("assertions", []):
        if a.get("label") == "org.claudedeck.chain":
            return a.get("data")
    return None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_minimal_png() -> bytes:
    """Generate a 1x1 pixel PNG file (valid, minimal)."""
    import struct
    import zlib

    signature = b"\x89PNG\r\n\x1a\n"

    def chunk(chunk_type: bytes, data: bytes) -> bytes:
        c = chunk_type + data
        crc = zlib.crc32(c) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + c + struct.pack(">I", crc)

    ihdr_data = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    idat_data = zlib.compress(b"\x00\xff\x00\x00")

    return (
        signature
        + chunk(b"IHDR", ihdr_data)
        + chunk(b"IDAT", idat_data)
        + chunk(b"IEND", b"")
    )
