"""
Tests du module isof.writer.

On verifie que ce qui est signe par le writer est verifie par le verifier
existant, aux niveaux 1 et 2, sur dict comme sur fichier, et que toute
alteration est detectee. La PKI utilisee est generee a la volee, aucune cle
de production n'intervient.
**********************************************************************
Tests for the isof.writer module.

We check that what the writer signs is verified by the existing verifier, at
levels 1 and 2, on dict and on file, and that any tampering is detected. The
PKI used is generated on the fly, no production key is involved.
"""
import json
from datetime import datetime, timezone, timedelta

import pytest

import isof
from isof.parser import load_string

cryptography = pytest.importorskip("cryptography")
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec


def _key():
    return ec.generate_private_key(ec.SECP256R1())


def _self_signed(key, cn):
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(name).issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=3650))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        .sign(key, hashes.SHA256())
    )


def _issue(subject_key, cn, issuer_key, issuer_cert, is_ca):
    now = datetime.now(timezone.utc)
    return (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
        .issuer_name(issuer_cert.subject)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now).not_valid_after(now + timedelta(days=730))
        .add_extension(x509.BasicConstraints(ca=is_ca, path_length=None), True)
        .sign(issuer_key, hashes.SHA256())
    )


def _pem(cert):
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key):
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


@pytest.fixture
def demo_pki(tmp_path):
    # Root -> Issuing -> Lab, ecrits sur disque pour alimenter le writer.
    rk = _key(); rc = _self_signed(rk, "Demo Root CA")
    ik = _key(); ic = _issue(ik, "Demo Issuing CA", rk, rc, True)
    lk = _key(); lc = _issue(lk, "Demo Lab", ik, ic, False)
    key_path = tmp_path / "lab_key.pem"
    cert_path = tmp_path / "lab_cert.pem"
    issuing_path = tmp_path / "issuing_ca.pem"
    key_path.write_text(_key_pem(lk))
    cert_path.write_text(_pem(lc))
    issuing_path.write_text(_pem(ic))
    return {"key": str(key_path), "cert": str(cert_path), "issuing": str(issuing_path)}


@pytest.fixture
def unsigned_document():
    return {
        "isof_version": "1.2",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "created_by": {"software": "test", "version": "1.0", "operator": "demo"},
        "project": {"name": "roundtrip", "description": "writer test"},
        "samples": [{
            "id": "S1", "name": "sample 1", "classification": "daughter",
            "material_type": "soil", "matrix": "sol", "sector": None,
            "project": "roundtrip", "latitude": None, "longitude": None,
            "altitude_m": None, "collection_date": "2026-05-01", "collector": None,
            "description": None, "workflow_stage": "analysed",
            "isotope_data": [{
                "element": "Sr", "system": "87Sr/86Sr", "ratio": 0.7104,
                "ratio_2se": 0.00002, "delta_notation": None, "delta_value": None,
                "delta_2sd": None, "standard": "NBS 987", "n_cycles": 60,
                "session_date": "2026-05-10", "instrument": "MC-ICP-MS", "notes": None,
            }],
            "geochem_data": [], "physico_data": [], "molecules_data": [],
        }],
        "methods": [], "pipelines": [], "purification": [], "assignments": [],
        "signature": None,
    }


def _verify(doc_dict):
    _, doc = load_string(json.dumps(doc_dict, ensure_ascii=False))
    return doc.verify()


def test_level1_roundtrip(unsigned_document):
    signed = isof.sign_document(unsigned_document, level=1, signed_by="Demo Lab")
    result = _verify(signed)
    assert result.valid is True
    assert result.level == 1


def test_level1_detects_tampering(unsigned_document):
    signed = isof.sign_document(unsigned_document, level=1, signed_by="Demo Lab")
    tampered = json.loads(json.dumps(signed))
    tampered["samples"][0]["isotope_data"][0]["ratio"] = 0.9999
    assert _verify(tampered).valid is False


def test_level2_roundtrip(unsigned_document, demo_pki):
    signed = isof.sign_document(
        unsigned_document, level=2, signed_by="Demo Lab",
        key_path=demo_pki["key"], cert_path=demo_pki["cert"],
        issuing_cert_path=demo_pki["issuing"],
    )
    result = _verify(signed)
    assert result.valid is True
    assert result.level == 2
    assert result.signer == "Demo Lab"


def test_level2_detects_tampering(unsigned_document, demo_pki):
    signed = isof.sign_document(
        unsigned_document, level=2, signed_by="Demo Lab",
        key_path=demo_pki["key"], cert_path=demo_pki["cert"],
        issuing_cert_path=demo_pki["issuing"],
    )
    tampered = json.loads(json.dumps(signed))
    tampered["samples"][0]["isotope_data"][0]["ratio"] = 0.9999
    assert _verify(tampered).valid is False


def test_sign_file_roundtrip(unsigned_document, demo_pki, tmp_path):
    src = tmp_path / "unsigned.isof"
    dst = tmp_path / "signed.isof"
    src.write_text(json.dumps(unsigned_document, ensure_ascii=False))
    isof.sign_file(
        str(src), str(dst), level=2, signed_by="Demo Lab",
        key_path=demo_pki["key"], cert_path=demo_pki["cert"],
        issuing_cert_path=demo_pki["issuing"],
    )
    result = isof.load(str(dst)).verify()
    assert result.valid is True
    assert result.level == 2


def test_level2_requires_key_and_cert(unsigned_document):
    # Sans cle ni certificat, la signature de niveau 2 doit echouer proprement.
    with pytest.raises(isof.ISOfSignatureError):
        isof.sign_document(unsigned_document, level=2, signed_by="Demo Lab")


# ---------------------------------------------------------------------------
# Construction de documents : chemin complet donnees -> .isof signe
# Document construction: full path from data to signed .isof
# ---------------------------------------------------------------------------

def test_build_sign_verify_full_path(demo_pki, tmp_path):
    iso = isof.make_isotope(element="Sb", system="123Sb/121Sb", ratio=0.46, ratio_2se=0.02)
    geo = isof.make_geochem(element="Sb", value_normalized=7824, display_unit="ug/L", method="ICP-MS")
    sample = isof.make_sample("OR-01", name="Oruro 1", matrix="water",
                              isotope_data=[iso], geochem_data=[geo])
    doc = isof.new_document([sample], created_by={"software": "test", "operator": "CF"},
                            doi="10.1007/s11270-025-08445-6")
    dst = tmp_path / "built.isof"
    signed = isof.sign_document(doc, level=2, signed_by="Demo Lab",
                                key_path=demo_pki["key"], cert_path=demo_pki["cert"],
                                issuing_cert_path=demo_pki["issuing"])
    dst.write_text(json.dumps(signed, ensure_ascii=False))
    loaded = isof.load(str(dst))
    result = loaded.verify()
    assert result.valid is True
    assert result.level == 2
    assert loaded.doi == "10.1007/s11270-025-08445-6"


def test_builder_never_invents_absent_fields():
    # Un champ non fourni doit rester None, jamais rempli d'une valeur devinee.
    iso = isof.make_isotope(element="Sb", system="123Sb/121Sb", ratio=0.46)
    assert iso["ratio"] == 0.46
    assert iso["delta_value"] is None
    assert iso["instrument"] is None
    assert iso["standard"] is None


def test_builder_warns_on_missing_meaning_field():
    with pytest.warns(UserWarning):
        isof.make_isotope(element="Sb")  # 'system' manquant
    with pytest.warns(UserWarning):
        isof.make_geochem(value_normalized=10.0)  # 'element' manquant


def test_builder_warns_and_drops_unknown_field():
    with pytest.warns(UserWarning):
        rec = isof.make_isotope(element="Sb", system="123Sb/121Sb", not_a_field=1)
    assert "not_a_field" not in rec


def test_sample_requires_id():
    with pytest.raises(isof.ISOfSignatureError):
        isof.make_sample("")
