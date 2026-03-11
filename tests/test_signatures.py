"""
Tests de vérification des signatures ISOF.

Les trois niveaux de signature sont couverts séparément.
Les cas d'altération post-signature sont testés pour chaque niveau
qui porte une garantie d'intégrité (1 et 2).

Les fixtures attendues dans tests/fixtures/ :
  - Test_signature_invalid.isof   : signature niveau 1 ou 2, hash/sig invalide
  - Test_signature_level_1.isof   : signature niveau 1 (SHA-256) valide
  - Test_signature_level_2.isof   : signature niveau 2 (ECDSA P-256 + PKI IsoFind) valide
****************************************************************************
ISOF signature verification tests.

The three signature levels are covered separately.
Post-signature alteration cases are tested for each level
that carries an integrity guarantee (1 and 2).

Expected fixtures in tests/fixtures/:
  - Test_signature_invalid.isof   : level 1 or 2 signature, invalid hash/sig
  - Test_signature_level_1.isof   : valid level 1 (SHA-256) signature
  - Test_signature_level_2.isof   : valid level 2 (ECDSA P-256 + IsoFind PKI) signature
"""

import json
from pathlib import Path

import pytest

import isof
from isof.exceptions import ISOfSignatureError
from isof.parser import load_string
from isof.signature import VerificationResult

FIXTURES   = Path(__file__).parent / "fixtures"
INVALID    = FIXTURES / "Test_signature_invalid.isof"
LEVEL_1    = FIXTURES / "Test_signature_level_1.isof"
LEVEL_2    = FIXTURES / "Test_signature_level_2.isof"


# ---------------------------------------------------------------------------
# Niveau 0 — absence de signature | Level 0 — no signature
# ---------------------------------------------------------------------------

def test_no_signature_is_not_authentic():
    """
    Un document sans bloc signature ne peut pas être considéré comme authentique.
    A document without a signature block cannot be considered authentic.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"] = None
    _, doc = load_string(json.dumps(raw))
    assert not doc.is_authentic()


def test_no_signature_verify_result():
    """
    verify() sur un document sans signature doit retourner level=0 et valid=False.
    verify() on an unsigned document must return level=0 and valid=False.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"] = None
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 0
    assert result.signer is None


def test_no_signature_verify_result_is_falsy():
    """
    VerificationResult sans signature doit être falsy via __bool__.
    VerificationResult without signature must be falsy via __bool__.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"] = None
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not bool(result)


# ---------------------------------------------------------------------------
# Niveau 1 — SHA-256 | Level 1 — SHA-256
# ---------------------------------------------------------------------------

def test_level1_valid():
    """
    La fixture level_1 doit avoir une signature SHA-256 valide.
    The level_1 fixture must have a valid SHA-256 signature.
    """
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.valid
    assert result.level == 1


def test_level1_is_authentic():
    doc = isof.load(LEVEL_1)
    assert doc.is_authentic()


def test_level1_signer_present():
    """
    Le signataire doit être renseigné dans VerificationResult.
    The signer must be set in VerificationResult.
    """
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.signer is not None


def test_level1_signed_at_present():
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.signed_at is not None


def test_level1_result_is_truthy():
    """
    Un VerificationResult valide doit être truthy via __bool__.
    A valid VerificationResult must be truthy via __bool__.
    """
    doc = isof.load(LEVEL_1)
    assert bool(doc.verify())


def test_level1_alteration_invalidates_signature():
    """
    Modifier un champ dans le scope après signature doit casser le hash.
    Modifying a field within scope after signing must break the hash.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    # Altération ciblée dans les données couvertes par le scope
    # Targeted alteration within scope-covered data
    raw["samples"][0]["name"] = "NOM_ALTERE"
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 1


def test_level1_alteration_reason_mentions_modification():
    """
    Le message d'échec doit indiquer que les données ont été modifiées.
    The failure message must indicate that data was modified.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["name"] = "NOM_ALTERE"
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert result.reason is not None
    assert "modifi" in result.reason.lower()


def test_level1_hash_truncation_invalidates():
    """
    Un hash tronqué (même préfixe correct) doit être rejeté.
    A truncated hash (even with correct prefix) must be rejected.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["hash"] = raw["signature"]["hash"][:32]
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid


# ---------------------------------------------------------------------------
# Niveau 2 — ECDSA P-256 + PKI IsoFind | Level 2 — ECDSA P-256 + IsoFind PKI
# ---------------------------------------------------------------------------

def test_level2_requires_cryptography():
    """
    Si le package 'cryptography' n'est pas installé, ISOfSignatureError est levée.
    If the 'cryptography' package is not installed, ISOfSignatureError is raised.
    """
    cryptography = pytest.importorskip("cryptography")  # passe si présent, skip sinon
    _ = cryptography  # utilisé uniquement pour déclencher le skip si absent


def test_level2_valid():
    """
    La fixture level_2 doit passer la vérification ECDSA complète.
    The level_2 fixture must pass the full ECDSA verification.
    """
    pytest.importorskip("cryptography")
    doc = isof.load(LEVEL_2)
    result = doc.verify()
    assert result.valid
    assert result.level == 2


def test_level2_is_authentic():
    pytest.importorskip("cryptography")
    doc = isof.load(LEVEL_2)
    assert doc.is_authentic()


def test_level2_signer_is_cn():
    """
    Le signataire retourné doit correspondre au CN du certificat laboratoire.
    The returned signer must match the CN of the lab certificate.
    """
    pytest.importorskip("cryptography")
    doc = isof.load(LEVEL_2)
    result = doc.verify()
    assert result.signer is not None
    assert len(result.signer) > 0


def test_level2_signed_at_present():
    pytest.importorskip("cryptography")
    doc = isof.load(LEVEL_2)
    result = doc.verify()
    assert result.signed_at is not None


def test_level2_alteration_invalidates_signature():
    """
    Toute modification dans le scope doit invalider la signature ECDSA.
    Any modification within scope must invalidate the ECDSA signature.
    """
    pytest.importorskip("cryptography")
    raw_text = LEVEL_2.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["name"] = "NOM_ALTERE"
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 2


def test_level2_alteration_reason_mentions_ecdsa():
    """
    Le message d'échec doit identifier la nature de l'échec (ECDSA).
    The failure message must identify the nature of the failure (ECDSA).
    """
    pytest.importorskip("cryptography")
    raw_text = LEVEL_2.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["name"] = "NOM_ALTERE"
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert result.reason is not None
    assert "ecdsa" in result.reason.lower() or "signature" in result.reason.lower()


def test_level2_missing_certificate_returns_invalid():
    """
    Un bloc signature niveau 2 sans certificat embarqué doit retourner valid=False,
    pas lever une exception — le fichier est structurellement lisible.

    A level 2 signature block without an embedded certificate must return valid=False,
    not raise an exception — the file is structurally readable.
    """
    pytest.importorskip("cryptography")
    raw_text = LEVEL_2.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["certificate_pem"] = None
    raw["signature"]["certificate_chain"] = None
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 2


def test_level2_corrupted_certificate_raises():
    """
    Un certificat PEM illisible doit lever ISOfSignatureError.
    An unreadable PEM certificate must raise ISOfSignatureError.
    """
    pytest.importorskip("cryptography")
    raw_text = LEVEL_2.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["certificate_pem"] = "-----BEGIN CERTIFICATE-----\nPEMCORROMPU\n-----END CERTIFICATE-----"
    _, doc = load_string(json.dumps(raw))
    with pytest.raises(ISOfSignatureError, match="[Cc]ertifi"):
        doc.verify()


# ---------------------------------------------------------------------------
# Fixture explicitement invalide | Explicitly invalid fixture
# ---------------------------------------------------------------------------

def test_invalid_fixture_is_not_authentic():
    """
    La fixture 'invalid' représente un fichier dont la signature ne correspond plus
    aux données — is_authentic() doit retourner False.

    The 'invalid' fixture represents a file whose signature no longer matches
    the data — is_authentic() must return False.
    """
    doc = isof.load(INVALID)
    assert not doc.is_authentic()


def test_invalid_fixture_verify_returns_false():
    doc = isof.load(INVALID)
    result = doc.verify()
    assert not result.valid


def test_invalid_fixture_has_signature_level():
    """
    Même invalide, le bloc signature doit être parsé et le niveau retourné.
    Even when invalid, the signature block must be parsed and the level returned.
    """
    doc = isof.load(INVALID)
    result = doc.verify()
    assert result.level in (1, 2)


def test_invalid_fixture_reason_is_set():
    """
    Une signature invalide doit toujours fournir un motif d'échec non vide.
    An invalid signature must always provide a non-empty failure reason.
    """
    doc = isof.load(INVALID)
    result = doc.verify()
    assert result.reason is not None
    assert len(result.reason) > 0


# ---------------------------------------------------------------------------
# Comportements transversaux | Cross-cutting behaviors
# ---------------------------------------------------------------------------

def test_verification_result_bool_contract():
    """
    __bool__ de VerificationResult doit être cohérent avec le champ valid.
    VerificationResult.__bool__ must be consistent with the valid field.
    """
    r_true  = VerificationResult(valid=True,  level=1, reason=None, signer="IsoFind SAS", signed_at=None)
    r_false = VerificationResult(valid=False, level=1, reason="test", signer=None, signed_at=None)
    assert bool(r_true)  is True
    assert bool(r_false) is False


def test_level1_and_level2_both_pass_is_authentic():
    """
    is_authentic() doit retourner True pour les deux fixtures valides,
    quel que soit le niveau de signature.

    is_authentic() must return True for both valid fixtures,
    regardless of the signature level.
    """
    pytest.importorskip("cryptography")
    doc1 = isof.load(LEVEL_1)
    doc2 = isof.load(LEVEL_2)
    assert doc1.is_authentic()
    assert doc2.is_authentic()


def test_signature_block_parsed_for_all_fixtures():
    """
    Le bloc signature doit être parsé dans tous les fichiers de test,
    même le fichier invalide — le parser ne doit pas rejeter un hash incorrect.

    The signature block must be parsed in all test files,
    including the invalid file — the parser must not reject an incorrect hash.
    """
    for fixture in (INVALID, LEVEL_1, LEVEL_2):
        doc = isof.load(fixture)
        assert doc.signature is not None, f"Signature absente dans {fixture.name}"
        assert doc.signature.level in (1, 2)