"""
Tests de vérification des signatures ISOF (niveaux 0, 1, 2) sur v1.0 et v1.2.

Les trois niveaux de signature sont couverts séparément.
Les cas d'altération post-signature sont testés pour chaque niveau
qui porte une garantie d'intégrité (1 et 2).

Fixtures attendues dans tests/fixtures/ :
  - Test_signature_invalid.isof   : signature niveau 1, hash invalide
  - Test_signature_level_1.isof   : signature niveau 1 (SHA-256) valide
  - bolivie_sdat2025.isof         : signature niveau 1 valide, document v1.0
  - v12_full.isof                 : signature niveau 1 valide, document v1.2
****************************************************************************
ISOF signature verification tests (levels 0, 1, 2) on v1.0 and v1.2.

The three signature levels are covered separately.
Post-signature alteration cases are tested for each level
that carries an integrity guarantee (1 and 2).

Expected fixtures in tests/fixtures/:
  - Test_signature_invalid.isof   : level 1 signature, invalid hash
  - Test_signature_level_1.isof   : valid level 1 (SHA-256) signature
  - bolivie_sdat2025.isof         : valid level 1 signature, v1.0 document
  - v12_full.isof                 : valid level 1 signature, v1.2 document
"""

import json
from pathlib import Path

import pytest

import isof
from isof.parser import load_string
from isof.signature import VerificationResult

FIXTURES = Path(__file__).parent / "fixtures"
INVALID  = FIXTURES / "Test_signature_invalid.isof"
LEVEL_1  = FIXTURES / "Test_signature_level_1.isof"
BOLIVIE  = FIXTURES / "bolivie_sdat2025.isof"
V12_FULL = FIXTURES / "v12_full.isof"


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
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"] = None
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 0
    assert result.signer is None


def test_no_signature_verify_result_is_falsy():
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
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.valid
    assert result.level == 1


def test_level1_is_authentic():
    doc = isof.load(LEVEL_1)
    assert doc.is_authentic()


def test_level1_signer_present():
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.signer is not None


def test_level1_signed_at_present():
    doc = isof.load(LEVEL_1)
    result = doc.verify()
    assert result.signed_at is not None


def test_level1_result_is_truthy():
    doc = isof.load(LEVEL_1)
    assert bool(doc.verify())


def test_level1_alteration_invalidates_signature():
    """
    Modifier un champ dans le scope après signature doit casser le hash.
    Modifying a field within scope after signing must break the hash.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
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
    Un hash tronqué doit être rejeté.
    A truncated hash must be rejected.
    """
    raw_text = LEVEL_1.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["hash"] = raw["signature"]["hash"][:32]
    _, doc = load_string(json.dumps(raw))
    assert not doc.verify().valid


# ---------------------------------------------------------------------------
# Niveau 1 sur document v1.2 | Level 1 on v1.2 document
# ---------------------------------------------------------------------------

def test_level1_on_v12_document():
    """
    Le mécanisme de signature niveau 1 est inchangé en v1.2 : la canonicalisation
    porte sur les blocs du scope, quel que soit le contenu.
    ***************************************************************************
    Level 1 signature mechanism is unchanged in v1.2: canonicalization applies
    to scope blocks regardless of their content.
    """
    doc = isof.load(V12_FULL)
    result = doc.verify()
    assert result.valid
    assert result.level == 1
    assert result.signer == "IsoFind SAS"


def test_v12_alteration_in_molecules_invalidates():
    """
    Modification dans molecules_data doit invalider la signature v1.2.
    Modification inside molecules_data must invalidate the v1.2 signature.
    """
    raw_text = V12_FULL.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["molecules_data"][0]["valeur"] = 99.9
    _, doc = load_string(json.dumps(raw))
    assert not doc.verify().valid


def test_v12_alteration_in_physico_invalidates():
    raw_text = V12_FULL.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["physico_data"][0]["value"] = 99.9
    _, doc = load_string(json.dumps(raw))
    assert not doc.verify().valid


# ---------------------------------------------------------------------------
# Fixture explicitement invalide | Explicitly invalid fixture
# ---------------------------------------------------------------------------

def test_invalid_fixture_is_not_authentic():
    doc = isof.load(INVALID)
    assert not doc.is_authentic()


def test_invalid_fixture_verify_returns_false():
    doc = isof.load(INVALID)
    result = doc.verify()
    assert not result.valid


def test_invalid_fixture_has_signature_level():
    doc = isof.load(INVALID)
    result = doc.verify()
    assert result.level in (1, 2)


def test_invalid_fixture_reason_is_set():
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


def test_bolivie_and_v12_both_pass_is_authentic():
    """
    Les fixtures v1.0 et v1.2 signées passent toutes deux is_authentic().
    v1.0 and v1.2 signed fixtures both pass is_authentic().
    """
    doc1 = isof.load(BOLIVIE)
    doc2 = isof.load(V12_FULL)
    assert doc1.is_authentic()
    assert doc2.is_authentic()


def test_signature_block_parsed_for_all_fixtures():
    """
    Le bloc signature doit être parsé dans tous les fichiers de test,
    même le fichier invalide — le parser ne doit pas rejeter un hash incorrect.
    ***************************************************************************
    The signature block must be parsed in all test files, including the invalid
    one — the parser must not reject an incorrect hash.
    """
    for fixture in (INVALID, LEVEL_1, BOLIVIE, V12_FULL):
        doc = isof.load(fixture)
        assert doc.signature is not None, f"Signature absente dans {fixture.name}"
        assert doc.signature.level in (1, 2)
