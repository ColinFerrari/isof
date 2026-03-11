"""
Tests du parser ISOF.

Les cas limites et les comportements non évidents sont testés en priorité
plutôt que les chemins heureux, ces derniers sont couverts par les exemples
dans le README.
****************************************************************************
ISOF parser tests.

Edge cases and non-obvious behaviors are tested first
rather than happy paths; the latter are covered by the examples
in the README.
"""

import hashlib
import json
from pathlib import Path

import pytest

import isof
from isof.exceptions import ISOfParseError, ISOfVersionError
from isof.parser import load_string

FIXTURES = Path(__file__).parent / "fixtures"
BOLIVIE  = FIXTURES / "bolivie_sdat2025.isof"


# ---------------------------------------------------------------------------
# Chargement de base | basic loadings
# ---------------------------------------------------------------------------

def test_load_fixture():
    doc = isof.load(BOLIVIE)
    assert doc.version == "1.0"
    assert len(doc.samples) == 2


def test_repr_contains_sample_count():
    doc = isof.load(BOLIVIE)
    assert "2 échantillon(s)" in repr(doc)


def test_created_by():
    doc = isof.load(BOLIVIE)
    assert doc.created_by is not None
    assert doc.created_by.organisation == "IsoFind SAS"
    assert doc.created_by.operator == "Colin Ferrari"


def test_project():
    doc = isof.load(BOLIVIE)
    assert doc.project is not None
    assert doc.project.reference == "SDAT-2025-007"


# ---------------------------------------------------------------------------
# Échantillons et données isotopiques | Samples and isoopic data
# ---------------------------------------------------------------------------

def test_sample_lookup():
    doc = isof.load(BOLIVIE)
    s = doc.sample("1")
    assert s is not None
    assert s.name == "BOL-24-01"
    assert s.classification == "source"


def test_sample_not_found():
    doc = isof.load(BOLIVIE)
    assert doc.sample("999") is None


def test_sample_has_coordinates():
    doc = isof.load(BOLIVIE)
    s = doc.sample("1")
    assert s.has_coordinates()
    assert abs(s.latitude - (-17.3895)) < 1e-6


def test_isotope_data():
    doc = isof.load(BOLIVIE)
    s = doc.sample("1")
    assert len(s.isotope_data) == 1
    iso = s.isotope_data[0]
    assert iso.element == "Sb"
    assert iso.ratio == pytest.approx(0.74815)
    assert iso.standard == "NIST SRM 3102a"


def test_elements():
    doc = isof.load(BOLIVIE)
    s = doc.sample("1")
    assert s.elements() == ["Sb"]


def test_filter_by_element():
    doc = isof.load(BOLIVIE)
    results = doc.filter_samples(element="Sb")
    assert len(results) == 2


def test_filter_by_classification():
    doc = isof.load(BOLIVIE)
    sources = doc.filter_samples(classification="source")
    assert len(sources) == 1
    assert sources[0].id == "1"


def test_filter_combined():
    doc = isof.load(BOLIVIE)
    results = doc.filter_samples(element="Sb", classification="fille")
    assert len(results) == 1
    assert results[0].id == "2"


# ---------------------------------------------------------------------------
# Méthodes et pipelines | Pipelines and methods
# ---------------------------------------------------------------------------

def test_methods_loaded():
    doc = isof.load(BOLIVIE)
    assert "chromato-sb-ag1" in doc.methods
    m = doc.methods["chromato-sb-ag1"]
    assert m.type == "purification"
    assert m.yield_min_pct == pytest.approx(88.0)
    assert len(m.steps) == 4
    assert m.reference.doi == "10.1039/C9JA00288J"


def test_pipeline_stages():
    doc = isof.load(BOLIVIE)
    assert "sb-minerai" in doc.pipelines
    p = doc.pipelines["sb-minerai"]
    assert len(p.stages) == 3
    assert p.stages[1].method_key == "chromato-sb-ag1"


# ---------------------------------------------------------------------------
# Rendements de purification | Purification yield
# ---------------------------------------------------------------------------

def test_purification_yields():
    doc = isof.load(BOLIVIE)
    yields = doc.yields_for_sample("1")
    assert len(yields) == 1
    assert yields[0].element == "Sb"
    assert yields[0].value_pct == pytest.approx(93.4)


def test_no_suspicious_yields():
    doc = isof.load(BOLIVIE)
    assert doc.suspicious_yields() == []


def test_suspicious_yield_detection():
    """
    Un rendement > 105 % doit être détecté comme suspect.
    A yield > 105% should be detected as suspect.
    """
    raw_text = Path(BOLIVIE).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["purification"]["1_Sb"]["value_pct"] = 112.5
    _, doc = load_string(json.dumps(raw))
    suspicious = doc.suspicious_yields()
    assert len(suspicious) == 1
    assert suspicious[0].value_pct == pytest.approx(112.5)


# ---------------------------------------------------------------------------
# Vérification de signature, niveau 1 | Signature verification, level 1
# ---------------------------------------------------------------------------

def _make_valid_signature(raw: dict) -> dict:
    """
    Recalcule un hash SHA-256 valide pour le document donné.
    Recalculates a valid SHA-256 hash for the given document.
    """
    sig = raw.get("signature", {})
    scope = sig.get("scope", ["samples", "methods", "purification"])
    payload = {block: raw.get(block) for block in scope}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_signature_invalid_with_placeholder():
    """
    La fixture bolivie contient un hash SHA-256 valide calculé sur les données.
    is_authentic() doit retourner True.

    The bolivie fixture contains a valid SHA-256 hash calculated on the data.
    is_authentic() must return True.
    """
    doc = isof.load(BOLIVIE)
    assert doc.is_authentic()


def test_signature_valid_after_recalculation():
    raw_text = Path(BOLIVIE).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["hash"] = _make_valid_signature(raw)
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert result.valid
    assert result.level == 1
    assert result.signer == "IsoFind SAS"


def test_signature_invalid_after_data_modification():
    """
    Modifier une valeur après avoir calculé le hash doit invalider la signature.
    Changing a value after calculating the hash should invalidate the signature.
    """
    raw_text = Path(BOLIVIE).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"]["hash"] = _make_valid_signature(raw)
    # Modification post-signature, simule une altération du fichier
    # Post-signature modification, simulates file alteration
    raw["samples"][0]["name"] = "NOM_ALTERE"
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert "modifiées" in result.reason


def test_no_signature():
    raw_text = Path(BOLIVIE).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["signature"] = None
    _, doc = load_string(json.dumps(raw))
    result = doc.verify()
    assert not result.valid
    assert result.level == 0


# ---------------------------------------------------------------------------
# Erreurs de parsing | Parsing errors
# ---------------------------------------------------------------------------

def test_invalid_json():
    with pytest.raises(ISOfParseError, match="JSON invalide"):
        isof.loads("{ pas du json valide }")


def test_missing_version():
    with pytest.raises(ISOfParseError, match="isof_version"):
        isof.loads('{"samples": []}')


def test_unsupported_version():
    with pytest.raises(ISOfVersionError) as exc_info:
        isof.loads('{"isof_version": "99.0", "samples": []}')
    assert exc_info.value.found == "99.0"
    assert "1.0" in exc_info.value.supported


def test_samples_not_a_list():
    with pytest.raises(ISOfParseError, match="tableau"):
        isof.loads('{"isof_version": "1.0", "samples": {}}')


def test_file_not_found():
    with pytest.raises(ISOfParseError, match="introuvable"):
        isof.load("/tmp/fichier_inexistant_isof_test.isof")


# ---------------------------------------------------------------------------
# Export pandas | Pandas export
# ---------------------------------------------------------------------------

def test_to_pandas():
    pd = pytest.importorskip("pandas")
    doc = isof.load(BOLIVIE)
    df = doc.to_pandas()
    assert len(df) == 2   # 2 échantillons × 1 mesure Sb chacun
    assert "ratio" in df.columns
    assert "element" in df.columns
    assert set(df["element"].unique()) == {"Sb"}


def test_to_pandas_sample_metadata_present():
    pd = pytest.importorskip("pandas")
    doc = isof.load(BOLIVIE)
    df = doc.to_pandas()
    assert "sample_name" in df.columns
    assert "BOL-24-01" in df["sample_name"].values


def test_to_pandas_missing_if_not_installed(monkeypatch):
    import builtins
    real_import = builtins.__import__

    def mock_import(name, *args, **kwargs):
        if name == "pandas":
            raise ImportError("pandas non disponible")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", mock_import)
    doc = isof.load(BOLIVIE)
    with pytest.raises(ImportError, match="pip install"):
        doc.to_pandas()