"""
Tests du parser ISOF pour les versions 1.0, 1.1 et 1.2.

Les cas limites et les comportements non évidents sont testés en priorité
plutôt que les chemins heureux, ces derniers sont couverts par les exemples
dans le README.

La rétrocompatibilité est vérifiée avec la fixture historique v1.0 bolivie,
et les nouveaux blocs v1.2 avec la fixture v12_full ainsi qu'avec un
fichier réel produit par IsoFind (real_v11_with_v12_blocks).
****************************************************************************
ISOF parser tests for versions 1.0, 1.1 and 1.2.

Edge cases and non-obvious behaviors are tested first
rather than happy paths; the latter are covered by the examples
in the README.

Backward compatibility is checked with the historical v1.0 bolivie fixture,
and new v1.2 blocks with the v12_full fixture as well as with a real
IsoFind-produced file (real_v11_with_v12_blocks).
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
V12_FULL = FIXTURES / "v12_full.isof"
REAL_V11 = FIXTURES / "real_v11_with_v12_blocks.isof"


# ---------------------------------------------------------------------------
# Chargement de base | basic loadings
# ---------------------------------------------------------------------------

def test_load_fixture():
    doc = isof.load(BOLIVIE)
    assert doc.version == "1.0"
    assert len(doc.samples) == 2


def test_load_v12_full():
    """
    La fixture v1.2 complète doit charger sans erreur avec les trois familles.
    v1.2 full fixture must load without error with all three families.
    """
    doc = isof.load(V12_FULL)
    assert doc.version == "1.2"
    assert len(doc.samples) == 2


def test_load_real_v11_with_v12_blocks():
    """
    Fichier réel IsoFind déclaré v1.1 mais contenant déjà les blocs v1.2.

    Vérifie la tolérance : un fichier minor-version antérieur peut embarquer
    des blocs introduits plus tard sans déclencher d'erreur de version.
    ***************************************************************************
    Real IsoFind file declared v1.1 but already carrying v1.2 blocks.

    Checks tolerance: an earlier minor-version file may embed blocks introduced
    later without triggering a version error.
    """
    doc = isof.load(REAL_V11)
    assert doc.version == "1.1"
    assert len(doc.samples) >= 1
    s = doc.samples[0]
    # Au moins une des trois familles v1.2 doit être présente pour justifier le test
    # At least one v1.2 family must be present to justify the test
    total_v12 = len(s.geochem_data) + len(s.physico_data) + len(s.molecules_data)
    assert total_v12 > 0


def test_repr_contains_sample_count():
    doc = isof.load(BOLIVIE)
    assert "2 échantillon(s)" in repr(doc)


def test_repr_reflects_version():
    doc = isof.load(V12_FULL)
    assert "v1.2" in repr(doc)


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


def test_elements_combines_isotope_and_geochem():
    """
    La méthode elements() v1.2 doit lister les éléments présents soit en
    isotopie, soit en géochimie. Un élément comme As mesuré uniquement en
    concentration remonte donc bien.
    ***************************************************************************
    The v1.2 elements() method must list elements present in either isotope
    or geochem families. An element like As measured only as concentration
    is therefore correctly surfaced.
    """
    doc = isof.load(V12_FULL)
    s = doc.sample("101")
    elements = s.elements()
    assert "Sb" in elements  # présent en isotope ET géochim
    assert "As" in elements  # présent uniquement en géochim


def test_elements_v10_unaffected():
    """
    Sur un fichier v1.0 sans bloc géochim, le comportement historique est intact.
    On a v1.0 file without geochem block, historical behavior is preserved.
    """
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


def test_filter_element_covers_geochem_only():
    """
    Filtrer par un élément présent uniquement en géochim doit remonter
    l'échantillon — v1.2 élargit le critère de filtrage.
    ***************************************************************************
    Filtering by an element present only in geochem must surface the sample —
    v1.2 widens the filter criterion.
    """
    doc = isof.load(V12_FULL)
    results = doc.filter_samples(element="As")
    assert len(results) == 1
    assert results[0].id == "101"


# ---------------------------------------------------------------------------
# Familles v1.2 | v1.2 families
# ---------------------------------------------------------------------------

def test_geochem_data_parsed():
    """
    Les entrées géochimiques sont désérialisées avec leurs deux représentations :
    value_normalized (mg/kg pivot) et display_value/display_unit (saisie d'origine).
    ***************************************************************************
    Geochem entries are deserialized with both representations: value_normalized
    (mg/kg pivot) and display_value/display_unit (original entry unit).
    """
    doc = isof.load(V12_FULL)
    s = doc.sample("101")
    assert len(s.geochem_data) == 2
    sb = [g for g in s.geochem_data if g.element == "Sb"][0]
    assert sb.value_normalized == pytest.approx(0.45)
    assert sb.display_value == pytest.approx(450.0)
    assert sb.display_unit == "µg/L"
    assert sb.method == "ICP-MS"


def test_physico_data_parsed():
    doc = isof.load(V12_FULL)
    s = doc.sample("101")
    assert len(s.physico_data) == 2
    ph = s.physico_parameter("pH")
    assert ph is not None
    assert ph.value == pytest.approx(4.5)


def test_physico_parameter_absent_returns_none():
    """
    physico_parameter() retourne None si l'identifiant demandé est absent,
    plutôt que de lever une exception — comportement conçu pour composer
    facilement dans des expressions conditionnelles.
    ***************************************************************************
    physico_parameter() returns None when the requested identifier is absent,
    rather than raising — designed for easy composition in conditional
    expressions.
    """
    doc = isof.load(V12_FULL)
    s = doc.sample("101")
    assert s.physico_parameter("conductivity") is None


def test_molecules_data_parsed():
    doc = isof.load(V12_FULL)
    s = doc.sample("101")
    assert len(s.molecules_data) == 2
    atrazine = [m for m in s.molecules_data if m.nom == "Atrazine"][0]
    assert atrazine.cas == "1912-24-9"
    assert atrazine.famille == "herbicide"
    assert atrazine.conforme is False
    assert atrazine.seuil_ref == pytest.approx(0.1)


def test_molecule_is_non_compliant():
    """
    La propriété is_non_compliant ne remonte que les cas explicitement False.
    Les None (donnée manquante) ne doivent pas être interprétés.
    ***************************************************************************
    The is_non_compliant property surfaces only explicit False values.
    None (missing data) must not be interpreted as non-compliance.
    """
    doc = isof.load(V12_FULL)
    alerts = doc.non_compliant_molecules()
    assert len(alerts) == 1
    sample, molecule = alerts[0]
    assert sample.id == "101"
    assert molecule.nom == "Atrazine"


def test_v12_families_absent_on_v10_file():
    """
    Sur un fichier v1.0 sans blocs v1.2, les tuples doivent être vides,
    pas absents. Cela garantit que les appelants peuvent itérer sans vérifier.
    ***************************************************************************
    On a v1.0 file without v1.2 blocks, the tuples must be empty, not absent.
    This ensures callers can iterate without checking.
    """
    doc = isof.load(BOLIVIE)
    s = doc.sample("1")
    assert s.geochem_data == tuple()
    assert s.physico_data == tuple()
    assert s.molecules_data == tuple()


def test_material_type_falls_back_to_matrix():
    """
    v1.2 introduit l'alias `matrix` pour material_type.
    Le parser doit accepter les deux noms de champ.
    ***************************************************************************
    v1.2 introduces the `matrix` alias for material_type.
    Parser must accept both field names.
    """
    # Reconstruire un sample minimal avec matrix mais pas material_type
    # Build a minimal sample with matrix but not material_type
    raw = {
        "isof_version": "1.2",
        "samples": [{"id": "s1", "matrix": "Water", "isotope_data": []}],
    }
    _, doc = load_string(json.dumps(raw))
    assert doc.samples[0].material_type == "Water"


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

def _make_valid_signature(raw: dict) -> str:
    """
    Recalcule un hash SHA-256 valide pour le document donné.
    Recalculates a valid SHA-256 hash for the given document.
    """
    sig = raw.get("signature", {})
    scope = sig.get("scope", ["samples", "methods", "purification"])
    payload = {block: raw.get(block) for block in scope}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def test_signature_valid_bolivie():
    """
    La fixture bolivie contient un hash SHA-256 valide calculé sur les données.
    is_authentic() doit retourner True.

    The bolivie fixture contains a valid SHA-256 hash calculated on the data.
    is_authentic() must return True.
    """
    doc = isof.load(BOLIVIE)
    assert doc.is_authentic()


def test_signature_v12_valid():
    """
    La fixture v12_full est signée à la génération. Doit vérifier positivement.
    v12_full fixture is signed at generation time. Must verify positively.
    """
    doc = isof.load(V12_FULL)
    result = doc.verify()
    assert result.valid
    assert result.level == 1


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


def test_v12_signature_invalid_after_geochem_modification():
    """
    En v1.2, une modification dans geochem_data doit invalider la signature
    au même titre qu'une modification de isotope_data : le scope 'samples'
    couvre l'intégralité de chaque échantillon.
    ***************************************************************************
    In v1.2, a modification inside geochem_data must invalidate the signature
    just like an isotope_data modification: the 'samples' scope covers the
    entirety of each sample.
    """
    raw_text = Path(V12_FULL).read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["samples"][0]["geochem_data"][0]["value_normalized"] = 999.0
    _, doc = load_string(json.dumps(raw))
    assert not doc.verify().valid


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
    assert "1.1" in exc_info.value.supported
    assert "1.2" in exc_info.value.supported


def test_samples_not_a_list():
    with pytest.raises(ISOfParseError, match="tableau"):
        isof.loads('{"isof_version": "1.0", "samples": {}}')


def test_file_not_found():
    with pytest.raises(ISOfParseError, match="introuvable"):
        isof.load("/tmp/fichier_inexistant_isof_test.isof")


# ---------------------------------------------------------------------------
# Export pandas multi-familles | Multi-family pandas export
# ---------------------------------------------------------------------------

def test_to_pandas_isotope_default():
    pd = pytest.importorskip("pandas")
    doc = isof.load(BOLIVIE)
    df = doc.to_pandas()
    assert len(df) == 2   # 2 échantillons × 1 mesure Sb chacun
    assert "ratio" in df.columns
    assert set(df["element"].unique()) == {"Sb"}


def test_to_pandas_geochem():
    """
    to_pandas(family='geochem') produit une ligne par mesure géochim
    avec les métadonnées d'échantillon dupliquées.
    ***************************************************************************
    to_pandas(family='geochem') yields one row per geochem measurement
    with duplicated sample metadata.
    """
    pd = pytest.importorskip("pandas")
    doc = isof.load(V12_FULL)
    df = doc.to_pandas(family="geochem")
    assert len(df) == 2   # 2 mesures géochim sur l'échantillon 101
    assert "value_normalized" in df.columns
    assert "display_unit" in df.columns
    assert set(df["element"].unique()) == {"Sb", "As"}


def test_to_pandas_physico():
    pd = pytest.importorskip("pandas")
    doc = isof.load(V12_FULL)
    df = doc.to_pandas(family="physico")
    assert len(df) == 3   # 2 sur ech 101 + 1 sur ech 102
    assert "parameter" in df.columns
    assert "pH" in df["parameter"].values


def test_to_pandas_molecules():
    pd = pytest.importorskip("pandas")
    doc = isof.load(V12_FULL)
    df = doc.to_pandas(family="molecules")
    assert len(df) == 2
    assert "cas" in df.columns
    assert "1912-24-9" in df["cas"].values


def test_to_pandas_rejects_unknown_family():
    pd = pytest.importorskip("pandas")
    doc = isof.load(V12_FULL)
    with pytest.raises(ValueError, match="Unknown family"):
        doc.to_pandas(family="rien")


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


# ---------------------------------------------------------------------------
# Robustesse : champs de haut niveau et 'project' textuel (fichier reel Oruro)
# Robustness: top-level fields and string 'project' (real Oruro file)
# ---------------------------------------------------------------------------

def test_project_as_string_is_accepted():
    # Le fichier Oruro stocke 'project' comme une chaine, pas comme un objet.
    doc = isof.load(FIXTURES / "oruro-bolivia-sb-2025.isof")
    assert doc.project is not None
    assert isinstance(doc.project.name, str)
    assert "Oruro" in doc.project.name


def test_top_level_doi_date_location_are_read():
    doc = isof.load(FIXTURES / "oruro-bolivia-sb-2025.isof")
    assert doc.doi == "10.1007/s11270-025-08445-6"
    assert doc.date == "2025"
    assert doc.location is not None
    assert doc.location.name == "Oruro"
    assert doc.location.country == "Bolivia"


def test_oruro_level2_signature_is_valid():
    doc = isof.load(FIXTURES / "oruro-bolivia-sb-2025.isof")
    result = doc.verify()
    assert result.valid is True
    assert result.level == 2
