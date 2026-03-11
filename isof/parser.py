"""
Lecture et désérialisation de documents ISOF.

Le parser est volontairement permissif sur les champs optionnels :
beaucoup de logiciels qui écrivent du ISOF omettront des champs
que la spec marque comme optionnels. Il est préférablede charger avec None
plutôt que lever une exception, les utilisateurs peuvent toujours
inspecter les données et décider quoi en faire.

En revanche, les invariants structurels sont stricts : version,
présence du tableau samples, cohérence du bloc signature.
**********************************************************************
Reading and deserializing ISOF documents.

The parser is intentionally permissive regarding optional fields:
many software programs that write ISOF will omit fields
that the specification marks as optional. It is preferable to load with None
rather than raise an exception; users can still
inspect the data and decide what to do with it.

On the other hand, structural invariants are strict: version,
presence of the samples array, and consistency of the signature block.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from .exceptions import ISOfParseError, ISOfVersionError
from .models import (
    Assignment,
    CreatedBy,
    IsotopeRecord,
    Method,
    MethodEquipment,
    MethodReference,
    MethodStep,
    Pipeline,
    PipelineStage,
    Project,
    PurificationYield,
    Sample,
    Signature,
)

SUPPORTED_VERSIONS = ("1.0",)


def load_file(path: Union[str, Path]) -> tuple[dict, "ISOfDocument"]:
    """
    Charge un fichier .isof depuis le disque.

    Retourne le dict brut (pour la vérification de signature)
    et le document parsé. On garde les deux séparément,
    la vérification de signature opère sur le JSON brut, pas sur
    les dataclasses reconstruites.
    **************************************************************************
    Loads an .isof file from disk.

    Returns the raw dictionary (for signature verification)
    and the parsed document. We keep both separate;
    signature verification operates on the raw JSON, not on
    the reconstructed dataclasses.
    """
    path = Path(path)
    if not path.exists():
        raise ISOfParseError(f"Fichier introuvable : {path}")

    try:
        raw_text = path.read_text(encoding="utf-8")
    except OSError as e:
        raise ISOfParseError(f"Unable to read the file: {e}") from e

    return load_string(raw_text)


def load_string(text: str) -> tuple[dict, "ISOfDocument"]:
    """
    Parse un document ISOF depuis une chaîne JSON.
    Parses an ISOF document from a JSON string.
    """
    try:
        raw = json.loads(text)
    except json.JSONDecodeError as e:
        raise ISOfParseError(f"JSON invalide : {e}") from e

    if not isinstance(raw, dict):
        raise ISOfParseError("The ISOF document must be a JSON object, not an array or a primitive value")

    return raw, _parse_document(raw)


# ---------------------------------------------------------------------------
# Document principal | Main document
# ---------------------------------------------------------------------------

class ISOfDocument:
    """
    Représentation en mémoire d'un document ISOF chargé.

    Une classe est utilisée plutôt qu'une dataclass pour pouvoir attacher
    des méthodes de haut niveau (is_authentic, to_pandas, etc.) sans
    alourdir les modèles de données.
    **************************************************************************
    In-memory representation of a loaded ISOF document.

    A class is used rather than a dataclass to allow the attachment of
    high-level methods (is_authentic, to_pandas, etc.) without
    increasing the complexity of the data models.
    """

    def __init__(
        self,
        version: str,
        created_at: Optional[str],
        created_by: Optional[CreatedBy],
        project: Optional[Project],
        samples: tuple[Sample, ...],
        methods: dict[str, Method],
        pipelines: dict[str, Pipeline],
        purification: dict[str, PurificationYield],
        assignments: tuple[Assignment, ...],
        signature: Optional[Signature],
        _raw: Optional[dict] = None,
    ) -> None:
        self.version = version
        self.created_at = created_at
        self.created_by = created_by
        self.project = project
        self.samples = samples
        self.methods = methods
        self.pipelines = pipelines
        self.purification = purification
        self.assignments = assignments
        self.signature = signature
        self._raw = _raw   # conservé pour la vérification de signature | kept for signature verification

    def __repr__(self) -> str:
        n = len(self.samples)
        org = self.created_by.organisation if self.created_by else "?"
        return f"<ISOfDocument v{self.version} — {n} échantillon(s) — {org}>"

    # ------------------------------------------------------------------
    # Accès aux données | Data access
    # ------------------------------------------------------------------

    def sample(self, sample_id: str) -> Optional[Sample]:
        """
        Cherche un échantillon par son identifiant.
        Search for a sample by its identifier.
        """
        for s in self.samples:
            if s.id == sample_id:
                return s
        return None

    def filter_samples(
        self,
        element: Optional[str] = None,
        classification: Optional[str] = None,
        material_type: Optional[str] = None,
    ) -> tuple[Sample, ...]:
        """
        Filtre les échantillons selon un ou plusieurs critères.

        Les critères sont combinés en AND. On retourne un tuple pour
        rester cohérent avec le type de samples.
        *******************************************************************
        Filters samples according to one or more criteria.

        The criteria are combined using an AND operation. A tuple is returned to
        maintain consistency with the sample type.
        """
        result = list(self.samples)
        if element:
            el = element.upper()
            result = [s for s in result if el in [e.upper() for e in s.elements()]]
        if classification:
            result = [s for s in result if s.classification == classification]
        if material_type:
            result = [s for s in result if s.material_type == material_type]
        return tuple(result)

    def yields_for_sample(self, sample_id: str) -> list[PurificationYield]:
        """
        Rendements de purification associés à un échantillon.
        Purification yield associated to a sample.
        """
        return [y for y in self.purification.values() if y.sample_id == sample_id]

    def suspicious_yields(self) -> list[PurificationYield]:
        """
        Rendements > 105 % : indicateurs de contamination potentielle.
        Yield > 105%: indicator of potential contamination.
        """
        return [y for y in self.purification.values() if y.is_suspicious]

    # ------------------------------------------------------------------
    # Vérification d'intégrité | Integrity check
    # ------------------------------------------------------------------

    def is_authentic(self) -> bool:
        """
        Vérifie l'intégrité et l'authenticité du document.

        Retourne True uniquement si la signature est présente ET valide.
        Un document sans signature retourne False, c'est un choix délibéré :
        l'absence de signature n'est pas une validation implicite.
        ******************************************************************
        Verifies the integrity and authenticity of the document.

        Returns True only if the signature is present AND valid.
        A document without a signature returns False; this is a deliberate choice:
        the absence of a signature is not an implicit validation.
        """
        result = self.verify()
        return result.valid

    def verify(self) -> "VerificationResult":  # noqa: F821
        """
        Vérification détaillée, retourne un VerificationResult.

        Préférer is_authentic() pour un simple bool, verify() pour
        accéder à level, signer, signed_at et reason.
        *****************************************************************
        Detailed verification returns a VerificationResult.

        Prefer is_authentic() for a simple boolean, and verify() to 
        access level, signer, signed_at, and reason.
        """
        from .signature import verify, _NO_SIGNATURE

        if self.signature is None:
            return _NO_SIGNATURE
        if self._raw is None:
            # Ne devrait pas arriver si le document a été chargé via load() | should not happen if the document was loaded via load()
            from .signature import VerificationResult
            return VerificationResult(
                valid=False, level=0,
                reason="Raw data not available (document created programmatically?)",
                signer=None, signed_at=None
            )
        return verify(self._raw, self.signature)

    # ------------------------------------------------------------------
    # Export vers d'autres formats | Export to other formats
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        """
        Retourne le document brut original tel que chargé depuis le fichier.
        Returns the original raw document as loaded from the file.
        """
        if self._raw is not None:
            return self._raw
        raise NotImplementedError("to_dict() is not available for programmatically created documents")

    def to_pandas(self):
        """
        Convertit les données isotopiques en DataFrame pandas.

        Nécessite pandas : pip install python-isof[pandas]

        Le DataFrame a une ligne par mesure isotopique (pas par échantillon),
        avec les colonnes de métadonnées de l'échantillon dupliquées sur
        chaque ligne, format "tidy" adapté à l'analyse exploratoire.
        *****************************************************************
        Converts isotopic data into a pandas DataFrame.

        Requires pandas: `pip install python-isof[pandas]`
        The DataFrame has one row per isotopic measurement (not per sample),
        with the sample metadata columns duplicated on
        each row, a "tidy" format suitable for exploratory analysis.
        """
        try:
            import pandas as pd
        except ImportError:
            raise ImportError(
                "pandas is required for to_pandas(). "
                "Install it with: pip install python-isof[pandas]"
            ) from None

        rows = []
        for sample in self.samples:
            base = {
                "sample_id":      sample.id,
                "sample_name":    sample.name,
                "classification": sample.classification,
                "material_type":  sample.material_type,
                "sector":         sample.sector,
                "project":        sample.project,
                "latitude":       sample.latitude,
                "longitude":      sample.longitude,
                "collection_date":sample.collection_date,
                "collector":      sample.collector,
            }
            if not sample.isotope_data:
                # On inclut quand même l'échantillon sans mesures pour ne pas perdre de données à l'export
                # We still include the sample without measurements to avoid losing data during export.
                rows.append({**base, "element": None, "system": None,
                             "ratio": None, "ratio_2se": None})
                continue
            for iso in sample.isotope_data:
                rows.append({
                    **base,
                    "element":        iso.element,
                    "system":         iso.system,
                    "ratio":          iso.ratio,
                    "ratio_2se":      iso.ratio_2se,
                    "delta_notation": iso.delta_notation,
                    "delta_value":    iso.delta_value,
                    "delta_2sd":      iso.delta_2sd,
                    "standard":       iso.standard,
                    "n_cycles":       iso.n_cycles,
                    "instrument":     iso.instrument,
                    "session_date":   iso.session_date,
                })

        return pd.DataFrame(rows)

    def to_csv(self, path: Union[str, Path], **kwargs) -> None:
        """
        Raccourci vers to_pandas().to_csv().

        Les kwargs sont passés directement à pandas.DataFrame.to_csv.
        Par défaut : index=False pour un CSV propre.
        *********************************************************************
        Shortcut to `to_pandas().to_csv()`.

        Kwargs are passed directly to `pandas.DataFrame.to_csv()`.
        Default: `index=False` for a clean CSV.
        """
        kwargs.setdefault("index", False)
        self.to_pandas().to_csv(path, **kwargs)


# ---------------------------------------------------------------------------
# Fonctions de désérialisation internes | Internal deserialization functions
# ---------------------------------------------------------------------------

def _parse_document(raw: dict) -> ISOfDocument:
    version = raw.get("isof_version")
    if not version:
        raise ISOfParseError("The 'isof_version' field is missing; this file may not be an ISOF document.")
    if str(version) not in SUPPORTED_VERSIONS:
        raise ISOfVersionError(str(version), SUPPORTED_VERSIONS)

    samples_raw = raw.get("samples")
    if not isinstance(samples_raw, list):
        raise ISOfParseError("Le champ 'samples' doit être un tableau JSON")

    return ISOfDocument(
        version    = str(version),
        created_at = raw.get("created_at"),
        created_by = _parse_created_by(raw.get("created_by")),
        project    = _parse_project(raw.get("project")),
        samples    = tuple(_parse_sample(s) for s in samples_raw),
        methods    = {k: _parse_method(k, v) for k, v in (raw.get("methods") or {}).items()},
        pipelines  = {k: _parse_pipeline(k, v) for k, v in (raw.get("pipelines") or {}).items()},
        purification = _parse_purification(raw.get("purification") or {}),
        assignments  = tuple(_parse_assignment(a) for a in (raw.get("assignments") or [])),
        signature    = _parse_signature(raw.get("signature")),
        _raw         = raw,
    )


def _parse_created_by(data: Optional[dict]) -> Optional[CreatedBy]:
    if not data:
        return None
    return CreatedBy(
        software         = data.get("software"),
        software_version = data.get("software_version"),
        operator         = data.get("operator"),
        organisation     = data.get("organisation"),
    )


def _parse_project(data: Optional[dict]) -> Optional[Project]:
    if not data:
        return None
    return Project(
        name           = data.get("name"),
        reference      = data.get("reference"),
        client         = data.get("client"),
        classification = data.get("classification"),
        notes          = data.get("notes"),
    )


def _parse_sample(data: dict) -> Sample:
    if "id" not in data:
        raise ISOfParseError(f"Sample without 'id' field: {data}")
    return Sample(
        id              = str(data["id"]),
        name            = data.get("name"),
        classification  = data.get("classification"),
        material_type   = data.get("material_type"),
        sector          = data.get("sector"),
        project         = data.get("project"),
        latitude        = _float_or_none(data.get("latitude")),
        longitude       = _float_or_none(data.get("longitude")),
        altitude_m      = _float_or_none(data.get("altitude_m")),
        collection_date = data.get("collection_date"),
        collector       = data.get("collector"),
        description     = data.get("description"),
        workflow_stage  = data.get("workflow_stage"),
        isotope_data    = tuple(_parse_isotope(iso) for iso in (data.get("isotope_data") or [])),
    )


def _parse_isotope(data: dict) -> IsotopeRecord:
    return IsotopeRecord(
        element        = data.get("element"),
        system         = data.get("system"),
        ratio          = _float_or_none(data.get("ratio")),
        ratio_2se      = _float_or_none(data.get("ratio_2se")),
        delta_notation = data.get("delta_notation"),
        delta_value    = _float_or_none(data.get("delta_value")),
        delta_2sd      = _float_or_none(data.get("delta_2sd")),
        standard       = data.get("standard"),
        n_cycles       = _int_or_none(data.get("n_cycles")),
        session_date   = data.get("session_date"),
        instrument     = data.get("instrument"),
        notes          = data.get("notes"),
    )


def _parse_method(key: str, data: dict) -> Method:
    eq = data.get("equipment") or {}
    ref = data.get("reference") or {}
    return Method(
        key             = key,
        name            = data.get("name") or key,
        type            = data.get("type"),
        element         = data.get("element"),
        target_matrices = tuple(data.get("target_matrices") or []),
        duration        = data.get("duration"),
        duration_hours  = _float_or_none(data.get("duration_hours")),
        yield_min_pct   = _float_or_none(data.get("yield_min_pct")),
        yield_max_pct   = _float_or_none(data.get("yield_max_pct")),
        equipment = MethodEquipment(
            column          = eq.get("column"),
            resin           = eq.get("resin"),
            resin_volume_ml = _float_or_none(eq.get("resin_volume_ml")),
            reagents        = eq.get("reagents"),
            temperature     = eq.get("temperature"),
        ) if eq else None,
        steps = tuple(
            MethodStep(
                num    = s.get("num", i + 1),
                title  = s.get("title", ""),
                detail = s.get("detail"),
                final  = bool(s.get("final", False)),
            )
            for i, s in enumerate(data.get("steps") or [])
        ),
        reference = MethodReference(
            doi      = ref.get("doi"),
            citation = ref.get("citation"),
        ) if ref else None,
        notes = data.get("notes"),
    )


def _parse_pipeline(key: str, data: dict) -> Pipeline:
    return Pipeline(
        key         = key,
        name        = data.get("name"),
        element     = data.get("element"),
        description = data.get("description"),
        stages      = tuple(
            PipelineStage(
                order      = s.get("order", i + 1),
                method_key = s.get("method_key", ""),
                label      = s.get("label"),
            )
            for i, s in enumerate(data.get("stages") or [])
        ),
    )


def _parse_purification(data: dict) -> dict[str, PurificationYield]:
    result = {}
    for composite_key, entry in data.items():
        # La clé est "{sample_id}_{ELEMENT}", on la décompose par le dernier '_'
        # plutôt que le premier, parce que les IDs peuvent contenir des underscores.
        #************************************************************************
        # The key is "{sample_id}_{ELEMENT}", we decompose it by the last '_'
        # rather than the first one, because IDs can contain underscores.
        parts = composite_key.rsplit("_", 1)
        if len(parts) != 2:
            # Clé malformée, on la garde quand même pour ne pas perdre de données
            # The key is malformed, but we'll keep it anyway to avoid losing data.
            sample_id, element = composite_key, ""
        else:
            sample_id, element = parts

        result[composite_key] = PurificationYield(
            sample_id  = sample_id,
            element    = element,
            value_pct  = float(entry.get("value_pct", 0)),
            date       = entry.get("date"),
            operator   = entry.get("operator"),
            method_key = entry.get("method_key"),
            notes      = entry.get("notes"),
        )
    return result


def _parse_assignment(data: dict) -> Assignment:
    return Assignment(
        sample_id    = str(data.get("sample_id", "")),
        method_key   = data.get("method_key"),
        pipeline_key = data.get("pipeline_key"),
        assigned_at  = data.get("assigned_at"),
        assigned_by  = data.get("assigned_by"),
    )


def _parse_signature(data: Optional[dict]) -> Optional[Signature]:
    if not data:
        return None

    import base64 as _b64

    # Niveau 2 : scope peut être dans "signed_scope", signature dans "signature_b64"
    scope_raw = data.get("scope") or data.get("signed_scope") or []
    hash_raw  = data.get("hash") or data.get("signature_b64")

    # Niveau 2 : certificate_chain est un tableau de PEM encodés en base64 ;
    # on extrait le certificat labo (index 0) pour certificate_pem
    cert_pem   = data.get("certificate_pem")
    cert_chain = data.get("certificate_chain")
    if not cert_pem and isinstance(cert_chain, list) and cert_chain:
        try:
            cert_pem = _b64.b64decode(cert_chain[0]).decode("utf-8")
        except Exception:
            cert_pem = None

    return Signature(
        level             = int(data.get("level", 1)),
        algorithm         = data.get("algorithm", "SHA-256"),
        scope             = tuple(scope_raw),
        hash              = hash_raw,
        signed_at         = data.get("signed_at"),
        signed_by         = data.get("signed_by"),
        contact           = data.get("contact"),
        certificate_pem   = cert_pem,
        certificate_chain = cert_chain,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _float_or_none(v: Any) -> Optional[float]:
    if v is None:
        return None
    try:
        return float(v)
    except (TypeError, ValueError):
        return None


def _int_or_none(v: Any) -> Optional[int]:
    if v is None:
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None