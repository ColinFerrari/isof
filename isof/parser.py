"""
Lecture et désérialisation de documents ISOF v1.0 / v1.1 / v1.2.

Le parser est volontairement permissif sur les champs optionnels :
beaucoup de logiciels qui écrivent du ISOF omettront des champs
que la spec marque comme optionnels. Il est préférable de charger avec None
plutôt que lever une exception, les utilisateurs peuvent toujours
inspecter les données et décider quoi en faire.

En revanche, les invariants structurels sont stricts : version,
présence du tableau samples, cohérence du bloc signature.

Évolutions v1.1 / v1.2 prises en charge :
  - v1.1 : signature niveau 2 PKI, pas de changement structurel vs v1.0.
  - v1.2 : trois familles additionnelles par échantillon (geochem_data,
    physico_data, molecules_data) et bloc `encryption` optionnel pour le
    chiffrement de bout en bout du contenu scientifique. Les fichiers v1.1
    qui embarquent déjà ces blocs sont acceptés (tolérance minor version).
**********************************************************************
Reading and deserializing ISOF v1.0 / v1.1 / v1.2 documents.

The parser is intentionally permissive regarding optional fields:
many software programs that write ISOF will omit fields
that the specification marks as optional. It is preferable to load with None
rather than raise an exception; users can still
inspect the data and decide what to do with it.

On the other hand, structural invariants are strict: version,
presence of the samples array, and consistency of the signature block.

v1.1 / v1.2 evolutions handled here:
  - v1.1: level 2 PKI signature, no structural change from v1.0.
  - v1.2: three additional per-sample families (geochem_data, physico_data,
    molecules_data) and an optional `encryption` block for end-to-end
    encryption of the scientific payload. v1.1 files already embedding
    these blocks are accepted (minor-version tolerance).
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Optional, Union

from .exceptions import ISOfEncryptionError, ISOfParseError, ISOfVersionError
from .models import (
    Assignment,
    CreatedBy,
    Encryption,
    GeochemRecord,
    IsotopeRecord,
    Method,
    MethodEquipment,
    MethodReference,
    MethodStep,
    MoleculeRecord,
    PhysicoRecord,
    Pipeline,
    PipelineStage,
    Project,
    PurificationYield,
    Sample,
    Signature,
)

# Trois versions supportées simultanément. v1.0 et v1.1 n'ont pas de blocs v1.2
# mais le parser tolère leur présence (observé en pratique : certains exports
# IsoFind plus anciens déclarent 1.1 tout en émettant les familles v1.2).
# v1.2 formalise la présence de ces blocs et introduit le chiffrement.
#***************************************************************************
# Three versions supported concurrently. v1.0 and v1.1 don't define v1.2 blocks
# but the parser tolerates their presence (observed in practice: some older
# IsoFind exports declare 1.1 yet emit v1.2 families). v1.2 formalizes these
# blocks and introduces encryption.
SUPPORTED_VERSIONS = ("1.0", "1.1", "1.2")


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
    des méthodes de haut niveau (is_authentic, to_pandas, decrypt, ...)
    sans alourdir les modèles de données.

    Quand le document est chiffré (encryption.active == True), les tuples
    samples/methods/pipelines/purification/assignments sont vides : le
    contenu a été remplacé par un payload opaque. Appeler `decrypt()` avec
    la clé privée du destinataire retourne un nouveau document déchiffré.
    **************************************************************************
    In-memory representation of a loaded ISOF document.

    A class is used rather than a dataclass to allow the attachment of
    high-level methods (is_authentic, to_pandas, decrypt, ...) without
    increasing the complexity of the data models.

    When the document is encrypted (encryption.active == True), the tuples
    samples/methods/pipelines/purification/assignments are empty: content
    has been replaced by an opaque payload. Calling `decrypt()` with the
    recipient private key returns a new decrypted document.
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
        encryption: Optional[Encryption] = None,
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
        self.encryption = encryption
        self._raw = _raw   # conservé pour la vérification de signature | kept for signature verification

    def __repr__(self) -> str:
        n = len(self.samples)
        org = self.created_by.organisation if self.created_by else "?"
        tag = " [chiffré]" if self.is_encrypted else ""
        return f"<ISOfDocument v{self.version}{tag} — {n} échantillon(s) — {org}>"

    # ------------------------------------------------------------------
    # État du document | Document state
    # ------------------------------------------------------------------

    @property
    def is_encrypted(self) -> bool:
        """
        True si le contenu scientifique est chiffré et actuellement opaque.

        Un document déchiffré via decrypt() conserve son bloc encryption
        mais retourne False ici : les données sont alors lisibles.
        ***********************************************************************
        True if the scientific content is encrypted and currently opaque.

        A document decrypted via decrypt() retains its encryption block
        but returns False here: data is then readable.
        """
        return self.encryption is not None and self.encryption.is_active

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
        rester cohérent avec le type de samples. Le filtre element
        examine à la fois les ratios isotopiques et les concentrations
        géochimiques (v1.2) : un échantillon avec As uniquement mesuré
        en géochim remonte bien pour element='As'.
        *******************************************************************
        Filters samples according to one or more criteria.

        The criteria are combined using an AND operation. A tuple is returned to
        maintain consistency with the sample type. The element filter inspects
        both isotope ratios and geochemistry concentrations (v1.2): a sample
        with As measured only in geochem is returned for element='As'.
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
    # Accès aux nouvelles familles v1.2 | v1.2 new family accessors
    # ------------------------------------------------------------------

    def non_compliant_molecules(self) -> list[tuple[Sample, "MoleculeRecord"]]:
        """
        Molécules explicitement non conformes aux seuils réglementaires.

        Retourne uniquement les cas où `conforme == False`. Les molécules
        sans information de conformité (None) ne remontent pas : le parser
        n'invente pas de jugement là où la donnée est absente.
        ***********************************************************************
        Molecules explicitly non-compliant with regulatory thresholds.

        Returns only cases where `conforme == False`. Molecules without
        compliance info (None) are not returned: the parser does not invent
        a verdict where data is missing.
        """
        out = []
        for sample in self.samples:
            for mol in sample.molecules_data:
                if mol.is_non_compliant:
                    out.append((sample, mol))
        return out

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
    # Déchiffrement v1.2 | v1.2 decryption
    # ------------------------------------------------------------------

    def decrypt(self, recipient_private_key: Union[str, bytes]) -> "ISOfDocument":
        """
        Déchiffre un document dont le contenu scientifique est opaque.

        Retourne un nouvel ISOfDocument avec les blocs samples, methods,
        pipelines, purification et assignments peuplés en clair. Le document
        d'origine n'est pas modifié : on peut donc vérifier la signature de
        l'enveloppe chiffrée, puis déchiffrer et travailler sur le résultat.

        La clé privée attendue est une clé X25519 du destinataire prévu,
        acceptée en trois formats : PEM PKCS#8, bytes bruts de 32 octets,
        ou base64 des 32 octets.

        Raises:
            ISOfEncryptionError: clé inadaptée, payload corrompu, ou
                algorithme de chiffrement non supporté.

        Exemple :
            >>> report = isof.load("mission_defense.isof")
            >>> if report.is_encrypted:
            ...     priv_pem = Path("ma_cle_privee.pem").read_text()
            ...     report = report.decrypt(priv_pem)
            >>> df = report.to_pandas()
        ***********************************************************************
        Decrypt a document whose scientific payload is opaque.

        Returns a new ISOfDocument with samples, methods, pipelines,
        purification and assignments populated in clear. The original document
        is not mutated: callers can verify the encrypted envelope signature,
        then decrypt and work on the result.

        The expected private key is an X25519 key of the intended recipient,
        accepted in three formats: PEM PKCS#8, raw 32 bytes, or base64 of
        32 bytes.

        Raises:
            ISOfEncryptionError: mismatched key, corrupted payload, or
                unsupported encryption algorithm.

        Example:
            >>> report = isof.load("mission_defense.isof")
            >>> if report.is_encrypted:
            ...     priv_pem = Path("my_private_key.pem").read_text()
            ...     report = report.decrypt(priv_pem)
            >>> df = report.to_pandas()
        """
        if not self.is_encrypted:
            # Appel idempotent : un document déjà clair est retourné tel quel.
            # Idempotent call: a document already in clear is returned as-is.
            return self

        if self._raw is None:
            raise ISOfEncryptionError(
                "Cannot decrypt a document without raw data (programmatic construction?)"
            )

        from .encryption import decrypt_document

        raw_decrypted = decrypt_document(self._raw, recipient_private_key)
        return _parse_document(raw_decrypted)

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

    def to_pandas(self, family: str = "isotope"):
        """
        Convertit les données en DataFrame pandas, une ligne par mesure.

        Le paramètre `family` sélectionne la famille de mesures :
          - 'isotope'   : ratios isotopiques (défaut, comportement v1.0/1.1)
          - 'geochem'   : concentrations élémentaires (v1.2)
          - 'physico'   : paramètres physico-chimiques (v1.2)
          - 'molecules' : molécules et ions dissous (v1.2)

        Dans tous les cas, les colonnes de métadonnées de l'échantillon sont
        dupliquées sur chaque ligne (format tidy).

        Nécessite pandas : pip install isof[pandas]
        ***********************************************************************
        Convert the data into a pandas DataFrame, one row per measurement.

        The `family` parameter selects the measurement family:
          - 'isotope'   : isotope ratios (default, v1.0/1.1 behavior)
          - 'geochem'   : elemental concentrations (v1.2)
          - 'physico'   : physicochemistry parameters (v1.2)
          - 'molecules' : dissolved molecules and ions (v1.2)

        In every case, sample metadata columns are duplicated on each row
        (tidy format).

        Requires pandas: pip install isof[pandas]
        """
        try:
            import pandas as pd
        except ImportError:
            raise ImportError(
                "pandas is required for to_pandas(). "
                "Install it with: pip install isof[pandas]"
            ) from None

        if family not in {"isotope", "geochem", "physico", "molecules"}:
            raise ValueError(
                f"Unknown family '{family}'. "
                "Expected one of: isotope, geochem, physico, molecules."
            )

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

            if family == "isotope":
                if not sample.isotope_data:
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

            elif family == "geochem":
                for geo in sample.geochem_data:
                    rows.append({
                        **base,
                        "element":          geo.element,
                        "value_normalized": geo.value_normalized,
                        "uncertainty":      geo.uncertainty,
                        "display_value":    geo.display_value,
                        "display_unit":     geo.display_unit,
                        "method":           geo.method,
                        "depth_m":          geo.depth_m,
                    })

            elif family == "physico":
                for phys in sample.physico_data:
                    rows.append({
                        **base,
                        "parameter":   phys.parameter,
                        "value":       phys.value,
                        "uncertainty": phys.uncertainty,
                        "method":      phys.method,
                        "measured_at": phys.measured_at,
                        "depth_m":     phys.depth_m,
                        "notes":       phys.notes,
                    })

            elif family == "molecules":
                for mol in sample.molecules_data:
                    rows.append({
                        **base,
                        "nom":            mol.nom,
                        "cas":            mol.cas,
                        "famille":        mol.famille,
                        "valeur":         mol.valeur,
                        "unite":          mol.unite,
                        "valeur_ug_l":    mol.valeur_ug_l,
                        "incertitude":    mol.incertitude,
                        "lod":            mol.lod,
                        "loq":            mol.loq,
                        "detecte":        mol.detecte,
                        "mz_mesure":      mol.mz_mesure,
                        "methode":        mol.methode,
                        "laboratoire":    mol.laboratoire,
                        "date_analyse":   mol.date_analyse,
                        "matrice":        mol.matrice,
                        "conforme":       mol.conforme,
                        "seuil_ref":      mol.seuil_ref,
                        "seuil_ref_unit": mol.seuil_ref_unit,
                        "depth_m":        mol.depth_m,
                    })

        return pd.DataFrame(rows)

    def to_csv(self, path: Union[str, Path], family: str = "isotope", **kwargs) -> None:
        """
        Raccourci vers to_pandas(family).to_csv().

        Les kwargs sont passés directement à pandas.DataFrame.to_csv.
        Par défaut : index=False pour un CSV propre.
        *********************************************************************
        Shortcut to `to_pandas(family).to_csv()`.

        Kwargs are passed directly to `pandas.DataFrame.to_csv()`.
        Default: `index=False` for a clean CSV.
        """
        kwargs.setdefault("index", False)
        self.to_pandas(family=family).to_csv(path, **kwargs)


# ---------------------------------------------------------------------------
# Fonctions de désérialisation internes | Internal deserialization functions
# ---------------------------------------------------------------------------

def _parse_document(raw: dict) -> ISOfDocument:
    version = raw.get("isof_version")
    if not version:
        raise ISOfParseError("The 'isof_version' field is missing; this file may not be an ISOF document.")
    if str(version) not in SUPPORTED_VERSIONS:
        raise ISOfVersionError(str(version), SUPPORTED_VERSIONS)

    # Bloc encryption (v1.2, optionnel et potentiellement absent en v1.0/1.1)
    # Encryption block (v1.2, optional and potentially absent in v1.0/1.1)
    encryption = _parse_encryption(raw.get("encryption"))
    encrypted_active = encryption is not None and encryption.is_active

    # Quand le document est chiffré, samples peut être absent ou remplacé par
    # une chaîne opaque ; on renvoie alors des collections vides pour que les
    # appelants puissent tester is_encrypted avant d'itérer, sans erreur.
    #***************************************************************************
    # When the document is encrypted, samples may be absent or replaced by an
    # opaque string; we return empty collections so that callers can test
    # is_encrypted before iterating, without errors.
    samples_raw = raw.get("samples")
    if encrypted_active and not isinstance(samples_raw, list):
        samples_tuple = tuple()
        methods_dict  = {}
        pipelines_dict = {}
        purification_dict = {}
        assignments_tuple = tuple()
    else:
        if not isinstance(samples_raw, list):
            raise ISOfParseError("Le champ 'samples' doit être un tableau JSON")
        samples_tuple = tuple(_parse_sample(s) for s in samples_raw)
        methods_dict  = {k: _parse_method(k, v) for k, v in (raw.get("methods") or {}).items()}
        pipelines_dict = {k: _parse_pipeline(k, v) for k, v in (raw.get("pipelines") or {}).items()}
        purification_dict = _parse_purification(raw.get("purification") or {})
        assignments_tuple = tuple(_parse_assignment(a) for a in (raw.get("assignments") or []))

    return ISOfDocument(
        version      = str(version),
        created_at   = raw.get("created_at"),
        created_by   = _parse_created_by(raw.get("created_by")),
        project      = _parse_project(raw.get("project")),
        samples      = samples_tuple,
        methods      = methods_dict,
        pipelines    = pipelines_dict,
        purification = purification_dict,
        assignments  = assignments_tuple,
        signature    = _parse_signature(raw.get("signature")),
        encryption   = encryption,
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
        material_type   = data.get("material_type") or data.get("matrix"),
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
        # v1.2 -- trois familles additionnelles, tolérantes à l'absence
        geochem_data    = tuple(_parse_geochem(g)   for g in (data.get("geochem_data")   or [])),
        physico_data    = tuple(_parse_physico(p)   for p in (data.get("physico_data")   or [])),
        molecules_data  = tuple(_parse_molecule(m)  for m in (data.get("molecules_data") or [])),
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


def _parse_geochem(data: dict) -> GeochemRecord:
    """
    Parse une entrée géochimique v1.2.

    Le couple (value_normalized, display_value/display_unit) reflète la
    convention IsoFind : valeur pivot en mg/kg + valeur d'origine préservée.
    Le parser reste permissif si seule une des deux est présente.
    ***************************************************************************
    Parse a v1.2 geochemistry entry.

    The (value_normalized, display_value/display_unit) pair reflects IsoFind
    convention: mg/kg pivot value + preserved entry value. The parser is
    permissive if only one of the two is present.
    """
    return GeochemRecord(
        element          = data.get("element"),
        value_normalized = _float_or_none(data.get("value_normalized")),
        uncertainty      = _float_or_none(data.get("uncertainty")),
        display_value    = _float_or_none(data.get("display_value")),
        display_unit     = data.get("display_unit"),
        method           = data.get("method"),
        depth_m          = _float_or_none(data.get("depth_m")),
    )


def _parse_physico(data: dict) -> PhysicoRecord:
    """
    Parse une entrée physico-chimique v1.2.

    L'identifiant `parameter` est conservé tel quel même s'il n'appartient
    pas à la liste canonique IsoFind : certains laboratoires ajoutent leurs
    propres mesures (ex. 'chlorophyll_a', 'fluorescence'), on ne veut pas
    les écarter silencieusement.
    ***************************************************************************
    Parse a v1.2 physicochemistry entry.

    The `parameter` identifier is preserved as-is even when it falls outside
    the canonical IsoFind list: some labs add their own measurements (e.g.
    'chlorophyll_a', 'fluorescence'), and we do not want to silently drop them.
    """
    return PhysicoRecord(
        parameter   = data.get("parameter"),
        value       = _float_or_none(data.get("value")),
        uncertainty = _float_or_none(data.get("uncertainty")),
        method      = data.get("method"),
        measured_at = data.get("measured_at"),
        depth_m     = _float_or_none(data.get("depth_m")),
        notes       = data.get("notes"),
    )


def _parse_molecule(data: dict) -> MoleculeRecord:
    """
    Parse une entrée moléculaire v1.2.

    Les booléens `detecte` et `conforme` peuvent être stockés en JSON sous
    trois formes : true/false, 1/0, ou null. On normalise en bool ou None,
    jamais en 0/1 pour éviter les confusions avec des mesures numériques.
    ***************************************************************************
    Parse a v1.2 molecule entry.

    The `detecte` and `conforme` booleans may be JSON-encoded in three forms:
    true/false, 1/0, or null. We normalize to bool or None, never 0/1 to
    avoid confusion with numeric measurements.
    """
    return MoleculeRecord(
        nom            = data.get("nom"),
        cas            = data.get("cas"),
        famille        = data.get("famille"),
        valeur         = _float_or_none(data.get("valeur")),
        unite          = data.get("unite"),
        valeur_ug_l    = _float_or_none(data.get("valeur_ug_l")),
        incertitude    = _float_or_none(data.get("incertitude")),
        lod            = _float_or_none(data.get("lod")),
        loq            = _float_or_none(data.get("loq")),
        detecte        = _bool_or_none(data.get("detecte")),
        mz_mesure      = _float_or_none(data.get("mz_mesure")),
        methode        = data.get("methode"),
        laboratoire    = data.get("laboratoire"),
        date_analyse   = data.get("date_analyse"),
        matrice        = data.get("matrice"),
        conforme       = _bool_or_none(data.get("conforme")),
        seuil_ref      = _float_or_none(data.get("seuil_ref")),
        seuil_ref_unit = data.get("seuil_ref_unit"),
        depth_m        = _float_or_none(data.get("depth_m")),
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


def _parse_encryption(data: Optional[dict]) -> Optional[Encryption]:
    """
    Parse le bloc encryption v1.2. Retourne None si absent.

    Le champ `active` est normalisé en bool : certains producteurs historiques
    ont pu émettre 1/0 ou la chaîne "true"/"false". Un bloc sans `active`
    est considéré inactif par sécurité : mieux vaut lire en clair un faux
    chiffrement que refuser l'import à cause d'un champ manquant.
    ***************************************************************************
    Parse the v1.2 encryption block. Returns None when absent.

    The `active` field is normalized to bool: some historical producers may
    have emitted 1/0 or the string "true"/"false". A block without `active`
    is treated as inactive by default: better to read in clear a pseudo
    encryption than to refuse import over a missing field.
    """
    if not data or not isinstance(data, dict):
        return None
    return Encryption(
        active               = bool(_bool_or_none(data.get("active")) or False),
        algorithm            = data.get("algorithm"),
        recipient_id         = data.get("recipient_id"),
        recipient_public_key = data.get("recipient_public_key"),
        encrypted_key        = data.get("encrypted_key"),
        encrypted_payload    = data.get("encrypted_payload"),
        nonce                = data.get("nonce"),
        encrypted_at         = data.get("encrypted_at"),
        encrypted_by         = data.get("encrypted_by"),
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


def _bool_or_none(v: Any) -> Optional[bool]:
    """
    Normalise un booléen stocké sous diverses formes : bool natif, int 0/1,
    chaîne 'true'/'false'/'1'/'0'. Retourne None si la valeur est None ou
    ne peut pas être interprétée : on préfère remonter une absence
    plutôt que d'inventer False.
    ***************************************************************************
    Normalize a boolean stored in various forms: native bool, int 0/1, string
    'true'/'false'/'1'/'0'. Returns None if the value is None or cannot be
    interpreted: we prefer surfacing an absence rather than inventing False.
    """
    if v is None:
        return None
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    if isinstance(v, str):
        s = v.strip().lower()
        if s in ("true", "1", "yes", "oui"):
            return True
        if s in ("false", "0", "no", "non"):
            return False
    return None
