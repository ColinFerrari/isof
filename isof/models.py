"""
Modèles de données du format ISOF v1.0 / v1.1 / v1.2.

Ces dataclasses sont en lecture seule (frozen=True) parce qu'un document
chargé depuis un fichier signé ne devrait jamais être modifié en mémoire,
toute modification rendrait la vérification de signature caduque.
Pour créer des documents, voir isof.writer.

Trois nouveaux types apparaissent en v1.2 et sont optionnels en v1.1 :
GeochemRecord, PhysicoRecord, MoleculeRecord. Ils vivent à l'intérieur
de chaque Sample, comme isotope_data.
****************************************************************************
ISOF v1.0 / v1.1 / v1.2 format data models.

These dataclasses are read-only (frozen=True) because a document loaded from
a signed file should never be modified in memory.
Any modification would invalidate the signature verification.

To create documents, see isof.writer.

Three new types appear in v1.2 and are optional in v1.1:
GeochemRecord, PhysicoRecord, MoleculeRecord. They live inside each Sample,
just like isotope_data.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional


# ---------------------------------------------------------------------------
# Données isotopiques | Isotope Data
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class IsotopeRecord:
    """
    Un rapport isotopique mesuré pour un élément donné.

    Un même échantillon peut avoir plusieurs IsotopeRecord (un par système
    isotopique mesuré, ex. Sr, Pb, Nd séparément).
    *************************************************************************
    An isotope ratio measured for a given element.

    A single sample can have multiple IsotopeRecords (one per measured
    isotopic system, e.g., Sr, Pb, Nd separately).
    """

    element: Optional[str]
    system: Optional[str]          # ex. "87Sr/86Sr", "206Pb/204Pb"
    ratio: Optional[float]
    ratio_2se: Optional[float]     # incertitude 2 sigma externe
    delta_notation: Optional[str]  # ex. "δ¹³C", "δ¹⁸O"
    delta_value: Optional[float]
    delta_2sd: Optional[float]
    standard: Optional[str]        # isotopic standard used as reference
    n_cycles: Optional[int]
    session_date: Optional[str]
    instrument: Optional[str]
    notes: Optional[str]


# ---------------------------------------------------------------------------
# Données géochimiques v1.2 | Geochemistry data v1.2
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class GeochemRecord:
    """
    Concentration élémentaire mesurée pour un élément donné.

    Le format ISOF stocke la valeur sous deux formes : `value_normalized`
    en unité canonique (mg/kg) pour l'interopérabilité, et `display_value`
    + `display_unit` pour préserver l'unité d'origine de la saisie
    (ppm, ppb, µg/L, etc.). Le destinataire peut afficher l'une ou l'autre.
    *************************************************************************
    Elemental concentration measured for a given element.

    The ISOF format stores the value in two forms: `value_normalized`
    in canonical unit (mg/kg) for interoperability, and `display_value`
    + `display_unit` to preserve the original entry unit (ppm, ppb,
    µg/L, etc.). The recipient may render either form.
    """

    element: Optional[str]
    value_normalized: Optional[float]  # mg/kg, unité pivot | pivot unit
    uncertainty: Optional[float]
    display_value: Optional[float]
    display_unit: Optional[str]
    method: Optional[str]
    depth_m: Optional[float]


# ---------------------------------------------------------------------------
# Paramètres physico-chimiques v1.2 | Physicochemistry parameters v1.2
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PhysicoRecord:
    """
    Paramètre physico-chimique contraint (pH, Eh, température, ...).

    Le champ `parameter` suit la convention d'identifiants d'IsoFind :
    'pH', 'Eh_mV', 'temperature_c', 'conductivity', 'dissolved_oxygen',
    'ionic_strength', 'alkalinity', 'TOC', 'turbidity', 'salinity'.
    Le parser reste permissif, les identifiants inconnus sont conservés tels quels.
    *************************************************************************
    Physicochemistry parameter (pH, Eh, temperature, ...).

    The `parameter` field follows the IsoFind identifier convention:
    'pH', 'Eh_mV', 'temperature_c', 'conductivity', 'dissolved_oxygen',
    'ionic_strength', 'alkalinity', 'TOC', 'turbidity', 'salinity'.
    The parser is permissive, unknown identifiers are preserved as-is.
    """

    parameter: Optional[str]
    value: Optional[float]
    uncertainty: Optional[float]
    method: Optional[str]
    measured_at: Optional[str]
    depth_m: Optional[float]
    notes: Optional[str]


# ---------------------------------------------------------------------------
# Molécules et ions dissous v1.2 | Dissolved molecules and ions v1.2
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class MoleculeRecord:
    """
    Molécule ou ion dissous avec conformité réglementaire.

    Les champs regulatoires (`conforme`, `seuil_ref`, `seuil_ref_unit`)
    sont optionnels : certaines molécules n'ont pas de seuil réglementaire.
    `valeur_ug_l` sert de pivot normalisé pour comparaisons inter-échantillons ;
    `valeur` + `unite` préservent la saisie d'origine (ng/L, mg/L, etc.).
    `detecte` est un booléen persistant indiquant si la molécule a passé le LOD.
    *************************************************************************
    Dissolved molecule or ion with regulatory compliance.

    Regulatory fields (`conforme`, `seuil_ref`, `seuil_ref_unit`) are
    optional: some molecules have no regulatory threshold.
    `valeur_ug_l` is the normalized pivot for cross-sample comparisons;
    `valeur` + `unite` preserve the original entry unit (ng/L, mg/L, etc.).
    `detecte` is a persistent boolean indicating whether the molecule
    passed the LOD.
    """

    nom: Optional[str]
    cas: Optional[str]
    famille: Optional[str]
    valeur: Optional[float]
    unite: Optional[str]
    valeur_ug_l: Optional[float]
    incertitude: Optional[float]
    lod: Optional[float]
    loq: Optional[float]
    detecte: Optional[bool]
    mz_mesure: Optional[float]
    methode: Optional[str]
    laboratoire: Optional[str]
    date_analyse: Optional[str]
    matrice: Optional[str]
    conforme: Optional[bool]
    seuil_ref: Optional[float]
    seuil_ref_unit: Optional[str]
    depth_m: Optional[float]
    notes: Optional[str]

    @property
    def is_non_compliant(self) -> bool:
        """
        True uniquement si la non-conformité est explicite.

        `conforme = None` (information manquante) retourne False :
        l'absence d'info ne doit pas être traitée comme une alerte.
        ***********************************************************************
        True only when non-compliance is explicit.

        `conforme = None` (missing information) returns False: missing info
        must not be treated as an alert.
        """
        return self.conforme is False


# ---------------------------------------------------------------------------
# Échantillon | Sample
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Sample:
    """
    Echantillon avec ses mesures isotopiques et ses trois familles additionnelles.

    Le champ `classification` suit la convention IsoFind :
    'source' = matériau de référence ou origine connue (ex. une mine),
    'fille' = produit ou matériau à tracer (ex. un métal/une pollution).
    Ces valeurs sont libres dans le format, elles ne sont pas vérifiées ici
    pour rester compatible avec des fichiers produits par d'autres outils.

    Les trois familles v1.2 (geochem_data, physico_data, molecules_data) sont
    des tuples vides par défaut : un fichier v1.0 ou v1.1 sans ces blocs
    charge un Sample parfaitement utilisable.
    **************************************************************************
    Sample with its isotopic measurements and three additional families.

    The `classification` field follows the IsoFind convention:
    'source' = reference material or known origin (e.g., a mine),
    'daughter' = product or material to be traced (e.g., a metal/pollution).
    These values are free-form and are not checked here to ensure
    compatibility with files generated by other tools.

    The three v1.2 families (geochem_data, physico_data, molecules_data)
    default to empty tuples: a v1.0 or v1.1 file without these blocks
    loads a perfectly usable Sample.
    """

    id: str
    name: Optional[str]
    classification: Optional[str]
    material_type: Optional[str]
    sector: Optional[str]
    project: Optional[str]
    latitude: Optional[float]
    longitude: Optional[float]
    altitude_m: Optional[float]
    collection_date: Optional[str]
    collector: Optional[str]
    description: Optional[str]
    workflow_stage: Optional[str]
    isotope_data: tuple[IsotopeRecord, ...] = field(default_factory=tuple)
    # v1.2 -- trois familles additionnelles, vides sur fichiers antérieurs
    geochem_data: tuple[GeochemRecord, ...] = field(default_factory=tuple)
    physico_data: tuple[PhysicoRecord, ...] = field(default_factory=tuple)
    molecules_data: tuple[MoleculeRecord, ...] = field(default_factory=tuple)

    def has_coordinates(self) -> bool:
        return self.latitude is not None and self.longitude is not None

    def elements(self) -> list[str]:
        """
        Éléments mesurés dans cet échantillon, sans doublons, triés.

        Combine les éléments présents dans isotope_data et geochem_data :
        un échantillon peut avoir Pb mesuré en isotopie et As mesuré en
        concentration, les deux comptent comme éléments de l'échantillon.
        ***********************************************************************
        Elements measured in this sample, without duplicates, sorted.

        Combines elements found in isotope_data and geochem_data: a sample
        can have Pb measured isotopically and As measured as concentration,
        both count as sample elements.
        """
        seen: list[str] = []
        for iso in self.isotope_data:
            if iso.element and iso.element not in seen:
                seen.append(iso.element)
        for geo in self.geochem_data:
            if geo.element and geo.element not in seen:
                seen.append(geo.element)
        return sorted(seen)

    def physico_parameter(self, name: str) -> Optional[PhysicoRecord]:
        """
        Récupère un paramètre physico-chimique par son identifiant.

        Retourne le premier match, utile pour pH/Eh/T qui apparaissent
        typiquement une seule fois par échantillon. Retourne None si absent.
        ***********************************************************************
        Retrieves a physicochemistry parameter by its identifier.

        Returns the first match, useful for pH/Eh/T which typically appear
        once per sample. Returns None if absent.
        """
        for p in self.physico_data:
            if p.parameter == name:
                return p
        return None


# ---------------------------------------------------------------------------
# Méthodes de préparation | Preparation method
# ---------------------------------------------------------------------------
    """
    Le format ISOF intègre directement les données de préparation et
    d'analyse et les lie aux échantillons pour une traçabilité totale
    de la chaîne d'analyse.
    *************************************************************************
    The ISOF format directly integrates preparation and analysis data and
    links them to samples for total traceability of the analysis chain.
    """


@dataclass(frozen=True)
class MethodStep:
    num: int
    title: str
    detail: Optional[str]
    final: bool


@dataclass(frozen=True)
class MethodEquipment:
    column: Optional[str]
    resin: Optional[str]
    resin_volume_ml: Optional[float]
    reagents: Optional[str]
    temperature: Optional[str]


@dataclass(frozen=True)
class MethodReference:
    doi: Optional[str]
    citation: Optional[str]


@dataclass(frozen=True)
class Method:
    """
    Protocole de préparation ou d'analyse (digestion, chromatographie, etc.).

    Les méthodes sont identifiées par une clé string dans le document ISOF,
    pas par leur nom, plusieurs méthodes peuvent avoir le même nom mais
    des paramètres différents.
    *************************************************************************
    Preparation or analysis protocol (digestion, chromatography, etc.).

    Methods are identified by a string key in the ISOF document,
    not by their name; several methods may have the same name but
    different parameters.
    """

    key: str                       # identifiant interne du fichier ISOF | Internal identification of the ISOF file
    name: str
    type: Optional[str]            # 'digestion' | 'purification' | 'separation' | 'analysis'
    element: Optional[str]
    target_matrices: tuple[str, ...]
    duration: Optional[str]
    duration_hours: Optional[float]
    yield_min_pct: Optional[float]
    yield_max_pct: Optional[float]
    equipment: Optional[MethodEquipment]
    steps: tuple[MethodStep, ...]
    reference: Optional[MethodReference]
    notes: Optional[str]


# ---------------------------------------------------------------------------
# Pipelines
# ---------------------------------------------------------------------------
    """
    Les pipelines représentent les chaînes analytiques complètes (des
    suites de méthodes dans des ordres précis).
    Ex. Protocole de digestion acide → puis procédure de purification →
    paramètres analytiques.
    *************************************************************************
    Pipelines represent complete analytical chains (sequences of methods in
    specific orders).
    Example: Acid digestion protocol → purification procedure → analytical
    parameters.
    """

@dataclass(frozen=True)
class PipelineStage:
    order: int
    method_key: str
    label: Optional[str]


@dataclass(frozen=True)
class Pipeline:
    """
    Séquence ordonnée de méthodes pour traiter un élément donné.
    Ordered sequence of methods for processing a given element.
    """

    key: str
    name: Optional[str]
    element: Optional[str]
    description: Optional[str]
    stages: tuple[PipelineStage, ...]


# ---------------------------------------------------------------------------
# Rendements de purification | Purification yield
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class PurificationYield:
    """
    Rendement mesuré pour un couple (échantillon, élément).

    La clé du dictionnaire dans le document ISOF est "{sample_id}_{ELEMENT}".
    Elle est décomposée ici pour faciliter les requêtes par échantillon ou par élément.
    **************************************************************************
    Yield measured for a pair (sample, element).

    The dictionary key in the ISOF document is "{sample_id}_{ELEMENT}".
    It is decomposed here to facilitate queries by sample or by element.
    """

    sample_id: str
    element: str
    value_pct: float
    date: Optional[str]
    operator: Optional[str]
    method_key: Optional[str]
    notes: Optional[str]

    @property
    def is_suspicious(self) -> bool:
        """
        Un rendement > 105 % indique une contamination probable.

        Le seuil de 105 % est une convention analytique, en dessous,
        l'écart peut s'expliquer par la variabilité de pesée.
        ***********************************************************************
        A yield > 105% indicates probable contamination.

        The 105% threshold is an analytical convention; below this threshold,
        the discrepancy may be explained by weighing variability.
        """
        return self.value_pct > 105.0


# ---------------------------------------------------------------------------
# Assignations méthode ↔ échantillon | Method assignments ↔ sample
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Assignment:
    sample_id: str
    method_key: Optional[str]
    pipeline_key: Optional[str]
    assigned_at: Optional[str]
    assigned_by: Optional[str]


# ---------------------------------------------------------------------------
# Métadonnées et provenance | Metadata and provenance
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class CreatedBy:
    software: Optional[str]
    software_version: Optional[str]
    operator: Optional[str]
    organisation: Optional[str]


@dataclass(frozen=True)
class Project:
    name: Optional[str]
    reference: Optional[str]
    client: Optional[str]
    classification: Optional[str]
    notes: Optional[str]


@dataclass(frozen=True)
class Location:
    """
    Situation geographique de l'etude, telle que stockee au niveau du document.
    Les deux champs sont facultatifs, un fichier peut n'indiquer que le pays.
    **************************************************************************
    Geographic setting of the study, as stored at the document level.
    Both fields are optional, a file may indicate only the country.
    """
    name: Optional[str]
    country: Optional[str]


# ---------------------------------------------------------------------------
# Signature
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Signature:
    """
    Bloc de signature tel que stocké dans le fichier.

    La structure des données est volontairement distinguée (ce fichier)
    du résultat de la vérification (VerificationResult dans signature.py).
    Un fichier peut avoir un bloc signature valide structurellement
    mais dont le hash ne correspond plus aux données.
    **************************************************************************
    Signature block as stored in the file.

    The data structure (this file) is intentionally distinguished from the
    verification result (VerificationResult in signature.py).
    A file may have a structurally valid signature block but whose hash
    no longer matches the data.
    """

    level: int                     # 1 = SHA-256 intégrity, 2 = PKI IsoFind
    algorithm: str
    scope: tuple[str, ...]         # covered blocks : 'samples', 'methods', etc.
    hash: Optional[str]            # level 1 only
    signed_at: Optional[str]
    signed_by: Optional[str]       # organization or CN certificate
    contact: Optional[str]
    # Niveau 2, champs PKI
    certificate_pem: Optional[str] = None
    certificate_chain: Optional[str] = None

    @property
    def signed_at_dt(self) -> Optional[datetime]:
        """
        Conversion en datetime pour les comparaisons et affichages.
        Conversion to datetime for comparisons and displays.
        """
        if not self.signed_at:
            return None
        try:
            return datetime.fromisoformat(self.signed_at.replace("Z", "+00:00"))
        except ValueError:
            return None


# ---------------------------------------------------------------------------
# Chiffrement v1.2 | Encryption v1.2
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class Encryption:
    """
    Bloc de chiffrement tel que stocké dans le fichier.

    Quand `active = True`, le contenu scientifique (samples, methods,
    purification, assignments) a été remplacé par un payload chiffré et
    ne peut pas être consulté sans la clé privée du destinataire prévu.
    Le parser expose ce bloc en lecture seule ; le déchiffrement se fait
    via ISOfDocument.decrypt(recipient_private_key_pem) qui retourne un
    nouveau document avec les blocs clairs.

    Le format utilise une enveloppe hybride : la clé de session symétrique
    est chiffrée pour le destinataire via X25519, le contenu scientifique
    est chiffré avec un AEAD (ChaCha20-Poly1305 ou AES-256-GCM selon le
    champ `algorithm`).
    **************************************************************************
    Encryption block as stored in the file.

    When `active = True`, the scientific content (samples, methods,
    purification, assignments) has been replaced by an encrypted payload
    and cannot be accessed without the intended recipient's private key.
    The parser exposes this block read-only; decryption is performed via
    ISOfDocument.decrypt(recipient_private_key_pem) which returns a new
    document with cleartext blocks.

    The format uses a hybrid envelope: the symmetric session key is
    encrypted for the recipient via X25519, the scientific content is
    encrypted with an AEAD (ChaCha20-Poly1305 or AES-256-GCM depending
    on the `algorithm` field).
    """

    active: bool
    algorithm: Optional[str]                  # ex. "X25519+ChaCha20-Poly1305"
    recipient_id: Optional[str]               # identifiant public du destinataire
    recipient_public_key: Optional[str]       # clé publique X25519 en PEM ou base64
    encrypted_key: Optional[str]              # clé de session chiffrée pour le destinataire
    encrypted_payload: Optional[str]          # contenu scientifique chiffré (base64)
    nonce: Optional[str]                      # nonce/IV de l'AEAD
    encrypted_at: Optional[str]
    encrypted_by: Optional[str]

    @property
    def is_active(self) -> bool:
        return bool(self.active)
