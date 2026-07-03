"""
Signature de documents ISOF.

Ce module sert à construire et à signer des documents ISOF.
Le package ne détient jamais de clés privées. Pour les signatures de niveau 2,
l'utilisateur fournit ses propres clés, qui ne doivent jamais quitter la machine. Seule
la clé publique est insérée à l'artefact.
****************************************************************************************
ISOF Document Signing

This module is used to build and sign ISOF documents.
The package never holds private keys. For Level 2 signatures, the user provides their own
keys, which must never leave the machine. Only the public key is embedded in the artifact.
"""

from __future__ import annotations

import base64
import hashlib
import json
import warnings
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence, Union

from .exceptions import ISOfSignatureError

# Périmètre signé par défaut. Doit rester aligné avec ce que la vérification
# reconstruit dans _verify_level1 / _verify_level2.
# Default signed scope. Must stay aligned with what verification rebuilds in
# _verify_level1 / _verify_level2.
DEFAULT_SCOPE = ("samples", "methods", "purification")

# Version emise pour tout document construit ici. Les fichiers antérieurs
# restent lisibles, seul le format le plus recent est produit.
# Version emitted for any document built here. Earlier files stay readable,
# only the most recent format is produced.
FORMAT_VERSION = "1.3"

PathLike = Union[str, Path]


# ---------------------------------------------------------------------------
# Construction de documents | Document construction
#
# Principe : le constructeur assemble et valide la structure, il ne fabrique
# aucune donnée. Un champ non fourni reste None, seule l'ossature
# technique (version, horodatage de creation, familles vides) est renseignée.
#***************************************************************************
# Principle: the builder assembles and validates structure, it fabricates no
# data. A field not supplied stays None, never filled with a default, only
# the technical scaffolding (version, creation timestamp, empty families)
# is filled in.
# ---------------------------------------------------------------------------

# Champs reconnus :
# Recognized fields:
_ISOTOPE_FIELDS = (
    "element", "system", "ratio", "ratio_2se", "delta_notation", "delta_value",
    "delta_2sd", "standard", "n_cycles", "session_date", "instrument", "notes",
)
_GEOCHEM_FIELDS = (
    "element", "value_normalized", "uncertainty", "display_value",
    "display_unit", "method", "depth_m",
)
_PHYSICO_FIELDS = (
    "parameter", "value", "uncertainty", "method", "measured_at", "depth_m", "notes",
)
_MOLECULE_FIELDS = (
    "nom", "cas", "famille", "valeur", "unite", "valeur_ug_l", "incertitude",
    "lod", "loq", "detecte", "mz_mesure", "methode", "laboratoire",
    "date_analyse", "matrice", "conforme", "seuil_ref", "seuil_ref_unit",
    "depth_m", "notes",
)
_SAMPLE_FIELDS = (
    "id", "name", "classification", "material_type", "matrix", "sector",
    "project", "latitude", "longitude", "altitude_m", "collection_date",
    "collector", "description", "workflow_stage", "is_crm", "data_origin",
)


def _record(known_fields, provided: dict, kind: str) -> dict:
    unknown = [k for k in provided if k not in known_fields]
    if unknown:
        warnings.warn(
            f"{kind}: unknown fields ignored: {', '.join(sorted(unknown))}",
            stacklevel=3,
        )
    return {field: provided.get(field, None) for field in known_fields}


def make_isotope(**fields) -> dict:
    """
    Construit un enregistrement isotopique. 'element' et 'system' portent le
    sens de la mesure ; s'ils manquent, un avertissement est émis sans bloquer,
    un fichier peut ne partager que certaines familles de données.
    ***********************************************************************
    Builds an isotope record. 'element' and 'system' carry the meaning of the
    measurement; if missing, a warning is issued without blocking, a file
    may share only some data families.
    """
    if not fields.get("element") or not fields.get("system"):
        warnings.warn(
            "Isotope record without 'element' or 'system': "
            "missing fields stay empty.",
            stacklevel=2,
        )
    return _record(_ISOTOPE_FIELDS, fields, "isotope")


def make_geochem(**fields) -> dict:
    """
    Construit un enregistrement géochimique. 'element' porte le sens.
    Builds a geochemistry record. 'element' carries the meaning.
    """
    if not fields.get("element"):
        warnings.warn(
            "Geochemistry record without 'element': "
            "missing fields stay empty.",
            stacklevel=2,
        )
    return _record(_GEOCHEM_FIELDS, fields, "geochem")


def make_physico(**fields) -> dict:
    """
    Construit un enregistrement physico-chimique. 'parameter' porte le sens.
    Builds a physicochemical record. 'parameter' carries the meaning.
    """
    if not fields.get("parameter"):
        warnings.warn(
            "Physicochemical record without 'parameter': "
            "missing fields stay empty.",
            stacklevel=2,
        )
    return _record(_PHYSICO_FIELDS, fields, "physico")


def make_molecule(**fields) -> dict:
    """
    Construit un enregistrement moléculaire. 'nom' porte le sens.
    Builds a molecule record. 'nom' carries the meaning.
    """
    if not fields.get("nom"):
        warnings.warn(
            "Molecule record without 'nom': "
            "missing fields stay empty.",
            stacklevel=2,
        )
    return _record(_MOLECULE_FIELDS, fields, "molecule")


def make_sample(
    id: str,
    *,
    isotope_data: Optional[List[dict]] = None,
    geochem_data: Optional[List[dict]] = None,
    physico_data: Optional[List[dict]] = None,
    molecules_data: Optional[List[dict]] = None,
    **fields,
) -> dict:
    """
    Construit un échantillon. 'id' est le seul champ requis, sans lui les
    mesures ne peuvent être rattachées. Les familles de données non fournies
    restent des listes vides. Aucun autre champ n'est inventé.
    ***********************************************************************
    Builds a sample. 'id' is the only required field, without it measurements
    cannot be attached. Data families not supplied stay empty lists. No other
    field is invented.
    """
    if not id:
        raise ISOfSignatureError(
            "A sample requires a non-empty 'id' to attach its measurements."
        )
    sample = _record(_SAMPLE_FIELDS, {"id": id, **fields}, "sample")
    sample["isotope_data"] = list(isotope_data or [])
    sample["geochem_data"] = list(geochem_data or [])
    sample["physico_data"] = list(physico_data or [])
    sample["molecules_data"] = list(molecules_data or [])
    return sample


def new_document(
    samples: List[dict],
    *,
    created_by: Optional[dict] = None,
    project: Optional[Any] = None,
    doi: Optional[str] = None,
    date: Optional[str] = None,
    location: Optional[Any] = None,
    methods: Optional[Any] = None,
    purification: Optional[Any] = None,
) -> dict:
    """
    Assemble un document ISOF non signé à partir d'échantillons déjà construits.

    Seule l'ossature technique est renseignée automatiquement : la version du
    format et l'horodatage de création. Ce qui n'est pas fournit reste vide.
    Le document retourné n'est pas signé (bloc 'signature' à None) ; passez-le
    à sign_document pour le signer.
    ***********************************************************************
    Assembles an unsigned ISOF document from already-built samples.

    Only the technical scaffolding is filled in automatically: the format
    version and the creation timestamp. Fields not filled remains empty. The
    returned document is unsigned (its 'signature' block is None); pass it to
    sign_document to sign it.
    """
    if not samples:
        warnings.warn(
            "Document built without samples: the 'samples' block is empty.",
            stacklevel=2,
        )
    document: Dict[str, Any] = {
        "isof_version": FORMAT_VERSION,
        "created_at": _now_iso(),
        "created_by": created_by,
        "project": project,
        "doi": doi,
        "date": date,
        "location": location,
        "samples": list(samples),
        "methods": methods if methods is not None else [],
        "pipelines": [],
        "purification": purification if purification is not None else [],
        "assignments": [],
        "signature": None,
    }
    return document


def _canonicalize(payload: dict) -> bytes:
    """
    Sérialisation déterministe pour le hachage.
    ***********************************************************************
    Deterministic serialization for hashing.
    """
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _build_payload(document: dict, scope: Sequence[str]) -> dict:
    """
    Reconstruit le sous-document effectivement signé, dans l'ordre du scope.
    ***********************************************************************
    Rebuilds the sub-document that is actually signed, in scope order.
    """
    return {block: document.get(block) for block in scope}


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_pem(path: PathLike, kind: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8")
    except Exception as e:
        raise ISOfSignatureError(f"{kind} unreadable ({path}): {e}") from e


def sign_document(
    document: dict,
    *,
    level: int = 2,
    scope: Sequence[str] = DEFAULT_SCOPE,
    signed_by: Optional[str] = None,
    contact: Optional[str] = None,
    key_path: Optional[PathLike] = None,
    key_password: Optional[bytes] = None,
    cert_path: Optional[PathLike] = None,
    issuing_cert_path: Optional[PathLike] = None,
) -> dict:
    """
    Signe un document ISOF (dict) et retourne une copie signée.

    Le document d'origine n'est pas modifié : un nouveau dict est retourné, avec son
    bloc 'signature' renseigné.

    Niveau 1 (SHA-256) : garantit l'intégrité, n'authentifie pas l'émetteur.
        Seuls level, scope et signed_by sont utilisés.

    Niveau 2 (ECDSA P-256) : ajoute l'authentification via un certificat X.509.
        key_path et cert_path sont requis. issuing_cert_path est optionnel : s'il est
        fourni, l'Issuing CA est embarquée dans l'artefact (index 1 de la chaîne), ce
        qui permet la vérification avec une PKI de test sans toucher au dossier trust/
        du package.

    Args:
        document: Document ISOF non signé.
        level: 1 ou 2.
        scope: Blocs de haut niveau couverts par la signature.
        signed_by: Nom de l'émetteur affiché. Au niveau 2, à défaut, le CN du
            certificat est utilisé à la vérification.
        contact: Contact optionnel.
        key_path: Chemin de la clé privée PEM (niveau 2).
        key_password: Mot de passe de la clé si elle est chiffrée (niveau 2).
        cert_path: Chemin du certificat laboratoire PEM (niveau 2).
        issuing_cert_path: Chemin du certificat de l'Issuing CA PEM (niveau 2, optionnel).

    Returns:
        Une copie du document avec le bloc 'signature' renseigné.

    Raises:
        ISOfSignatureError: niveau inconnu, dépendances manquantes, ou paramètres
            de niveau 2 incomplets.
    ***********************************************************************
    Signs an ISOF document (dict) and returns a signed copy.

    The original document is not modified: a new dict is returned, with its
    'signature' block filled in.

    Level 1 (SHA-256): guarantees integrity, does not authenticate the sender.
        Only level, scope and signed_by are used.

    Level 2 (ECDSA P-256): adds authentication through an X.509 certificate.
        key_path and cert_path are required. issuing_cert_path is optional: when
        provided, the Issuing CA is embedded in the artefact (index 1 of the chain),
        which enables verification with a test PKI without touching the package
        trust/ directory.

    Args:
        document: Unsigned ISOF document.
        level: 1 or 2.
        scope: Top-level blocks covered by the signature.
        signed_by: Displayed signer name. At level 2, when omitted, the certificate
            CN is used at verification.
        contact: Optional contact.
        key_path: Path to the PEM private key (level 2).
        key_password: Key password if the key is encrypted (level 2).
        cert_path: Path to the PEM laboratory certificate (level 2).
        issuing_cert_path: Path to the PEM Issuing CA certificate (level 2, optional).

    Returns:
        A copy of the document with the 'signature' block filled in.

    Raises:
        ISOfSignatureError: unknown level, missing dependencies, or incomplete
            level-2 parameters.
    """
    if level not in (1, 2):
        raise ISOfSignatureError(f"Unsupported signature level: {level}")

    payload = _build_payload(document, scope)
    canonical = _canonicalize(payload)
    signed = dict(document)

    if level == 1:
        digest = hashlib.sha256(canonical).hexdigest()
        signed["signature"] = {
            "level": 1,
            "algorithm": "SHA-256",
            "scope": list(scope),
            "hash": digest,
            "signed_at": _now_iso(),
            "signed_by": signed_by,
            "contact": contact,
        }
        return signed

    # Niveau 2 | Level 2
    if not key_path or not cert_path:
        raise ISOfSignatureError(
            "Level 2 signature requires key_path (private key) and cert_path "
            "(laboratory certificate)."
        )

    try:
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.hazmat.primitives.serialization import load_pem_private_key
    except ImportError:
        raise ISOfSignatureError(
            "The 'cryptography' package is required to sign at level 2. "
            "pip install cryptography"
        )

    key_pem = _load_pem(key_path, "Private key")
    cert_pem = _load_pem(cert_path, "Laboratory certificate")

    try:
        private_key = load_pem_private_key(key_pem.encode(), password=key_password)
    except Exception as e:
        raise ISOfSignatureError(f"Invalid private key: {e}") from e

    if not isinstance(private_key, ec.EllipticCurvePrivateKey):
        raise ISOfSignatureError(
            "The provided key is not an elliptic-curve key. ISOF level 2 "
            "expects an ECDSA P-256 key."
        )

    signature_bytes = private_key.sign(canonical, ec.ECDSA(hashes.SHA256()))

    # La chaîne embarquée place le certificat laboratoire en index 0 et, si fourni,
    # l'Issuing CA en index 1 : c'est l'ordre que la vérification attend.
    # The embedded chain places the lab certificate at index 0 and, when provided,
    # the Issuing CA at index 1: this is the order verification expects.
    chain = [base64.b64encode(cert_pem.encode()).decode()]
    if issuing_cert_path:
        issuing_pem = _load_pem(issuing_cert_path, "Issuing CA certificate")
        chain.append(base64.b64encode(issuing_pem.encode()).decode())

    signed["signature"] = {
        "level": 2,
        "algorithm": "ECDSA-P256",
        "signed_scope": list(scope),
        "signature_b64": base64.b64encode(signature_bytes).decode(),
        "certificate_chain": chain,
        "signed_at": _now_iso(),
        "signed_by": signed_by,
        "contact": contact,
    }
    return signed


def sign_file(
    input_path: PathLike,
    output_path: PathLike,
    *,
    level: int = 2,
    scope: Sequence[str] = DEFAULT_SCOPE,
    signed_by: Optional[str] = None,
    contact: Optional[str] = None,
    key_path: Optional[PathLike] = None,
    key_password: Optional[bytes] = None,
    cert_path: Optional[PathLike] = None,
    issuing_cert_path: Optional[PathLike] = None,
) -> Path:
    """
    Signe un fichier .isof sur disque et écrit le résultat signé.

    Le fichier d'entrée est relu tel quel : on ne repasse pas par les modèles typés,
    afin de préserver octet pour octet les blocs signés et d'éviter qu'une
    normalisation à la lecture ne décale le contenu par rapport à ce qui sera vérifié.

    Args:
        input_path: Fichier .isof non signé.
        output_path: Destination du fichier signé.
        (autres paramètres identiques à sign_document)

    Returns:
        Le chemin du fichier signé.
    ***********************************************************************
    Signs an .isof file on disk and writes the signed result.

    The input file is read as-is: it is not passed through the typed models, so that
    the signed blocks are preserved byte for byte and a normalization at read time
    cannot shift the content relative to what will be verified.

    Args:
        input_path: Unsigned .isof file.
        output_path: Destination of the signed file.
        (other parameters identical to sign_document)

    Returns:
        The path of the signed file.
    """
    raw_text = Path(input_path).read_text(encoding="utf-8")
    try:
        document = json.loads(raw_text)
    except Exception as e:
        raise ISOfSignatureError(f"ISOF file unreadable ({input_path}): {e}") from e

    signed = sign_document(
        document,
        level=level,
        scope=scope,
        signed_by=signed_by,
        contact=contact,
        key_path=key_path,
        key_password=key_password,
        cert_path=cert_path,
        issuing_cert_path=issuing_cert_path,
    )

    out = Path(output_path)
    out.write_text(json.dumps(signed, ensure_ascii=False), encoding="utf-8")
    return out
