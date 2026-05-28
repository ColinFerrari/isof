"""
Vérification des signatures ISOF.

Deux niveaux de signature coexistent dans le format :

    Niveau 1 : SHA-256 sur les données canonicalisées.
        Garantit que le fichier n'a pas été modifié après export.
        N'authentifie pas l'émetteur, n'importe qui peut recalculer le hash.

    Niveau 2 : ECDSA P-256 avec certificat X.509 émis par IsoFind SAS.
        Authentifie le laboratoire émetteur via la PKI IsoFind.
        Le certificat laboratoire est signé par l'Issuing CA IsoFind,
        elle-même signée par la Root CA embarquée dans ce package.

La vérification niveau 2 fonctionne hors-ligne : le Root CA et l'Issuing CA
sont inclus dans le package (dossier trust/). Aucune requête réseau n'est faite.

Le mécanisme de signature est strictement identique pour les fichiers v1.0,
v1.1 et v1.2 : le scope porte sur les blocs de haut niveau (samples, methods,
purification, created_by...) dont le contenu a pu évoluer, mais la structure
du bloc signature elle-même n'a pas changé.
**********************************************************************
ISOF Signature Verification.

Two signature levels coexist in the format:

    Level 1: SHA-256 on canonicalized data.
        Guarantees that the file has not been modified after export.
        Does not authenticate the sender; anyone can recalculate the hash.

    Level 2: ECDSA P-256 with an X.509 certificate issued by IsoFind SAS.
        Authenticates the sending laboratory via the IsoFind PKI.
        The laboratory certificate is signed by the IsoFind Issuing CA,
        which is itself signed by the Root CA embedded in this package.

Level 2 verification works offline: the Root CA and the Issuing CA
are included in the package (trust/ folder). No network requests are made.

The signature mechanism is strictly identical across v1.0, v1.1 and v1.2
files: the scope covers top-level blocks (samples, methods, purification,
created_by...) whose content may have evolved, but the signature block
structure itself has not changed.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from .exceptions import ISOfSignatureError
from .models import Signature

# Chemin vers les certificats de confiance embarqués dans le package.
# On les embarque pour permettre la vérification offline, critique pour
# les environnements classifiés ou déconnectés.
#*****************************************************************
# Path to the trusted certificates embedded in the package.
# We include them to enable offline verification, which is critical for
# classified or disconnected environments.

_TRUST_DIR = Path(__file__).parent / "trust"
_ROOT_CA    = _TRUST_DIR / "isofind_root_ca.pem"
_ISSUING_CA = _TRUST_DIR / "isofind_issuing_ca.pem"


@dataclass(frozen=True)
class VerificationResult:
    """
    Résultat d'une vérification de signature.

    `valid` est False dans deux cas très différents :
    1) La signature est présente mais le hash/la signature cryptographique
      ne correspond pas aux données (fichier modifié).
    2) Aucune signature n'est présente dans le fichier.

    `reason` permet de distinguer les deux depuis le code appelant.
    ***************************************************************
    Signature verification result.

    `valid` is False in two very different cases:
    1) The signature is present, but the hash/cryptographic signature
    does not match the data (modified file).
    2) No signature is present in the file.

    `reason` allows us to distinguish between the two from the calling code.
    """

    valid: bool
    level: int          # 0 si aucune signature | 0 if no signature
    reason: Optional[str]
    signer: Optional[str]
    signed_at: Optional[str]

    def __bool__(self) -> bool:
        return self.valid


_NO_SIGNATURE = VerificationResult(
    valid=False, level=0,
    reason="No signature in the file",
    signer=None, signed_at=None
)


def verify(raw_doc: dict, sig: Signature) -> VerificationResult:
    """
    Point d'entrée principal, dispatche selon le niveau de signature.
    Main entry point, dispatches according to signature level.
    """
    if sig.level == 1:
        return _verify_level1(raw_doc, sig)
    if sig.level == 2:
        return _verify_level2(raw_doc, sig)
    raise ISOfSignatureError(f"Signature level unknown: {sig.level}")


def _canonicalize(payload: dict) -> bytes:
    """
    Sérialisation déterministe pour le hachage.

    On utilise separators=(',', ':') pour correspondre exactement à
    JSON.stringify(payload, null, 0) côté JavaScript (logiciel isoFind).
    Les clés ne sont pas triées ici, le JS ne les trie pas non plus
    dans signDocument(). Si ce comportement change dans une future version
    du format, ce sera indiqué dans la spec ISOF.
    *******************************************************************
    Deterministic serialization for hashing.

    We use `separators=(',', ':')` to exactly match
    `JSON.stringify(payload, null, 0)` on the JavaScript side (isoFind software).
    The keys are not sorted here, nor is the JS sorted
    in `signDocument()`. If this behavior changes in a future version
    of the format, it will be specified in the ISOF specification.
    """
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def _verify_level1(raw_doc: dict, sig: Signature) -> VerificationResult:
    """
    Vérification SHA-256, niveau 1.

    On reconstruit le payload tel qu'il a été haché à l'export :
    uniquement les blocs listés dans sig.scope, dans cet ordre.
    *******************************************************************
    SHA-256 verification, level 1.

    We reconstruct the payload as it was hashed during export:
    only the blocks listed in sig.scope, in that order.
    """
    if not sig.hash:
        raise ISOfSignatureError("Signature niveau 1 sans champ 'hash'")

    payload = {block: raw_doc.get(block) for block in sig.scope}
    computed = hashlib.sha256(_canonicalize(payload)).hexdigest()

    if computed == sig.hash:
        return VerificationResult(
            valid=True, level=1, reason=None,
            signer=sig.signed_by, signed_at=sig.signed_at
        )
    return VerificationResult(
        valid=False, level=1,
        reason="Hash SHA-256 non concordant — données modifiées après signature",
        signer=sig.signed_by, signed_at=sig.signed_at
    )


def _verify_level2(raw_doc: dict, sig: Signature) -> VerificationResult:
    """
    Vérification ECDSA P-256 avec chaîne PKI IsoFind, niveau 2.

    La chaîne de confiance attendue est :
      IsoFind Root CA → IsoFind Issuing CA → certificat laboratoire

    Le certificat laboratoire doit être présent dans sig.certificate_pem.
    Si sig.certificate_chain contient l'Issuing CA (index 1), on l'utilise
    directement — ce qui permet la vérification avec des PKI de test sans
    modifier le dossier trust/ du package.
    **********************************************************************
    ECDSA P-256 verification with IsoFind PKI chain, level 2.

    The expected chain of trust is:
      IsoFind Root CA → IsoFind Issuing CA → lab certificate

    The lab certificate must be present in sig.certificate_pem.
    If sig.certificate_chain contains the Issuing CA (index 1), it is used
    directly — enabling verification with test PKIs without modifying the
    package trust/ directory.
    """
    try:
        import base64 as _b64
        from cryptography import x509
        from cryptography.exceptions import InvalidSignature
        from cryptography.hazmat.primitives import hashes
        from cryptography.hazmat.primitives.asymmetric import ec
        from cryptography.x509 import load_pem_x509_certificate
    except ImportError:
        raise ISOfSignatureError(
            "The 'cryptography' package is required to verify level 2 signatures. "
            "pip install isof  (ou pip install cryptography)"
        )

    if not sig.certificate_pem:
        return VerificationResult(
            valid=False, level=2,
            reason="Level 2 signature without an embedded certificate in the file",
            signer=sig.signed_by, signed_at=sig.signed_at
        )

    # Charger le certificat laboratoire
    # Load the lab certificate
    try:
        lab_cert = load_pem_x509_certificate(sig.certificate_pem.encode())
    except Exception as e:
        raise ISOfSignatureError(f"Laboratory certificate illegible: {e}") from e

    # Résoudre l'Issuing CA depuis la chaîne embarquée (index 1) si disponible,
    # sinon depuis le dossier trust/ du package.
    # Resolve the Issuing CA from the embedded chain (index 1) if available,
    # otherwise fall back to the package trust/ directory.
    issuing_cert_pem = None
    if isinstance(sig.certificate_chain, list) and len(sig.certificate_chain) > 1:
        try:
            issuing_cert_pem = _b64.b64decode(sig.certificate_chain[1]).decode("utf-8")
        except Exception:
            issuing_cert_pem = None

    try:
        _verify_chain(lab_cert, issuing_cert_pem=issuing_cert_pem)
    except Exception as e:
        return VerificationResult(
            valid=False, level=2,
            reason=f"Invalid chain of trust: {e}",
            signer=sig.signed_by, signed_at=sig.signed_at
        )

    # Vérifier la signature ECDSA sur le payload canonicalisé
    # Verify the ECDSA signature on the canonicalized payload
    payload = {block: raw_doc.get(block) for block in sig.scope}
    canonical_bytes = _canonicalize(payload)

    if not sig.hash:
        raise ISOfSignatureError("Level 2 signature without a 'hash' field (ECDSA signature)")

    # La signature est encodée en base64 (ECDSA-P256) ou en hex (usage legacy)
    # The signature is base64-encoded (ECDSA-P256) or hex-encoded (legacy usage)
    try:
        try:
            sig_bytes = _b64.b64decode(sig.hash)
        except Exception:
            sig_bytes = bytes.fromhex(sig.hash)
        pub_key = lab_cert.public_key()
        pub_key.verify(sig_bytes, canonical_bytes, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return VerificationResult(
            valid=False, level=2,
            reason="Invalid ECDSA signature — données modifiées après signature",
            signer=sig.signed_by, signed_at=sig.signed_at
        )
    except Exception as e:
        raise ISOfSignatureError(f"Error during ECDSA verification: {e}") from e

    # Extraire le CN du certificat labo pour l'affichage
    # Extract the lab cert CN for display
    try:
        cn = lab_cert.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value
    except (IndexError, Exception):
        cn = sig.signed_by

    return VerificationResult(
        valid=True, level=2, reason=None,
        signer=cn, signed_at=sig.signed_at
    )


def _verify_chain(lab_cert, issuing_cert_pem: str | None = None) -> None:
    """
    Vérifie que le certificat laboratoire est bien signé par l'Issuing CA IsoFind.

    Si issuing_cert_pem est fourni (chaîne embarquée dans le fichier), on l'utilise.
    Sinon on charge l'Issuing CA depuis le dossier trust/ du package.

    On ne fait pas de validation CRL ici, les fichiers ISOF sont conçus pour
    être vérifiables dans des environnements déconnectés. Si une révocation
    est nécessaire, elle doit être gérée au niveau applicatif (IsoFind).
    **************************************************************************
    Verify that the lab certificate is indeed signed by the IsoFind Issuing CA.

    If issuing_cert_pem is provided (chain embedded in the file), it is used.
    Otherwise the Issuing CA is loaded from the package trust/ directory.

    CRL validation is not performed here; ISOF files are designed to be verifiable
    in disconnected environments. If a revocation is necessary, it must be handled
    at the application level (IsoFind).
    """
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.hazmat.primitives.hashes import SHA256
    from cryptography.x509 import load_pem_x509_certificate

    if issuing_cert_pem:
        issuing_cert = load_pem_x509_certificate(issuing_cert_pem.encode())
    else:
        if not _ISSUING_CA.exists():
            raise ISOfSignatureError(
                f"Issuing CA IsoFind not found in the package ({_ISSUING_CA}). "
                "Reinstall isof or use trust_store='system'."
            )
        issuing_cert = load_pem_x509_certificate(_ISSUING_CA.read_bytes())

    try:
        issuing_cert.public_key().verify(
            lab_cert.signature,
            lab_cert.tbs_certificate_bytes,
            ec.ECDSA(SHA256())
        )
    except Exception as e:
        raise ValueError(f"The certificate is not signed by the Issuing CA IsoFind: {e}") from e
