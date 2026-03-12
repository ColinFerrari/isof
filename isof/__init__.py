"""
isof — Lecteur et vérificateur du format ISOF v1.0 | ISOF v1.0 reader and verificator

Usage minimal : | minimal use :

    import isof

    report = isof.load("analyse_bolivie.isof")
    if report.is_authentic():
        print(f"Signé par : {report.signature.signed_by}")
    df = report.to_pandas()

Le format ISOF est un standard ouvert pour l'échange de données isotopiques | ISOF format is an open standard for isotope data exchange
Spécification : https://isofind.tech/isof-spec
"""

from .exceptions import ISOfError, ISOfParseError, ISOfSignatureError, ISOfVersionError
from .models import (
    Assignment,
    CreatedBy,
    IsotopeRecord,
    Method,
    Pipeline,
    Project,
    PurificationYield,
    Sample,
    Signature,
)
from .parser import ISOfDocument, load_file, load_string
from .signature import VerificationResult

__version__ = "0.1.1"
__author__ = "Colin Ferrari"
__all__ = [
    # Fonctions d'entrée principales
    "load",
    "loads",
    # Document
    "ISOfDocument",
    # Modèles
    "Sample",
    "IsotopeRecord",
    "Method",
    "Pipeline",
    "PurificationYield",
    "Assignment",
    "CreatedBy",
    "Project",
    "Signature",
    "VerificationResult",
    # Exceptions
    "ISOfError",
    "ISOfParseError",
    "ISOfVersionError",
    "ISOfSignatureError",
]


def load(path) -> ISOfDocument:
    """Charge un fichier .isof depuis le disque. | Load an .isof file from disk

    Args:
        path: Chemin vers le fichier, str ou pathlib.Path.

    Returns:
        ISOfDocument prêt à l'emploi. | Ready to use

    Raises:
        ISOfParseError: Fichier introuvable, JSON invalide, ou structure ISOF non reconnue. | Unfound file, invalid JSON or ISOF structure unrecognised
        ISOfVersionError: Version du format non supportée par ce parser. | Format unsupported by this parser

    Example: | Exemple :
        >>> report = isof.load("analyse_bolivie.isof")
        >>> print(report)
        <ISOfDocument v1.0 — 12 échantillon(s) — IGE Grenoble>
    """
    _, doc = load_file(path)
    return doc


def loads(text: str) -> ISOfDocument:
    """Charge un document ISOF depuis une chaîne JSON. | Load a ISOF document from a JSON chain.

    Utile pour tester, ou pour lire depuis une API qui retourne du ISOF. | Useful to test or read from an API returning ISOF.

    Args:
        text: Contenu JSON d'un document ISOF. | JSON content of an ISOF document.

    Returns:
        ISOfDocument prêt à l'emploi. | ISOFDocument ready to use.
    """
    _, doc = load_string(text)
    return doc
