"""
Hiérarchie d'exceptions du parser ISOF.

On distingue les erreurs de parsing (fichier malformé ou incompatible)
des erreurs de signature (fichier valide structurellement mais dont
l'intégrité ne peut pas être confirmée) et des erreurs de chiffrement
(le contenu scientifique est opaque sans la clé privée appropriée).
Cette séparation permet aux appelants de traiter chaque cas
différemment sans inspecter le message.

ISOF parser exception hierarchy.

A distinction is made between parsing errors (malformed or incompatible file),
signature errors (structurally valid file but whose integrity cannot be
confirmed) and encryption errors (scientific payload opaque without the
appropriate private key). This separation allows callers to handle each
case differently without inspecting the message.
"""

from __future__ import annotations


class ISOfError(Exception):
    """
    Classe de base, attraper celle-ci pour gérer toutes les erreurs ISOF.
    Base class, catch this one to handle all ISOF errors.
    """


class ISOfParseError(ISOfError):
    """
    Le fichier n'est pas un document ISOF valide ou lisible.
    Causes typiques : JSON malformé, champ obligatoire absent,
    version du format incompatible avec ce parser.

    The file is not a valid or readable ISOF document.
    Typical causes: Malformed JSON, missing required field,
    format version incompatible with this parser.
    """


class ISOfVersionError(ISOfParseError):
    """
    La version du format déclarée dans le fichier n'est pas supportée.
    Elle est différente d'ISOfParseError pour que les outils puissent
    suggérer une mise à jour du parser plutôt qu'un message d'erreur classique.

    The format version declared in the file is not supported.
    It differs from ISOfParseError so that tools can
    suggest a parser update rather than a standard error message.
    """

    def __init__(self, found: str, supported: tuple[str, ...]) -> None:
        self.found = found
        self.supported = supported
        super().__init__(
            f"Version ISOF '{found}' non supportée. "
            f"Versions supportées : {', '.join(supported)}"
        )


class ISOfSignatureError(ISOfError):
    """
    La signature est présente mais ne peut pas être vérifiée.

    Distinct d'une signature invalide (is_authentic() → False) :
    ici c'est le processus de vérification lui-même qui a échoué,
    par exemple parce que l'algorithme est inconnu ou que le certificat
    est illisible.

    The signature is present but cannot be verified.

    This differs from an invalid signature (is_authentic() → False):
    here, the verification process itself failed, for example,
    because the algorithm is unknown or the certificate is unreadable.
    """


class ISOfEncryptionError(ISOfError):
    """
    Le contenu scientifique du fichier est chiffré et ne peut pas être lu
    sans la clé privée du destinataire prévu.

    Distinct d'une erreur de signature : le fichier est structurellement
    valide et sa signature peut rester vérifiable sur l'enveloppe, mais
    les blocs samples/methods/purification sont opaques tant que le
    destinataire n'a pas fourni sa clé privée via decrypt().

    The scientific payload of the file is encrypted and cannot be read
    without the intended recipient's private key.

    Distinct from a signature error: the file remains structurally valid
    and its signature may still verify on the envelope, but the
    samples/methods/purification blocks are opaque until the recipient
    provides a private key through decrypt().
    """
