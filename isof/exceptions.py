"""
Hiérarchie d'exceptions du parser ISOF.

On distingue les erreurs de parsing (fichier malformé ou incompatible)
des erreurs de signature (fichier valide structurellement mais dont
l'intégrité ne peut pas être confirmée). Cette séparation permet aux
appelants de traiter les deux cas différemment sans inspecter le message.

ISOF parser exception hierarchy.

A distinction is made between parsing errors (malformed or incompatible file)
and signature errors (structurally valid file but whose
integrity cannot be confirmed). This separation allows
callers to handle the two cases differently without inspecting the message.
"""


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
