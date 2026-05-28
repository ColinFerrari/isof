"""
Déchiffrement du contenu scientifique des fichiers ISOF v1.2.

Le format ISOF v1.2 introduit un chiffrement optionnel de bout en bout
pour les échanges sensibles (défense, forensique, confidentialité client).
L'enveloppe est hybride :

  1) Une clé de session symétrique aléatoire (32 octets) est générée à
     l'export par IsoFind.
  2) Cette clé est chiffrée pour le destinataire via X25519 ECDH + HKDF,
     le résultat est stocké dans `encryption.encrypted_key`.
  3) Le contenu scientifique (samples, methods, purification, assignments)
     est sérialisé en JSON canonique puis chiffré avec un AEAD
     (ChaCha20-Poly1305 par défaut, AES-256-GCM en alternative) sous cette
     clé de session, le ciphertext est stocké dans `encryption.encrypted_payload`.

La signature de niveau 1 ou 2 peut être appliquée avant ou après chiffrement ;
IsoFind signe après, ce qui permet de vérifier l'intégrité de l'enveloppe sans
avoir à déchiffrer. Le parser respecte cette convention.

Ce module n'est requis que lorsque `ISOfDocument.decrypt()` est appelé ;
l'import de `isof` ne déclenche aucune opération cryptographique.
***************************************************************************
Decryption of the scientific payload for ISOF v1.2 encrypted files.

ISOF v1.2 introduces optional end-to-end encryption for sensitive exchanges
(defense, forensics, client confidentiality). The envelope is hybrid:

  1) A random 32-byte symmetric session key is generated at export by IsoFind.
  2) This key is wrapped for the recipient using X25519 ECDH + HKDF; the
     result is stored in `encryption.encrypted_key`.
  3) The scientific payload (samples, methods, purification, assignments) is
     JSON-canonicalized and encrypted with an AEAD (ChaCha20-Poly1305 default,
     AES-256-GCM alternative) under that session key; the ciphertext is
     stored in `encryption.encrypted_payload`.

A level 1 or 2 signature can be applied before or after encryption; IsoFind
signs after, which allows integrity verification of the envelope without
decrypting. The parser respects this convention.

This module is only required when `ISOfDocument.decrypt()` is called;
importing `isof` does not trigger any cryptographic operation.
"""

from __future__ import annotations

import base64 as _b64
import json
from typing import Any, Optional, Union

from .exceptions import ISOfEncryptionError


# Blocs scientifiques qu'un payload chiffré peut restituer. L'ordre est fixé
# par la spec : il détermine la canonicalisation de la signature éventuelle.
#***************************************************************************
# Scientific blocks that an encrypted payload may carry. Order is spec-fixed:
# it determines the canonicalization of any signature.
_PAYLOAD_BLOCKS = ("samples", "methods", "pipelines", "purification", "assignments")


def decrypt_document(raw_doc: dict, recipient_private_key: Union[str, bytes]) -> dict:
    """
    Déchiffre le contenu scientifique d'un document ISOF et retourne un dict
    strictement équivalent à un document non chiffré.

    L'appelant doit fournir la clé privée X25519 du destinataire en PEM
    (format PKCS#8 ou raw). Le bloc `encryption` du document d'entrée
    désigne le destinataire attendu via `recipient_id` ou
    `recipient_public_key` ; la clé fournie doit correspondre.

    Retourne un nouveau dict (le document d'entrée n'est pas modifié) dans
    lequel :
      - les blocs scientifiques sont remplacés par leur version claire,
      - le bloc `encryption` est conservé mais `active` passe à False pour
        indiquer que le contenu est désormais lisible en mémoire,
      - les autres blocs (created_by, project, signature...) restent inchangés.

    Raises:
        ISOfEncryptionError: clé inadaptée, payload corrompu, algorithme
            non supporté, ou bloc `encryption` structurellement incomplet.
    ***************************************************************************
    Decrypt the scientific payload of an ISOF document and return a dict
    strictly equivalent to an unencrypted document.

    The caller must provide the recipient's X25519 private key as PEM
    (PKCS#8 or raw format). The input document's `encryption` block names
    the intended recipient via `recipient_id` or `recipient_public_key`;
    the supplied key must match.

    Returns a new dict (input document is not mutated) in which:
      - scientific blocks are replaced by their cleartext version,
      - the `encryption` block is preserved but `active` flips to False to
        indicate the content is now readable in memory,
      - other blocks (created_by, project, signature...) remain unchanged.

    Raises:
        ISOfEncryptionError: mismatched key, corrupted payload, unsupported
            algorithm, or structurally incomplete `encryption` block.
    """
    enc = raw_doc.get("encryption") or {}
    if not isinstance(enc, dict) or not enc.get("active"):
        # Aucun chiffrement actif : on retourne le document tel quel
        # pour permettre un appel idempotent depuis l'API publique.
        # No active encryption: we return the document as-is to allow
        # idempotent calls from the public API.
        return raw_doc

    try:
        from cryptography.hazmat.primitives.asymmetric.x25519 import (
            X25519PrivateKey, X25519PublicKey
        )
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives.ciphers.aead import (
            ChaCha20Poly1305, AESGCM
        )
    except ImportError as e:
        raise ISOfEncryptionError(
            "The 'cryptography' package is required to decrypt ISOF files. "
            "pip install isof  (or pip install cryptography)"
        ) from e

    algorithm = (enc.get("algorithm") or "").lower()
    encrypted_key_b64     = enc.get("encrypted_key")
    encrypted_payload_b64 = enc.get("encrypted_payload")
    nonce_b64             = enc.get("nonce")

    if not encrypted_key_b64 or not encrypted_payload_b64 or not nonce_b64:
        raise ISOfEncryptionError(
            "Incomplete encryption block: "
            "encrypted_key, encrypted_payload and nonce are all required"
        )

    # Charger la clé privée destinataire. On accepte PEM texte ou bytes,
    # et on tolère une clé en format raw base64 pour les tests.
    # Load the recipient private key. PEM text/bytes accepted; raw
    # base64 tolerated for testing convenience.
    priv_key = _load_x25519_private_key(recipient_private_key)

    # Dérouler l'enveloppe X25519 : recompose la clé de session de 32 octets.
    # Structure attendue pour encrypted_key : base64( ephemeral_pub(32) || wrapped(32) )
    # où wrapped = session_key XOR HKDF(shared_secret). Le choix du XOR + HKDF
    # plutôt qu'un AEAD sur la clé reflète la convention IsoFind : la clé de
    # session est déjà aléatoire et le wrapping sert uniquement à la transporter.
    #***************************************************************************
    # Unwrap the X25519 envelope: recover the 32-byte session key.
    # Expected structure for encrypted_key: base64( ephemeral_pub(32) || wrapped(32) )
    # where wrapped = session_key XOR HKDF(shared_secret). The XOR + HKDF choice
    # rather than AEAD on the key follows IsoFind convention: the session key is
    # already random, wrapping only transports it.
    try:
        envelope = _b64.b64decode(encrypted_key_b64)
    except Exception as e:
        raise ISOfEncryptionError(f"encrypted_key is not valid base64: {e}") from e

    if len(envelope) != 64:
        raise ISOfEncryptionError(
            f"Unexpected encrypted_key length: {len(envelope)} bytes (expected 64)"
        )

    ephemeral_pub_bytes = envelope[:32]
    wrapped_key         = envelope[32:]

    try:
        ephemeral_pub = X25519PublicKey.from_public_bytes(ephemeral_pub_bytes)
    except Exception as e:
        raise ISOfEncryptionError(
            f"Ephemeral public key malformed in encrypted_key: {e}"
        ) from e

    shared_secret = priv_key.exchange(ephemeral_pub)

    # Dérivation HKDF-SHA256 avec le contexte spécifique au format.
    # L'info-string est constante pour que deux implémentations (JS, Python)
    # dérivent la même clé de wrapping à partir du même shared_secret.
    # HKDF-SHA256 derivation with format-specific context. The info-string is
    # constant so that JS and Python implementations derive the same wrapping
    # key from the same shared_secret.
    wrap_key = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"ISOF-v1.2-key-wrap",
    ).derive(shared_secret)

    session_key = bytes(a ^ b for a, b in zip(wrapped_key, wrap_key))

    # Déchiffrer le payload scientifique avec l'AEAD désigné
    # Decrypt the scientific payload with the designated AEAD
    try:
        ciphertext = _b64.b64decode(encrypted_payload_b64)
        nonce = _b64.b64decode(nonce_b64)
    except Exception as e:
        raise ISOfEncryptionError(f"Ciphertext or nonce not base64: {e}") from e

    if "chacha20" in algorithm or "chacha" in algorithm:
        aead = ChaCha20Poly1305(session_key)
    elif "aes" in algorithm and "gcm" in algorithm:
        aead = AESGCM(session_key)
    else:
        # Tolérance : si l'algorithme n'est pas explicite, on tente ChaCha20-Poly1305
        # qui est le défaut IsoFind. L'échec se manifestera par une InvalidTag
        # et sera rapporté plus bas.
        # Tolerance: if algorithm is not explicit, we try ChaCha20-Poly1305
        # which is the IsoFind default. Failure surfaces as InvalidTag and is
        # reported below.
        aead = ChaCha20Poly1305(session_key)

    try:
        cleartext = aead.decrypt(nonce, ciphertext, associated_data=None)
    except Exception as e:
        raise ISOfEncryptionError(
            f"Payload decryption failed (wrong key or corrupted data): {e}"
        ) from e

    try:
        payload_blocks = json.loads(cleartext.decode("utf-8"))
    except Exception as e:
        raise ISOfEncryptionError(
            f"Decrypted payload is not valid JSON: {e}"
        ) from e

    if not isinstance(payload_blocks, dict):
        raise ISOfEncryptionError(
            "Decrypted payload must be a JSON object keyed by block name"
        )

    # Construire le document déchiffré. On part d'une copie superficielle du
    # document d'entrée et on remplace les blocs scientifiques. Le bloc
    # encryption est conservé mais marqué inactif : un lecteur aval saura
    # qu'il manipule un document qui a transité chiffré mais est désormais clair.
    #***************************************************************************
    # Build the decrypted document. Start from a shallow copy of the input
    # document and replace scientific blocks. The encryption block is preserved
    # but flagged inactive: downstream readers will know the document was in
    # transit encrypted but is now cleartext.
    decrypted: dict[str, Any] = dict(raw_doc)
    for block_name in _PAYLOAD_BLOCKS:
        if block_name in payload_blocks:
            decrypted[block_name] = payload_blocks[block_name]

    decrypted["encryption"] = dict(enc)
    decrypted["encryption"]["active"] = False

    return decrypted


def _load_x25519_private_key(material: Union[str, bytes]):
    """
    Charge une clé privée X25519 depuis trois formats possibles :
      - PEM PKCS#8 (texte ou bytes)
      - base64 brut des 32 octets de la clé privée
      - bytes bruts de 32 octets

    Le support multi-format facilite les tests et les intégrations tierces ;
    IsoFind lui-même émet du PEM PKCS#8.
    ***************************************************************************
    Load an X25519 private key from three possible formats:
      - PEM PKCS#8 (text or bytes)
      - raw base64 of the 32-byte private key
      - raw 32 bytes

    Multi-format support eases testing and third-party integrations;
    IsoFind itself emits PKCS#8 PEM.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    if isinstance(material, str):
        material_b = material.encode("utf-8")
    else:
        material_b = material

    # PEM PKCS#8
    if b"-----BEGIN" in material_b:
        try:
            key = serialization.load_pem_private_key(material_b, password=None)
        except Exception as e:
            raise ISOfEncryptionError(f"Invalid PEM private key: {e}") from e
        if not isinstance(key, X25519PrivateKey):
            raise ISOfEncryptionError(
                "Private key is not X25519 (required for ISOF v1.2 decryption)"
            )
        return key

    # Raw 32 bytes
    if len(material_b) == 32:
        try:
            return X25519PrivateKey.from_private_bytes(material_b)
        except Exception as e:
            raise ISOfEncryptionError(f"Invalid raw X25519 private key: {e}") from e

    # Base64 des 32 octets
    try:
        decoded = _b64.b64decode(material_b)
    except Exception as e:
        raise ISOfEncryptionError(
            "Private key must be PEM PKCS#8, raw 32 bytes or base64 of 32 bytes"
        ) from e

    if len(decoded) != 32:
        raise ISOfEncryptionError(
            f"Base64-decoded key length: {len(decoded)} bytes (expected 32)"
        )

    try:
        return X25519PrivateKey.from_private_bytes(decoded)
    except Exception as e:
        raise ISOfEncryptionError(f"Invalid decoded X25519 private key: {e}") from e
