"""
Tests de déchiffrement ISOF v1.2.

Les fichiers chiffrés ont un contenu scientifique opaque : samples, methods,
purification et assignments sont None jusqu'à l'appel de decrypt(). Ces tests
couvrent le round-trip complet (fixture chiffrée + clé → document clair), les
cas d'erreur (clé étrangère, payload corrompu, bloc incomplet), et la
tolérance d'appel idempotent sur un document déjà clair.

Fixtures attendues :
  - v12_encrypted.isof       : document v1.2 chiffré X25519 + ChaCha20-Poly1305
  - v12_encrypted_key.pem    : clé privée X25519 du destinataire (PEM PKCS#8)
  - v12_full.isof            : document v1.2 clair (pour tests idempotence)
****************************************************************************
ISOF v1.2 decryption tests.

Encrypted files have an opaque scientific payload: samples, methods,
purification and assignments are None until decrypt() is called. These tests
cover the full round-trip (encrypted fixture + key → cleartext document),
error cases (foreign key, corrupted payload, incomplete block), and the
idempotent-call tolerance on an already-cleartext document.

Expected fixtures:
  - v12_encrypted.isof       : v1.2 X25519 + ChaCha20-Poly1305 encrypted document
  - v12_encrypted_key.pem    : recipient X25519 private key (PEM PKCS#8)
  - v12_full.isof            : cleartext v1.2 document (for idempotence tests)
"""

import base64
import json
from pathlib import Path

import pytest

import isof
from isof.exceptions import ISOfEncryptionError
from isof.parser import load_string

FIXTURES      = Path(__file__).parent / "fixtures"
ENC_FILE      = FIXTURES / "v12_encrypted.isof"
ENC_KEY_PEM   = FIXTURES / "v12_encrypted_key.pem"
V12_FULL      = FIXTURES / "v12_full.isof"


# cryptography est nécessaire pour tout ce module ; on skip proprement s'il
# manque plutôt que d'échouer en collection.
# cryptography is required for this whole module; we skip cleanly when absent
# rather than failing at collection time.
pytest.importorskip("cryptography")


# ---------------------------------------------------------------------------
# Détection du chiffrement actif | Active encryption detection
# ---------------------------------------------------------------------------

def test_encrypted_document_is_flagged():
    doc = isof.load(ENC_FILE)
    assert doc.is_encrypted
    assert doc.encryption is not None
    assert doc.encryption.algorithm is not None


def test_encrypted_document_has_empty_scientific_blocks():
    """
    Un document chiffré doit exposer des collections vides côté scientifique.
    Cela permet aux appelants d'itérer sans vérifier is_encrypted en amont
    sans risquer de confondre "zéro donnée" avec "donnée chiffrée".
    ***************************************************************************
    An encrypted document must expose empty scientific collections. This lets
    callers iterate without checking is_encrypted upfront, without risking
    confusion between "zero data" and "encrypted data" — is_encrypted is the
    reliable signal.
    """
    doc = isof.load(ENC_FILE)
    assert doc.samples == tuple()
    assert doc.methods == {}
    assert doc.pipelines == {}
    assert doc.purification == {}
    assert doc.assignments == tuple()


def test_encrypted_document_preserves_metadata():
    """
    Les métadonnées d'enveloppe (created_by, project) restent lisibles
    même sur un document chiffré : elles vivent en dehors du payload opaque.
    ***************************************************************************
    Envelope metadata (created_by, project) remains readable on an encrypted
    document: it lives outside the opaque payload.
    """
    doc = isof.load(ENC_FILE)
    assert doc.created_by is not None
    assert doc.created_by.organisation == "IsoFind SAS"
    assert doc.project is not None


def test_cleartext_document_is_not_flagged():
    doc = isof.load(V12_FULL)
    assert not doc.is_encrypted
    assert doc.encryption is None


# ---------------------------------------------------------------------------
# Round-trip chiffrement + déchiffrement | Encryption round-trip
# ---------------------------------------------------------------------------

def test_decrypt_roundtrip_pem():
    """
    Déchiffrement complet avec la clé PEM PKCS#8 attendue :
    le document résultant doit contenir les mêmes blocs que v12_full.
    ***************************************************************************
    Full decryption with the expected PEM PKCS#8 key: resulting document
    must contain the same blocks as v12_full.
    """
    encrypted_doc = isof.load(ENC_FILE)
    priv_pem = ENC_KEY_PEM.read_text()

    clear_doc = encrypted_doc.decrypt(priv_pem)

    assert not clear_doc.is_encrypted
    assert len(clear_doc.samples) == 2
    assert clear_doc.samples[0].name == "CR1"
    assert len(clear_doc.samples[0].geochem_data) == 2
    assert len(clear_doc.samples[0].molecules_data) == 2


def test_decrypt_preserves_envelope_fields():
    """
    Après déchiffrement, l'enveloppe est conservée pour audit : created_by,
    project et le bloc encryption (flag active passé à False) restent accessibles.
    ***************************************************************************
    After decryption, the envelope is preserved for audit: created_by,
    project and the encryption block (active flag flipped to False) remain
    accessible.
    """
    encrypted_doc = isof.load(ENC_FILE)
    priv_pem = ENC_KEY_PEM.read_text()
    clear_doc = encrypted_doc.decrypt(priv_pem)

    assert clear_doc.created_by is not None
    assert clear_doc.project is not None
    assert clear_doc.encryption is not None
    assert clear_doc.encryption.is_active is False


def test_decrypt_accepts_pem_as_bytes():
    """
    La clé peut être fournie en bytes ou en str, indifféremment.
    The key can be provided as bytes or str, interchangeably.
    """
    encrypted_doc = isof.load(ENC_FILE)
    priv_pem_bytes = ENC_KEY_PEM.read_bytes()
    clear_doc = encrypted_doc.decrypt(priv_pem_bytes)
    assert len(clear_doc.samples) == 2


def test_decrypt_accepts_raw_32_bytes():
    """
    Une clé fournie au format raw (32 octets) est acceptée.
    La conversion PEM → raw passe par la sérialisation cryptography.
    ***************************************************************************
    A raw-format key (32 bytes) is accepted. PEM → raw conversion goes
    through cryptography's serialization.
    """
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

    priv_key = serialization.load_pem_private_key(ENC_KEY_PEM.read_bytes(), password=None)
    assert isinstance(priv_key, X25519PrivateKey)
    raw_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    assert len(raw_bytes) == 32

    encrypted_doc = isof.load(ENC_FILE)
    clear_doc = encrypted_doc.decrypt(raw_bytes)
    assert len(clear_doc.samples) == 2


def test_decrypt_accepts_base64_of_raw():
    """
    Une clé encodée en base64 de ses 32 octets raw doit aussi fonctionner.
    A base64-encoded raw 32-byte key must also work.
    """
    from cryptography.hazmat.primitives import serialization
    priv_key = serialization.load_pem_private_key(ENC_KEY_PEM.read_bytes(), password=None)
    raw_bytes = priv_key.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    b64 = base64.b64encode(raw_bytes).decode("ascii")

    encrypted_doc = isof.load(ENC_FILE)
    clear_doc = encrypted_doc.decrypt(b64)
    assert len(clear_doc.samples) == 2


# ---------------------------------------------------------------------------
# Cas d'erreur | Error cases
# ---------------------------------------------------------------------------

def test_decrypt_wrong_key_raises():
    """
    Une clé privée sans rapport avec le destinataire chiffré doit lever
    ISOfEncryptionError : le shared_secret sera différent, donc la tag
    AEAD du payload ne validera pas.
    ***************************************************************************
    A private key unrelated to the encrypted recipient must raise
    ISOfEncryptionError: the shared_secret will differ, so the payload AEAD
    tag will not validate.
    """
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    foreign_key = X25519PrivateKey.generate()
    foreign_pem = foreign_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    encrypted_doc = isof.load(ENC_FILE)
    with pytest.raises(ISOfEncryptionError, match="decryption failed"):
        encrypted_doc.decrypt(foreign_pem)


def test_decrypt_corrupted_payload_raises():
    """
    Un ciphertext tronqué ou altéré doit lever une erreur de déchiffrement.
    A truncated or tampered ciphertext must raise a decryption error.
    """
    raw_text = ENC_FILE.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    # Altération ciblée : on remplace le dernier octet du ciphertext (tag AEAD)
    # Targeted alteration: replace the last byte of the ciphertext (AEAD tag)
    ct = base64.b64decode(raw["encryption"]["encrypted_payload"])
    tampered = ct[:-1] + bytes([(ct[-1] ^ 0xFF) & 0xFF])
    raw["encryption"]["encrypted_payload"] = base64.b64encode(tampered).decode()

    _, encrypted_doc = load_string(json.dumps(raw))
    priv_pem = ENC_KEY_PEM.read_text()
    with pytest.raises(ISOfEncryptionError):
        encrypted_doc.decrypt(priv_pem)


def test_decrypt_missing_block_field_raises():
    """
    Un bloc encryption actif mais incomplet (nonce absent par exemple) doit
    remonter une erreur explicite plutôt qu'un traceback cryptographique brut.
    ***************************************************************************
    An active but incomplete encryption block (e.g. missing nonce) must raise
    an explicit error rather than a raw cryptographic traceback.
    """
    raw_text = ENC_FILE.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["encryption"]["nonce"] = None
    _, encrypted_doc = load_string(json.dumps(raw))

    priv_pem = ENC_KEY_PEM.read_text()
    with pytest.raises(ISOfEncryptionError, match="Incomplete encryption block"):
        encrypted_doc.decrypt(priv_pem)


def test_decrypt_malformed_envelope_raises():
    """
    encrypted_key doit faire exactement 64 octets (pub éphémère + clé enveloppée).
    Une longueur différente est une corruption d'enveloppe.
    ***************************************************************************
    encrypted_key must be exactly 64 bytes (ephemeral pub + wrapped key).
    A different length indicates envelope corruption.
    """
    raw_text = ENC_FILE.read_text(encoding="utf-8")
    raw = json.loads(raw_text)
    raw["encryption"]["encrypted_key"] = base64.b64encode(b"trop court").decode()
    _, encrypted_doc = load_string(json.dumps(raw))

    priv_pem = ENC_KEY_PEM.read_text()
    with pytest.raises(ISOfEncryptionError, match="encrypted_key length"):
        encrypted_doc.decrypt(priv_pem)


def test_decrypt_invalid_pem_raises():
    """
    Une clé PEM syntaxiquement invalide doit lever ISOfEncryptionError.
    A syntactically invalid PEM key must raise ISOfEncryptionError.
    """
    encrypted_doc = isof.load(ENC_FILE)
    bogus_pem = "-----BEGIN PRIVATE KEY-----\nRIEN_DU_TOUT\n-----END PRIVATE KEY-----"
    with pytest.raises(ISOfEncryptionError, match="PEM"):
        encrypted_doc.decrypt(bogus_pem)


# ---------------------------------------------------------------------------
# Idempotence | Idempotence
# ---------------------------------------------------------------------------

def test_decrypt_idempotent_on_cleartext():
    """
    Appeler decrypt() sur un document déjà clair retourne le document tel quel.
    Permet d'écrire du code défensif sans branchement sur is_encrypted.
    ***************************************************************************
    Calling decrypt() on an already-cleartext document returns it as-is.
    Allows defensive code without branching on is_encrypted.
    """
    clear_doc = isof.load(V12_FULL)
    # Une clé arbitraire : elle n'est pas consultée puisque l'appel doit court-circuiter
    # An arbitrary key: it is not consulted since the call must short-circuit
    priv_pem = ENC_KEY_PEM.read_text()
    same_doc = clear_doc.decrypt(priv_pem)
    assert same_doc is clear_doc


# ---------------------------------------------------------------------------
# Vérification de signature sur enveloppe chiffrée | Signature on encrypted envelope
# ---------------------------------------------------------------------------

def test_encrypted_document_with_signature_remains_verifiable():
    """
    La signature porte sur l'enveloppe ; elle doit rester vérifiable même
    quand le contenu scientifique est chiffré. On ajoute une signature
    niveau 1 sur created_by uniquement (scope qui ne dépend pas du payload
    chiffré) et on vérifie qu'elle passe.
    ***************************************************************************
    The signature targets the envelope; it must remain verifiable even when
    the scientific payload is encrypted. We add a level 1 signature on
    created_by only (scope independent of the encrypted payload) and verify
    it passes.
    """
    import hashlib
    raw_text = ENC_FILE.read_text(encoding="utf-8")
    raw = json.loads(raw_text)

    scope = ["created_by"]
    payload = {b: raw.get(b) for b in scope}
    canonical = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    raw["signature"] = {
        "level": 1,
        "algorithm": "SHA-256",
        "scope": scope,
        "hash": digest,
        "signed_at": "2026-04-01T10:01:00+00:00",
        "signed_by": "IsoFind SAS",
        "contact": None,
    }
    _, doc = load_string(json.dumps(raw))
    assert doc.is_encrypted
    assert doc.is_authentic()
