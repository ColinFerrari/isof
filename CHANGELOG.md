# Changelog

Toutes les évolutions notables de `isof` sont listées ici.
All notable changes to `isof` are listed here.

---

## [0.2.0] - 2026-04-22

### Ajouté | Added

- Support des versions **ISOF v1.1 et v1.2** en plus de v1.0.
  Le parser accepte maintenant les trois versions simultanément via
  `SUPPORTED_VERSIONS = ("1.0", "1.1", "1.2")`.
- Trois nouvelles familles de données par échantillon (v1.2) :
  - `GeochemRecord` - concentrations élémentaires avec valeur pivot
    `value_normalized` (mg/kg) et valeur d'affichage `display_value` /
    `display_unit` préservant l'unité d'origine.
  - `PhysicoRecord` - paramètres physico-chimiques (pH, Eh, T, conductivité...).
  - `MoleculeRecord` - molécules et ions dissous avec conformité réglementaire
    (`conforme`, `seuil_ref`, `seuil_ref_unit`).
- `ISOfDocument.non_compliant_molecules()` - retourne uniquement les molécules
  avec `conforme == False`, ignore les `None` (donnée manquante).
- `Sample.physico_parameter(name)` - récupère un paramètre physico-chimique
  par son identifiant (retourne None si absent).
- `Sample.elements()` étendu : combine les éléments présents en isotope_data
  ET en geochem_data.
- `ISOfDocument.to_pandas(family=...)` - l'export DataFrame prend désormais
  une famille parmi `isotope` (défaut), `geochem`, `physico`, `molecules`.
- `ISOfDocument.to_csv(family=...)` aligné.
- **Chiffrement de bout en bout v1.2** :
  - Nouveau bloc `Encryption` exposé au parsing.
  - `ISOfDocument.is_encrypted` - propriété booléenne.
  - `ISOfDocument.decrypt(recipient_private_key)` - déchiffre le contenu
    scientifique et retourne un nouveau document clair.
  - Module `isof.encryption` avec enveloppe hybride X25519 + HKDF-SHA256
    + ChaCha20-Poly1305 (AES-256-GCM supporté en alternative).
  - Clé privée acceptée en PEM PKCS#8, raw 32 octets, ou base64 des 32 octets.
  - Appel idempotent sur un document déjà clair.
- Nouvelle exception `ISOfEncryptionError` dans la hiérarchie.
- Tolérance : `material_type` tombe désormais sur l'alias `matrix` s'il est
  le seul présent (convention IsoFind).
- Les booléens `detecte` et `conforme` sont normalisés en bool ou None via
  un helper, supportant les formats JSON true/false, 1/0, "true"/"false".

### Modifié | Changed

- Version bump **0.1.1 → 0.2.0**.
- `Sample.__dataclass__` : trois nouveaux champs tuples vides par défaut.
  La rétrocompat est totale : un fichier v1.0 charge avec les tuples vides.
- Représentation `__repr__` de `ISOfDocument` : ajoute `[chiffré]` quand
  applicable, reflète la version 1.0/1.1/1.2.
- Description du package dans `pyproject.toml` élargie.

### Correctifs | Fixed

- Les fichiers v1.1 émis par IsoFind qui embarquent déjà les blocs v1.2
  (observé en production sur des exports 2026-04) sont désormais acceptés
  sans erreur de version.

### Tests

- 84 tests passent : couvre v1.0 bolivie, v1.1 réel, v1.2 pure, v1.2 chiffrée.
- Tests de rétrocompat : blocs v1.2 absents sur fichier v1.0 → tuples vides.
- Tests de signature : altération dans n'importe quelle famille v1.2 invalide.
- Tests de chiffrement : round-trip, clé étrangère, payload corrompu,
  enveloppe malformée, PEM invalide, idempotence.

---

## [0.1.1] - 2026-03-11

- Publication initiale sur PyPI.
- Support ISOF v1.0 : parsing, vérification signature niveau 1 (SHA-256) et
  niveau 2 (ECDSA P-256 + PKI IsoFind), export pandas/CSV.
- Certificats Root CA et Issuing CA IsoFind embarqués pour vérification
  hors-ligne.
