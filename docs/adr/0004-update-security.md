# ADR 0004 — Sécurité des mises à jour

- **Statut** : Proposé
- **Date** : 2026-11-12
- **Étude** : `docs/research/06-supply-chain-updates.md`

## Contexte

Une mise à jour compromise est une menace critique (brief §6). Kaput doit aussi publier très vite les
correctifs du navigateur. Pour l'instant, le projet a **un seul mainteneur et détenteur de clés**
(décision D13).

## Alternatives

| Option | Avantages | Inconvénients | Verdict |
|---|---|---|---|
| Hash publié + HTTPS | Simple | Aucune protection contre la compromission du serveur, le rollback ou le gel | Rejeté |
| Signature unique (minisign, updater Tauri) | Simple | Une seule clé, pas de fraîcheur, pas de délégation | Rejeté |
| Sigstore seul (keyless) | Transparence publique | Ne prouve que l'identité de la CI : si la CI est compromise, l'artefact passe | Complément |
| **TUF + provenance SLSA** | Fraîcheur, anti-rollback, délégations, seuils, robustesse face à la compromission du dépôt | Plus complexe ; dépend de l'organisation des clés | **Retenu** |

## Décision

- **TUF est l'unique autorité**, pour l'image invitée comme pour l'application hôte.
- **Rôles** :
  - `root` hors ligne, **2-sur-3** sur clés matérielles conservées en lieux distincts ;
  - `targets` hors ligne ;
  - délégations terminantes :
    - `guest-image` (expiration 14 j) ;
    - `host-app` ;
    - `trust-config` ;
  - `snapshot` et `timestamp` (24 h) signés **hors CI et hors CDN**. Le CDN ne détient aucune clé.
- **Deux contrôles** (qui ne forment deux domaines de confiance indépendants qu'avec au moins deux personnes) :
  - la CI produit une provenance SLSA L3 (Sigstore keyless) ;
  - le signataire humain la vérifie avec `kaput-sign` avant de signer `guest-image` ;
  - en v1, le client ne vérifie que TUF, faute de bibliothèque Rust Sigstore mature.
- **Client** : `tough` épinglé, avec des métadonnées de taille bornée et fuzzées.
- **Avant chaque boot** :
  - fraîcheur, version et `security_epoch` ;
  - fichiers ouverts en lecture exclusive ;
  - hash du noyau calculé sur le **tampon effectivement passé au VMM** ;
  - ligne de commande construite **uniquement** depuis le champ signé (contient `roothash`) ;
  - dm-verity couvre toute altération postérieure.
- **Politique** :
  - erreur de vérification : refus de l'artefact, jamais de repli vers du non vérifié ;
  - rollback : refus et alerte ;
  - `minimum_version` signé : révocation ;
  - fraîcheur : bandeau après 24 h, modal après 72 h, **blocage après 7 j**, sans contournement par
    défaut.
- **Build** :
  - mkosi hermétique ;
  - snapshot Debian et lockfile ;
  - actions GitHub épinglées par SHA ;
  - double build comparé ;
  - SBOM CycloneDX + SPDX ;
  - **la CI ne détient aucune clé TUF**.

## Conséquences et risque résiduel (mainteneur unique)

Le seuil 2-sur-3 protège contre la perte ou le vol d'**une** clé. Face à la compromission du mainteneur
ou de son poste, il équivaut à du **1-sur-1**.

En v1, le client ne vérifie que TUF. Le « double domaine CI + humain » se réduit donc à **un seul
domaine : le poste de signature** (revue 0001, RT-03). TB6 est classée **risque élevé en v1**.

Contrôles compensatoires retenus, par ordre d'effet réel :
1. **Rebuild reproductible indépendant dès la phase 1.** Un second build sur une autre infrastructure,
   ouvert aux tiers, doit produire le même `verity_roothash`. Une divergence est d'abord signalée, puis
   bloquante dès que la reproductibilité est prouvée (NEG-REBUILD-01).
2. **Transparence publique** : toutes les métadonnées TUF, SBOM et attestations sont publiées dans des
   logs append-only (immutable releases + Rekor).
3. **Poste de signature isolé** : média live hors ligne, vérification de la provenance et du diff
   SBOM/lockfile sur ce poste, journal de cérémonie signé.
4. Révocation rapide (`guest-image` à 14 j, `minimum_version`, `security_epoch`) et clés distinctes par
   délégation.
5. Zéro `build.rs` ni proc-macro dans la TCB des parseurs (leçon `arrayref`).
6. Empreinte root et identité du workflow publiées par un canal indépendant.

Dès qu'un second mainteneur existe, les rôles `root` et `host-app` sont redistribués entre de vrais
détenteurs distincts.

L'identifiant de session ajouté à la ligne de commande est une **valeur de longueur fixe, au charset
fermé**. Tout autre ajout est refusé (RT-14, NEG-CMDLINE-01).
