# 06 — Chaîne de confiance des mises à jour et supply chain

Auteur : agent *Update / Supply Chain Engineer* — Date : 2026-11-12 — Statut : RECHERCHE (aucune décision finale, à valider en ADR `0004-update-security.md`)

Périmètre : (1) application hôte Kaput (Windows + Linux) et son auto-update ; (2) image invitée (noyau + initrd + rootfs + navigateur) ; (3) pipeline de build CI de l'image ; (4) évaluation des dépendances supply chain.

Les versions et dates citées ont été vérifiées en ligne le 2026-11-12, sauf mention « non revérifié ». Le budget de recherche web de la session a été épuisé en fin d'étude ; les points marqués « à confirmer » n'ont pas pu être revérifiés.

---

## 1. Résumé exécutif

1. **TUF est l'autorité de mise à jour** pour l'image invitée *et* pour l'application hôte : root hors ligne à seuil, rôles délégués par composant, timestamp/snapshot en ligne à expiration courte. TUF borne l'impact d'une compromission du serveur de distribution (au pire : gel jusqu'à expiration du timestamp).
2. **Défense en profondeur à deux domaines de confiance indépendants** : un artefact n'est accepté que s'il est (a) signé dans TUF par une clé matérielle humaine (YubiKey) *et* (b) accompagné d'une attestation de provenance SLSA Build L3 (Sigstore, keyless) émise par *le* workflow réutilisable attendu. Compromettre la CI seule ou un signataire seul ne suffit pas.
3. **L'hôte vérifie avant de lancer la VM** : hash TUF du noyau/initrd + manifeste de boot signé contenant le `roothash` dm-verity, passé par la ligne de commande en *direct kernel boot*. Le rootfs (lecture seule) est ensuite vérifié bloc par bloc par dm-verity dans l'invité, ce qui couvre aussi la modification du fichier image sur le disque hôte après vérification.
4. **Anti-rollback** : versions TUF persistées + `minimum_version` signé dans les métadonnées + expiration du rôle `guest-image` à 14 jours (force un re-signage au moins à chaque cycle Chrome de 2 semaines).
5. **Politique** : toute erreur de vérification = refus (fail closed) sans repli vers du non vérifié. Hors ligne : image en cache autorisée avec délai de grâce (avertissement > 72 h, blocage > 7 jours), seuils à valider par l'utilisateur.
6. **Risque n°1 : la latence du patch navigateur**, pas la cryptographie. Exemple mesuré : Chromium 156.0.8078.79 publié le 29/10/2026 → DSA Debian le 02/11/2026 (~4 jours). Le choix de la source du binaire navigateur est une décision produit.
7. **Le build de l'image doit être quasi-hermétique et reproductible** : mkosi + snapshot Debian épinglé + actions GitHub épinglées par SHA (cf. compromissions tj-actions 2025 et Trivy 2026).

---

## 2. Menaces sur la chaîne de mise à jour

Une mise à jour compromise est traitée comme **critique** : elle donne à l'attaquant du code exécuté *par l'hôte* (application) ou *dans la frontière de confiance de l'invité* (image), sur tous les utilisateurs en même temps, et contourne l'isolation, qui est le produit lui-même.

### 2.1 Acteurs et points de compromission

| # | Point de compromission | Exemple réel / scénario | Impact sans contre-mesure |
|---|---|---|---|
| T1 | Serveur/CDN de distribution | Notepad++ 2025 : l'hébergeur mutualisé a été compromis et le trafic de mise à jour redirigé vers des installeurs malveillants pendant ~6 mois, de façon ciblée, parce que WinGUp ne vérifiait pas les fichiers téléchargés ([Help Net Security](https://www.helpnetsecurity.com/2026/02/02/2025-notepad-supply-chain-compromise/)) | Installation arbitraire, ciblage individuel |
| T2 | Réseau (MITM, DNS, TLS d'entreprise interceptant) | Proxy TLS, DNS empoisonné | Idem T1 |
| T3 | CI / runner / actions tierces | tj-actions/changed-files (mars 2025) : tags réécrits vers un commit malveillant qui écrit les secrets dans les logs ([Wiz](https://www.wiz.io/it-it/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066)). Trivy (19/03/2026) : binaire v0.69.4 malveillant, 76 tags sur 77 de `trivy-action` et tous les tags de `setup-trivy` réécrits, exfiltration des secrets CI ; la rotation de credentials incomplète du 1er mars a laissé l'accès à l'attaquant ([Aqua](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)) | Build empoisonné **signé légitimement** |
| T4 | Clés de signature | Vol d'une clé en ligne, d'un token, d'un compte GitHub | Signature d'artefacts arbitraires |
| T5 | Dépendance amont (paquet distro, Chromium, noyau) | Porte dérobée du type xz-utils (CVE-2024-3094) | Code malveillant *authentique* |
| T6 | Mainteneur / insider | Signataire unique contraint ou malveillant | Release malveillante |
| T7 | Stockage local de l'hôte | Remplacement de l'image en cache entre vérification et lancement (TOCTOU) | Exécution d'une image non vérifiée |
| T8 | Plateforme (GitHub, Sigstore public good, OIDC) | Compromission de l'émetteur OIDC ou de Fulcio | Faux certificats keyless |

### 2.2 Attaques propres aux systèmes de mise à jour (taxonomie TUF)

D'après la [page sécurité TUF](https://theupdateframework.io/security/) :

- **Installation arbitraire** : le client accepte n'importe quel fichier.
- **Rollback** : le client reçoit des fichiers plus anciens que ceux qu'il a déjà vus, donc des vulnérabilités connues (critique pour un navigateur).
- **Freeze indéfini** : on rejoue des métadonnées anciennes mais valides et le client ne voit jamais les nouvelles versions. Particulièrement dangereux ici, puisqu'il permet de garder les utilisateurs sur un Chromium vulnérable à un 0-day.
- **Fast-forward** : versions gonflées dans les métadonnées pour que les vraies mises à jour ultérieures soient rejetées comme rollback.
- **Mix-and-match** : combinaison de fichiers qui n'ont jamais coexisté dans le dépôt (par exemple un noyau N avec un rootfs N-1).
- **Endless data** : flux infini qui épuise le disque ou la mémoire.
- **Wrong software** : fichier authentique mais pas celui demandé (image ARM servie à x86, canal beta servi en stable).
- **Miroirs malveillants**, **dépendances superflues**, **compromission d'une clé sous le seuil**.

Un simple « fichier + signature détachée » (minisign, GPG, Authenticode) couvre l'installation arbitraire mais **pas** freeze, mix-and-match, wrong-software ni la révocation/rotation de clés. C'est la raison principale pour laquelle TUF est retenu plutôt qu'une signature ad hoc.

---

## 3. Comparaison des outils

### 3.1 Frameworks de mise à jour (TUF)

| Implémentation | Langage | Dernière version vérifiée | Licence | Évaluation |
|---|---|---|---|---|
| python-tuf (référence, `ngclient`) | Python | v7.0.1 (01/09/2026), v7.0.0 (18/05/2026) ([Release Alert](https://releasealert.dev/github/theupdateframework/python-tuf)) | MIT / Apache-2.0 | Implémentation de référence, très suivie. **Recommandée côté dépôt/outillage CI**, pas dans le client hôte (runtime Python à embarquer). |
| go-tuf v2 | Go | v2.3.0 (~oct. 2026), v2.2.0 (~août 2026) ([ecosyste.ms](https://packages.ecosyste.ms/registries/proxy.golang.org/packages/github.com%2Ftheupdateframework%2Fgo-tuf%2Fv2/versions)) | Apache-2.0 | Réécriture calquée sur python-tuf, utilisée par l'écosystème Sigstore. Antécédent : CVE-2022-29173 (workflow client incorrect pour les rôles non-root, v0.x) ([OpenCVE](https://ocve.arawa.fr/cve/CVE-2022-29173)). **Recommandée si l'hôte est en Go.** |
| tough / tuftool (AWS) | Rust | tough v0.24.0 / tuftool v0.17.0 (10/07/2026) ([Release Alert](https://releasealert.dev/github/awslabs/tough)) | MIT / Apache-2.0 ([GitHub](https://github.com/awslabs/tough)) | Maintenu par AWS (utilisé par Bottlerocket, non revérifié). Trois CVE (CVE-2026-6966/6967/6968) corrigées en 0.22.0, sans contournement possible ([bulletin AWS 2026-019](https://aws.amazon.com/jp/security/security-bulletins/2026-019-aws/)) : signe d'audit actif, mais aussi d'une surface de bugs réelle. **Recommandée si l'hôte est en Rust**, version ≥ 0.24, avec tests de conformité. |
| rust-tuf | Rust | 0.3.0-beta9 (19/07/2022) sur crates.io ([lib.rs](https://lib.rs/crates/tuf)) ; dépôt peu actif ([ecosyste.ms](https://repos.ecosyste.ms/hosts/GitHub/repositories/theupdateframework%2Frust-tuf)) | MIT / Apache-2.0 | Bêta, API instable, pas de release depuis 2022. **À écarter.** |
| RSTUF (Repository Service for TUF) | Python (service) | v1.0.0 stable, auditée ([RSTUF](https://repository-service-tuf.readthedocs.io/en/latest/blog/posts/rstuf-v1.0.0-is-out.html), [OpenSSF](https://openssf.org/blog/2025/04/25/repository-service-for-the-update-framework-rstuf-reaches-new-security-milestone-with-successful-audit/)) | à confirmer | Service de dépôt : root via YubiKey/PEM/Sigstore, clés en ligne via KMS cloud ou Vault, délégations. Pertinent si le volume grossit ; **surdimensionné pour la v1** (python-tuf + scripts suffit). |

Exigence transverse : quelle que soit l'implémentation, passer une **suite de tests de conformité TUF** (projet `tuf-conformance`, à confirmer) et nos propres tests négatifs (rollback, freeze, mix-and-match, endless data, rotation de root) en CI.

### 3.2 Signature et transparence : Sigstore / cosign

- **État** : Rekor v2 en GA depuis le 10/10/2025 (log à tuiles basé sur Tessera, uniquement `hashedrekord` et `dsse`, preuves d'inclusion à stocker dans le bundle, horodatage fourni par une TSA séparée, witnessing pas encore implémenté) ; support à partir de cosign v2.6.0+/v3.0.1+ ; Rekor v1 sera gelé avec un préavis d'un an ([blog Sigstore](https://blog.sigstore.dev/rekor-v2-ga/)).
- **Vérification hors ligne** : possible avec un bundle complet et un `TrustedRoot` distribué au préalable. Un bundle ne révèle pas un changement de racine de confiance postérieur, donc les environnements hors ligne ont besoin d'un rafraîchissement contrôlé ([OneUptime](https://oneuptime.com/blog/post/2026-08-11-rekor-cosign-verification-transparency-log-outage/markdown)).
- **Keyless vs clés** :
  - *Keyless* (OIDC → certificat Fulcio éphémère → Rekor). Avantages : pas de clé longue durée à protéger, transparence publique, identité = workflow CI précis. Limites : l'autorisation repose sur GitHub OIDC + Fulcio + la racine TUF de Sigstore (T8), et **quiconque contrôle le workflow (T3) obtient une signature valide**. Le keyless prouve *d'où* vient l'artefact, pas *que l'éditeur l'a approuvé*.
  - *Clés gérées* (cosign + KMS/YubiKey) : l'autorisation est contrôlée, mais il faut gérer rotation et révocation, ce que TUF fait mieux.
- **Bibliothèque Rust** : `sigstore-rs` se déclare expérimental avant 1.0, sans vérification d'attestations ([GitHub](https://github.com:443/sigstore/sigstore-rs), [lib.rs](https://lib.rs/crates/sigstore) : 0.10.0 de sept. 2024 selon la page consultée, possiblement obsolète). Des crates `sigstore-verify`/`sigstore-bundle` (0.6.3, 02/2026) existent mais leur rattachement officiel n'est pas établi ([lib.rs](https://lib.rs/crates/sigstore-verify)). En Go, les bibliothèques Sigstore officielles sont matures (sigstore-go, non revérifié). **Conséquence : si l'hôte est en Rust, la vérification de provenance côté client est un risque de dépendance.** Option : vérifier la provenance côté *serveur de release* uniquement (voir §4.4, variante B).

**Recommandation** : Sigstore keyless pour les **attestations de provenance et de SBOM** (auditabilité, transparence) ; **TUF avec des clés Kaput pour l'autorisation** de mise à jour.

### 3.3 in-toto, SLSA, attestations GitHub

- **in-toto** : projet CNCF diplômé (graduated) le 23/04/2025 ([CNCF](https://cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries)). Nous utilisons son **format d'attestation** (enveloppe DSSE + statement + prédicat SLSA/SPDX/CycloneDX). Les *layouts* in-toto complets (chaîne d'étapes signées) sont optionnels en v1 : on ne vérifie que la provenance du build final.
- **SLSA** : v1.2 publiée le 24/11/2025, ajoute la Source Track et reste rétrocompatible avec v1.1 ([slsa.dev](https://slsa.dev/blog/2025/11/announce-slsa-v1.2)). Build L1 = la provenance existe ; L2 = plateforme hébergée et provenance signée par le plan de contrôle ; **L3 = provenance infalsifiable (secrets inaccessibles aux étapes utilisateur) et builds isolés et éphémères**. L3 **n'exige ni hermiticité ni reproductibilité** ([SLSA build requirements](https://slsa.dev/spec/v1.2/build-requirements)). Ces deux propriétés sont donc des exigences Kaput *en plus* de SLSA.
- **GitHub artifact attestations** : L2 par défaut, **L3 avec un workflow réutilisable** qui isole le build de l'appelant. Dépôts publics : Sigstore public good + log de transparence ; dépôts privés : instance Sigstore GitHub *sans* log de transparence ([GitHub Docs](https://docs.github.com/en/actions/concepts/security/artifact-attestations)). Vérification : `gh attestation verify --signer-workflow <owner>/<repo>/.github/workflows/build-image.yml --source-ref refs/tags/vX --deny-self-hosted-runners`, hors ligne avec `--bundle` + `--custom-trusted-root` ([man gh-attestation-verify](https://www.mankier.com/1/gh-attestation-verify)).
- **GitHub immutable releases** (GA 28/10/2025) : assets et tags verrouillés, attestation de release au format bundle Sigstore ([GitHub changelog](https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/)). Utile comme miroir, mais le retour d'expérience Trivy recommande de ne pas se fier au badge « Immutable » pour les actions ([Aqua](https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/)).

### 3.4 SBOM : SPDX vs CycloneDX

| Critère | SPDX (2.3 / 3.0.x) | CycloneDX (1.6 = ECMA-424 1re éd. ; 1.7 du 21/10/2025) |
|---|---|---|
| Orientation | Licences et conformité (ISO/IEC 5962 pour 2.2.1) | Sécurité : VEX, vulnérabilités, CBOM |
| Maturité outillage | 2.3 universel ; 3.0 encore inégal (à confirmer) | 1.6 universel ; 1.7 en déploiement ([CycloneDX](https://cyclonedx.org/news/cyclonedx-v1.7-released)) |
| Usage Kaput | Inventaire de licences (Chromium, noyau, firmware) | Suivi des vulnérabilités + VEX par image |

**Recommandation** : produire **les deux** par image (CycloneDX 1.6 JSON + SPDX 2.3 JSON), générés à partir du manifeste de paquets de mkosi et recoupés avec **syft** (Apache-2.0, v1.57.1 du 09/11/2026, sorties CycloneDX/SPDX, [pkg.go.dev](https://pkg.go.dev/github.com/anchore/syft@v1.57.1)). Les SBOM sont attachés comme attestations in-toto signées et publiés comme cibles TUF (pour qu'un client ou un auditeur puisse les obtenir de manière authentifiée). Scan de vulnérabilités : grype ou osv-scanner, épinglés par digest. **Trivy uniquement épinglé par digest vérifié** après l'incident de mars 2026.

### 3.5 Builds reproductibles

- **Debian** : 96,9 % des paquets de trixie/amd64 se construisent de manière reproductible ([reproducible-builds.org](https://tests.reproducible-builds.org/debian/trixie/amd64/)). Depuis le 09/05/2026, la reproductibilité est une **condition bloquante de migration vers testing** pour le cycle Forky ([It's FOSS](https://itsfoss.com/news/debian-makes-reproducible-builds-mandatory.md)). Le paquet **chromium 156.0.8078.79-1 est marqué reproductible** dans forky/amd64 (test du 06/11/2026, [r-b.org](https://tests.reproducible-builds.org/debian/rb-pkg/forky/amd64/chromium.html)).
- **Chromium amont** : la build est conçue pour être déterministe (même révision → même binaire), vérifiée par des bots Linux/Windows, avec une liste d'exceptions ([docs Chromium](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/deterministic_builds.md)).
- **Image complète** : mkosi rend reproductibles les sorties tar et gzip, borne les mtimes à `SourceDateEpoch`, et propose `ToolsTreeSnapshot=`/`Snapshot=` pour épingler les dépôts. v27.1 est la dernière version ([mkosi NEWS](https://man.archlinux.org/man/extra/mkosi/mkosi.news.7.en)).
- **Faisabilité** : une image Debian + Chromium **reproductible au bit près est réaliste** si l'on consomme les `.deb` Debian (eux-mêmes reproductibles) depuis un snapshot figé et que mkosi assemble de façon déterministe (erofs/squashfs, ordre des fichiers, UUID dérivés, `SOURCE_DATE_EPOCH`). Reconstruire Chromium *depuis les sources* à chaque release est en revanche coûteux (plusieurs heures par build sur une grosse machine, à mesurer) et n'apporte la reproductibilité que si la toolchain est elle-même figée. **Limite fondamentale** : la reproductibilité prouve que le binaire correspond aux sources déclarées. Elle ne détecte **pas** une porte dérobée présente dans les sources amont (T5).

### 3.6 Intégrité de démarrage de l'invité

- **dm-verity** : `roothash=` / `usrhash=` sur la ligne de commande permettent à `systemd-veritysetup-generator` de monter le rootfs vérifié (partitions dérivées du hash, ou `systemd.verity_root_data=`/`_hash=` explicites, `root-hash-signature=` en option) ([man systemd-veritysetup-generator](https://man.archlinux.org/man/systemd-veritysetup-generator.8.en)). mkosi produit nativement des images verity. Le mode `defer` réserve la partition de signature pour une **signature hors ligne du roothash** ([mkosi NEWS](https://man.archlinux.org/man/extra/mkosi/mkosi.news.7.en)).
- **UKI** (systemd-stub + `.linux` + `.initrd` + `.cmdline`, signé PE/Authenticode, construit par `ukify`/mkosi) : regroupe noyau, initrd et ligne de commande (donc le roothash) en **un seul objet signé**. Il n'est utile que si la VM démarre via un firmware UEFI avec Secure Boot dont **nous** contrôlons les clés.
- **Direct kernel boot** : WSL2 démarre son noyau et son initrd via HCS ([wsl.dev](https://wsl.dev/technical-documentation/boot-process/)). Sous Linux, QEMU et Cloud Hypervisor permettent `-kernel/-initrd/-append`. L'**hôte fournit lui-même** la ligne de commande : le firmware et le Secure Boot de l'invité sortent alors du TCB de démarrage.
- **Secure Boot Hyper-V** : les modèles de Secure Boot Hyper-V reposent sur les CA Microsoft (renouvellement des certificats 2011 en cours en 2026, avec des incidents KEK sur Hyper-V qui exigent des correctifs côté hôte *et* invité ([Microsoft](https://support.microsoft.com/en-us/servicing/os/secure-boot/2026/03/known-issues-and-resolutions-for-secure-boot-certificates-updates))). L'enrôlement de clés propres dans une VM Gen2 n'a pas pu être confirmé (**inconnue**). Il serait fragile de faire dépendre la chaîne Kaput du Secure Boot invité.

**Position** : l'**hôte est la racine de confiance** du démarrage invité. Le Secure Boot invité est au mieux une couche supplémentaire, pas un contrôle principal.

### 3.7 Application hôte : signature et auto-update

| Mécanisme | Ce qu'il garantit | Limites pour Kaput |
|---|---|---|
| **Authenticode** (signtool) | Identité de l'éditeur vue par Windows/SmartScreen/WDAC | Certificats publics limités à **460 jours** depuis le 01/03/2026 (ballot CSC-31, [SSL Insights](https://sslinsights.com/code-signing-certificate-validity-reduced-460-days/)) ; clés obligatoirement sur matériel FIPS 140-2 niveau 2 ; un certificat EV ne donne plus de réputation SmartScreen immédiate depuis 2024 ([ToDesktop](https://www.todesktop.com/blog/posts/windows-apps-psa-ev-certs-do-not-grant-immediate-reputation-anymore)). **Ne protège ni du rollback ni du freeze.** |
| **Azure Artifact Signing** (ex-Trusted Signing) | Certificats renouvelés quotidiennement, clés gérées par Microsoft ; 9,99 $/mois (5 000 signatures) ou 99,99 $/mois | GA en janvier 2026 ; éligibilité : particuliers et organisations aux États-Unis/Canada, **organisations** dans l'UE/au Royaume-Uni ([DevClass](https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554)). Un particulier européen n'est pas éligible. |
| **MSIX + App Installer** | Mises à jour au lancement et en arrière-plan, URI de repli ; `ForceUpdateFromAnyVersion` autorise le downgrade ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/msix/app-installer/auto-update-and-repair--overview)) | Modèle de confiance = certificat de l'éditeur, sans protection anti-freeze. Compatibilité avec un service privilégié/HCS à valider par l'agent Windows. |
| **Velopack** (successeur de Squirrel) | Signe binaires, Setup et MSI au packaging ([docs](https://docs.velopack.io/packaging/signing)) | Vérification cryptographique du flux côté client **non documentée** : on ne peut pas s'appuyer dessus seul. |
| **Tauri updater** | Signature obligatoire (minisign via `minisign_verify`), refus par défaut si la version n'est pas supérieure ([docs Tauri](https://v2.tauri.app/fr/plugin/updater/), [source](https://docs.rs/crate/tauri-plugin-updater/2.10.1/source/src/updater.rs)) | Une seule clé, pas de seuil, rotation manuelle, la perte de clé bloque les mises à jour. L'anti-downgrade est une comparaison de version, pas un contrôle cryptographique. |
| **Paquets .deb/.rpm signés** (dépôt APT/DNF) | Intégration distro, Release signé, `Valid-Until` optionnel | Clé GPG unique, anti-freeze partiel. |
| **Flatpak** | Sandboxing, OSTree signé GPG ; `--device=kvm` existe | Ajoute un tiers (Flathub) ; le sandbox Flatpak complique l'accès KVM/réseau virtuel (à valider par l'agent Linux). |
| **AppImage** | Portable | Mise à jour (zsync) et signature embarquée faibles et non vérifiées par défaut. **Déconseillé.** |

Le retour d'expérience Doyensec (février 2026) sur les updaters Electron rejoint nos exigences : lier signature et version, signer le manifeste, vérifier puis installer **le même descripteur de fichier** (TOCTOU), répertoire temporaire réservé au propriétaire, séparation cryptographique des canaux, downgrade explicite uniquement ([Doyensec](https://blog.doyensec.com/2026/02/16/electron-safe-updater.html)).

**Conclusion** : Authenticode et la signature des paquets sont **nécessaires** (confiance de l'OS, SmartScreen, WDAC, gestionnaires de paquets) mais **pas suffisants**. L'autorisation de mise à jour de l'application passe par **le même dépôt TUF** que l'image, sous un rôle délégué distinct.

---

## 4. Architecture de confiance recommandée

### 4.1 Rôles TUF et clés

```text
root  (hors ligne, 3-sur-5 YubiKey, expiration 12 mois)
 ├── timestamp (en ligne, KMS/HSM, 1 clé, expiration 24 h, re-signé toutes les 6 h)
 ├── snapshot  (en ligne, KMS/HSM, 1 clé distincte, expiration 7 j)
 └── targets   (hors ligne, 2-sur-3 YubiKey, expiration 6 mois) — délégations terminantes :
      ├── guest-image   chemins guest/<canal>/<arch>/*   seuil 1-sur-N (YubiKey d'astreinte), expiration 14 j
      ├── host-app      chemins host/<os>/<arch>/*       seuil 2-sur-N (règle des deux personnes), expiration 3 mois
      ├── trust-config  chemins config/*                 seuil 2-sur-N : trusted_root Sigstore épinglé, politique de provenance
      └── (phase 2) rebuilder : co-signature exigée sur guest/* (seuil 2 = release + rebuilder indépendant)
```

Justification des choix :
- **root 3-sur-5** : supporte la perte de 2 clés et la compromission de 2 clés. Les clés sont réparties géographiquement entre personnes distinctes.
- **timestamp 24 h** : borne la fenêtre de *freeze* à ≤ 24 h pour un client en ligne. Après un 0-day, un attaquant qui contrôle le CDN ne peut pas cacher plus d'un jour l'existence d'une nouvelle image.
- **guest-image 14 j** : borne l'âge de toute image acceptée à ~14 jours, même si les rôles en ligne étaient compromis, et force une release au moins à chaque cycle Chrome (deux semaines depuis Chrome 153, 08/09/2026, [Chrome for Developers](https://developer.chrome.com/blog/chrome-two-week-start)).
- **host-app 2-sur-N** : l'application hôte est dans le TCB et sa cadence est plus lente, la règle des deux personnes est donc acceptable.
- **Délégations terminantes + motifs de chemins** : une clé `guest-image` ne peut jamais signer un binaire hôte (protection *wrong software* et réduction du rayon d'impact).

### 4.2 Métadonnées custom par cible (champ `custom` de TUF)

Pour chaque image `guest/stable/x86_64/kaput-guest-<version>.*` :

```json
{
  "kaput_version": "2026.11.12.1",          // monotone, comparé à l'anti-rollback local
  "security_epoch": 7,                       // incrémenté à chaque correctif critique
  "minimum_host_version": "1.4.0",           // compatibilité protocole hôte↔invité
  "browser": {"name": "chromium", "version": "156.0.8078.79", "source": "debian-trixie-security"},
  "boot": {
    "kernel_sha256": "…", "initrd_sha256": "…",
    "cmdline": "ro quiet roothash=<hex> systemd.verity_root_options=panic-on-corruption lockdown=confidentiality …",
    "rootfs_sha256": "…", "verity_roothash": "<hex>"
  },
  "provenance": {"bundle": "guest/…/provenance.sigstore.json", "builder": "…/.github/workflows/build-image.yml@refs/tags/…"},
  "sbom": ["…cdx.json", "…spdx.json"]
}
```

En complément, `guest-image` publie un fichier cible `guest/stable/policy.json` avec `minimum_version` et `minimum_security_epoch` : c'est le **mécanisme de révocation** d'une image vulnérable ou défectueuse, sans dépendre de l'expiration.

### 4.3 Flux de publication

```text
[commit/PR bump] → CI build hermétique (runner éphémère, workflow réutilisable)
   → artefacts + manifeste de boot + SBOM
   → attestation SLSA L3 (Sigstore keyless, log public)          ← domaine de confiance A (CI)
   → rebuild indépendant (2e infra) → comparaison des hashes      ← (phase 2 : co-signature rebuilder)
   → tests automatiques (boot, verity, versions, tests d'évasion de non-régression)
   → signataire humain : vérifie provenance + diff SBOM, signe guest-image.json avec YubiKey  ← domaine B (humain)
   → snapshot/timestamp re-signés par le signataire en ligne (KMS)
   → publication statique (CDN + miroir GitHub Releases immuable), consistent snapshots
```

Le **signataire en ligne** (snapshot/timestamp) tourne sur une infrastructure distincte de l'hébergement et de la CI (KMS cloud avec IAM dédié, ou YubiHSM 2 sur une machine dédiée). Le CDN ne détient **aucune** clé : sa compromission permet au plus un déni de service ou un gel ≤ 24 h.

### 4.4 Flux de vérification côté client (hôte)

1. Charger le `root.json` de confiance : celui embarqué dans le binaire Kaput (lui-même livré via TUF et Authenticode) ou, s'il est plus récent, celui persisté localement.
2. Workflow TUF standard : chaîne de rotation de root (N+1 signé par le seuil de N *et* de N+1), puis timestamp, snapshot, targets et délégations, avec vérification des versions monotones, des expirations, de la cohérence snapshot↔targets et des longueurs/hashes. Les métadonnées ont des tailles maximales (root ≤ 512 Kio, timestamp ≤ 16 Kio, etc.), avec un débit minimal et des timeouts (slow retrieval).
3. Télécharger les cibles dans un répertoire temporaire réservé à l'utilisateur, vérifier longueur et SHA-256 **pendant** le flux et s'arrêter dès que la longueur est dépassée.
4. **Vérification de provenance** (domaine A), selon l'une de deux variantes :
   - *Variante A (préférée)* : le client vérifie le bundle Sigstore contre un `trusted_root` **épinglé via le rôle `trust-config`** (donc pas de requête réseau vers Sigstore), avec identité exacte du workflow, ref de tag, absence de runner auto-hébergé et digest identique.
   - *Variante B (si aucune bibliothèque client fiable n'existe dans le langage hôte)* : la provenance est vérifiée par le signataire humain avant signature TUF, et elle est republiée pour audit public. Le client ne vérifie que TUF, ce qui revient à un seul domaine de confiance côté client.
5. Vérifier `kaput_version ≥ dernière version lancée`, `security_epoch ≥ local`, `≥ policy.minimum_version` et `minimum_host_version ≤ version hôte`.
6. Installer de façon **atomique** dans `images/<version>/`, basculer le pointeur `current` seulement après succès complet, conserver N-1 pour un éventuel repli *s'il reste valide au regard de la politique*.

### 4.5 Vérification à chaque lancement de VM (avant démarrage)

1. Relire les métadonnées TUF locales et appliquer la politique de fraîcheur (§5).
2. Ouvrir noyau, initrd et image rootfs **en lecture seule, avec verrouillage** (Windows : `FILE_SHARE_READ` sans `FILE_SHARE_WRITE` ; Linux : `O_RDONLY` + fichiers immuables si possible).
3. Recalculer le SHA-256 du noyau et de l'initrd (quelques dizaines de Mo, coût négligeable) **à partir du tampon mémoire qui sera passé à l'hyperviseur**, ou d'une copie privée créée après vérification : aucun ré-accès par chemin (TOCTOU, T7).
4. Construire la ligne de commande **exclusivement** à partir du champ `boot.cmdline` signé. Aucun paramètre fourni par l'utilisateur ou l'invité ne peut modifier `roothash`, `init=`, `lockdown`, etc. Les seuls ajouts autorisés sont une liste blanche de paramètres non sensibles (par exemple un identifiant de session).
5. Attacher le rootfs **en lecture seule** (disque virtuel RO). L'intégrité de chaque bloc lu est garantie par dm-verity avec `panic-on-corruption` : une altération du fichier sur le disque hôte provoque l'arrêt de l'invité, jamais l'exécution de code modifié. Une revérification complète du rootfs n'est faite qu'en tâche de fond (optionnel).
6. L'état inscriptible (tmpfs/overlay, disque scratch éphémère) n'est jamais réutilisé d'une session à l'autre (voir les documents isolation/éphémère).

Option UKI : si l'architecture retient un démarrage UEFI (par exemple Hyper-V Gen2 sans direct boot), la cible TUF devient un **UKI signé** (noyau, initrd et cmdline avec roothash dans un seul PE). L'hôte vérifie son hash TUF avant de l'attacher, et le Secure Boot invité avec clés propres ne sert qu'en couche supplémentaire (sous réserve de l'inconnue §8).

### 4.6 Mise à jour de l'application hôte elle-même

- Le client TUF de Kaput télécharge `host/<os>/<arch>/kaput-<v>.(msix|msi|exe|deb|rpm)` et vérifie TUF, la provenance, puis **Authenticode** (Windows : `WinVerifyTrust` + nom de l'éditeur attendu ; ne pas épingler le certificat feuille si Artifact Signing est utilisé, puisqu'il change chaque jour).
- L'installation est confiée à un **composant privilégié minimal** (service/broker) qui **revérifie lui-même** le hash TUF du fichier sur un descripteur ouvert en lecture exclusive. L'interface utilisateur non privilégiée ne peut jamais demander l'installation d'un chemin arbitraire.
- **Linux** : canal principal = dépôt APT/DNF signé pour l'installation initiale (clé sur matériel), **avec en plus** une vérification TUF par Kaput qui refuse de lancer une session si la version hôte est sous `minimum_host_version` ou révoquée. Flatpak/AppImage restent hors périmètre v1 (à rediscuter avec l'agent Linux).
- Le `root.json` embarqué est mis à jour à chaque release hôte, ce qui raccourcit la chaîne de rotation à parcourir.

---

## 5. Politique de vérification au lancement

Principe : **une mise à jour qui échoue n'est pas un lancement qui échoue**. On ne lance qu'une image vérifiée et non révoquée. Si la *récupération* d'une nouvelle version échoue, on peut lancer l'image *déjà vérifiée* dans les limites de fraîcheur.

| Situation | Comportement | Justification |
|---|---|---|
| Hash, signature, seuil, longueur ou format de métadonnées invalide | **Refus de la nouvelle version**, artefact supprimé, métadonnées de confiance inchangées, événement journalisé (sans données personnelles). Lancement de l'image courante autorisé si elle reste valide. | Fail closed sur le nouvel artefact. Un échec de vérification peut signaler une attaque : on ne l'« auto-répare » jamais vers du non vérifié. |
| Rotation de root invalide ou chaîne cassée | Mises à jour bloquées, alerte forte, lancement selon la fraîcheur | Signe probable de compromission ou d'erreur grave |
| Version annoncée < version locale (rollback), ou version de métadonnées en baisse | Refus et alerte | Anti-rollback |
| Image courante < `policy.minimum_version` / `minimum_security_epoch` | **Blocage du lancement** jusqu'à mise à jour | Révocation (0-day exploité) |
| `minimum_host_version` > version hôte | Blocage, proposition de mise à jour de l'hôte | Compatibilité et sécurité du protocole |
| Rotation de root non vérifiable hors ligne | Lancement selon la fraîcheur, pas de nouvelle image | — |
| **Fraîcheur** = temps écoulé depuis le dernier timestamp vérifié avec succès : ≤ 24 h | Normal | Fenêtre de freeze nominale |
| 24 h – 72 h | Bandeau « mise à jour non vérifiée depuis X h » | Réseau capricieux |
| 72 h – 7 j | Avertissement modal, confirmation par session | Risque 0-day croissant |
| > 7 j, ou métadonnées `guest-image` expirées (> 14 j) | **Blocage** (fail closed). Contournement seulement par politique administrateur explicite (option désactivée par défaut, à valider) | Un navigateur non patché depuis plus d'une semaine est hors des hypothèses de sécurité |
| Horloge hôte antérieure à la dernière vérification de plus de 24 h | Traiter comme métadonnées expirées et avertir | Protection basique contre le recul d'horloge (TUF dépend de l'horloge locale) |
| Premier lancement hors ligne | Impossible, sauf installeur hors ligne contenant image et métadonnées vérifiables par le root embarqué, soumis aux mêmes règles d'expiration | Pas de TOFU |
| Erreur dm-verity en session | Arrêt immédiat de la VM, quarantaine de l'image, retéléchargement et revérification | Corruption ou altération locale |

Les seuils 72 h / 7 j / 14 j sont **des propositions à valider** (§9). Ils échangent disponibilité contre exposition aux 0-days.

---

## 6. Pipeline de build CI de l'image

### 6.1 Principes

- **Isolé et éphémère** (SLSA L3) : workflow réutilisable dédié `build-image.yml`, runners hébergés éphémères, `permissions:` minimales (`id-token: write` seulement pour l'attestation, `contents: read`), environnement GitHub protégé pour la publication.
- **Quasi-hermétique** : toutes les entrées sont épinglées par hash, et le réseau pendant le build est limité au miroir de snapshot épinglé (proxy à liste blanche). Objectif à terme : build hors réseau à partir d'un cache vérifié.
- **Épinglage par hash** :
  - actions GitHub par **SHA de commit complet** (tj-actions 2025, Trivy 2026), avec Dependabot/Renovate pour les mises à jour sous revue ;
  - images de conteneurs de build par **digest** `@sha256:` ;
  - paquets Debian via un **horodatage `snapshot.debian.org`** + `Release` signé (clés d'archive Debian épinglées dans le dépôt) ; un **lockfile** `packages.lock` (nom, version, SHA-256 de chaque .deb) est généré, committé, et la CI échoue si la résolution diffère ;
  - mkosi et son ToolsTree épinglés (version + `ToolsTreeSnapshot=`).
- **Reproductibilité** : `SOURCE_DATE_EPOCH` = date du snapshot, système de fichiers déterministe (erofs/squashfs avec ordre et horodatages fixés), UUID et sels de verity dérivés de manière déterministe. Deux builds indépendants (job A sur GitHub, job B sur une autre infrastructure, par exemple un runner chez un autre fournisseur) doivent produire **le même `verity_roothash`**, sinon la release est bloquée (phase 1 : alerte, phase 2 : bloquant + co-signature rebuilder).
- **Séparation des secrets** : la CI ne détient **aucune clé TUF**. Elle produit des artefacts et des attestations keyless. Seuls les signataires humains (hors ligne) et le signataire en ligne (snapshot/timestamp, hors CI) signent dans TUF.

### 6.2 Déclencheurs et cadence

| Déclencheur | Action | Cible de délai |
|---|---|---|
| Veille toutes les 15 min : nouvelle version `chromium` dans la source retenue (par exemple `trixie-security`) ou bulletin Chrome « exploited in the wild » | PR automatique de bump du snapshot, puis build, tests, page d'astreinte au signataire | **< 12 h** entre la disponibilité du paquet et la publication signée |
| DSA noyau / glibc / mesa / autres paquets de l'image | Idem | < 48 h (critique : < 24 h) |
| Hebdomadaire (cron) | Reconstruction complète même sans changement (dérive, nouveaux correctifs, re-signature avant l'expiration de 14 j) | Hebdomadaire |
| Avis de compromission amont | Gel des builds, publication de `policy.minimum_version` si nécessaire | Immédiat |

**Point critique (latence amont)** : avec Debian comme source, on hérite de leur délai. Exemple mesuré : Chrome 156.0.8078.79 publié le 29/10/2026 ([note de release relayée](https://braindetox.kr/en/posts/chrome_stable_security_update_2026_10.html)), DSA-6605-1 publiée le 02/11/2026 ([LinuxSecurity](https://linuxsecurity.com/advisories/debian/debian-dsa-6605-1-chromium)), soit environ 4 jours. Le sixième 0-day Chrome exploité de 2026 (CVE-2026-85046, V8) a été corrigé en septembre ([eSecurityPlanet](https://esecurityplanet.com/threats/news-google-chrome-cve-2026-85046-zero-day)) : quelques jours d'exposition comptent. Options : (a) Debian (reproductible, signé, mais en retard) ; (b) compiler Chromium nous-mêmes depuis le tag amont (latence minimale, coût CI élevé, maintenance des correctifs Linux) ; (c) une autre distribution plus rapide (à mesurer) ; (d) binaire Google Chrome (licence et redistribution à vérifier, non reproductible). **Décision utilisateur** (§9), à croiser avec le document navigateur.

### 6.3 Étapes du pipeline

1. `verify-inputs` : vérifier les signatures `Release` du snapshot, le lockfile et les digests d'images de build.
2. `build` (mkosi) : rootfs erofs + verity, noyau et initrd (ou UKI), manifeste de boot, manifeste de paquets.
3. `sbom` : CycloneDX 1.6 + SPDX 2.3 (mkosi + syft), recoupement des deux.
4. `scan` : grype/osv-scanner sur le SBOM, échec si une CVE critique est corrigeable et non traitée (avec VEX justifié sinon).
5. `test` : démarrage QEMU/KVM en CI, vérification de `roothash`, `chromium --version` = version attendue, tests négatifs (rootfs altéré → l'invité doit s'arrêter ; cmdline altérée → refus côté hôte).
6. `rebuild-compare` : second build indépendant et comparaison des hashes.
7. `attest` : `actions/attest-build-provenance` (SLSA L3 via le workflow réutilisable) + attestations SBOM.
8. `stage` : dépôt dans un bucket de staging (non servi aux clients).
9. **Signature humaine** (hors CI) : outil `kaput-sign` qui vérifie provenance + diff de SBOM et de lockfile, affiche le résumé, puis signe `guest-image.json` avec une YubiKey (PIV, ECDSA P-256 ou Ed25519 selon le support de l'implémentation TUF).
10. `publish` : le signataire en ligne met à jour snapshot et timestamp, puis publication sur le CDN et le miroir.

### 6.4 Sécurité de la CI elle-même

- Protection de branche + revue obligatoire (Source Track SLSA L2/L3 visée), signatures de commits, CODEOWNERS sur `.github/`, `mkosi.*`, `packages.lock` et les fichiers de politique TUF.
- Aucun `pull_request_target` sur les workflows de build, aucun secret long terme (OIDC vers le KMS de staging uniquement), rotation **complète** des credentials en cas d'incident (leçon Trivy).
- Journaux CI publics vérifiés pour l'absence de secrets.

---

## 7. Gestion des clés

| Clé | Support | Seuil / détenteurs | Rotation | Sauvegarde |
|---|---|---|---|---|
| TUF root | 5 YubiKey (PIV) ou Nitrokey, jamais branchées sur une machine connectée | 3-sur-5, 5 personnes ou lieux distincts | Re-signature annuelle, rotation immédiate en cas de suspicion | Les clés *sont* la redondance ; pas de copie logicielle |
| TUF targets | 3 YubiKey | 2-sur-3 | 6 mois | Idem |
| guest-image | YubiKey d'astreinte (≥ 3 personnes pour couvrir le 24/7) | 1-sur-N (+ provenance CI côté client) | Révocation par targets | — |
| host-app | YubiKey | 2-sur-N | Révocation par targets | — |
| snapshot / timestamp | KMS cloud (clé non exportable, IAM dédié, journaux d'audit) ou YubiHSM 2 sur hôte dédié | 1 clé chacun, distinctes | Rotation par root (récupération après fast-forward) | Re-génération possible : root fait autorité |
| Authenticode | Azure Artifact Signing (si éligible) ou certificat OV sur HSM/cloud HSM (≤ 460 j) | — | Annuelle au plus | Selon l'autorité de certification |
| Dépôt APT/RPM | Sous-clé GPG sur YubiKey | — | 1–2 ans | Clé maîtresse hors ligne |
| Sigstore | Keyless (aucune clé) | Identité = workflow réutilisable + tag | — | — |

**Cérémonie root** : machine neuve ou dédiée, système live éphémère sans réseau, hash du support de démarrage lu à voix haute et vérifié par les participants, script de cérémonie versionné et audité, journal de cérémonie signé et publié. C'est la méthode employée par CalyxOS en 2026 (YubiHSM 2, clé d'enveloppement découpée en Shamir 3-sur-5, Tails hors ligne, audit Trail of Bits). Leurs pièges sont instructifs : sessions PKCS#11 non fermées, journal d'audit du HSM non signé et de capacité limitée ([CalyxOS](https://calyxos.org/news/2026/02/10/calyxos-hsm-signing/)). Oxide a réécrit l'outillage de cérémonie YubiHSM pour la même raison ([oxidecomputer/offline-keystore](https://github.com/oxidecomputer/offline-keystore)). Référence de processus public : [sigstore/root-signing](https://www.github.com/sigstore/root-signing/blob/18fce446c2858b8a463c838d37612ee2420beef0/playbooks/ORCHESTRATION.md).

**Avertissement** : des seuils multi-personnes avec **une seule personne réelle** derrière toutes les clés n'ont aucune valeur (théâtre de sécurité). Si l'équipe est réduite, il vaut mieux l'assumer explicitement (seuil 2-sur-3 avec des clés en des lieux distincts, détenues par la même personne, contre le vol mais pas contre l'insider) et le documenter comme risque résiduel.

Vulnérabilités matérielles : les tokens ont leurs propres failles (par exemple l'attaque par canal auxiliaire EUCLEAK de 2024 sur certaines YubiKey 5 antérieures au firmware 5.7, qui exige un accès physique ; non revérifié dans cette session). Il faut acheter des modèles à firmware récent et garder les clés sous contrôle physique.

---

## 8. Risques résiduels et inconnues

### 8.1 Risques résiduels (après contre-mesures)

1. **Code malveillant amont authentique (T5)** : TUF, SLSA et la reproductibilité prouvent que nous livrons ce que nous avons construit à partir des sources déclarées, pas que ces sources sont saines. Atténuation partielle : image minimale (moins de paquets), retard volontaire de quelques heures sur les paquets non critiques, veille.
2. **Confiance héritée de Debian** (clés d'archive, buildd) et de Chromium amont.
3. **Compromission conjointe CI + signataire d'astreinte** : contournerait la double vérification (atténuée en phase 2 par le rebuilder indépendant).
4. **Hôte compromis** : hors périmètre, puisque l'hôte est le TCB de la vérification. Un malware sur l'hôte peut modifier Kaput lui-même.
5. **Fenêtre de freeze ≤ 24 h** et **fenêtre de 0-day** = latence amont + latence Kaput (+ délai de grâce hors ligne).
6. **Bugs des implémentations TUF/Sigstore** (exemples : CVE tough 2026, CVE go-tuf 2022) : nécessitent conformité, fuzzing des parseurs de métadonnées et mises à jour rapides de ces dépendances.
7. **Dépendance à la disponibilité** du CDN, de GitHub et de la TSA Sigstore : elle affecte la publication, pas la vérification (bundles hors ligne).
8. **Confidentialité** : les requêtes de mise à jour révèlent l'IP et l'usage de Kaput au CDN. Pas d'identifiant unique, contenu statique, en-têtes minimaux.

### 8.2 Inconnues (à lever avant implémentation)

- I1 : langage de l'application hôte (Rust → tough + vérification Sigstore immature ; Go → go-tuf v2 + bibliothèques Sigstore officielles). Cela détermine la variante A ou B du §4.4.
- I2 : HCS (Windows) accepte-t-il un démarrage direct noyau + initrd + cmdline arbitraire pour une VM tierce aussi simplement que WSL2 ? Disque virtuel RO garanti ? (agent Virtualisation/Windows)
- I3 : possibilité d'enrôler nos propres clés Secure Boot dans une VM Hyper-V Gen2 (non confirmé).
- I4 : reproductibilité *au bit près* de l'image mkosi complète (erofs/verity, initrd) : à prouver par un prototype.
- I5 : latence réelle de la source navigateur retenue (mesurer sur 3 mois : Debian, Fedora, Alpine, build maison).
- I6 : algorithmes de clé supportés de bout en bout (YubiKey PIV ECDSA P-256 vs Ed25519, et support dans tough/go-tuf/python-tuf) : à valider.
- I7 : compatibilité MSIX avec les besoins de privilèges (service, Hyper-V) ; sinon MSI + broker.
- I8 : licence et statut exact de RSTUF, et existence et couverture de la suite `tuf-conformance`.
- I9 : maturité de SPDX 3.0 dans syft et dans les outils de scan.

---

## 9. Décisions nécessitant l'avis de l'utilisateur

| # | Décision | Options | Recommandation | Impact |
|---|---|---|---|---|
| D1 | **Source du binaire navigateur** (latence 0-day vs coût) | Debian (~jours de retard, reproductible) / build maison depuis les sources (heures, coût CI élevé) / autre distro / Chrome Google (licence) | Debian en v1 + mesure de la latence ; build maison si la latence médiane dépasse 48 h | Sécurité, coût, maintenance |
| D2 | **Politique hors ligne** | Seuils 24 h / 72 h / 7 j / 14 j, ou plus stricts ; contournement administrateur oui/non | Seuils proposés, contournement désactivé par défaut | UX vs exposition |
| D3 | **Hébergement** | GitHub Releases seul (gratuit, mais même plateforme que la CI : compromission corrélée) / CDN objet (S3/R2/…) + miroir GitHub | CDN + miroir GitHub (TUF rend les deux non fiables par construction) | Coût faible (ordre : quelques €/mois à petite échelle, à chiffrer) |
| D4 | **Signataire en ligne** | KMS cloud (AWS/GCP/Azure) / YubiHSM 2 sur machine dédiée | KMS cloud (audit, disponibilité), compte isolé | Coût récurrent faible, dépendance fournisseur |
| D5 | **Détenteurs de clés** | Combien de personnes réelles ? Astreinte 24/7 pour `guest-image` ? | ≥ 5 pour root, ≥ 3 en astreinte | Organisationnel ; sans cela les seuils sont fictifs |
| D6 | **Matériel** | 8–12 YubiKey (+ éventuellement 1–2 YubiHSM 2) | Oui | Achat unique (ordre de quelques centaines à ~1 500 €, prix non revérifiés) |
| D7 | **Signature Windows** | Azure Artifact Signing (9,99 $/mois, nécessite une **organisation** UE/UK ou un résident US/CA) / certificat OV sur HSM (renouvellement ≤ 460 j) | Artifact Signing si une entité légale existe | Coût, entité juridique |
| D8 | **Dépôt public ou privé** | Le dépôt privé prive les attestations GitHub du log de transparence public | Public (transparence) | Visibilité du code |
| D9 | **Rebuilder indépendant** (phase 2) | 2e infrastructure de build et co-signature obligatoire | Oui, après preuve de reproductibilité | Coût CI x2 |

---

## 10. Évaluation des dépendances (supply chain)

| Dépendance | Rôle | Maintenance (vérifiée 11/2026) | Licence | Risque | Décision |
|---|---|---|---|---|---|
| python-tuf | Outillage dépôt TUF (CI/signature) | v7.0.1, 09/2026 | MIT/Apache-2.0 | Faible | Adopter |
| go-tuf v2 | Client TUF (si Go) | v2.3.0, ~10/2026 | Apache-2.0 | Faible à moyen | Adopter si Go |
| tough | Client TUF (si Rust) | v0.24.0, 07/2026 ; 3 CVE corrigées en 04/2026 | MIT/Apache-2.0 | Moyen | Adopter si Rust, version épinglée, fuzzing |
| rust-tuf | — | Bêta, 2022 | MIT/Apache-2.0 | Élevé (abandon) | Rejeter |
| cosign v3 / Rekor v2 | Attestations | GA 10/2025 | Apache-2.0 | Faible | Adopter (CI) |
| sigstore-rs | Vérification client Rust | Expérimental < 1.0 | Apache-2.0 | Élevé | Éviter en v1 (variante B) |
| in-toto (format) | Attestations | CNCF graduated 04/2025 | Apache-2.0 | Faible | Adopter |
| mkosi | Build d'image | v27.1 | LGPL-2.1+ (outil de build, non distribué) | Faible | Adopter |
| systemd (veritysetup, ukify) | Boot invité | Actif (v260 documenté) | LGPL-2.1+ | Faible | Adopter |
| syft | SBOM | v1.57.1, 09/11/2026 | Apache-2.0 | Faible | Adopter, épinglé |
| Trivy | Scan | Compromis 03/2026 | Apache-2.0 | Moyen (historique) | Éviter, ou épingler par digest vérifié |
| Velopack | Auto-update Windows | Actif | MIT | Moyen (vérification client non documentée) | Uniquement comme mécanisme d'installation sous contrôle TUF |
| Tauri updater | Auto-update | Actif | MIT/Apache-2.0 | Moyen (une seule clé) | Non retenu comme autorité |
| RSTUF | Service TUF | v1.0, audité | à confirmer | Faible à moyen | Phase 2 éventuelle |

Méthode d'évaluation continue : OpenSSF Scorecard et deps.dev pour chaque dépendance directe ([OpenSSF Concise Guide](https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software)), revue manuelle des mainteneurs et de la fréquence des releases, alerte si aucune release depuis 12 mois, `cargo vet`/`cargo deny` ou `govulncheck` selon le langage, vérification de licence en CI (liste blanche : MIT, Apache-2.0, BSD, MPL-2.0, LGPL pour les outils de build ; GPL uniquement dans l'image invitée, avec obligations de fourniture des sources à documenter : noyau, paquets Debian).

---

## 11. Sources

TUF et implémentations
- TUF — attaques couvertes : https://theupdateframework.io/security/
- python-tuf releases : https://releasealert.dev/github/theupdateframework/python-tuf
- go-tuf v2 versions : https://packages.ecosyste.ms/registries/proxy.golang.org/packages/github.com%2Ftheupdateframework%2Fgo-tuf%2Fv2/versions
- CVE-2022-29173 (go-tuf) : https://ocve.arawa.fr/cve/CVE-2022-29173
- tough (dépôt) : https://github.com/awslabs/tough — releases : https://releasealert.dev/github/awslabs/tough
- Bulletin AWS 2026-019 (tough/tuftool) : https://aws.amazon.com/jp/security/security-bulletins/2026-019-aws/
- rust-tuf : https://lib.rs/crates/tuf — https://repos.ecosyste.ms/hosts/GitHub/repositories/theupdateframework%2Frust-tuf
- RSTUF 1.0 : https://repository-service-tuf.readthedocs.io/en/latest/blog/posts/rstuf-v1.0.0-is-out.html — audit : https://openssf.org/blog/2025/04/25/repository-service-for-the-update-framework-rstuf-reaches-new-security-milestone-with-successful-audit/

Sigstore, SLSA, in-toto, GitHub
- Rekor v2 GA : https://blog.sigstore.dev/rekor-v2-ga/
- Vérification pendant une indisponibilité de Rekor : https://oneuptime.com/blog/post/2026-08-11-rekor-cosign-verification-transparency-log-outage/markdown
- sigstore-rs : https://github.com:443/sigstore/sigstore-rs — https://lib.rs/crates/sigstore — https://lib.rs/crates/sigstore-verify
- SLSA v1.2 : https://slsa.dev/blog/2025/11/announce-slsa-v1.2 — exigences build : https://slsa.dev/spec/v1.2/build-requirements — nouveautés : https://slsa.dev/spec/v1.2/whats-new
- GitHub artifact attestations : https://docs.github.com/en/actions/concepts/security/artifact-attestations
- gh attestation verify : https://www.mankier.com/1/gh-attestation-verify
- GitHub immutable releases : https://github.blog/changelog/2025-10-28-immutable-releases-are-now-generally-available/
- in-toto CNCF graduation : https://cncf.io/announcements/2025/04/23/cncf-announces-graduation-of-in-toto-security-framework-enhancing-software-supply-chain-integrity-across-industries

SBOM
- CycloneDX 1.7 : https://cyclonedx.org/news/cyclonedx-v1.7-released
- syft : https://pkg.go.dev/github.com/anchore/syft@v1.57.1

Reproductibilité, image, boot
- Debian trixie amd64 (96,9 %) : https://tests.reproducible-builds.org/debian/trixie/amd64/
- Debian : reproductibilité obligatoire (Forky) : https://itsfoss.com/news/debian-makes-reproducible-builds-mandatory.md
- chromium reproductible (forky) : https://tests.reproducible-builds.org/debian/rb-pkg/forky/amd64/chromium.html
- Chromium deterministic builds : https://chromium.googlesource.com/chromium/src/+/HEAD/docs/deterministic_builds.md
- mkosi NEWS : https://man.archlinux.org/man/extra/mkosi/mkosi.news.7.en
- systemd-veritysetup-generator : https://man.archlinux.org/man/systemd-veritysetup-generator.8.en
- WSL2 boot process (HCS) : https://wsl.dev/technical-documentation/boot-process/
- Secure Boot — problèmes connus 2026 (Hyper-V) : https://support.microsoft.com/en-us/servicing/os/secure-boot/2026/03/known-issues-and-resolutions-for-secure-boot-certificates-updates

Navigateur (cadence, latence)
- Chrome : cycle de 2 semaines : https://developer.chrome.com/blog/chrome-two-week-start
- Chrome 156 (27 et 29/10/2026) : https://braindetox.kr/en/posts/chrome_stable_security_update_2026_10.html
- DSA-6605-1 chromium : https://linuxsecurity.com/advisories/debian/debian-dsa-6605-1-chromium
- CVE-2026-85046 (0-day V8) : https://esecurityplanet.com/threats/news-google-chrome-cve-2026-85046-zero-day

Application hôte
- Validité des certificats de signature de code à 460 jours : https://sslinsights.com/code-signing-certificate-validity-reduced-460-days/
- EV et SmartScreen : https://www.todesktop.com/blog/posts/windows-apps-psa-ev-certs-do-not-grant-immediate-reputation-anymore
- Azure Artifact Signing : https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554
- MSIX auto-update : https://learn.microsoft.com/en-us/windows/msix/app-installer/auto-update-and-repair--overview
- Velopack signing : https://docs.velopack.io/packaging/signing
- Tauri updater : https://v2.tauri.app/fr/plugin/updater/ — source : https://docs.rs/crate/tauri-plugin-updater/2.10.1/source/src/updater.rs
- Doyensec, updater Electron sûr : https://blog.doyensec.com/2026/02/16/electron-safe-updater.html

Incidents supply chain
- Notepad++ 2025 : https://www.helpnetsecurity.com/2026/02/02/2025-notepad-supply-chain-compromise/
- tj-actions/changed-files : https://www.wiz.io/it-it/blog/github-action-tj-actions-changed-files-supply-chain-attack-cve-2025-30066
- Trivy 2026 : https://www.aquasec.com/blog/trivy-supply-chain-attack-what-you-need-to-know/

Gestion des clés
- CalyxOS, refonte de la signature HSM : https://calyxos.org/news/2026/02/10/calyxos-hsm-signing/
- Oxide offline-keystore : https://github.com/oxidecomputer/offline-keystore
- Sigstore root-signing : https://www.github.com/sigstore/root-signing/blob/18fce446c2858b8a463c838d37612ee2420beef0/playbooks/ORCHESTRATION.md
- OpenSSF, guide d'évaluation des dépendances : https://best.openssf.org/Concise-Guide-for-Evaluating-Open-Source-Software
