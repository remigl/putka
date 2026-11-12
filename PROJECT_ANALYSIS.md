# Kaput — Analyse de projet (Phase 0 : Discovery)

> **Statut** : synthèse de phase 0, rédigée par l'orchestrateur à partir de huit études indépendantes
> (`docs/research/01` à `08`), puis soumise à une revue offensive indépendante (§17).
> **Date** : 12 novembre 2026.
> **Portée** : ce document ne prétend pas qu'une isolation soit « sûre à 100 % ». Il décrit une
> architecture, ses frontières de confiance, ses hypothèses et son **risque résiduel**.
> **Avertissement de méthode** : aucune affirmation n'a été vérifiée par prototype, car le conteneur
> d'étude n'a ni KVM ni WHP. Les budgets de recherche web des agents se sont épuisés en fin d'étude ;
> les points marqués `[non revérifié]` dans les études, ainsi que **tous les identifiants CVE cités**,
> doivent être recoupés avec les bulletins officiels (NVD, éditeur) avant d'être repris dans un ADR.
> La revue offensive a confirmé un échantillon de 11 faits porteurs (§17) ; les autres restent marqués.
> Les études `docs/research/` sont conservées telles que rédigées. En cas de divergence, **cette synthèse
> et les ADR prévalent**.

---

## 0. Résumé exécutif

1. **Frontière principale** : la **virtualisation matérielle** (KVM sous Linux, hyperviseur Microsoft
   via WHP sous Windows). Aucune solution à noyau partagé (conteneurs, AppContainer, gVisor, sandbox du
   navigateur seule) n'est retenue comme frontière principale. Ces solutions servent de couches de
   confinement secondaires.
2. **Runtime** : un **contrat invité unique** (boot direct du noyau, `virtio-blk` en lecture seule,
   `virtio-vsock`, rien d'autre) exécuté par **deux VMM en Rust** : **Firecracker** sous Linux et
   **OpenVMM** sous Windows (repli : crosvm/WHPX). Chaque VMM est confiné sans privilège :
   jail maison namespaces/seccomp/Landlock sous Linux, AppContainer/LPAC + Job Object sous Windows.
3. **Le VMM ne parse aucun protocole applicatif.** Il n'expose ni carte réseau virtuelle, ni GPU virtuel,
   ni son, ni dossier partagé, ni USB. Il reste toutefois une **surface d'émulation résiduelle** à
   énumérer et à fuzzer : transport MMIO, virtqueues, éventuellement i8042, horloge, APIC, MSR et CPUID
   (§2.3, RT-06). Réseau, affichage et entrées passent par des **protocoles minimaux sur vsock**. Ils
   sont analysés par des **brokers hôtes séparés et confinés**, écrits en Rust et fuzzés.
4. **Réseau** : l'invité n'a **aucune interface réseau**. Un proxy de sortie hôte (`kaput-egress`)
   résout le DNS lui-même en DoH puis refuse par défaut loopback, LAN, link-local, ULA, multicast,
   adresses de l'hôte, préfixes on-link, routes non-défaut et métadonnées cloud. **TCP seul en v1.**
5. **Invité** : paquets **Debian 13** assemblés par **mkosi** en image immuable. Noyau LTS Kaput
   sans modules, rootfs EROFS + **dm-verity** sans initramfs, état 100 % tmpfs, init statique Kaput,
   aucun shell ni gestionnaire de paquets. Le navigateur est **Chromium** (sandbox actif, jamais `--no-sandbox`).
6. **Mises à jour** : **TUF** comme seule autorité, plus une provenance SLSA vérifiée avant signature.
   L'hôte vérifie hash, signature, version et `roothash` avant chaque démarrage. **Fail closed.**
7. **Application hôte** : Rust, processus séparés (UI, VMM, réseau, affichage, mise à jour). La session
   est tuée par le noyau (Job Object / cgroup) même si Kaput plante. Les logs sont typés et ne
   contiennent ni URL, ni domaine, ni IP.
8. **Risques résiduels principaux** : hyperviseur et noyau hôte (TCB non réductible), canaux auxiliaires
   CPU, nos propres brokers (code neuf), RAM de session paginable sur le disque hôte (pagefile, swap,
   hibernation), délai de correctif du navigateur.
9. **Inconnues bloquantes** avant de figer l'ADR 0001 : WHP utilisable depuis un AppContainer ;
   périmètre réel d'un build OpenVMM minimal et son support virtio-vsock ; débit de l'affichage sur vsock.
   Toutes demandent un **prototype sur une vraie machine Windows**.
10. **Décisions produit à valider par l'utilisateur** : §16.

---

## 1. Compréhension du produit

Kaput est un **navigateur jetable** : chaque session démarre une machine virtuelle Linux minimale qui
ne contient que le navigateur. L'utilisateur voit le navigateur dans une fenêtre Kaput. À la fermeture,
tout l'état de la session est détruit, faute d'avoir jamais existé ailleurs qu'en RAM invitée.

**Cas d'usage dimensionnant** : ouvrir un lien douteux en supposant que le site parviendra à exécuter du
code dans l'invité, y compris avec les droits root. Kaput doit alors garantir que :
- l'attaquant n'atteint ni les fichiers, ni les processus, ni le réseau local de l'hôte ;
- il ne persiste pas d'une session à l'autre.

**Ce que Kaput n'est pas** (à écrire dans l'UX) :
- un outil d'anonymat : les sites voient l'IP publique de l'utilisateur ;
- une protection contre un hôte déjà compromis ;
- une protection contre l'utilisateur qui recopie volontairement un secret dans une page malveillante.

**Exigences du brief qui structurent l'architecture**

| Exigence | Section du brief | Conséquence |
|---|---|---|
| Sécurité > correction > fiabilité > maintenabilité > performance > UX | §30 | Pas de GPU, pas de codec côté hôte, TCP seul en v1 |
| Ne pas présupposer l'architecture | §3 | Comparaison complète : `docs/research/01` |
| Windows et Linux | §1 | Deux backends VMM, un seul contrat invité |
| Aucune persistance | §7 | Rootfs RO + tmpfs, aucun disque hôte inscriptible |
| L'hôte est une frontière de sécurité | §8 | Pas de partage, pas de presse-papiers par défaut, pas de NIC |
| Privilèges minimaux | §10, §11 | Admin/root **uniquement à l'installation**, jamais à l'exécution |
| Mise à jour compromise = menace critique | §6 | TUF + provenance, vérification avant chaque boot |
| Audits indépendants | §16 | Chaque frontière : implémentation → revue → test offensif → QA |

---

## 2. Architecture proposée

### 2.1 Vue d'ensemble

```text
 HÔTE (Windows 11 / Linux)        ── T0 : noyau hôte + hyperviseur (TCB non réductible)
 │
 ├─ kaput            UI + superviseur. Utilisateur standard. Possède le Job Object / cgroup.
 │                   Vérifie l'image, ouvre les fichiers, crée les sandboxes, tue tout à la fermeture.
 │                   Ne parse AUCUN protocole riche venant de l'invité.
 │
 ├─ kaput-update     (éphémère) réseau → TUF ; écrit uniquement dans le cache d'images.
 │
 ├─ kaput-vmm        ── S1, le plus confiné : aucun FS (handles hérités), AUCUN réseau, aucune vue
 │   Firecracker │      processus, pas de Win32k/GUI. Émule virtio-blk(ro) + virtio-vsock.
 │   OpenVMM         Relaie chaque port vsock vers un broker via un pipe/socketpair hérité.
 │
 ├─ kaput-egress     ── S2 : réseau sortant seulement. Parse KEP (Kaput Egress Protocol),
 │                      résout en DoH, applique la politique deny-by-default, connecte en TCP.
 │
 ├─ kaput-display    ── S3 : aucun FS, aucun réseau, pas de fenêtre. Parse KDP (Kaput Display
 │                      Protocol), écrit des pixels validés dans une mémoire partagée de taille fixe.
 │                      L'UI ne fait que copier ces pixels à l'écran et dessiner le cadre hôte.
 │
 ═══════════════ T1 : virtualisation matérielle (VT-x/AMD-V, EPT/NPT) ═══════════════
 │
 └─ INVITÉ Linux minimal (EROFS ro + dm-verity, tmpfs noexec, pas de shell)
      ├─ kaput-init (PID 1, statique)
      ├─ kaput-agent (uid 1002) : relais SOCKS→KEP, trames→KDP (réserver AF_VSOCK à cet uid est un
      │                          durcissement best effort, sans effet contre un root invité)
      ├─ compositeur kiosque headless (uid 1001), rendu logiciel
      └─ Chromium (uid 1000) ── T2 : sandbox navigateur (userns + seccomp-bpf, site isolation)
```

### 2.2 Chemins d'attaque vers l'utilisateur hôte

_Section réécrite après la revue offensive (RT-01, RT-02, RT-04). La version précédente annonçait « au
moins trois vulnérabilités indépendantes » sans distinguer les chemins ; cette formulation était trop
rassurante._

| Chemin | Étapes requises après RCE dans un renderer | Nombre minimal de vulnérabilités hôte |
|---|---|---|
| **A. Hyperviseur** | Évasion de la sandbox → LPE noyau invité (root) → bug de KVM, de l'hyperviseur Microsoft ou du noyau hôte atteignable depuis l'invité | **1** (une fois root dans l'invité). **Risque résiduel R1, non réductible par Kaput** |
| **B. Périphériques virtio / émulation du VMM** | Évasion de la sandbox → root invité → bug du VMM (S1) → évasion du confinement S1 (LPE noyau hôte, bug AppContainer/Win32k) | **2** (VMM + confinement) |
| **C. Protocoles applicatifs (KEP, KDP)** | **Aucune marche invitée n'est garantie.** Le trafic web est relayé vers KEP par conception, et le contenu des pages détermine les pixels envoyés en KDP. Un renderer ou un Network Service compromis **influence directement** les entrées des parseurs S2/S3. Root dans l'invité donne un contrôle total de ces trames | **2** (parseur du broker + confinement du broker) |

Conséquences :
- `kaput-egress` et `kaput-display` sont des **parseurs de première ligne**, exposés au contenu web. Ils
  reçoivent le niveau d'exigence d'un VMM :
  - Rust sans `unsafe` ;
  - fuzzing `required` ;
  - destruction de la session à la première violation ;
  - revue indépendante ;
  - confinement aussi strict que S1.
- Les restrictions **internes à l'invité** (vsock réservé à l'uid agent, seccomp/LSM invité) **ne sont
  pas des garanties** : un root invité les désactive. Ce sont des durcissements « best effort ». La
  garantie réelle est côté hôte : **seuls les ports vsock créés par Kaput existent** (« hybrid vsock » en
  espace utilisateur), et chaque port n'accepte qu'un protocole borné.
- L'objectif de conception devient : **aucun chemin ne doit exister avec une seule vulnérabilité dans du
  code Kaput ou dans un VMM**. Le chemin A est assumé comme risque résiduel de toute architecture à
  machine virtuelle.
- Le nombre réel de vulnérabilités requises sera **mesuré** par le labo d'évasion (NEG-CHAIN-01).

### 2.3 Contrat invité commun (indépendant du VMM)

| Élément | Décision | Pourquoi |
|---|---|---|
| Boot | Boot direct du noyau, **sans firmware**, sans initramfs | Supprime UEFI, SMM, NVRAM, la persistance par variables EFI et l'ACPI riche |
| Transport virtio | **MMIO** | CVE Firecracker 2026 dans le transport PCI optionnel ; MMIO = surface minimale `[CVE à recouper]` |
| `virtio-blk` | 1 disque **raw, lecture seule**, sans auto-détection de format, ouvert par le superviseur et transmis par handle | Évite la classe « l'invité réécrit l'en-tête du disque » (Cloud Hypervisor 2026) `[CVE à recouper]` |
| `virtio-vsock` | **Émulé en espace utilisateur dans le VMM** sur les deux OS (« hybrid vsock » à la Firecracker). Un port par service : contrôle, KDP, KEP | Pas de vhost-vsock noyau sous Linux ; **pas de hvsocket/VMBus sous Windows**, donc pas d'enregistrement de GUID admin et pas d'accès aux services hvsock tiers (Docker, WSL) |
| Réseau | **Aucun** périphérique | Fail closed par construction |
| GPU / son / fs / USB / TPM / balloon | **Aucun** | Pas de besoin justifié en v1 |
| Console série | Builds de développement uniquement | Brief §8 : pas d'interface inutile |
| Entropie | RDRAND/RDSEED + jitterentropy ; `virtio-rng` seulement si la mesure l'exige | Petite surface, mais une de plus |
| **Émulation résiduelle** (RT-06) | **Inventaire obligatoire par backend**, publié dans `docs/isolation.md`. Pour chaque élément (i8042/reset, UART, LAPIC/IOAPIC, PIT/RTC/kvmclock/TSC, ports I/O, MSR, feuilles CPUID, registres MMIO) : activé ou non en release, émulé par l'hyperviseur ou par le VMM, fuzzé ou non | « Deux périphériques virtio » ne décrit pas toute la surface. Les PoC U3 (OpenVMM) et U6 (Firecracker) rendent cet inventaire **bloquant** ; NEG-MSR/CPUID/IOPORT le vérifient |
| Initramfs | **Aucun** : dm-verity est créé par `dm-mod.create` sur la ligne de commande signée | Tranche l'incohérence entre l'étude 01 (« + initramfs ») et l'étude 03 (RT-18). Le champ `boot` signé ne contient que le noyau et la ligne de commande |

Ce choix lève deux divergences entre études :
- l'étude Windows prévoyait hvsocket ;
- l'étude Linux prévoyait `virtio-net` + TAP.

Les deux sont **écartés** au profit d'un vsock en espace utilisateur sans NIC, recommandé par les études runtime et réseau.

---

## 3. Alternatives étudiées (résumé — détail dans `docs/research/01`)

| Option | Verdict | Raison principale |
|---|---|---|
| Conteneurs (namespaces, cgroups, seccomp, Landlock, AppArmor, SELinux) | Couche de confinement **du VMM** | Noyau hôte partagé avec le contenu hostile |
| gVisor | Écarté | Linux uniquement, compatibilité graphique partielle, ne règle pas Windows |
| AppContainer / LPAC | Couche de confinement **du VMM et des brokers** | Noyau NT et Win32k partagés |
| Sandbox navigateur seule | Couche interne (T2) | Évasions régulières (Pwn2Own 2026) |
| Windows Sandbox | Écarté | Invité Windows, absent de Home, réseau/vGPU/presse-papiers actifs par défaut |
| WSL2 | Écarté | L'invité peut monter `C:` (drvfs) ; réglages appliqués dans l'invité |
| Hyper-V complet / HCS | Écarté, **repli documenté** | Admin ou service SYSTEM requis ; VSP en noyau root |
| QEMU (KVM / WHPX) | Repli ultime seulement | C, surface immense, évasions virtio-gpu/virtio-blk en 2026 `[CVE à recouper]` |
| Cloud Hypervisor | Alternative Linux n° 2 | Plus large que Firecracker ; CVE 2026 instructives |
| crosvm | Repli Windows | Excellent modèle de confinement ; backend WHPX non testé en amont |
| libkrun | Écarté v1 | TSI donne le réseau hôte au VMM ; WHP pas en amont |
| Hyperlight | À surveiller | Orienté fonctions, pas d'OS graphique |
| Kata | Écarté | Orchestration OCI inutile sur un poste de travail |
| **Firecracker (Linux) + OpenVMM (Windows)** | **Retenu** | VMM Rust minimaux ; seul VMM Rust porté par Microsoft sur WHP |

**Pourquoi cette architecture offre la meilleure frontière de sécurité pour Kaput**
1. Le noyau hôte n'est pas partagé : l'invité ne voit que l'interface de virtualisation matérielle et deux périphériques virtio.
2. Toute l'émulation est **en espace utilisateur, en Rust, et confinée**. Avec Hyper-V classique, une partie s'exécute en noyau root.
3. Le VMM n'a ni réseau, ni fichiers, ni vue sur les processus. Une évasion qui passe par le VMM n'aboutit pas directement chez l'utilisateur. Seul un bug de l'hyperviseur lui-même (chemin A, §2.2) le permettrait.
4. Les données riches (pixels, réseau) sont analysées hors du VMM, dans des brokers à un seul privilège chacun.
5. WHP et KVM sont disponibles sur les éditions grand public, sans service privilégié.

---

## 4. Threat model

Le document de référence est `docs/threat-model.md`. Ses sections 1 à 5 sont indépendantes de
l'architecture : actifs A1–A8, adversaires T1–T6, hypothèses H1–H5, objectifs O1–O8.
Hypothèse dimensionnante : **l'invité est entièrement compromis (root)**.

### 4.1 Frontières de confiance

| ID | Frontière | De → vers | Mécanisme | Menaces principales | Mitigations | Risque résiduel |
|---|---|---|---|---|---|---|
| **TB0** | Matériel / hyperviseur | invité → hôte | VT-x/AMD-V, EPT/NPT, KVM ou hyperviseur MS | Bug KVM/hyperviseur, canaux auxiliaires | Surface exposée minimale, OS hôte à jour, diagnostic des mitigations CPU | **Critique, non réductible par Kaput** |
| **TB1** | Invité ↔ VMM | invité → S1 | Émulation virtio-blk/vsock en Rust | Bug d'émulation, virtqueue malformée, double fetch | 2 périphériques, MMIO, raw RO, fuzzing, mise à jour rapide des commits épinglés | Élevé (impact) / moyen (probabilité) |
| **TB2** | VMM ↔ session utilisateur | S1 → utilisateur | Jail Linux (userns, mount, pid, net, seccomp, Landlock, cgroup) ; AppContainer/LPAC + Job + mitigations Windows | Évasion du confinement | Aucun FS, aucun réseau, pas de `ptrace`/`kill` possible, Win32k désactivé | Moyen |
| **TB3** | Invité ↔ brokers | invité → S2/S3 | Protocoles KEP/KDP à trames bornées | Bug de parseur, DoS, logique de politique | Rust `forbid(unsafe)`, fuzzing, violation = destruction de session | Moyen |
| **TB4** | Brokers ↔ session | S2/S3 → utilisateur | Mêmes primitives que TB2, un seul privilège chacun | Évasion du confinement | Idem TB2 | Moyen |
| **TB5** | Proxy ↔ réseau local | S2 → LAN/hôte | Politique P0–P15 (`docs/research/05` §5) | Rebinding, IPv4-mapped, NAT64, split-tunnel, IPv6 GUA du LAN | Résolution par le proxy, contrôle de l'IP connectée, P9–P13 | Faible-moyen (intranets publics derrière la route par défaut) |
| **TB6** | Chaîne de mise à jour | Internet → hôte | TUF + provenance SLSA + Authenticode/paquets signés | Freeze, rollback, mix-and-match, clé compromise, CI compromise, **poste de signature compromis** | Rôles TUF séparés, expirations, anti-rollback. Avec un mainteneur unique, la v1 n'a **qu'un seul domaine humain** (RT-03) ; contrôles compensatoires au §10 | **Élevé en v1** (mainteneur unique) ; faible-moyen avec un second domaine réel |
| **TB7** | Contenu invité ↔ perception de l'utilisateur | pixels → humain | Cadre hôte dessiné hors de la zone invitée | Usurpation de l'UI Kaput ou OS (faux UAC, faux mot de passe) | Aucun vrai plein écran en v1, touche hôte non transmise, « Kaput ne demande jamais de mot de passe » | Moyen (ingénierie sociale) |
| **TB8** | Autres processus de la session utilisateur → Kaput | T5 → Kaput | Partiellement dans le périmètre (RT-08) | **Dans le périmètre** : remplacement de l'image ou des métadonnées en cache, TOCTOU entre vérification et boot → hash calculé sur le tampon passé au VMM, dm-verity, Authenticode. **Hors périmètre** : lecture de la RAM du VMM, injection dans un processus Kaput, lecture de `session.lock` par un malware de même UID (équivaut à un hôte déjà partiellement compromis, H1) | `PR_SET_DUMPABLE=0` (Linux) ; NEG-TOCTOU-IMG-01 | Accepté et documenté |

### 4.2 Menaces du brief → couverture

| Menace (brief §2) | Couverture principale | Statut |
|---|---|---|
| Site, JS, exploit navigateur | T2 (sandbox Chromium) + JIT désactivé (à valider, D3) + T1 | Défense en profondeur ; on suppose la chaîne réalisable |
| Téléchargements malveillants | Bloqués ou confinés dans l'invité (D6) ; aucun transfert vers l'hôte en v1 | Couvert par conception |
| Exploit OS invité, malware invité, persistance invitée | Hypothèse root invité ; rootfs RO + verity ; tmpfs ; aucun état réutilisé | Couvert |
| Accès FS, processus, réseau, sockets de l'hôte | Pas de partage ; VMM sans FS ni réseau ; netns/Landlock ABI ≥ 6 (sockets abstraits) ; KEP deny-by-default | Couvert, à prouver par le labo d'évasion |
| Évasion sandbox, hyperviseur, runtime | TB1/TB2 ; surface minimale | **Risque résiduel principal** |
| Périphériques | Aucun périphérique passé à l'invité | Couvert |
| Clipboard, drag & drop | Désactivés par défaut ; options bornées (D6) | Couvert |
| Interfaces graphiques | KDP minimal, pixels seulement, aucune chaîne de l'invité affichée | Couvert, à fuzzer |
| DNS, réseau, DNS rebinding | Résolution DoH côté hôte, contrôle de l'IP connectée (P13/P14) | Couvert |
| Mise à jour, image, supply chain | TUF + SLSA + reproductibilité + vendoring Rust + `cargo-vet` | Couvert, dépend de l'organisation des clés |
| Fuites de logs | Événements typés, aucun champ texte libre | Couvert par construction |

---

## 5. Composants

| Composant | Langage | Rôle | Reçoit des données hostiles ? | Confinement cible |
|---|---|---|---|---|
| `kaput` (UI + superviseur) | Rust | Machine à états, watchdog, journal de session, fenêtre winit + softbuffer, cadre anti-spoofing | Indirectement (pixels déjà validés, événements de contrôle à taille fixe revalidés) | Utilisateur standard ; Landlock (Linux) ; mitigations de processus (Windows) |
| `kaput-vmm` | Rust | Intégration Firecracker (Linux) / OpenVMM (Windows), émulation blk + vsock | **Oui, directement (surface n° 1)** | S1 : le plus strict |
| `kaput-jail` (Linux) | Rust | Construit le jail sans root puis `execve` le VMM | Non | — |
| `kaput-egress` | Rust | Proxy de sortie KEP, DoH, politique | Oui | S2 : réseau sortant seulement |
| `kaput-display` | Rust | Parseur KDP → framebuffer partagé | Oui | S3 : aucun FS, aucun réseau |
| `kaput-update` | Rust | Client TUF, téléchargement, vérification | Données réseau hostiles | Réseau + écriture du cache d'images seulement |
| `kaput-proto` | Rust (`no_std` possible) | Codecs KDP, KEP, contrôle ; zéro dépendance | — | Bibliothèque, fuzzée |
| `kaput-policy` | Rust | Moteur de politique réseau pur (tables générées depuis les registres IANA versionnés) | — | Bibliothèque, tests exhaustifs |
| `kaput-sys` | Rust | **Seul crate avec `unsafe`** : FFI Win32/WHP/KVM, mémoire partagée | — | Double revue obligatoire |
| `kaput-init` | Rust statique | PID 1 invité : montages, sysctls, 3 services sous uid distincts, poweroff à la sortie | Invité | — |
| `kaput-agent` | Rust | Relais SOCKS5 → KEP, capture des trames → KDP, injection d'entrées | Invité (code non fiable par hypothèse) | uid dédié |
| Image invitée | mkosi + Debian 13 | Noyau LTS Kaput, EROFS + verity, Chromium, compositeur kiosque | — | — |
| Pipeline release | GitHub Actions + `python-tuf` | Build hermétique, SBOM, provenance, staging ; signature humaine hors CI | — | — |

**Langage : Rust partout.** Raisons :
- sécurité mémoire ;
- écosystème rust-vmm ;
- pas de runtime qui empêcherait un seccomp strict ;
- Firecracker et OpenVMM sont eux-mêmes en Rust.

Tout le code est en `#![forbid(unsafe_code)]`, à l'exception de `kaput-sys`.

---

## 6. Dépendances

**Principe** : minimiser, vendoriser, auditer. L'incident `arrayref` d'août 2026 (un `build.rs`
malveillant via typosquat) montre que la compromission a lieu **à la compilation** `[à recouper]`.

| Dépendance | Usage | Évaluation (études 06 et 08) | Décision |
|---|---|---|---|
| Firecracker (commit/tag épinglé) | VMM Linux | Production AWS, Apache-2.0, avis de sécurité publiés | Adopter, build depuis les sources, MMIO seul |
| OpenVMM (commit épinglé) | VMM Windows | MIT, actif, **pas de releases**, interfaces « évolutives », processus d'avis inconnu | Adopter **sous condition du PoC** ; Kaput devient intégrateur et veilleur |
| crosvm | Repli Windows | BSD-3, WHPX non testé en amont | Évaluer si le PoC OpenVMM échoue |
| rust-vmm (`kvm-ioctls`, `vm-memory`, `virtio-*`) | Via Firecracker | Apache/BSD, maintenu | Transitif, audité via `cargo-vet` |
| `windows-sys` | FFI Win32/WHP | MIT/Apache, Microsoft | Adopter |
| winit 0.30.x + softbuffer 0.4.x | Fenêtre hôte | MIT/Apache ; winit 0.31 encore en bêta | Adopter (épinglé) ; SDL3 en repli |
| tough ≥ 0.24 | Client TUF Rust | 3 CVE corrigées en 04/2026 `[à recouper]` | Adopter, épingler, fuzzer les métadonnées |
| sigstore-rs | Vérif. provenance côté client | Expérimental < 1.0 | **Éviter en v1** : provenance vérifiée par le signataire avant la signature TUF (variante B de l'étude 06) |
| hickory-resolver (stub DoH, sans DNSSEC) | DNS dans `kaput-egress` | Avis RUSTSEC 2026 sur DNSSEC/recursor `[à recouper]` | Adopter le stub seulement ; ne jamais utiliser `hickory-recursor` |
| rustls | TLS du DoH et des mises à jour | Mémoire-sûr, audité | Adopter ; magasin de racines embarqué et signé |
| mkosi, systemd-veritysetup | Build de l'image | LGPL, outils de build non distribués | Adopter |
| Chromium (Debian `trixie-security`) | Navigateur | BSD + composants divers, ~4 j de retard sur l'amont (un seul échantillon) | Adopter en v1 (D4) |
| python-tuf, cosign, syft | Outillage release | Maintenus, licences permissives | Adopter (CI/signature) |
| Trivy | Scanner | Compromis en 03/2026 `[à recouper]` | Éviter ; OSV-Scanner/grype à la place |

**Garde-fous supply chain** (pour l'ensemble du dépôt) :
- `cargo vendor`, et `--locked --offline` en CI ;
- `cargo-vet` et `cargo-deny` (advisories, licences, sources, doublons) ;
- liste blanche des crates à `build.rs` et proc-macros, avec un objectif de zéro dans `kaput-vmm` et les brokers ;
- pas de `serde_derive` aux frontières IPC ;
- actions GitHub épinglées par SHA ;
- budget de dépendances mesuré à chaque PR.

---

## 7. Stratégie Windows

Détail dans `docs/research/02`.

- **Cible** : Windows 11 build 26100+ encore en support, x64 en v1 (ARM64 ensuite). **Home inclus** si le PoC-1 confirme WHP.
  Windows 10 (ESU jusqu'au 12/10/2027) est exclu, sous réserve de validation (D9).
- **Hyperviseur** : Windows Hypervisor Platform (WHP). Il coexiste nativement avec VBS/HVCI.
  **Kaput ne demande jamais de désactiver VBS, HVCI, Credential Guard ni Defender**, ni d'ajouter une exclusion.
- **Privilèges** :
  - **une seule élévation UAC à l'installation** : MSI per-machine, activation de `HypervisorPlatform`, redémarrage proposé et jamais forcé ;
  - **exécution sans élévation** ;
  - jamais l'appartenance à « Hyper-V Administrators », qui équivaut à admin selon MSRC ;
  - aucun service, aucun pilote, aucun vSwitch, aucune règle de pare-feu.
- **Confinement** :
  - `kaput-vmm` en **LPAC sans capability**, avec Job Object (`KILL_ON_JOB_CLOSE`, limites mémoire et processus, aucun enfant) et mitigations CIG, ACG, CFG, CET, `disallow_win32k`, extension points désactivés ;
  - `kaput-egress` en AppContainer avec `internetClient` seul. La couche « réseau privé » de WFP est un **bonus**, pas la politique ;
  - `kaput-display` en AppContainer sans réseau ;
  - **PoC-2 bloquant** : si WHP refuse l'AppContainer, le repli est un jeton restreint + intégrité Low + Job. Un service SYSTEM n'est envisagé qu'avec l'accord de l'utilisateur (D-6 de l'étude 02).
- **Artefacts** :
  - la RAM invitée est de la mémoire du processus VMM ;
  - mitigations : `WerRegisterExcludedMemoryBlock` + exclusion WER, destruction de session avant mise en veille (`PowerRegisterSuspendResumeNotification`), tentative de `VirtualLock` bornée par le working set, recommandation BitLocker ;
  - `ClearPageFileAtShutdown` est proposé à l'installation mais décoché par défaut ;
  - Prefetch, Amcache et SRUM révèlent l'**usage** de Kaput, pas le contenu : c'est documenté.
- **Packaging** : MSI (WiX) signé, plus WinGet comme canal secondaire. Chaque EXE et chaque DLL est signé (exigence de Smart App Control).
- **Signature** : un particulier belge n'est pas éligible à Azure Artifact Signing `[à recouper]`. Les options sont décrites en D10.
- **Mises à jour de l'image** : dans `%LOCALAPPDATA%`, donc sans élévation, mais avec **vérification TUF et anti-rollback à chaque lancement**.
  Les binaires hôtes restent dans `Program Files` et chaque mise à jour passe par l'UAC.

---

## 8. Stratégie Linux

Détail dans `docs/research/03`, partie A.

- **Prérequis vérifiés au lancement, fail closed** :
  - KVM accessible sans root (groupe `kvm`) ;
  - cgroup v2 avec délégation systemd utilisateur ;
  - user namespaces ;
  - **Landlock ABI ≥ 6** (scoping des sockets abstraits et des signaux) ;
  - état des mitigations CPU affiché, sans blocage.
- **Jail `kaput-jail` sans root**, qui remplace le jailer Firecracker (exécuté en root, CVE 2026 d'écrasement de fichiers `[à recouper]`). Les étapes :
  - `close_range`, puis scope systemd transitoire (`MemoryMax`, **`MemorySwapMax=0`**, `TasksMax`) ;
  - `unshare(USER|MNT|PID|NET|IPC|UTS|CGROUP)`, puis `pivot_root` vers un tmpfs vide ;
  - `/dev/kvm` et les fichiers invités en bind RO ;
  - capabilities à zéro, `no_new_privs`, `PR_SET_DUMPABLE=0`, `RLIMIT_CORE=0` ;
  - Landlock (aucun FS hors jail, réseau TCP refusé, scoping) ;
  - seccomp en liste blanche avec action `KILL_PROCESS`, ioctl filtrés ;
  - puis `execve` du VMM, qui ajoute ses propres filtres par thread.
- **netns vide obligatoire** : c'est lui qui empêche un VMM compromis de joindre les sockets Unix
  **abstraits** de la session (X11, D-Bus). Les sockets **à chemin** (Wayland, PipeWire, agent SSH) sont
  hors d'atteinte grâce au `pivot_root` vers un tmpfs sans FS.
  Landlock ABI 6 est une **seconde couche** qui ne couvre que les sockets abstraits et les signaux ; les
  sockets à chemin exigent l'ABI 9 (RT-16). Landlock seul n'est jamais présenté comme suffisant.
- **MAC** :
  - un profil AppArmor est livré (obligatoire sur Ubuntu ≥ 24.04 pour autoriser `userns` au seul `kaput-jail`) ;
  - un module SELinux est livré (Fedora/RHEL) ;
  - ces couches sont **additionnelles**, les garanties reposent sur le socle namespaces + seccomp + Landlock ;
  - Kaput ne recommande **jamais** `apparmor_restrict_unprivileged_userns=0`.
- **Fenêtre** : client Wayland natif. X11 est toléré avec un bandeau « isolation réduite côté hôte » (D11).
  Le processus UI ne parse jamais de données invitées brutes : c'est le rôle de `kaput-display`.
- **Installation** : un paquet deb/rpm signé est la **seule étape root** (profil MAC, groupe `kvm`, binaires root-owned dans `/usr/lib/kaput`).
  Aucun setuid, aucun service root.
- **Distributions** :
  - Tier 1 : Ubuntu 24.04/26.04 LTS, Debian 13, Fedora N/N-1 ;
  - Tier 2 : RHEL/Alma/Rocky 9–10, openSUSE (sous réserve que son MAC par défaut soit confirmé) ;
  - best effort : Arch.
- **Hôte incomplet** (pas de userns ou Landlock < 6) : **refus par défaut** (D12).

---

## 9. Stratégie réseau

Détail dans `docs/research/05`.

- **Modèle M3** : aucune NIC dans l'invité. Le navigateur utilise un proxy SOCKS5 local à l'invité,
  traduit par `kaput-agent` en **KEP v1** sur un port vsock.
  - `kaput-egress` reçoit `CONNECT_TCP(nom|IPv4|IPv6, port)`.
  - Sa réponse ne contient **aucune adresse**, contrairement au `BND.ADDR` de SOCKS5 qui révélerait l'IP LAN de l'hôte.
- **Pipeline de décision P0–P15** (premier match ; défaut = REFUS) :
  - validation de trame et ASCII LDH seul ;
  - littéraux IPv4 historiques (octal, hexadécimal, formes courtes) ;
  - noms spéciaux (`localhost`, `.local`, `.internal`, nom à un seul label…) ;
  - profil de ports ;
  - résolution **DoH** (A et AAAA) ;
  - normalisation IPv4-mapped et NAT64 ;
  - listes noires statiques générées depuis les registres IANA ;
  - IPv6 limitée à `2000::/3` ;
  - adresses de toutes les interfaces hôtes ;
  - préfixes on-link ;
  - routes non-défaut (split-tunnel VPN) ;
  - métadonnées cloud ;
  - **refus de toute la réponse DNS si une seule adresse est interne** ;
  - `connect()` vers l'IP validée sans re-résolution.
- **Ajouts issus de la revue offensive** :
  - **P16 (RT-05)** : refus de l'**IP publique de sortie** de l'hôte, qui est souvent l'IP WAN du routeur
    domestique et donne accès à son interface d'administration par hairpin NAT.
    - Elle est détectée au démarrage et à chaque changement de réseau par un canal de confiance
      **sans UDP** : requête « quelle est mon IP » via le résolveur DoH configuré, méthode exacte à
      valider (U13).
    - Elle amorce la liste noire utilisateur (D10 de l'étude réseau), qui est **activée par défaut**.
    - Si la détection échoue, la session démarre avec un avertissement, et le risque est documenté.
  - **NAT64 (RT-13)** : tout préfixe NAT64 **non vérifié** (préfixe spécifique au réseau non découvert)
    est traité comme interne. Fail closed.
  - **Limite assumée** : les services publics qui relaient vers un réseau interne (proxys ouverts,
    prévisualiseurs d'URL, SSRF tiers) sont hors de portée de toute politique fondée sur la destination
    TCP. C'est une limite documentée, pas un bug.
- **DNS** :
  - uniquement dans `kaput-egress`, en DoH (HTTP/2, TLS 1.3) ;
  - bootstrap par IP littérales et racines TLS embarquées et signées ;
  - cache en RAM borné, effacé avec la session ;
  - **jamais `getaddrinfo` ni le client DNS de l'OS** (fuite et cache de l'hôte) ;
  - DoH injoignable → fail closed ;
  - résolveur par défaut proposé : Quad9 (D7).
- **TCP seul en v1** : HTTP/3 se replie sur HTTP/2, WebRTC passe par TURN-TCP, et le P2P UDP ne fonctionne pas (D1).
- **Navigateur** : `QuicAllowed=false`, `WebRtcIPHandling=disable_non_proxied_udp`, DoH interne désactivé, proxy imposé par politique.
- **Hors v1** : proxy d'entreprise amont (risque de pivot SSRF), exception pour portail captif, DNS système, Tor/VPN intégré.
- **Quotas anti-DoS** : 512 flux, 100 ouvertures/s, 200 requêtes DNS/s, timeouts.
- **Logs** : compteurs par **catégorie** de refus, jamais de destination.
- **Test de vérité** : environ 45 tests négatifs (`docs/research/05` §9). Chacun échoue si **un octet** atteint une sentinelle.

---

## 10. Stratégie de mise à jour

Détail dans `docs/research/06`.

- **TUF** est l'unique autorité pour l'image invitée **et** pour l'application hôte. Les rôles :
  - root hors ligne ;
  - targets hors ligne ;
  - délégations terminantes `guest-image` (expiration 14 j), `host-app` et `trust-config` ;
  - timestamp (24 h) et snapshot signés **hors CI et hors CDN**.
- **Deux contrôles** : provenance SLSA L3 (Sigstore keyless, workflow réutilisable) **et** signature TUF humaine. Avec un seul mainteneur, cela ne fait pas deux domaines de confiance indépendants (voir plus bas).
  - En v1, la provenance est vérifiée par l'outil du signataire **avant** la signature TUF. sigstore-rs est trop jeune pour le client.
  - Le CDN ne détient aucune clé.
- **Avant chaque boot** :
  - vérification des métadonnées locales et de la fraîcheur ;
  - ouverture des fichiers en lecture exclusive ;
  - SHA-256 du noyau calculé **sur le tampon effectivement passé au VMM** (anti-TOCTOU) ;
  - ligne de commande construite **uniquement** depuis le champ signé (avec `roothash`) ;
  - rootfs RO, avec dm-verity `panic_on_corruption` qui couvre une altération après vérification.
- **Politique** :
  - toute erreur de vérification → refus de l'artefact, sans jamais d'« auto-réparation » vers du non vérifié ;
  - rollback → refus et alerte ;
  - `policy.minimum_version` / `security_epoch` signés font office de révocation 0-day ;
  - fraîcheur : bandeau après 24 h, modal après 72 h, **blocage après 7 j** (D8) ;
  - pas de premier lancement hors ligne sans installeur complet vérifiable.
- **Build** :
  - mkosi avec un snapshot Debian horodaté et un lockfile des `.deb` ;
  - `SOURCE_DATE_EPOCH`, EROFS déterministe, sels verity déterministes ;
  - double build indépendant (alerte en v1, bloquant en v2) ;
  - SBOM CycloneDX + SPDX ;
  - surveillance du paquet Chromium toutes les 15 min ;
  - **objectif < 12 h** entre le paquet de la distribution et l'image signée.
- **Organisation des clés** : voir **D13**. Avec un seul mainteneur, des seuils « 3-sur-5 » seraient du théâtre de sécurité.
- **Modèle à mainteneur unique : ce qu'il vaut réellement (RT-03)**
  - En v1, le client ne vérifie que TUF. La provenance SLSA est contrôlée par le signataire **avant** de
    signer.
  - Le « double domaine de confiance » se réduit donc à **un seul domaine : le mainteneur et son poste
    de signature**. La compromission de ce poste pendant une cérémonie suffit à publier une image
    malveillante acceptée par tous les clients.
  - Contrôles compensatoires retenus, par ordre d'effet réel :
    1. **Rebuild reproductible indépendant, dès la phase 1** (au lieu de la phase 2). Les instructions de
       build hermétique sont publiées. Un second build sur une autre infrastructure doit donner le même
       `verity_roothash` : une divergence est d'abord signalée, puis bloquante dès que la
       reproductibilité est prouvée (NEG-REBUILD-01). Des tiers sont invités à attester publiquement
       l'égalité des hash. C'est le seul substitut crédible à un second humain.
    2. **Transparence publique** :
       - toutes les métadonnées TUF, SBOM et attestations sont publiées dans des logs append-only
         (GitHub immutable releases + Rekor) ;
       - une release inattendue devient détectable par un tiers.
    3. **Poste de signature isolé** :
       - média live hors ligne, jamais le poste de développement ;
       - vérification de la provenance et du diff SBOM/lockfile **sur ce poste** ;
       - journal de cérémonie signé.
    4. Révocation rapide conservée (`guest-image` à 14 j, `minimum_version`, `security_epoch`) et clés
       distinctes par délégation.
    5. **Zéro `build.rs` ni proc-macro** dans `kaput-vmm`, `kaput-egress`, `kaput-display` et
       `kaput-proto` (leçon `arrayref`).
    6. Empreinte root et identité attendue du workflow publiées par un canal indépendant (README signé,
       site).

---

## 11. Stratégie navigateur

Détail dans `docs/research/04`, partie A.

- **Moteur** : Chromium.
  - Sous Linux, ses renderers ont une sandbox à deux couches (userns + seccomp-bpf).
  - Site isolation stricte et V8 heap sandbox (une défense pratique, pas encore une frontière forte selon Google).
  - Catalogue de politiques le plus complet, correctifs tous les 14 jours plus des correctifs de sécurité hebdomadaires.
  - Firefox reste le second choix documenté.
- **Binaire** : **Chromium de Debian `trixie-security`** en v1 : libre, signé, reconstructible depuis un snapshot. Les écarts :
  - Google Chrome : licence propriétaire, redistribution dans une image très probablement non autorisée `[à vérifier juridiquement]` ;
  - Chromium compilé par Kaput : cible à moyen terme si la latence médiane Debian dépasse 48 h (mesure continue).
- **Exécution** :
  - utilisateur dédié, profil en tmpfs ;
  - Wayland dans un compositeur kiosque headless, **sans GPU** (rendu logiciel) ;
  - **`--no-sandbox` interdit**, avec une vérification au démarrage (`Seccomp: 2`, namespaces distincts) qui tue la session si la sandbox est inactive ;
  - aucune mise à jour autonome dans l'invité.
- **Politiques** (environ 40, détail dans l'étude 04 §A.5) : WebUSB, HID, Serial, Bluetooth, capteurs, capture, impression, extensions, synchronisation, gestionnaire de mots de passe, autofill, DevTools distants, WebGPU et accélération matérielle sont désactivés. HTTPS-Only est activé.
  - Un test automatisé lit `chrome://policy` et échoue sur toute politique inconnue ou en erreur.
- **JIT** : désactivé par défaut (`DefaultJavaScriptJitSetting=2`). 5 des 7 0-days Chrome de 2026 visaient V8 `[à recouper]`.
  En contrepartie, JavaScript est plus lent et WebAssembly est probablement indisponible (D3).
- **Âge maximal** : l'image du navigateur est refusée au-delà de 14 jours (aligné sur l'expiration `guest-image`) ou si sa version figure dans une liste signée de versions à 0-day exploité.

---

## 12. Affichage, entrées et canaux hôte

Détail dans `docs/research/04`, partie B.

- **KDP v1**, protocole maison inspiré du protocole GUI de Qubes :
  - en-tête fixe de 12 octets ;
  - moins de 15 types de messages, chacun à taille fixe ou bornée ;
  - pixels XRGB8888 en tuiles ≤ 1024×1024 ;
  - crédits de flux (au plus 2 images en vol) ;
  - séquence stricte ;
  - **toute violation détruit la session** ;
  - l'hôte impose la taille, le format et le stride ;
  - **aucune chaîne venant de l'invité n'est affichée** (titre de fenêtre fixe) ;
  - **v1 : mode `INLINE` uniquement.** Le mode `TILE_SHM` (mémoire partagée écrite par l'invité, donc
    double fetch possible et `unsafe` dans `kaput-sys`) est reporté. Il ne sera introduit qu'avec une
    double revue et un fuzzing concurrent obligatoire (NEG-SHM-RACE-01, RT-10).
- **Rejetés** :
  - virtio-gpu (2D et 3D), virgl, Venus, gfxstream, DRM native context ;
  - SPICE, VNC générique, RDP/WSLg ;
  - Wayland transféré au compositeur hôte.
  Tous exposent un gros parseur C/C++ ou le pilote GPU de l'hôte.
- **Pas de codec vidéo côté hôte.** La 4K60 vidéo sera dégradée (30 fps ou sous-résolution) (D2).
- **Entrées** :
  - codes physiques evdev, jamais de keysyms ;
  - disposition (AZERTY belge, etc.) choisie par l'hôte dans une liste fermée et appliquée dans l'invité ;
  - les combinaisons système hôte ne sont pas transmises ;
  - **touche hôte réservée** jamais transmise (D14).
- **Défauts** :
  - audio coupé ;
  - presse-papiers coupé dans les deux sens ;
  - glisser-déposer absent ;
  - téléchargements bloqués ;
  - aucun transfert de fichier vers l'hôte ;
  - pas d'upload depuis l'hôte (D6).
- **Anti-spoofing** :
  - cadre « frise-tapis » dessiné par l'hôte hors de la zone invitée, aux couleurs d'état ;
  - aucun vrai plein écran en v1 (D14) ;
  - règle affichée : « Kaput ne vous demandera jamais de mot de passe ».
- **Accessibilité** : les lecteurs d'écran hôtes ne voient pas le contenu (transport par pixels). C'est une limite documentée.

---

## 13. Cycle de vie et UX

Détail dans `docs/research/08`.

- **Machine à états pure** de 15 états, de `RECOVERING` à `CONFIRMED`.
  - **Invariant : dès `PREPARING`, tout chemin mène à `DESTROYING`.**
  - Les tests sont exhaustifs (état × événement) et incluent des injections de pannes, dont un `kill -9` de `kaput` à chaque état.
- **Arrêt forcé**, budget d'environ 10 s, dans cet ordre :
  1. `SHUTDOWN` à l'agent ;
  2. arrêt des vCPU et suppression de la partition ;
  3. `TerminateProcess` / `pidfd_send_signal` ;
  4. `TerminateJobObject` / `cgroup.kill` ;
  5. vérification que le Job ou le cgroup est vide.
- **Si Kaput plante**, la mort de la session est garantie par le noyau :
  - Windows : Job `KILL_ON_JOB_CLOSE` détenu seul par `kaput` ;
  - Linux : cgroup de session, plus `PDEATHSIG` depuis un thread dédié, car le signal suit le thread créateur et non le processus.
  - Au lancement suivant, `session.lock` (PID + heure de création, sans contenu) permet de détecter et détruire une session orpheline.
- **Une seule session à la fois en v1.**
- **UX** : accueil « Naviguer en sécurité », 7 étapes visibles, écran de destruction en 6 étapes, puis confirmation honnête : « Session détruite. Aucune donnée de navigation n'a été conservée. » Aucune promesse de 100 %.
- **Identité visuelle** : le concept A « Médaillon-enclave » est recommandé (K en espace négatif dans un médaillon *toranj* gardé par une bordure de tapis), avec la construction à degrés du concept B pour les tailles 16–32 px.
  Le concept C (*mihrab*) est écarté faute de validation culturelle (D15).

---

## 14. Stratégie de tests

Détail dans `docs/research/07`.

- **Pyramide** :
  - unit et propriétés ;
  - intégration ;
  - cycle de vie VM ;
  - réseau ;
  - évasion et forensique ;
  - fuzzing.
- **Tests négatifs `NEG-*`** : le vert signifie que l'attaque échoue. Ils sont marqués `required` et ne peuvent être retirés qu'après une revue sécurité.
- **Labo d'évasion** : une image invitée **red team dédiée**, jamais signée par la clé de production (gate `NEG-BUILD-01`), avec des sondes :
  - FS, processus et localhost de l'hôte ;
  - LAN, PCI, ports I/O, hypercalls, ports vsock ;
  - presse-papiers et persistance.
  Les résultats sont des rapports JSON corrélés à des sentinelles côté hôte, réunis dans une matrice de couverture menace × backend × OS.
- **Forensique** : scan des répertoires temporaires, journaux, swap, pagefile et dumps après une fermeture normale **et** après un `kill -9`.
- **Fuzzing** :
  - cibles : KDP, KEP, IPC de contrôle et métadonnées TUF ;
  - en PR : `cargo-fuzz` en rejeu de corpus ;
  - la nuit : AFL++ ;
  - un crash de parseur est classé `critical`.
- **CI** :
  - `ubuntu-latest` expose `/dev/kvm`, ce qui permet de vrais tests microVM Linux en CI hébergée (best effort) ;
  - **`windows-latest` n'a pas de virtualisation imbriquée** : les tests VM Windows exigent des runners self-hosted ou loués (D16).
- **Security gates séparés des tests fonctionnels** :
  - CodeQL, Semgrep ;
  - `cargo-deny`, `cargo-audit`, `cargo-vet` ;
  - OSV-Scanner, gitleaks, zizmor ;
  - OpenSSF Scorecard, SBOM ;
  - CODEOWNERS sur les chemins de frontière.
  Une modification de sécurité ne passe pas sur la seule foi d'une CI verte.

---

## 15. Risques et inconnues

### 15.1 Risques résiduels (après mitigations)

| ID | Risque | Gravité | Commentaire |
|---|---|---|---|
| R1 | Vulnérabilité KVM / hyperviseur Microsoft / noyau hôte atteignable depuis l'invité | Critique, probabilité faible | Hors de notre contrôle ; surface exposée minimale ; exiger un OS à jour |
| R2 | Canaux auxiliaires CPU (Spectre, MDS, SMT, rowhammer) | Élevée | Diagnostic et avertissement ; pas de correction possible par Kaput |
| R3 | Bug dans le VMM Rust (bogue logique, `unsafe`) | Élevée | Déjà observé chez Firecracker et Cloud Hypervisor en 2026 ; options minimales, confinement, veille |
| R4 | Bug dans nos brokers (KDP, KEP) ou dans `kaput-sys` | Élevée | Code neuf : fuzzing, revue indépendante, audit offensif, destruction sur violation |
| R5 | RAM de session sur le disque hôte (pagefile, swap hors cgroup, zswap, hibernation, kdump) | Moyenne-élevée | Mitigations partielles ; recommander le chiffrement du disque ; détruire la session avant la veille |
| R6 | Fenêtre N-day du navigateur (amont → Debian → image → poste) | Élevée | Pipeline < 12 h + mesure continue ; build maison si la latence se dégrade |
| R7 | OpenVMM sans releases ni processus d'avis connu | Moyenne | Veille à notre charge ; repli crosvm |
| R8 | Deux backends VMM → divergence de propriétés | Moyenne | Contrat invité unique ; même suite d'évasion bloquante sur les deux |
| R9 | Organisation des clés insuffisante (mainteneur unique) | Élevée | D13 ; seuils assumés et documentés |
| R10 | Intranets en IP publiques derrière la route par défaut | Moyenne | P10/P11 + liste noire utilisateur (ajout uniquement) |
| R11 | Usurpation visuelle et ingénierie sociale | Moyenne | Cadre hôte, pas de saisie hôte, éducation |
| R12 | Faux sentiment de sécurité (« CI verte = sûr ») | Moyenne | Matrice de couverture avec ses trous, langage de risque résiduel |
| R13 | Hôte X11 : un composant UI compromis devient un keylogger de la session | Moyenne | UI sans parsing invité ; avertissement ; Wayland recommandé |
| R14 | **kdump** (crash du noyau hôte), **hibernation déclenchée hors de Kaput** (batterie critique, commande tierce), zswap/zram (RT-07) | Moyenne | Aucune mitigation applicative complète. **Le chiffrement intégral du disque est la seule mitigation réelle** : Kaput détecte son absence et l'affiche (D19). NEG-FOR-KDUMP-01 et NEG-FOR-HIBER-01 |
| R15 | Parseurs KEP/KDP exposés au contenu web sans marche invitée préalable (chemin C, RT-02) | Élevée | Exigences de VMM appliquées aux brokers (§2.2) |
| R16 | Signature Windows : SignPath Foundation exige une équipe (author/reviewer/approver distincts) et affiche son propre nom d'éditeur (RT-15) | Moyenne | Demander une confirmation écrite d'éligibilité pour un projet solo ; repli : certificat OV |

### 15.2 Inconnues critiques (à lever par prototype avant les ADR définitifs)

| ID | Inconnue | Bloque | Méthode |
|---|---|---|---|
| U1 | WHP utilisable en **utilisateur standard**, y compris sur Windows 11 Home | ADR 0001 (Windows) | PoC-1 : partition minimale + 1 vCPU, en Rust |
| U2 | WHP utilisable depuis un **AppContainer / LPAC** | ADR 0005 (confinement Windows) | PoC-2 |
| U3 | Build OpenVMM minimal : crates liées, présence de virtio-vsock et virtio-blk MMIO sur WHP, absence de VMBus/UEFI/chipset legacy | ADR 0001 | PoC-3 : build + `cargo tree` + boot du noyau Kaput |
| U4 | Débit et latence KDP sur vsock (1080p60, damage rects) ; besoin d'une mémoire partagée | ADR affichage | Benchmark sur les deux backends |
| U5 | Destruction garantie de la partition et libération de la RAM à la mort brutale du VMM | Cycle de vie | Tests de crash |
| U6 | Firecracker sans jailer sous `kaput-jail` sur la matrice Tier 1 | ADR 0001 (Linux) | Matrice CI (`/dev/kvm` sur `ubuntu-latest`) |
| U7 | Compatibilité de la sandbox Chromium avec le noyau invité durci (userns, `memfd_noexec`, `IO_URING=n`, absence de `/bin/sh`) | Image invitée | Boot + `chrome://sandbox` |
| U8 | Latence réelle des correctifs Chromium Debian sur 8 à 12 semaines | D4 | Relevé automatisé |
| U9 | Effet réel de `DefaultJavaScriptJitSetting=2` sur Chromium 157 (Wasm ?) et taux de casse sur un échantillon de sites | D3 | Mesure |
| U10 | Taux de casse de P13 (« refus total si une IP interne ») sur le Web réel | Politique réseau | Top 10 000 sites |
| U11 | Pagination de la RAM invitée sans privilège (`VirtualLock`, `mlock`, `MemorySwapMax=0` vs zswap) | R5 | Mesure sous pression mémoire |
| U12 | Identifiants CVE et faits « 2026 » cités dans les études | ADR | Recoupement NVD / éditeur avant citation. **Échantillon de 11 faits porteurs confirmé** par la revue 0001 ; restent à recouper : CVE QEMU virtio-gpu/blk, CVE tough 04/2026, RUSTSEC hickory, CVE Hyper-V 2026, libslirp |
| U13 | Méthode fiable de détection de l'IP publique de sortie sans UDP (P16) | Politique réseau | Prototype via DoH |
| U14 | Éligibilité de Kaput à SignPath Foundation (projet solo, classification « non outil offensif ») | D10 | Demande écrite à SignPath |

**Conséquence** : l'ADR 0001 (runtime) est rédigé dès la phase 0 avec le statut **« Proposé »**.
Il passera à **« Accepté »** après les PoC U1–U3 et U6.
Les composants indépendants du VMM (protocoles, politique réseau, machine à états, client TUF, image
invitée) peuvent avancer en parallèle **sans risque de jeter du code** si le backend Windows change.

---

## 16. Décisions nécessitant la validation de l'utilisateur

Ce sont les décisions qui changent fortement le produit (brief §32). Chaque recommandation reflète la
priorité sécurité du brief.

| ID | Décision | Recommandation | Coût de la recommandation |
|---|---|---|---|
| **D1** | Réseau v1 : TCP seul (pas d'UDP/QUIC, WebRTC via TURN-TCP seulement) | **Oui** ; UDP encapsulé et audité en phase 2 | Visio dégradée, quelques services P2P cassés |
| **D2** | Aucune accélération GPU ; vidéo 4K60 dégradée ; pas de codec vidéo côté hôte | **Oui** | WebGL/WebGPU absents ou lents, CPU plus sollicité |
| **D3** | JIT JavaScript désactivé par défaut | **Oui** (Kaput sert à visiter des sites douteux) | Sites lourds plus lents, WebAssembly probablement indisponible |
| **D4** | Binaire navigateur : Chromium Debian (libre) | **Oui** en v1 ; build Kaput si la latence > 48 h | ~4 j de retard sur l'amont (un échantillon) |
| **D5** | DRM Widevine (Netflix…) | **Non** (binaire fermé supplémentaire) | Pas de streaming DRM |
| **D6** | Presse-papiers, audio, téléchargements par défaut | Tout désactivé. Options v1 : collage texte hôte→invité sur geste explicite ; audio PCM sortant ; téléchargements **confinés dans l'invité** (tmpfs, détruits). Jamais invité→hôte en v1 | Confort réduit |
| **D7** | Résolveur DoH par défaut | Quad9, choix visible au premier lancement | — |
| **D8** | Politique hors ligne | Bandeau après 24 h, modal après 72 h, blocage après 7 j, sans contournement par défaut | Kaput inutilisable après une semaine hors ligne |
| **D9** | Périmètre plateformes v1 | Windows 11 (Home inclus si le PoC réussit) + Linux Tier 1 ; x86_64 ; **pas Windows 10** | Utilisateurs Windows 10 exclus |
| **D10** | Signature Windows | Si Kaput est open source : **SignPath Foundation** (gratuit). Sinon certificat OV (~150–300 USD/an) ou entité légale UE + Azure Artifact Signing | Dépend de la licence (D17) |
| **D11** | Hôtes Linux X11 | Acceptés avec avertissement « isolation réduite » | — |
| **D12** | Hôte Linux incomplet (pas de userns ou Landlock < 6) | **Refus** par défaut | Vieux noyaux exclus (ex. RHEL 9 à vérifier) |
| **D13** | Clés de signature des mises à jour | Avec un mainteneur unique : root 2-sur-3 sur YubiKeys en lieux distincts, **assumé et documenté** (protège contre le vol, pas contre l'insider) ; ouvrir le rôle à d'autres mainteneurs dès que possible | Achat de 4–6 YubiKeys (prix à vérifier) |
| **D14** | Plein écran réel et touche hôte | **Aucun vrai plein écran en v1** (RT-12) ; « plein écran Kaput » = fenêtre maximisée, cadre hôte toujours visible ; touche hôte = Ctrl droit | Pas d'immersion totale (vidéo plein écran avec cadre) |
| **D19** | Chiffrement intégral du disque hôte absent (BitLocker / LUKS) | **Avertissement persistant**, sans blocage. C'est la seule mitigation réelle de R5/R14 | Blocage possible si l'utilisateur préfère (plus strict) |
| **D15** | Icône | Concept A « Médaillon-enclave » | — |
| **D16** | Runners CI Windows avec virtualisation imbriquée | Nécessaires pour tester réellement le chemin WHP ; alternative : tests manuels sur ta machine Windows | Coût mensuel ou temps manuel |
| **D17** | Licence du projet | À choisir par l'utilisateur. Compatible avec toutes les dépendances : Apache-2.0 ou MIT/Apache (permissive) ; GPL-3.0 si l'on veut que les dérivés restent libres | Conditionne D10 |
| **D18** | Proxy d'entreprise, portail captif, DNS système | Non supportés en v1 | Inutilisable derrière certains proxys d'entreprise |

### 16.1 Décisions prises par l'utilisateur (12/11/2026)

| ID | Décision | Conséquences appliquées |
|---|---|---|
| **D17** | Licence **GPL-3.0** | `LICENSE` GPL-3.0. Liste blanche de licences `cargo-deny` compatible GPL-3.0 : MIT, Apache-2.0, BSD, ISC, MPL-2.0, LGPL, Zlib, Unicode. Firecracker (Apache-2.0), OpenVMM (MIT) et rust-vmm (Apache/BSD) restent compatibles en une seule direction : du code permissif peut entrer dans un projet GPL-3.0, pas l'inverse. |
| **D10** | Découle de D17 : demande à **SignPath Foundation** (signature OV gratuite pour l'open source). Repli : certificat OV | Le nom affiché par Windows sera celui de la fondation ; à mentionner dans `docs/release.md`. **Réserve (RT-15)** : SignPath exige une équipe author/reviewer/approver avec MFA, ce qui s'accorde mal avec un projet solo. Éligibilité à faire confirmer par écrit (U14) avant d'en dépendre |
| **D3** | **JIT désactivé par défaut** (`DefaultJavaScriptJitSetting=2`) | U9 reste à mesurer (WebAssembly, taux de casse) ; pas d'exception par site en v1 |
| **D16** | PoC Windows (U1–U3, U5) **sur le PC Windows 11 de l'utilisateur**, via l'app Claude, chaque action étant soumise à son accord | Activer WHP demandera une élévation UAC et un redémarrage, faits par l'utilisateur. Aucun runner payant pour l'instant. Les tests VM Windows en CI restent un trou de couverture documenté |
| **D13** | **Un seul détenteur de clés** pour l'instant : root TUF 2-sur-3 sur clés matérielles en lieux distincts | Protège contre le vol ou la perte d'une clé, **pas** contre la compromission du détenteur ou de son poste de signature. Risque R9 maintenu « élevé » ; contrôles compensatoires : voir §17 |

Les autres décisions (D1, D2, D4–D9, D11, D12, D14, D15, D18) suivent la recommandation par défaut
jusqu'à avis contraire de l'utilisateur.

---

## 17. Revue offensive indépendante

Revue complète : [`docs/reviews/0001-offensive-review-phase0.md`](docs/reviews/0001-offensive-review-phase0.md).
Son auteur, un agent distinct, n'a pas participé à la conception.

**Verdict** : l'architecture tient comme direction. En revanche, trois garanties étaient sur-vendues et
ont été requalifiées. Le choix fondamental (VM matérielle + VMM Rust confiné + brokers + absence de NIC
+ TUF) n'est pas remis en cause.

**Vérification des faits** : 11 faits porteurs sur 11 sont confirmés : CVE Firecracker, CVE du jailer,
CVE Cloud Hypervisor, gvproxy, deux 0-days V8, spice-server, incident `arrayref`, éligibilité Azure
Artifact Signing, SignPath, Landlock ABI 6. Aucun identifiant n'a été fabriqué ; le défaut relevé était
la sur-interprétation.

| Constat | Gravité | Correction appliquée |
|---|---|---|
| RT-01 Chemin hyperviseur en une seule vulnérabilité | Critical | §2.2 réécrit par chemin (A/B/C) ; R1 assumé |
| RT-02 KEP/KDP exposés au contenu web sans LPE invité | Critical | Chemin C ; brokers traités comme parseurs de première ligne ; R15 |
| RT-03 Double domaine illusoire avec un seul mainteneur | Critical | TB6 requalifié « élevé en v1 » ; rebuild indépendant avancé en phase 1 ; transparence publique ; poste de signature isolé (§10, ADR 0004) |
| RT-04 Restriction vsock « uid agent » sans effet contre root | High | Retirée des garanties ; seule l'énumération des ports côté hôte compte (§2.2) |
| RT-05 IP WAN du routeur, relais publics | High | P16 + liste noire utilisateur active par défaut ; relais tiers = limite documentée (§9) |
| RT-06 Émulation résiduelle sous-estimée | High | Inventaire obligatoire par backend, bloquant (§2.3) |
| RT-07 kdump, hibernation non notifiée | High | R14 ; chiffrement du disque = seule mitigation réelle ; D19 |
| RT-08 T5 à la fois couvert et hors modèle | High | TB8 précisé ; threat model §3 corrigé |
| RT-09 TCB Windows reposant sur OpenVMM non publié | High | **crosvm/WHPX testé en parallèle** d'OpenVMM pendant les PoC ; plan de réponse 0-day OpenVMM exigé avant toute release Windows |
| RT-10 Double fetch en mode SHM | Medium | v1 en mode `INLINE` seulement (§12) |
| RT-11 TOCTOU sur l'image dans `%LOCALAPPDATA%` | Medium | Invariant testé NEG-TOCTOU-IMG-01 |
| RT-12 Spoofing en vrai plein écran | Medium | Aucun vrai plein écran en v1 (D14) |
| RT-13 Préfixe NAT64 réseau non découvert | Medium | Préfixe non vérifié = interne (fail closed) |
| RT-14 Injection dans la ligne de commande noyau | Medium | Identifiant de session à longueur fixe et charset fermé ; NEG-CMDLINE-01 |
| RT-15 SignPath et projet solo | Medium | U14, R16, réserve sur D10 |
| RT-16 Portée exacte de Landlock ABI 6 | Low | §8 précisé |
| RT-17 `session.lock` et logs | Low | Déjà spécifié ; tests `required` |
| RT-18 Incohérence initramfs | Low | Tranché : aucun initramfs (§2.3) |

**Tests négatifs ajoutés au catalogue** : NEG-CHAIN-01, NEG-VSOCK-ROOT-01, NEG-NET-WAN-01,
NEG-MSR-01, NEG-CPUID-01, NEG-IOPORT-01, NEG-FOR-KDUMP-01, NEG-FOR-HIBER-01, NEG-TOCTOU-IMG-01,
NEG-CMDLINE-01, NEG-SHM-RACE-01, NEG-REBUILD-01 (détail : revue 0001 §6).

---

## 18. Organisation de l'équipe et plan de livraison

### 18.1 Phase 0 (ce document)

Huit études parallèles indépendantes, une synthèse par l'orchestrateur, une revue offensive séparée,
puis les ADR 0001–0005 au statut « Proposé ».

### 18.2 Phases suivantes

Chaque fonctionnalité de sécurité suit le flux du brief §16 :
implémentation → revue sécurité → test offensif → QA → intégration.
Le rédacteur ne déclare jamais seul sa fonctionnalité sûre.

| Phase | Contenu | Où | Parallélisable |
|---|---|---|---|
| **1. Fondations** | Workspace Rust, CI + security gates, `kaput-proto` (KDP, KEP, contrôle) + fuzz targets, `kaput-policy` + tests de bornes, machine à états pure + tests exhaustifs, squelette de docs | Ce conteneur + CI | Oui (3–4 agents dans des worktrees séparés) |
| **2. PoC Windows** | PoC-1/2/3 (WHP en utilisateur standard, dans un AppContainer, OpenVMM minimal) **et, en parallèle, crosvm/WHPX** (RT-09) | **PC Windows 11 de l'utilisateur** (décision D16), chaque action soumise à son accord | Indépendant |
| **3. Image invitée** | Config mkosi, noyau Kaput, `kaput-init`, `kaput-agent`, verity, Chromium + politiques | CI `ubuntu-latest` (réseau + KVM) | Oui |
| **4. Backend Linux** | `kaput-jail`, intégration Firecracker, boot de bout en bout, labo d'évasion v0 | CI `ubuntu-latest` + KVM | Après 1 et 3 |
| **5. Brokers** | `kaput-egress` (DoH, politique), `kaput-display`, UI winit | CI | Après 1 |
| **6. Backend Windows** | Intégration OpenVMM ou crosvm, confinement, MSI | Windows réel | Après 2 |
| **7. Mises à jour** | Dépôt TUF, `kaput-update`, pipeline de release, cérémonie de clés | CI + clés matérielles | Après 3 |
| **8. Durcissement et audit** | Campagnes de fuzzing, labo d'évasion complet sur les deux backends, forensique, audit offensif, documentation | Tous | — |

**Limite de l'environnement actuel.** Ce conteneur n'a ni KVM ni réseau pour les paquets. La phase 1
s'y fait avec des crates **sans dépendance externe**, ce qui sert aussi l'objectif de minimalité. Les
phases 3 et 4 tournent en CI. Les phases 2 et 6 exigent une machine Windows.
Kaput ne sera **pas** déclaré terminé sur la foi d'une compilation (brief §29) : chaque critère de
terminaison sera coché avec la preuve correspondante.
