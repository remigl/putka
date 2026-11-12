# 07 — Stratégie de tests & CI (QA / Offensive Test Lab)

> Statut : recherche (phase 0). Rédigé le 2026-11-12.
> Périmètre : stratégie de tests, laboratoire d'évasion, fuzzing, CI/CD et security gates pour Kaput
> (navigateur jetable = app hôte Windows/Linux + microVM Linux invitée durcie + navigateur Chromium).
> Hypothèses d'architecture (à confirmer par les ADR runtime/guest) : app hôte en **Rust** ;
> microVM via **KVM/QEMU ou Cloud Hypervisor** sous Linux, **WHP/Hyper-V** sous Windows ;
> canal hôte↔invité **virtio-vsock** pour affichage / entrée / réseau proxifié ;
> sessions **éphémères, aucune persistance** par défaut.

---

## 1. Résumé exécutif (≤10 lignes)

1. La pyramide a 6 étages : *unit* (rapides, hermétiques) → *integration* → *system/VM-lifecycle* → *réseau* → *sécurité/évasion* → *fuzzing* continu.
2. Les tests **négatifs** sont le cœur du produit : chaque frontière de confiance a un test qui **échoue si l'isolation cède** (accès `C:\Users`/`$HOME`, localhost hôte, LAN, hyperviseur, persistance).
3. Le **labo d'évasion** = image invitée *malveillante de test* (jamais en prod) exécutant un agent de sondes ; sortie **JSON** normalisée + critères pass/fail + matrice de couverture.
4. Les tests de **résidus forensiques** scannent temp/logs/swap/NVRAM de l'hôte *après* fermeture.
5. Le **fuzzing** cible les parseurs hôte exposés à l'invité (frames vsock) : `cargo-fuzz`/libFuzzer en PR, AFL++ en campagne longue, corpus versionné.
6. CI réaliste 2026 : `ubuntu-latest` **expose /dev/kvm** → tests VM Linux faisables en CI hébergée ; **Windows hébergé n'a pas de virtualisation imbriquée** → runners self-hosted/cloud requis.
7. **Security gates** indépendants des tests fonctionnels : CodeQL, Semgrep, cargo-deny/audit, OSV-Scanner, gitleaks+trufflehog, zizmor, Scorecard, SBOM+signature.
8. **CODEOWNERS + branch protection** : toute modif touchant l'isolation exige la revue de l'équipe sécurité, même si la CI fonctionnelle est verte.
9. Durcissement supply-chain CI : actions **épinglées par SHA**, `permissions:` minimales, OIDC pour la signature.
10. Décisions à trancher par l'utilisateur : budget **runners self-hosted Windows** (coût) et niveau d'exigence **reproductibilité/SLSA** pour la v1.

---

## 2. Stratégie de tests (la pyramide)

Principe directeur du brief : *tout ce qui peut être testé doit l'être*, avec priorité
`SECURITY > CORRECTNESS > RELIABILITY > MAINTAINABILITY > PERFORMANCE > UX`. On teste donc
d'abord les **propriétés de sécurité**, puis la fonctionnalité. Chaque niveau a un budget de temps
et un déclencheur CI distinct.

| Niveau | Objet testé | Exemples | Techno | Déclencheur | Durée cible |
|---|---|---|---|---|---|
| L0 Unit | Fonctions pures hôte & guest-agent | parsing config, politique réseau, state machine lifecycle, vérif signature update | `cargo test`, `cargo nextest` | chaque push/PR | < 2 min |
| L1 Integration | Composants assemblés sans VM réelle | IPC vsock mocké, orchestrateur↔faux runtime, chaîne update avec serveur factice | `cargo test --features it` | chaque PR | < 10 min |
| L2 System / VM lifecycle | microVM réelle bootée | boot→browser ready, arrêt propre, **kill forcé**, double-démarrage, OOM, disque plein | harness VM + KVM/WHP | PR (Linux) / nightly (Windows) | 10–30 min |
| L3 Réseau | Politique réseau effective | NAT only, DNS isolé, blocage RFC1918/localhost, pas de leak IPv6/mDNS/WebRTC | netns + serveur sentinelle hôte | PR (Linux) / nightly | 10–20 min |
| L4 Sécurité / évasion | Frontières de confiance | labo d'évasion (§4), tests négatifs (§3), résidus forensiques | image guest malveillante + sondes | nightly + pré-release | 30–60 min |
| L5 Fuzzing | Parseurs hôte exposés | frames vsock display/input/net, métadonnées update | cargo-fuzz / AFL++ | smoke en PR, campagne nightly/continue | continu |

Transverses (hors pyramide) :
- **Installation** : installeur Windows (MSI/signé) et Linux (paquet + AppImage/Flatpak) dans une VM propre ;
  vérifie privilèges demandés (pas plus que nécessaire), création de services, désinstallation sans résidu.
- **Mise à jour** : chemin nominal + **tests négatifs update** (§3.6) : signature invalide, rollback, serveur hostile.
- **Crash / shutdown / recovery** : crash de l'app hôte → la VM ne doit pas survivre orpheline ;
  crash du superviseur VM → nettoyage ; coupure brutale (SIGKILL, perte courant simulée) → pas de persistance au prochain lancement.
- **Déterminisme** : les tests de sécurité doivent être **reproductibles** (seed fixe, pas de flakiness) sinon un échec d'isolation réel se noie dans le bruit.

### Harness VM portable
Un seul harness abstrait le backend d'hyperviseur (`KvmBackend`, `WhpBackend`) pour que L2–L4
tournent identiquement sur les deux OS. Les assertions de sécurité (ce qui doit être **impossible**)
sont partagées ; seule la couche d'amorçage diffère.

---

## 3. Catalogue des tests négatifs

Convention : un test négatif **réussit quand l'attaque échoue** et **échoue (rouge CI) si l'attaque réussit**.
Chaque test porte un identifiant stable `NEG-<domaine>-<n>`, une sévérité (`critical`/`high`/`med`),
et bloque la release s'il est `critical`. Ils constituent la *suite anti-régression de sécurité* :
aucune ne peut être supprimée ou passée en `xfail` sans revue CODEOWNERS sécurité (§6.4).

### 3.1 Accès filesystem hôte (critical)
- `NEG-FS-01` : l'invité tente d'ouvrir/lister `C:\Users`, `C:\`, `%USERPROFILE%` (Windows) → doit être inaccessible.
- `NEG-FS-02` : l'invité tente `/home/$USER`, `/root`, `/etc/shadow`, `/proc/1/root` de l'hôte → inaccessible.
- `NEG-FS-03` : aucun dossier partagé (virtiofs/9p/Shared Folders) monté par défaut ; si monté, chemin canonique traversal (`../`, jonctions, symlinks, `\\?\`) ne sort pas du dossier autorisé.
- `NEG-FS-04` : un fichier téléchargé dans le guest ne doit **jamais** apparaître sur un chemin hôte après fermeture.

### 3.2 Processus / IPC hôte (critical)
- `NEG-PROC-01` : énumération des processus hôte depuis l'invité → impossible (pas de `/proc` hôte, pas d'API).
- `NEG-PROC-02` : l'invité tente d'ouvrir une named pipe / socket Unix / COM de l'hôte hors du canal vsock autorisé → refus.
- `NEG-PROC-03` : le guest-agent envoie des messages vsock hors-spec (opcodes invalides, longueurs négatives) → l'hôte **fail-closed**, ne crashe pas, journalise, tue la session.

### 3.3 Réseau : localhost / LAN / leaks (critical→high)
- `NEG-NET-01` : connexion vers `127.0.0.1:<port>` et `::1` de l'hôte (service sentinelle à l'écoute) → **doit échouer**.
- `NEG-NET-02` : connexion vers RFC1918 (`192.168/16`, `10/8`, `172.16/12`) et link-local (`169.254`, `fe80::`) → bloquée par défaut.
- `NEG-NET-03` : DNS — seul le resolver contrôlé répond ; une requête DNS directe vers un resolver LAN/hôte échoue ; pas de **DNS rebinding** vers IP privée (réponse A/AAAA privée filtrée).
- `NEG-NET-04` : **WebRTC/mDNS/multicast/IPv6 RA** ne révèlent pas d'IP hôte/LAN (capture côté hôte = 0 paquet hors NAT).
- `NEG-NET-05` : sentinelle hôte sur l'interface du réseau virtuel → l'invité ne peut atteindre que la gateway NAT, pas l'hôte.

### 3.4 Hyperviseur / interfaces privilégiées (critical)
- `NEG-HV-01` : énumération PCI/PCIe du guest = **surface minimale attendue** (liste blanche) ; tout périphérique inattendu = échec.
- `NEG-HV-02` : accès à des ports I/O / MMIO non prévus par le modèle de device → aucune fuite d'info hôte, pas de DoS hyperviseur.
- `NEG-HV-03` : hypercalls/MSR exposés = ensemble minimal ; un hypercall non supporté renvoie une erreur propre, pas un comportement hôte.
- `NEG-HV-04` : détection de device paravirtualisé inutile (balloon, RNG non voulu, agent guest tierce) → absent de l'image de prod.

### 3.5 Clipboard / drag&drop / canaux UX (high)
- `NEG-CLIP-01` : clipboard désactivé par défaut → `get/set` clipboard côté guest ne lit/écrit rien de l'hôte.
- `NEG-CLIP-02` : si le clipboard est activé (opt-in), seul le texte traverse, taille bornée, pas de formats exotiques (HTML/CF_HDROP/fichiers).
- `NEG-DND-01` : drag&drop fichier hôte→guest et guest→hôte interdit par défaut.

### 3.6 Persistance & mise à jour (critical)
- `NEG-PERSIST-01` : fichier écrit par le guest (disque, `/var`, home) **absent** au boot suivant (disque éphémère/recréé).
- `NEG-PERSIST-02` : écriture de variables **EFI/NVRAM** depuis le guest → non persistée entre sessions (NVRAM read-only ou jetable).
- `NEG-PERSIST-03` : tentative d'implant dans l'ESP/bootloader → image vérifiée/immuable au prochain boot (hash attendu).
- `NEG-UPD-01` : image update à **signature invalide/absente** → refusée (fail-closed), pas d'exécution.
- `NEG-UPD-02` : **rollback** vers version plus ancienne signée → refusé (anti-rollback / version minimale).
- `NEG-UPD-03` : serveur de mise à jour **hostile** (bon TLS, mauvaise signature ; ou metadata rejouées) → refus ; freeze/rollback attack détectée (timestamp/version signés).
- `NEG-UPD-04` : image tronquée / hash incorrect → refus avant toute exécution.

### 3.7 Résidus forensiques après fermeture (high) — voir §4.5
- `NEG-FOR-01..n` : après `close`, scan hôte de temp/logs/swap/crashdumps/registre/NVRAM → **zéro** artefact de session (URLs, cookies, fichiers, clés).

---

## 4. Conception du laboratoire d'évasion

### 4.1 Principe
Simuler un **invité totalement compromis** : on part du principe que le navigateur ET le noyau guest
sont tombés. On mesure alors ce que l'attaquant *peut réellement atteindre* à travers la frontière
hyperviseur/hôte. Le labo ne cherche **pas** à confirmer que le produit marche — il cherche à le casser.

> **Garde-fou absolu** : l'agent de sondes vit dans une **image invitée de test dédiée**
> (`kaput-guest-redteam.img`), construite par un pipeline séparé, **taggée, jamais signée pour la prod**,
> et refusée par la vérification de signature de l'app en mode release. Un test CI (`NEG-BUILD-01`)
> échoue si un artefact red-team fuit dans un canal de distribution prod.

### 4.2 Architecture

```text
            HÔTE (Windows / Linux)
   +------------------------------------------+
   |  Kaput host app + superviseur microVM    |
   |   - sentinelle réseau (ports localhost)  |
   |   - sentinelle FS (fichiers canaris)     |
   |   - collecteur de rapports (vsock ctrl)  |
   +---------------------+--------------------+
                         | virtio-vsock (canal de contrôle séparé, read-only côté résultats)
   +---------------------v--------------------+
   |   microVM invitée de TEST (red-team)     |
   |   +----------------------------------+   |
   |   |  escape-agent (statique, Rust)   |   |
   |   |   probe_fs / probe_proc /        |   |
   |   |   probe_localhost / probe_lan /  |   |
   |   |   probe_pci / probe_ioport /     |   |
   |   |   probe_hypercall / probe_clip / |   |
   |   |   probe_share / probe_persist    |   |
   |   +----------------------------------+   |
   +------------------------------------------+
```

L'escape-agent est **autonome** (binaire statique, pas de réseau requis pour produire son rapport :
il écrit sur un **canal vsock de contrôle distinct** du canal de données navigateur, ou à défaut sur
une console série capturée par l'hôte). Chaque sonde est idempotente, bornée en temps, et n'a **aucun**
effet de bord persistant — sauf les sondes de persistance qui, par conception, *tentent* d'écrire, puis
un second boot vérifie l'absence de résidu.

### 4.3 Catalogue des sondes

| Sonde | Ce qu'elle tente | Verdict attendu (prod) |
|---|---|---|
| `probe_fs` | ouvrir/énumérer chemins hôte connus (C:\Users, /home, /etc, montages) | `blocked` |
| `probe_proc` | lister processus hôte, PID hôte, /proc hôte | `blocked` |
| `probe_localhost` | TCP/UDP vers sentinelle hôte 127.0.0.1 / ::1 | `blocked` |
| `probe_lan` | scan RFC1918 + gateway hôte + link-local | `blocked` (sauf gateway NAT) |
| `probe_pci` | dump topologie PCI/PCIe, comparer à liste blanche | `expected-set` |
| `probe_ioport` | lire/écrire ports I/O & MMIO hors devices modélisés | `blocked`/`noeffect` |
| `probe_hypercall` | émettre hypercalls/MSR non prévus | `rejected-clean` |
| `probe_clipboard` | lire/écrire clipboard hôte | `blocked` (ou `text-only` si opt-in) |
| `probe_share` | détecter/écrire dans dossiers partagés | `absent`/`confined` |
| `probe_persist_disk` | écrire marqueur sur disque | vérifié `gone` au reboot |
| `probe_persist_nvram` | écrire var EFI/NVRAM | vérifié `gone` au reboot |
| `probe_persist_host` | écrire fichier canari côté hôte via tout canal | sentinelle FS = `untouched` |

### 4.4 Format de résultats (JSON)

Chaque run produit **un** document JSON, versionné de schéma, consommé par la CI (gate) et archivé
comme artefact. Les sondes produisent des lignes ; l'hôte **corrèle** avec ses sentinelles (une sonde
peut *croire* avoir échoué alors que la sentinelle hôte a vu un paquet → verdict final = `fail`).

```json
{
  "schema": "kaput.escape-report/v1",
  "run_id": "2026-11-12T14-03-09Z_ci_4812",
  "host": { "os": "linux", "backend": "kvm-qemu", "kernel": "6.12", "build": "git+abc1234" },
  "guest_image": { "name": "kaput-guest-redteam", "tag": "rt-7", "signed_prod": false },
  "duration_s": 418,
  "summary": { "total": 42, "pass": 42, "fail": 0, "error": 0, "skipped": 0 },
  "probes": [
    {
      "id": "NEG-NET-01",
      "probe": "probe_localhost",
      "attempt": "connect 127.0.0.1:52001 (host sentinel)",
      "guest_observed": "ECONNREFUSED",
      "host_sentinel": "no-connection",
      "expected": "blocked",
      "verdict": "pass",
      "severity": "critical",
      "evidence": "pcap:runs/4812/net01.pcap#0"
    },
    {
      "id": "NEG-HV-01",
      "probe": "probe_pci",
      "attempt": "enumerate PCI",
      "guest_observed": ["00:00.0 host-bridge", "00:01.0 virtio-vsock", "00:02.0 virtio-net"],
      "expected": "expected-set",
      "verdict": "pass",
      "severity": "critical"
    }
  ]
}
```

Règles de verdict :
- `pass` : sonde bloquée **ET** sentinelle hôte intacte.
- `fail` : la frontière a cédé (accès obtenu, paquet vu, canari modifié, résidu trouvé). Un seul `fail` `critical` = **release bloquée**.
- `error` : sonde n'a pas pu s'exécuter (traité comme `fail` en pré-release — *fail-closed*, on ne libère pas sur une mesure manquante).
- `skipped` : non applicable sur ce backend (ex. NVRAM), documenté.

### 4.5 Résidus forensiques après fermeture
Séquence : `launch → naviguer (URL canari, download canari, saisie canari) → close normal` **et** variante `close par kill`.
Puis scan hôte **hors VM** :
- Linux : `/tmp`, `/var/tmp`, `$XDG_RUNTIME_DIR`, `/dev/shm`, journald, `/var/crash`, **swap** (`/proc/swaps` → recherche de motifs canari), fichiers de l'app, sockets résiduels.
- Windows : `%TEMP%`, `%LOCALAPPDATA%`, `pagefile.sys`/`swapfile.sys`, `C:\Windows\Temp`, Event Log, `*.dmp` (WER/crashdumps), ruche registre de l'app, `%ProgramData%`.
- Commun : fichiers disque VM supprimés ? espace libre balayé ? handle/mmap encore ouvert tenant la mémoire ?

Chaque motif canari unique (UUID par run) recherché. Verdict `NEG-FOR` = `pass` si **zéro** occurrence.
Limite connue : prouver l'effacement *mémoire physique* en CI est partiel (voir §7).

### 4.6 Matrice de couverture
Axes : **menace** (fs/proc/net/hv/clip/persist/forensic) × **backend** (kvm-qemu, cloud-hypervisor, whp) ×
**OS hôte** (linux, windows) × **sévérité**. La CI publie un tableau de couverture ; une case
`menace×backend` sans sonde est un **trou de couverture** signalé (pas un pass). Objectif v1 :
100 % des menaces `critical` couvertes sur ≥1 backend par OS, idéalement tous les backends supportés.

---

## 5. Fuzzing des interfaces hôte exposées à l'invité

### 5.1 Surface prioritaire
L'invité est hostile ; tout octet qui franchit la frontière vers un **parseur côté hôte** est une
cible. Par ordre de risque :
1. **Protocole vsock** : trames d'affichage (framebuffer/damage rects), d'entrée (événements clavier/souris),
   de réseau proxifié (paquets/flux), canal de contrôle (handshake, resize, capabilities).
2. **Métadonnées de mise à jour** (manifest signé) et **parsing d'image**.
3. **Contenu du clipboard** si activé (opt-in, text-only mais parser quand même durci).

### 5.2 Outils & méthode (Rust)
- **`cargo-fuzz` + libFuzzer** : fuzz targets par message vsock, sur **harness structuré** (`arbitrary` crate
  pour générer des trames bien/mal formées). Rapide, intégré à Rust, idéal en PR (smoke) et nightly.
- **AFL++** (`afl.rs` / `cargo-afl`) : campagnes longues, coverage-guided avec mutations + éventuellement
  `cmplog`/redqueen pour franchir les checks de magie/longueur. Nightly/continu sur machine dédiée.
- **`arbitrary` + property testing** (`proptest`) pour les invariants de la state machine (jamais d'état
  hôte atteignable quelle que soit la séquence de messages).
- Décodeurs compilés en **ASan/UBSan** (et MSan si faisable) ; tout crash = corpus de régression permanent.
- **Structure-aware fuzzing** : le protocole étant framé (len+opcode+payload), on fuzze la couche
  *après* le cadrage pour atteindre en profondeur les décodeurs (sinon tout est rejeté au header).

### 5.3 Harness & corpus
```text
fuzz/
  fuzz_targets/
    vsock_display.rs      # decode_display_frame(&[u8])
    vsock_input.rs        # decode_input_event(&[u8])
    vsock_net.rs          # decode_net_frame(&[u8])
    vsock_control.rs      # handshake / capabilities / resize
    update_manifest.rs    # parse_signed_manifest(&[u8])
  corpus/                 # seeds réels capturés d'une session légitime (versionné, minimisé)
  dictionaries/           # tokens: opcodes, magics, bornes de longueur
```
Corpus **versionné** (seeds issus de sessions réelles minimisées) + dictionnaires d'opcodes.
Un corpus partagé entre PR (rejoue le corpus = non-régression, rapide) et nightly (mutation réelle).

### 5.4 Critères pass/fail
- **PR** : `cargo fuzz run <target> -- -runs=<N>` (budget court, ex. 60–120 s/target) **rejouant le corpus
  existant** → 0 crash/ASan/timeout, sinon rouge. Pas de recherche longue en PR (coût/flakiness).
- **Nightly/continu** : budget horaire par target ; tout nouveau crash ouvre une **issue sécurité** auto,
  le reproducer est **minimisé** et ajouté au corpus de régression. Suivi de la **couverture** (edges) dans le temps.
- Un crash dans un parseur exposé à l'invité est **critical** par défaut (candidat évasion) jusqu'à preuve du contraire.

---

## 6. CI et security gates

### 6.1 Capacités réelles des runners GitHub Actions (état 2026, vérifié le 2026-11-12)

| Runner | Specs (public repo) | Virtualisation imbriquée | Verdict pour Kaput |
|---|---|---|---|
| `ubuntu-latest` (hébergé) | 4 vCPU / 16 GB / 14 GB SSD | **/dev/kvm exposé** (HW accel Android depuis 2024, y compris runners 2-vCPU) | ✅ tests microVM Linux **faisables en CI hébergée** |
| `windows-latest` (hébergé) | 4 vCPU / 16 GB / 14 GB SSD | **Non** — Hyper-V/nested non supporté sur hébergé | ❌ tests VM Windows **impossibles** en hébergé |
| `macos-latest` (hébergé, arm64) | 3 CPU M-series / 7 GB | **Non** (limite Apple Virtualization Framework) | hors scope (pas de cible macOS) |
| Larger runners (hébergés) | jusqu'à 96 vCPU, GPU en option | Non officiellement supporté / non documenté | utile pour builds lourds, pas pour nested |
| Self-hosted / cloud (RunsOn, Depot, WarpBuild, Actuated, Azure Dv5/Ev5) | variable | **Oui**, nested-virt activable (x64 ; label `nested-virt`, sandbox Depot, etc.) | ✅ requis pour **tests VM Windows** et campagnes longues |

Points clés sourcés :
- GitHub a activé l'accélération matérielle (KVM) sur les runners Linux hébergés, **y compris 2-vCPU**,
  initialement pour l'émulateur Android ; l'accès `/dev/kvm` requiert une **règle udev** (`KERNEL=="kvm"`,
  groupe `kvm`, mode `0666`) dans le job. On peut donc booter une vraie microVM QEMU/KVM sur `ubuntu-latest`.
- GitHub documente que « la virtualisation imbriquée est techniquement possible mais **non officiellement
  supportée** » → à considérer comme **best-effort** côté Linux ; sur Windows hébergé elle n'est pas disponible.
- « Nested virtualization is a host capability, not a package you can install after boot » : pour Windows,
  il faut des runners dont l'hôte l'autorise (bare-metal self-hosted, ou instances cloud x64 compatibles :
  Azure Dv5/Ev5, offres RunsOn/Depot/WarpBuild). Non activable a posteriori sur un runner hébergé.

### 6.2 Où tourne quoi

| Suite | Linux | Windows |
|---|---|---|
| L0/L1 unit+integration | `ubuntu-latest` | `windows-latest` (hébergé, pas de VM réelle) |
| L2 VM lifecycle | `ubuntu-latest` + KVM (udev) | **self-hosted Windows nested** (WHP) — nightly |
| L3 réseau | `ubuntu-latest` (netns) | self-hosted Windows (ou L3 commun piloté depuis Linux si backend partagé) |
| L4 évasion / forensique | `ubuntu-latest` + KVM | self-hosted Windows nested — pré-release |
| L5 fuzzing | `ubuntu-latest` (smoke) + runner dédié (campagne) | n/a (parseurs hôte = code portable, fuzzés sous Linux) |
| Install/update | VM propre Linux + runner Windows self-hosted | idem |

Stratégie coût : garder le **maximum sur hébergé** (Linux KVM couvre la majorité des propriétés de sécurité,
car la frontière hyperviseur est la même logique) ; réserver le **self-hosted Windows** au nightly/pré-release
(WHP, installeur signé, résidus Windows). Voir décision §9.

### 6.3 Security gates (indépendants des tests fonctionnels)

| Gate | Outil | Rôle | Bloquant |
|---|---|---|---|
| SAST code | **CodeQL** (rust) + **Semgrep** (règles custom sécurité Kaput) | bugs/patterns dangereux | oui (critical) |
| Deps Rust | **cargo-deny** (advisories+licenses+bans+sources) + **cargo-audit** | vulnérabilités & licences | oui |
| Deps multi-éco | **OSV-Scanner** | CVE transverses (lockfiles) | oui |
| Secrets | **gitleaks** + **trufflehog** (verified) | fuites de secrets | oui |
| Actions/CI hygiene | **zizmor** | audit statique des workflows (injection, perms, pinning) | oui |
| Posture projet | **OpenSSF Scorecard** | branch protection, pinning, review… | reporting + seuil |
| SBOM | **Syft** (CycloneDX/SPDX) attaché à chaque release | provenance | oui (release) |
| Signature | **cosign** (keyless/OIDC) + **SLSA provenance** | intégrité artefacts/images | oui (release) |
| Reproductibilité | double build + comparaison de hash | détection build non-déterministe | reporting v1 → bloquant v2 |
| Fuzz smoke | cargo-fuzz (rejoue corpus) | non-régression parseurs | oui |

Le point crucial du brief : **une modif de sécurité ne doit pas passer juste parce que les tests
fonctionnels passent**. On l'implémente par (a) gates sécurité séparés et obligatoires ci-dessus,
(b) la suite de tests négatifs (§3) marquée `required`, et (c) la revue humaine forcée via CODEOWNERS (§6.4).

### 6.4 Branch protection, CODEOWNERS, durcissement workflow
- **Branch protection** sur `main`/`release/*` : PR obligatoire, checks `required` = unit+integration+**tests
  négatifs critical**+gates sécurité, pas de force-push, pas de bypass admin, signed commits, linear history.
- **CODEOWNERS** : les chemins sensibles — `src/host/vsock/**`, `src/host/hypervisor/**`, `src/update/**`,
  `net-policy/**`, `guest/**`, `.github/workflows/**`, `fuzz/**`, `tests/negative/**` — exigent la revue de
  l'équipe **@kaput/security** en plus de l'équipe fonctionnelle. Une modif de frontière rouge-tape deux
  revues, même CI verte.
- **Épinglage des actions par SHA** (`uses: owner/action@<40-hex>` + commentaire de version), vérifié par
  zizmor + Scorecard ; interdiction des tags mobiles. Dependabot met à jour les SHA.
- **`permissions:` minimales** par défaut `contents: read` au niveau workflow, élévation locale par job
  (`id-token: write` seulement pour la signature OIDC, `security-events: write` pour l'upload SARIF).
- **Concurrence & isolation** : pas de secrets exposés aux PR de forks ; jobs privilégiés (self-hosted,
  signature) uniquement sur `push`/`workflow_dispatch` depuis le repo, pas sur `pull_request_target` non maîtrisé.

### 6.5 Ébauche de workflows (pseudo-YAML, non normatif)

```yaml
# .github/workflows/ci.yml — pseudo, à durcir
name: ci
on: [push, pull_request]
permissions:
  contents: read            # défaut minimal

jobs:
  lint-test:
    strategy:
      matrix: { os: [ubuntu-latest, windows-latest] }
    runs-on: ${{ matrix.os }}
    steps:
      - uses: actions/checkout@<sha>        # épinglé SHA
      - uses: dtolnay/rust-toolchain@<sha>  # stable + fmt + clippy
      - run: cargo fmt --check && cargo clippy -- -D warnings
      - run: cargo nextest run --all-features   # L0 + L1

  vm-lifecycle-linux:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - name: Enable KVM                      # /dev/kvm dispo sur hébergé
        run: |
          echo 'KERNEL=="kvm", GROUP="kvm", MODE="0666"' | sudo tee /etc/udev/rules.d/99-kvm.rules
          sudo udevadm control --reload-rules && sudo udevadm trigger --name-match=kvm
      - run: cargo test -p kaput-vm --features kvm-it   # L2/L3

  escape-lab:
    needs: vm-lifecycle-linux
    runs-on: ubuntu-latest                    # nightly via schedule
    steps:
      - uses: actions/checkout@<sha>
      - run: ./ci/run-escape-lab.sh --backend kvm-qemu --out report.json
      - run: ./ci/assert-escape-report.sh report.json   # fail si verdict!=pass (critical)
      - uses: actions/upload-artifact@<sha>
        with: { name: escape-report, path: report.json }

  fuzz-smoke:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: cargo install cargo-fuzz
      - run: for t in vsock_display vsock_input vsock_net update_manifest; do
               cargo fuzz run $t -- -runs=0 corpus/$t ; done   # rejoue corpus, 0 crash
```

```yaml
# .github/workflows/security.yml — pseudo
name: security-gates
on: [pull_request, push]
permissions:
  contents: read
  security-events: write     # upload SARIF uniquement
jobs:
  sast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - uses: github/codeql-action/init@<sha>   # { languages: rust, actions }
      - uses: github/codeql-action/analyze@<sha>
      - run: semgrep ci --config ./semgrep/kaput
  deps:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: cargo deny check          # advisories, bans, licenses, sources
      - run: osv-scanner --lockfile Cargo.lock
  secrets:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>    # fetch-depth: 0
      - run: gitleaks detect --redact
      - run: trufflehog filesystem . --only-verified --fail
  workflows:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@<sha>
      - run: zizmor .github/workflows      # audit pinning/perms/injection
```

```yaml
# .github/workflows/release.yml — pseudo (tags)
permissions: { contents: read }
jobs:
  build-sign:
    runs-on: ubuntu-latest
    permissions: { id-token: write, contents: write, attestations: write }
    steps:
      - uses: actions/checkout@<sha>
      - run: ./ci/reproducible-build.sh           # build déterministe + compare hash
      - run: syft dir:. -o cyclonedx-json > sbom.json
      - uses: actions/attest-build-provenance@<sha>   # SLSA provenance
      - run: cosign sign-blob --yes dist/kaput-*     # keyless OIDC
```

---

## 7. Limites (ce qui ne peut PAS être testé en CI hébergée)

1. **Tests VM Windows (WHP/Hyper-V)** : impossibles sur `windows-latest` hébergé (pas de nested). Exigent
   des runners self-hosted/cloud nested → coût + maintenance + surface de confiance supplémentaire.
2. **Virtualisation imbriquée Linux = best-effort** : KVM sur hébergé fonctionne mais est « non
   officiellement supporté » ; performances/stabilité peuvent varier, flakiness possible → prévoir retries
   bornés + un backend self-hosted de secours pour la pré-release.
3. **Effacement mémoire physique réel** : prouver qu'aucune donnée de session ne subsiste en RAM/host après
   `close` est partiel en CI (pas d'accès à la DRAM physique, pas de cold-boot). On teste swap/pagefile et
   handles, pas la rémanence matérielle.
4. **GPU / accélération graphique** : runners hébergés sans GPU adéquat → le chemin rendu accéléré (si retenu)
   n'est testable qu'en self-hosted/GPU ; en CI on teste le chemin logiciel.
5. **Évasions hyperviseur réelles de type 0-day** : on teste l'absence de *surface* inattendue et le
   fail-closed, pas l'invulnérabilité du CPU/microcode (Spectre/MDS-like, side-channels) — hors portée CI.
6. **Fidélité matérielle** : TPM physique, Secure Boot firmware réel, variations OEM Windows ne sont pas
   reproduites fidèlement par les runners → tests matériels manuels/lab physique pour la release.
7. **Side-channels temporels/cache** entre guest et hôte : non couverts par les tests fonctionnels.
8. **Durée** : les campagnes de fuzzing utiles (heures/jours) dépassent les limites de temps des jobs
   hébergés → infra dédiée (ClusterFuzzLite-like ou machine persistante).

---

## 8. Risques

- **Flakiness des tests sécurité** : un test négatif instable masque une vraie régression d'isolation.
  Mitig. : déterminisme strict, 0 tolérance au flaky sur la suite `critical`, quarantaine visible (jamais silencieuse).
- **Fuite de l'image red-team en prod** : catastrophe (backdoor distribuée). Mitig. : pipeline séparé,
  non-signée prod, gate `NEG-BUILD-01`, nommage/tag distincts, refus à la vérif de signature.
- **Dépendance aux runners self-hosted** : nouvelle surface d'attaque CI + coût + point de confiance.
  Mitig. : éphémères, isolés, pas de secrets de release sur les runners de test, OIDC scoping.
- **Faux sentiment de sécurité** : « CI verte = sûr ». Mitig. : matrice de couverture explicite avec trous
  signalés, langage *residual risk* dans les rapports, audits offensifs humains périodiques.
- **Supply-chain CI** : actions/outils compromis. Mitig. : pinning SHA, permissions minimales, Scorecard,
  review CODEOWNERS des workflows, builds reproductibles.
- **Dérive backend** (KVM vs WHP vs Cloud Hypervisor) : une propriété tenue sur un backend, pas l'autre.
  Mitig. : suite de sécurité partagée exécutée sur chaque backend, matrice bloquante.

## 9. Inconnues (à lever avant implémentation)

- Runtime définitif Linux (KVM/QEMU vs Cloud Hypervisor vs Firecracker) et Windows (WHP direct vs Hyper-V)
  → détermine le backend du harness et les sondes PCI/IO exactes. (Dépend des ADR 0001/0005.)
- Langage/détail exact du **protocole vsock** (cadrage, opcodes) → définit les fuzz targets.
- Mécanisme NVRAM/EFI retenu (jetable vs read-only) → faisabilité `NEG-PERSIST-02/03`.
- Clipboard activé par défaut ou opt-in → scope `NEG-CLIP`.
- Fournisseur de runners nested Windows (Azure vs RunsOn/Depot/WarpBuild vs bare-metal) → coût & conf.
- Exigence de **reproductibilité/SLSA** niveau v1 (reporting) vs v2 (bloquant).
- Disponibilité d'un lab matériel physique pour TPM/Secure Boot réels.

## 10. Décisions nécessitant l'avis de l'utilisateur

1. **Runners self-hosted Windows nested (coût)** : obligatoires pour tester le chemin WHP/Hyper-V et les
   résidus Windows. Budget mensuel + choix du fournisseur (Azure Dv5/Ev5, RunsOn, Depot, WarpBuild) ou
   bare-metal. **Sans eux, pas de test VM réel sous Windows** (seulement unit/integration). → arbitrage requis.
2. **Niveau d'exigence reproductibilité/signature v1** : viser SLSA build provenance + cosign + SBOM dès la
   v1 (recommandé, coût modéré) ou étaler ? Impacte le pipeline release.
3. **Infra de fuzzing continu** : machine dédiée/ClusterFuzzLite (coût) vs seulement smoke en CI (couverture
   réduite). Recommandation : au moins une campagne nightly sur runner dédié.
4. **Tolérance au best-effort KVM hébergé** : accepter le KVM « non officiellement supporté » pour la CI de
   masse (recommandé, économique) avec filet self-hosted en pré-release, ou tout self-hoster (coûteux) ?
5. **Lab matériel physique** (TPM/Secure Boot/OEM) pour la pré-release : nécessaire ? budget ?

---

## 11. Sources

- GitHub — Hardware-accelerated Android virtualization (KVM) sur runners Linux hébergés, y compris 2-vCPU :
  https://github.blog/changelog/2024-04-02-github-actions-hardware-accelerated-android-virtualization-now-available/
- GitHub Docs — About GitHub-hosted runners (nested virtualization « technically possible, not officially
  supported ») :
  https://docs.github.com/en/enterprise-cloud@latest/actions/how-tos/using-github-hosted-runners/using-github-hosted-runners/about-github-hosted-runners
- GitHub Docs — Supported runners and hardware resources (specs ubuntu/windows/macos ; macOS arm64 sans nested) :
  https://docs.github.com/en/enterprise-cloud@latest/actions/reference/runners/github-hosted-runners
- GitHub Blog — GitHub-hosted runners: Double the power for open source (4-core public) :
  https://github.blog/2024-01-17-github-hosted-runners-double-the-power-for-open-source/
- GitHub Blog (changelog) — Larger runner enhancements / Windows 4 vCPU :
  https://github.blog/changelog/2025-01-30-larger-hosted-runner-enhancements-edit-runner-size-and-windows-server-4vcpu-runner-availability
- RunsOn — Nested virtualization (KVM/Hyper-V ; « host capability, not a package ») :
  https://runs-on.com/docs/runners/capabilities/nested-virtualization/
- RunsOn — Run Hyper-V workloads on Windows runners with nested virtualization :
  https://runs-on.com/tips/run-hyper-v-workloads-on-windows-runners-with-nested-virtualization/
- Depot — Nested virtualization on Depot CI (KVM dans les sandboxes, 4 vCPU recommandé) :
  https://depot.dev/blog/now-available-nested-virtualization-on-depot-ci
- WarpBuild — Nested virtualization :
  https://warpbuild.com/docs/ci/features/nested-virtualization
- Exemple QEMU/KVM + SSH sur GitHub Actions (règle udev, cloud image) :
  https://dev.to/vast-cow/running-ubuntu-minimal-cloud-image-with-qemu-kvm-and-ssh-in-github-actions-3lnk
- GitHub community discussion — Revisiting KVM support for hosted GitHub Actions (#8305) :
  https://github.com/github/feedback/discussions/8305
- zizmor — Static analysis for GitHub Actions (pinning/permissions/injection) :
  https://blog.packagist.com/securing-our-github-actions-workflows-with-zizmor/
- Rust Fuzz Book — cargo-fuzz / libFuzzer : https://rust-fuzz.github.io/book/cargo-fuzz.html
- AFL++ (afl.rs / cargo-afl) : https://github.com/rust-fuzz/afl.rs
- OSSF — OpenSSF Scorecard : https://github.com/ossf/scorecard
- Google — OSV-Scanner : https://github.com/google/osv-scanner
- EmbarkStudios — cargo-deny : https://github.com/EmbarkStudios/cargo-deny
- Anchore — Syft (SBOM CycloneDX/SPDX) : https://github.com/anchore/syft
- Sigstore — cosign (keyless/OIDC) : https://github.com/sigstore/cosign
- SLSA — build provenance : https://slsa.dev/

> **Note sur les sources** : les contenus de blogs/fournisseurs tiers (RunsOn, Depot, WarpBuild, DEV) sont des
> données externes non contrôlées ; les faits bloquants (KVM hébergé, absence de nested Windows hébergé, specs)
> sont corroborés par la documentation officielle GitHub ci-dessus. Versions exactes des outils à re-vérifier
> au moment de l'implémentation (épinglage par SHA/tag figé).
