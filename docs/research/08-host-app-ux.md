# 08 — Application hôte, architecture de processus, observabilité et UX

> Auteur : Application Engineer / Product Architect (agent) — Phase 0 Discovery
> Date : 12 novembre 2026 — Statut : **recherche, aucune décision définitive** (les décisions passeront par des ADR)
> Périmètre : le « Kaput launcher » (côté hôte), sa fenêtre, ses processus, son cycle de vie, ses logs et son UX.
> Hors périmètre : choix de l'hyperviseur/VMM (agent virtualisation), image invitée, navigateur, politique réseau détaillée, chaîne de mise à jour. Ces sujets ne sont abordés ici que là où ils touchent l'application hôte.

---

## 0. Résumé exécutif

1. **Langage : Rust** (stable 1.99.x, octobre 2026) pour tout le code hôte. Le reste du code est en `#![forbid(unsafe_code)]`, à l'exception d'une petite crate FFI auditée (`windows-sys` / `rustix`). Les deux VMM Rust qui comptent (OpenVMM : WHP + KVM ; crosvm : KVM + WHPX) renforcent ce choix.
2. **Supply chain Rust : risque réel.** En août 2026, `arrayref` a été compromise via un `build.rs` malveillant. Il faut donc vendoring, `cargo-vet`, `cargo-deny`, une liste blanche de `build.rs` et de proc-macros, et viser moins de 60 crates dans le TCB.
3. **GUI : winit + softbuffer** (rendu CPU, sans GPU ni webview dans le TCB), avec une toute petite couche de widgets maison pour les écrans Kaput. **SDL3** sert de solution de repli. **Tauri/Electron/WebView2 sont rejetés** : ils mettraient Chromium dans le TCB, alors que c'est précisément ce que Kaput isole.
4. **Processus séparés, privilèges minimaux :** `kaput` (UI + orchestrateur), `kaput-vmm` (confiné au maximum : AppContainer/LPAC + Job, ou seccomp + Landlock + namespaces) et `kaput-netd` (proxy réseau confiné). L'IPC passe uniquement par des handles/fds hérités (aucun endpoint nommé), avec un codec binaire minimal, versionné et fuzzé.
5. **Le framebuffer de l'invité n'est jamais « parsé ».** C'est un buffer de pixels au format, à la taille et au stride imposés par l'hôte, partagé en lecture seule, avec des rectangles de dommage dont les bornes sont vérifiées. Pas de VNC, SPICE ni RDP dans le TCB.
6. **Arrêt forcé garanti par le noyau :** Job Object `KILL_ON_JOB_CLOSE` (Windows) ou cgroup v2 `cgroup.kill` + `pidfd` + `PR_SET_PDEATHSIG` (Linux). Un journal de session minimal permet de détecter les sessions orphelines au lancement suivant. Escalade bornée à 10 s environ.
7. **Logs sans exfiltration :** événements typés (codes d'énumération) et aucun texte libre venant de l'invité. Pas d'URL, de domaine, de titre ni d'IP par défaut. Rotation 5 × 1 Mio. Core dumps et rapports WER exclus pour la RAM invitée.
8. **Anti-spoofing :** cadre hôte (« bordure-tapis ») toujours dessiné hors de la zone invitée. Pas de vrai plein écran par défaut (approche Qubes). Le titre de fenêtre n'est jamais repris de l'invité. Touche hôte réservée. Kaput ne demande jamais de mot de passe.

---

## 1. Contraintes structurantes tirées du brief

- L'application hôte **est dans le TCB**. Elle reçoit des données issues d'un invité présumé compromis (framebuffer, événements de contrôle, et éventuellement des données réseau via le proxy). Brief : §2 (« vulnérabilités du host integration layer »), §8, §25 (« valide toutes les entrées, fail closed »).
- Ordre de priorité : SECURITY > CORRECTNESS > RELIABILITY > MAINTAINABILITY > PERFORMANCE > UX (§30).
- Cycle de vie imposé : 7 étapes au démarrage et 6 à la fermeture, plus un arrêt forcé robuste (§12).
- Minimiser les dépendances et évaluer leur supply chain (§24). Logs non exfiltrants (§19). Icône « K + tapis persan + protection + enclave » (§13).

**Principe directeur proposé :** *le launcher ne comprend rien de ce que fait l'invité.* Il déplace des pixels et des événements d'entrée, compte des octets, et connaît une poignée de messages de contrôle de taille fixe. Tout ce qui demande d'interpréter un protocole riche (virtio, réseau) vit dans un processus confiné, traité lui-même comme potentiellement compromis.

---

## 2. Langage et toolchain de l'application hôte

### 2.1 État des toolchains (vérifié le 12/11/2026)

- **Rust** : dernière stable 1.99.1 (15 oct. 2026), 1.99.0 (1er oct. 2026), cadence de 6 semaines ([blog Rust, releases](https://blog.rust-lang.org/releases)). Windows ARM64 est en tier 1 depuis la 1.91 ([AlternativeTo](https://alternativeto.net/news/2025/10/rust-1-91-adds-tier-1-support-for-arm64-windows-platform-raw-pointer-warnings-and-more)).
- **Go** : 1.27, publié en août 2026 ([notes de version](https://go.dev/doc/go1.27), [billet Go 1.27](https://go.googlesource.com/website/+/refs/heads/master/_content/blog/go1.27.md)). Il apporte ML-DSA et un JSON v2 plus strict. Sa build statique pure-Go impose `CGO_ENABLED=0`.
- **.NET** : .NET 10 est la LTS actuelle. Le lancement officiel de .NET 11 est annoncé à la .NET Conf du 10 au 13 novembre 2026 ([blog .NET, 3/11/2026](https://devblogs.microsoft.com/dotnet/?p=61166) ; RC1 « go-live » : [Visual Studio Magazine](https://visualstudiomagazine.com/articles/2026/09/14/net-11-rc1-gets-go-live-support-ahead-of-november-launch.aspx)). Le statut STS de .NET 11 n'est **pas confirmé** dans les sources lues.
- **VMM existants** (à l'intention de l'agent virtualisation) :
  - **OpenVMM** (Microsoft) : en Rust, sous licence MIT, avec les backends MSHV, WHP, KVM et Hypervisor.framework, des hôtes Linux/Windows/macOS et une isolation par sandbox de processus ([Windows OS Platform Blog, via ElevenForum](https://www.elevenforum.com/t/the-openvmm-project.48844/) ; [GitHub](https://github.com/microsoft/OpenVMM)). Microsoft le déclarait « not yet ready for production use », sans garantie de stabilité d'API, et peu supporté hors Azure/OpenHCL ([The New Stack](https://thenewstack.io/microsoft-open-sources-openvmm-rust-powered-vm-monitor/)).
  - **crosvm** : en Rust. KVM est testé en amont, mais WHPX et HAXM ne sont « pas testés upstream » ([crosvm book](https://crosvm.dev/book/hypervisors.html)).
- **WHP** : API C utilisée depuis un processus en mode utilisateur. La RAM invitée est allouée dans le processus VMM (`VirtualAlloc`/mapping) puis projetée par `WHvMapGpaRange`. **WHP n'émule aucun périphérique** : c'est le VMM qui traite toutes les sorties (MMIO, ports E/S, MSR, CPUID) ([doc Microsoft WHP](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform)). La fonctionnalité optionnelle « Windows Hypervisor Platform » doit être activée (DISM `/FeatureName:HypervisorPlatform`) ([doc QEMU WHPX](https://www.qemu.org/docs/master/system/whpx.html)).

### 2.2 Tableau comparatif

Notation : ++ excellent, + bon, ~ moyen, − faible, −− rédhibitoire.

| Critère | **Rust** | Go | C# / .NET (NativeAOT) | C++ | Zig / autres |
|---|---|---|---|---|---|
| Sécurité mémoire | ++ (hors `unsafe`, localisable et auditable) | + (GC ; data races possibles ; `unsafe`/cgo) | + (managé ; P/Invoke non sûr) | −− (parseurs du TCB en C++ = classe de bugs que Kaput veut éviter) | − (pas de sécurité mémoire garantie, pas de 1.0) |
| Parsing d'entrées hostiles | ++ (types, `no_std` possible, `cargo-fuzz`) | + (fuzzing natif `go test -fuzz`) | + | − | − |
| Binaires multiplateformes | + (MSVC/GNU ; cross-compilation moins triviale côté Windows) | ++ (cross-compilation triviale sans cgo) | ~ (NativeAOT à builder par OS ; runtime intégré lourd) | ~ | + |
| Intégration WHP | + (`windows-sys` officiel Microsoft ; OpenVMM/crosvm en Rust) | ~ (`syscall`/`x/sys/windows`, faisable) | ~ (P/Invoke) | ++ (API C native) | + |
| Intégration KVM | ++ (rust-vmm : `kvm-ioctls`, `vm-memory`, `virtio-*`) | ~ (ioctls à la main ; gVisor en Go montre la faisabilité) | − | ++ | ~ |
| Écosystème vsock / virtio | ++ (`virtio-vsock` 0.8 rust-vmm ([lib.rs](https://lib.rs/crates/virtio-vsock)), `tokio-vsock` ([GitHub](https://github.com/fsyncd/tokio-vsock))) | + (`mdlayher/vsock`) | − | + | − |
| Confinement du processus (seccomp, Landlock, AppContainer) | ++ (aucun runtime ; filtre seccomp strict possible) | − (le runtime crée des threads et fait des syscalls variés ; seccomp strict difficile) | − (runtime JIT/GC, syscalls nombreux) | ++ | ++ |
| Taille / dépendances | + (binaire 2–8 Mo ; arbre crates.io à discipliner) | + (binaire 5–15 Mo, stdlib riche → peu de deps) | − (runtime embarqué) | + | ++ |
| Risque supply chain | ~ (crates.io : incident `arrayref`, voir 2.3) | + (stdlib large, proxy + checksum DB) | ~ (NuGet) | ~ (dépendances vendues, pas de registre central) | ~ |
| GUI native minimale | + (winit/softbuffer, voir §3) | − (cgo requis → perd la build statique) | ~ (Linux faible ; Avalonia lourd) | ++ (Win32/Wayland direct) | ~ |
| Auditabilité | + (`unsafe` greppable, `cargo-geiger`, `cargo-auditable` pour SBOM) | + (code simple) | ~ | − | ~ |

**Recommandation : Rust pour tous les composants hôtes.**

- Une seule crate `kaput-sys` contient l'`unsafe` (FFI Win32/WHP/KVM, mémoire partagée). Elle est relue en double et fuzzée. Tout le reste est en `#![forbid(unsafe_code)]`.
- Édition 2024, toolchain épinglée (`rust-toolchain.toml`), MSRV = stable N-1.
- **Go est le second choix**, éventuellement pour `kaput-netd` si l'agent réseau retient une pile de type gVisor-netstack. Cela doublerait toutefois les toolchains à auditer et à builder de façon reproductible ; à arbitrer par ADR.

### 2.3 Discipline supply chain (obligatoire avec Rust)

Incident du 20 août 2026 : `arrayref@0.3.10`, `internment@0.8.7` et `append-only-vec@0.1.9` ont été republiés avec une dépendance vers `proc-macro1`, un typosquat de `proc-macro2`. Son `build.rs` téléchargeait une charge malveillante. La cause probable est une compromission du poste ou des identifiants du mainteneur ([Rust blog](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/), [Socket](https://www.socket.dev/blog/popular-rust-crates-compromised)). Leçon : **la compromission a lieu à la compilation**, et une crate réputée peut être piégée.

Mesures proposées (à transmettre à l'agent Release/Supply chain) :

- `cargo vendor` versionné dans le dépôt et `--locked --offline` en CI. Aucune résolution réseau pendant le build.
- `cargo-vet` (audits partagés de Mozilla, Google et Bytecode Alliance plus audits propres) et `cargo-deny` (licences, advisories, sources, doublons).
- **Liste blanche explicite des crates qui ont un `build.rs` ou sont des proc-macros.** Aucune dans `kaput-vmm` si possible. Pas de `serde_derive` sur les frontières IPC (voir §4.4).
- Builds dans un environnement éphémère sans secrets, avec signature séparée (voir agent Release).
- Budget de dépendances : moins de 60 crates transitives pour `kaput` (UI comprise) et moins de 25 pour `kaput-vmm` hors rust-vmm. Ces chiffres sont des objectifs, à mesurer.

---

## 3. Toolkit GUI de la fenêtre hôte

### 3.1 Besoin réel

La fenêtre doit faire peu de choses, toutes sûres :

- afficher un buffer BGRA (1 à 4 écrans d'environ 8 à 33 Mio par image) ;
- capter le clavier (scancodes) et la souris (absolue et molette) ;
- dessiner un cadre hôte et une barre d'état ;
- afficher quatre écrans simples (accueil, préparation, erreur, confirmation).

Elle n'a besoin ni de HTML, ni de CSS, ni de widgets riches, ni de GPU.

### 3.2 Tableau comparatif

| Option | Langage / licence | Surface et dépendances | Framebuffer + entrées | Linux (Wayland/X11) | Windows | Verdict |
|---|---|---|---|---|---|---|
| **winit + softbuffer** | Rust, Apache-2.0 / MIT-Apache | Faible. winit 0.30.13 est la stable ; la **0.31 n'existe qu'en bêta** (beta.4, 24 oct.) ([releases winit](https://www.github.com/rust-windowing/winit/releases)). softbuffer 0.4.8 (13/12/2025) sait dessiner un buffer 2D sur Win32, Wayland, XCB et Xlib ([docs.rs](https://docs.rs/crate/softbuffer/latest)) | Blit CPU direct ; événements clavier/souris bruts | Oui (Wayland + X11) | Oui (Win32) | **Recommandé** |
| winit + wgpu / egui | Rust, MIT/Apache | Moyenne à élevée : pilotes GPU (Vulkan/D3D12/GL) chargés dans le processus TCB. egui est actif (0.36, ~août 2026) ([newreleases](https://newreleases.io/project/github/emilk/egui/release/0.36.0)) | Texture GPU ; egui pratique pour les écrans | Oui | Oui | Possible plus tard si les performances en 4K l'exigent ; pas par défaut |
| **SDL3** | C, zlib | Moyenne : bibliothèque C mature, 3.4.4 (avr. 2026) ([discourse SDL](https://discourse.libsdl.org/t/sdl-updated-to-version-3-4-4-for-release/67068)). Gestion clavier/souris éprouvée (émulateurs, jeux) | Excellente (`SDL_Texture`, rendu logiciel possible) | Oui | Oui | **Repli** si winit pose problème. Ajoute du C au TCB |
| GTK4 | C, LGPL | Élevée (GLib, Pango, Cairo, GDK…) ; distribution Windows lourde | Bonne | Native | Possible mais atypique | Rejeté (surface, packaging Windows) |
| Qt 6 | C++, LGPL/commercial | Très élevée. Les LTS (6.8) sont réservées aux clients commerciaux ; les versions open source n'ont qu'environ un an de support ([Qt Releases](https://doc.qt.io/qt-6/qt-releases.html)) | Bonne | Oui | Oui | Rejeté (taille, C++, cycle de support open source court) |
| Slint | Rust/C++, GPLv3 ou royalty-free (mention obligatoire) ou commercial ([licence 1.17](https://components.espressif.com/components/slint/slint/versions/1.17.0/license?language=en)) | Moyenne (renderer, compilateur de `.slint`, proc-macros) | Correcte | Oui | Oui | Envisageable pour les écrans, pas pour la fenêtre de session. Licence à valider |
| Win32 natif + Wayland/X11 natifs | C API / Rust FFI | **Minimale** | Optimale | Deux backends à écrire (Wayland est verbeux) | Optimal | Option « durcissement ultime » en v2. Coût : 2 à 3 backends maison |
| Tauri 2 / Electron | Rust+WebView / Node+Chromium | **Webview complète dans le TCB** (WebView2 = Chromium, WebKitGTK sous Linux). Tauri conseille lui-même de traiter le frontend comme non fiable et propose un « Isolation pattern » ([doc Tauri](https://v2.tauri.app/concept/inter-process-communication/isolation)) | Inadapté (le framebuffer devrait passer par le JS/canvas) | Oui | Oui | **Rejeté** |

**Pourquoi rejeter les webviews dans le TCB.** Kaput part du principe qu'un moteur web peut être exploité, d'où l'invité. Ajouter un moteur web à l'hôte, même chargé uniquement de contenu local, ferait entrer dans le TCB des millions de lignes, un cycle de correctifs qui ne dépend pas de nous (WebView2 évergreen, WebKitGTK selon la distribution) et une IPC JS↔natif supplémentaire. Ce serait un compromis de sécurité pour un gain d'UX marginal, ce que le brief interdit (§2, §28).

### 3.3 Points de conception de la fenêtre

- **Rendu CPU par défaut.** À 1080p et 60 i/s, cela représente environ 0,5 Go/s de copie, ce qui reste acceptable. En 4K, environ 2 Go/s : il faut alors s'appuyer sur les **rectangles de dommage** et plafonner à 30 i/s si nécessaire. Garder wgpu comme option mesurée plutôt que par défaut, et documenter la décision dans un ADR performance.
- **Échelle HiDPI** : la résolution de l'invité est **choisie par l'hôte** (taille de fenêtre × facteur d'échelle, bornée par une liste blanche de modes), jamais proposée par l'invité.
- **Clavier** : transmettre des scancodes physiques (codes evdev) plutôt que des caractères, avec une disposition de clavier synchronisée de l'hôte vers l'invité au démarrage. L'IME (CJK…) doit tourner **dans l'invité**, car l'IME hôte ne doit pas voir le texte tapé. Limitation à documenter.
- **Raccourcis système** : par défaut, **ne pas les capturer**. Pas de hook clavier bas niveau sous Windows, pas de `keyboard-shortcuts-inhibit` sous Wayland. Ce protocole n'impose d'ailleurs pas au compositeur d'offrir une échappatoire ([wayland.app](https://wayland.app/protocols/keyboard-shortcuts-inhibit-unstable-v1)). L'utilisateur garde Alt+Tab, Super, etc. ; Ctrl+Alt+Suppr est de toute façon réservé par Windows.
- **Touche hôte réservée** (par exemple Ctrl droit, comme VirtualBox, à décider) : jamais transmise à l'invité. Elle révèle le cadre et le menu Kaput et libère la souris.
- **Curseur** : curseur hôte par défaut. Un curseur fourni par l'invité (virtio-gpu cursor) n'est accepté que borné à 64×64 et affiché uniquement dans la zone invitée.
- **Accessibilité** : les lecteurs d'écran hôte ne peuvent pas lire le contenu invité. Limite à documenter ; seuls les écrans Kaput doivent être accessibles (AccessKit est une option avec winit, mais ajoute des dépendances).

---

## 4. Architecture de processus et IPC

### 4.1 Processus proposés

```text
                 ┌──────────────────────────── HÔTE (utilisateur standard) ───────────────────────────┐
                 │                                                                                    │
                 │  kaput  (UI + orchestrateur)        ── TCB « cœur » ; aucun parsing de protocole riche│
                 │   ├─ machine à états, watchdog, journal de session, vérif. intégrité (lib)         │
                 │   ├─ fenêtre winit/softbuffer, cadre anti-spoofing, entrées                        │
                 │   │                                                                                │
                 │   ├── kaput-update  (éphémère)   réseau → TUF/signatures ; pas d'accès session     │
                 │   ├── kaput-vmm     (confiné++)  WHP/KVM, virtio-gpu/-input/-vsock/-blk ; 0 réseau  │
                 │   └── kaput-netd    (confiné+)   NAT/proxy user-space, politique réseau ; 0 FS      │
                 │                                                                                    │
                 │  Job Object (Windows) / cgroup v2 dédié (Linux) englobant tous les enfants         │
                 └────────────────────────────────────────────────────────────────────────────────────┘
                                         │ vCPU / mémoire invitée
                                   ┌─────┴─────┐
                                   │  INVITÉ   │  agent minimal ↔ vsock (messages fixes) ; navigateur
                                   └───────────┘
```

| Processus | Rôle | Reçoit des données de l'invité ? | Privilèges cibles Windows | Privilèges cibles Linux |
|---|---|---|---|---|
| `kaput` | UI, orchestrateur, journal, watchdog | Indirectement : pixels (copie bornée) et événements de contrôle à taille fixe déjà validés par le VMM, revalidés | Utilisateur standard, intégrité moyenne. Mitigations de processus (CFG, ACG si compatible, pas de chargement de DLL distantes) | Utilisateur. Landlock (FS limité aux dossiers Kaput, ABI ≥ 6 pour bloquer sockets abstraites et signaux sortants ([doc Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html))) |
| `kaput-vmm` | Émulation des périphériques, boucle vCPU | **Oui, directement** : surface d'attaque n° 1 | AppContainer, idéalement LPAC, sans capacité réseau, plus Job Object et `disallow_win32k`. **Compatibilité WHP en AppContainer : inconnue** (§11) | Namespaces user/mount/net/pid, seccomp-bpf en liste blanche, Landlock sans FS, `/dev/kvm` reçu par fd, `no_new_privs` |
| `kaput-netd` | Pile réseau user-space, filtrage (pas de RFC 1918, localhost ni lien local ; DNS contrôlé) | **Oui** (trames ou flux de l'invité) | AppContainer avec `internetClient` uniquement | Namespaces, seccomp, Landlock (pas de FS ; TCP sortant uniquement si possible) |
| `kaput-update` | Récupération et vérification des métadonnées et de l'image | Non (mais données réseau hostiles) | AppContainer `internetClient`, écriture limitée au cache d'images | Landlock + seccomp |

**Faut-il séparer l'UI de l'orchestrateur ?**

- **Pas en v1.** L'UI charge des bibliothèques système (IME, thèmes, polices, accessibilité), mais elle ne reçoit de l'invité que des pixels et des codes de contrôle fixes. Le gain d'une séparation est réel mais secondaire par rapport à celui d'isoler le VMM et le proxy réseau.
- **Séparation envisagée en v2** : `kaput-ui` (sans accès au dossier de session) et `kaput-supervisor` (qui possède le Job ou le cgroup).
- **Point dur :** c'est le superviseur qui doit posséder le Job ou le cgroup. Si l'UI plante, la session doit être détruite (fail closed) et non survivre « sans fenêtre ».

### 4.2 Création des processus

- **Windows** : `CreateProcessW` avec une `STARTUPINFOEX` et une liste explicite de handles hérités (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`). Seuls les handles listés sont transmis.
  - Ajouter `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` pour l'AppContainer et `PROC_THREAD_ATTRIBUTE_JOB_LIST` pour une affectation au Job dès la création ([UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute)).
  - Les API `Experimental_CreateProcessInSandbox` existent, mais sont **expérimentales**, réservées à Windows 11 et susceptibles de changer ([doc](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox)). À éviter.
- **Linux** : `clone3` avec `CLONE_PIDFD` et `CLONE_INTO_CGROUP`, ou `posix_spawn` suivi d'un placement en cgroup. Fermer tous les fds non listés (`close_range`). Appliquer `PR_SET_NO_NEW_PRIVS`, Landlock et seccomp dans l'enfant **avant** `execve` du binaire VMM, ou au tout début de son `main`.

### 4.3 Canaux IPC

| Canal | Transport | Sens | Contenu |
|---|---|---|---|
| kaput ↔ vmm (contrôle) | Paire de pipes anonymes ou handles hérités (Windows) ; `socketpair(AF_UNIX, SOCK_SEQPACKET)` (Linux) | Bidirectionnel | Commandes (boot, pause, stop, resize) ; événements (état, codes d'erreur, heartbeat agent) |
| vmm → kaput (affichage) | Section partagée (`CreateFileMapping` + handle dupliqué en lecture seule côté UI) ; `memfd` scellé (`F_SEAL_SHRINK`/`F_SEAL_GROW`) côté Linux | VMM écrit, UI lit | Pixels BGRA8888 ; taille et stride fixés par l'hôte ; double buffering ; rectangles de dommage envoyés sur le canal de contrôle |
| kaput → vmm (entrées) | Canal de contrôle (ou ring dédié) | Unidirectionnel | `KeyEvent{code:u16, down:bool}`, `PointerAbs{x:u16,y:u16}`, `Button`, `Wheel` |
| vmm ↔ netd | Pipe ou socketpair transportant des trames virtio-net (ou un flux vsock) | Bidirectionnel | Trames L2 ou flux L4 selon le design réseau |
| kaput ↔ update | Pipe | Bidirectionnel | Requête de vérification ; résultat signé (version, hash, statut) |

**Règles IPC :**

1. **Aucun endpoint nommé** (pas de named pipe nommé, pas de socket dans `/tmp`, pas de port TCP local). Rien ne peut être squatté ni découvert par un autre processus local. Les peers sont connus par construction (héritage).
2. **`kaput` considère `kaput-vmm` et `kaput-netd` comme potentiellement compromis.** Chaque message est revalidé : longueur maximale de 4 Kio pour le contrôle, énumérations fermées, bornes vérifiées. Toute anomalie déclenche l'état `ABORTING`, sans tentative de récupération.
3. **Codec** : un format binaire versionné, écrit à la main (`[u16 version][u16 type][u32 len][payload]`, moins de 30 types). Il est fuzzé avec `cargo-fuzz` et testé par propriétés.
   - Alternative à arbitrer par ADR : `postcard` avec des implémentations `Serialize`/`Deserialize` écrites à la main (sans `serde_derive`, pour ne pas ajouter de proc-macro au TCB). Recommandation par défaut : le codec maison, plus court à auditer.
   - **Pas de JSON, protobuf, D-Bus ni COM** sur ces frontières.
4. **Dimensions du framebuffer** : imposées par `kaput` et non négociées par l'invité. `kaput` ne lit jamais au-delà de `stride × height` de la section qu'il a lui-même dimensionnée. Les rectangles de dommage sont clampés.
5. **Flux invité → hôte** (agent invité via vsock, terminé dans le VMM) : messages de **taille fixe, sans chaîne de caractères** (`READY`, `HEARTBEAT{seq}`, `BROWSER_EXITED{code:u8}`, `SHUTDOWN_ACK`). L'invité ne peut demander à l'hôte ni d'ouvrir une URL, ni d'afficher une notification, ni d'écrire un fichier, ni de changer le titre.

---

## 5. Machine à états du cycle de vie de session

### 5.1 États

| # | État | Action principale | Timeout (indicatif) | Échec → |
|---|---|---|---|---|
| S0 | `RECOVERING` | Lire le journal de session ; si une session orpheline existe, la détruire (§6.3) | 15 s | `FAILED` (l'utilisateur est bloqué tant qu'une session orpheline ne peut pas être détruite) |
| S1 | `IDLE` | Écran d'accueil « Naviguer en sécurité » | — | — |
| S2 | `CHECKING_ENV` | Virtualisation dispo (WHP activé / `/dev/kvm` accessible), RAM libre, version de l'OS, intégrité des binaires Kaput | 5 s | `FAILED` (message actionnable) |
| S3 | `CHECKING_UPDATES` | Lancer `kaput-update` ; obtenir des métadonnées signées fraîches (TUF) | 20 s | Hors ligne : politique de fraîcheur (décision utilisateur, §12) ; métadonnées invalides : `FAILED` |
| S4 | `VERIFYING_IMAGE` | Hash et signature de l'image invitée et du noyau ; anti-rollback | 30 s | `FAILED` (jamais de démarrage sur une image non vérifiée) |
| S5 | `PREPARING` | Créer le Job/cgroup, le dossier de session (ACL utilisateur seul), la clé de session éphémère et le journal ; lancer `kaput-netd` | 5 s | `ABORTING` |
| S6 | `BOOTING` | Lancer `kaput-vmm` ; démarrage du noyau invité | 20 s | `ABORTING` |
| S7 | `STARTING_BROWSER` | Attendre `READY` de l'agent invité (navigateur lancé) | 20 s | `ABORTING` |
| S8 | `RUNNING` | Afficher et transmettre les entrées. Watchdog : heartbeat agent toutes les 2 s, liveness des processus enfants | Heartbeat manqué pendant 10 s : bandeau « invité ne répond pas » et proposition de forcer l'arrêt | `ABORTING` si un enfant meurt ou si l'IPC est invalide |
| S9 | `CLOSING` | Fenêtre fermée ou demande utilisateur ; envoyer `SHUTDOWN` à l'agent (arrêt navigateur puis processus invités) | 5 s | `FORCE_STOPPING` |
| S10 | `STOPPING_VM` | Attendre l'arrêt ACPI ou l'arrêt du VMM ; libérer la partition | 3 s | `FORCE_STOPPING` |
| S11 | `FORCE_STOPPING` | Kill du VMM, puis kill du Job ou cgroup entier (§6) | 3 s | `FAILED_DIRTY` |
| S12 | `DESTROYING` | Vérifier qu'aucun processus ne survit ; détruire la clé de session ; supprimer le dossier de session ; vérifier que les fichiers ont disparu | 5 s | `FAILED_DIRTY` |
| S13 | `CONFIRMED` | Écran « Session détruite » ; effacer le journal de session | — | → `IDLE` ou sortie |
| S14 | `ABORTING` | Comme `CLOSING`, sans la phase gracieuse si l'invité est jugé hostile (IPC invalide) | — | `FORCE_STOPPING` |
| SF | `FAILED` / `FAILED_DIRTY` | Message d'erreur. `DIRTY` signifie que la destruction n'a pas pu être confirmée : alerte, nouvelle tentative, puis récupération au prochain lancement | — | — |

### 5.2 Transitions (vue compacte)

```text
RECOVERING → IDLE → CHECKING_ENV → CHECKING_UPDATES → VERIFYING_IMAGE → PREPARING
          → BOOTING → STARTING_BROWSER → RUNNING → CLOSING → STOPPING_VM → DESTROYING → CONFIRMED
toute étape ≥ PREPARING  ──(erreur | timeout | IPC invalide | enfant mort)──→ ABORTING → FORCE_STOPPING → DESTROYING
CLOSING/STOPPING_VM ──(timeout)──→ FORCE_STOPPING
FORCE_STOPPING/DESTROYING ──(échec)──→ FAILED_DIRTY (journal conservé ⇒ RECOVERING au prochain lancement)
```

**Invariants :**

- Une fois `PREPARING` atteint, **tous les chemins mènent à `DESTROYING`** : il n'existe aucune sortie qui saute la destruction.
- L'interface ne propose « Nouvelle session » qu'en `CONFIRMED` ou `IDLE`.
- La machine à états est **pure** (fonction `(état, événement) → (état, actions)`), testée de façon exhaustive : toutes les paires état × événement, plus des injections de pannes. Les effets de bord sont isolés dans un exécuteur.
- Fermer la fenêtre pendant `BOOTING` déclenche `ABORTING`, puis la destruction. Il n'y a pas de « fermer sans détruire ».

---

## 6. Arrêt forcé et récupération

### 6.1 Escalade (budget total d'environ 10 s, configurable)

1. **Gracieux** (≤ 5 s) : `SHUTDOWN` envoyé à l'agent invité, qui tue le navigateur et lance un `poweroff`.
2. **VMM** (≤ 3 s) : commande `STOP`. Le VMM annule les vCPU (`WHvCancelRunVirtualProcessor` ou signal au thread KVM), puis supprime la partition (`WHvDeletePartition`) ou ferme les fds KVM.
3. **Kill du processus** : `TerminateProcess(vmm)` ou `pidfd_send_signal(SIGKILL)`.
4. **Kill du groupe** : `TerminateJobObject(job)` ; sous Linux, écriture de `1` dans `cgroup.kill`, qui tue avec SIGKILL tous les processus du cgroup et de ses descendants en gérant les forks concurrents ([patch cgroup.kill](https://lore.kernel.org/all/20210508121542.1269256-2-brauner@kernel.org/)).
5. **Vérification** : attendre les handles de processus ou les pidfd (`poll`) et confirmer que le Job ou le cgroup est vide (`cgroup.events: populated 0`).

### 6.2 Si Kaput lui-même plante

- **Windows** : un Job Object avec `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, dont le handle est **non héritable** et détenu seulement par `kaput`. La fermeture du dernier handle tue tous les processus du Job ([explication + exemple](https://www.meziantou.net/killing-all-child-processes-when-the-parent-exits-job-object.htm) ; [doc Job Objects](https://learn.microsoft.com/nl-nl/windows/win32/procthread/job-objects)). Un crash de `kaput` ferme ses handles, donc le VMM meurt. Ajouter `DIE_ON_UNHANDLED_EXCEPTION` et des limites mémoire (`JobMemoryLimit`) ([doc](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information)).
- **Linux, deux mécanismes complémentaires :**
  - (a) `PR_SET_PDEATHSIG(SIGKILL)` dans chaque enfant. **Attention :** le signal part à la mort du **thread** créateur, pas du processus ([man7](https://www.man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html)). Il faut donc lancer les enfants depuis un thread dédié qui vit autant que la session.
  - (b) Un cgroup de session délégué via systemd user (`StartTransientUnit`, scope `kaput-session-<id>.scope`), ce qui permet un `cgroup.kill` lors de la récupération.
  - Repli si cgroup v2 n'est pas délégué : `PR_SET_CHILD_SUBREAPER` et un PID namespace (la mort du PID 1 du namespace tue tout le reste).
- **Ressources noyau** : la RAM invitée est allouée dans le processus VMM (WHP : `VirtualAlloc` ; KVM : `mmap`). Elle est donc libérée à la mort du processus. Le nettoyage de la partition WHP ou de la VM KVM à la fermeture des handles relève de **ma déduction**, et reste à vérifier par des tests de crash.

### 6.3 Journal de session et détection d'orphelins

- Le fichier `session.lock` est créé en `PREPARING` dans le dossier d'état de Kaput (§7.3), avec une ACL limitée à l'utilisateur. Il contient : `session_id` (aléatoire), `pid` et **heure de création** de chaque enfant (protection contre la réutilisation de PID), nom du scope cgroup, chemin du dossier de session et version de Kaput. **Aucune URL ni aucun contenu.**
- Ce fichier est détenu sous verrou exclusif (`LockFileEx` / `flock`) pendant toute la session. Au lancement, si le fichier existe et que le verrou est libre, la session est orpheline :
  1. retrouver chaque processus enfant par PID + heure de création et le tuer ;
  2. `cgroup.kill` sur le scope ;
  3. effacer le dossier de session ;
  4. afficher « Une session précédente n'avait pas été fermée correctement ; elle a été détruite. »
- Si le verrou est tenu, une autre instance de Kaput tourne. **Une seule session à la fois en v1** : l'interface affiche « Kaput est déjà ouvert ».

### 6.4 Résidus : ce que l'hôte doit empêcher

| Résidu | Mesure côté application |
|---|---|
| Disque de session | **Préférer le 100 % RAM** (rootfs en lecture seule, overlay tmpfs dans l'invité). Si un fichier hôte est inévitable (swap invité, overlay), il doit être **chiffré avec une clé de session générée en mémoire et jamais écrite**. La destruction de la clé équivaut à un effacement cryptographique. L'effacement physique sur SSD n'est pas garanti par un simple `delete`. |
| Core dumps du VMM (contiennent la RAM invitée !) | Linux : `prctl(PR_SET_DUMPABLE, 0)` et `madvise(MADV_DONTDUMP)` sur la RAM invitée. Windows : `WerRegisterExcludedMemoryBlock` sur la RAM invitée (Windows 10 1703+ ; nombre de blocs limité par `WER_MAX_REGISTERED_ENTRIES`) ([doc](https://learn.microsoft.com/en-us/windows/desktop/api/Werapi/nf-werapi-werregisterexcludedmemoryblock)). Envisager de désactiver WER pour `kaput-vmm`. |
| Pagefile / swap hôte | La RAM invitée peut être paginée. `VirtualLock`/`mlock` sont limités (working set, `RLIMIT_MEMLOCK`). **Risque résiduel à documenter** (§10) ; à traiter avec l'agent Windows/Linux. |
| Titre de fenêtre, historique du shell | Titre fixe « Kaput — Session isolée », **jamais le titre de la page**, sinon il fuit vers la barre des tâches, Alt+Tab ou l'historique d'activité du bureau. |
| Presse-papiers, glisser-déposer | Désactivés (brief §8). La fenêtre n'enregistre pas de cible de dépôt (pas d'`IDropTarget` ni de DnD Wayland). |
| Miniatures et aperçus de l'OS | Windows : `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` évite que le contenu soit capturé dans les miniatures et outils de capture. **Contrepartie :** l'utilisateur ne peut plus faire de capture d'écran ; décision utilisateur (§12). |
| Logs | Voir §7. |

---

## 7. Observabilité sans exfiltration

### 7.1 Modèle d'événements

- Les logs sont des **événements typés, pas du texte libre** : `{ts, level, component, event: EnumCode, fields: {typed}}`, sérialisés en JSON Lines par un sérialiseur maison minimal.
- Champs autorisés : codes d'état, durées, tailles, compteurs, versions, hash d'image, codes d'erreur Win32/errno, `session_id` aléatoire.
- **Interdits par construction**, car le type `LogField` ne propose pas de variante `String` libre : URL, domaines, IP de destination, titres, contenu de pages, noms de fichiers téléchargés, frappes, coordonnées souris, chemins utilisateur (remplacés par `%LOCALAPPDATA%`/`$HOME`).
- **Aucune donnée venant de l'invité n'atteint le log sans conversion** en énumération ou en entier borné. Cela empêche l'injection de logs et l'usage du log comme canal de stockage par un malware.
- **Limitation de débit** par type d'événement (par exemple 10/s, puis un compteur « N événements supprimés »), pour éviter qu'un invité ne remplisse le disque hôte.
- Côté `kaput-netd`, par défaut : uniquement des compteurs agrégés (octets, connexions, refus par **catégorie** : RFC 1918, loopback, link-local, multicast, IPv6 ULA, DNS hors politique). Aucune destination.

### 7.2 Niveaux et mode diagnostic

| Niveau | Défaut | Contenu |
|---|---|---|
| `error`, `warn`, `info` | Activé | Transitions d'état, durées des étapes, erreurs, résultats des vérifications d'intégrité ou de mise à jour |
| `debug` | Désactivé | Détails IPC (types et tailles), timings vCPU, statistiques d'affichage |
| Mode diagnostic | Opt-in explicite, **limité à la session en cours** puis désactivé automatiquement | `debug` + codes d'erreur de l'agent invité + statistiques réseau par catégorie. **Toujours sans URL ni domaine.** Un hash salé des domaines reste attaquable par dictionnaire : il est donc exclu. |

- L'export d'un « paquet de diagnostic » se fait par une action explicite de l'utilisateur. Il produit une archive locale dont le contenu est affiché avant enregistrement. **Aucun envoi automatique, aucune télémétrie.**

### 7.3 Stockage et rotation

- **Windows** : `%LOCALAPPDATA%\Kaput\logs\` (ACL : utilisateur + SYSTEM). État et journal de session dans `%LOCALAPPDATA%\Kaput\state\`.
- **Linux** : `$XDG_STATE_HOME/kaput/logs/` (par défaut `~/.local/state`), répertoire prévu pour les logs et l'historique ([XDG basedir](https://specifications.freedesktop.org/basedir/latest/)), en mode 0700. Fichiers de session temporaires sous `$XDG_RUNTIME_DIR/kaput/` : ce répertoire est en 0700, local, et ne survit ni au reboot ni à la déconnexion (même source).
- **Rotation** : 5 fichiers × 1 Mio maximum, rétention de 14 jours, purge au démarrage. Écriture atomique ou append avec `fsync` sur `error`.
- **Crash de Kaput** : un handler de panique Rust écrit un événement `panic{component, code}` sans message libre (le message peut contenir des données). Pas de minidump par défaut. En mode diagnostic, minidump du seul processus `kaput` (jamais de `kaput-vmm`).

### 7.4 État exposé à l'utilisateur

Le panneau « Détails » (touche hôte → menu) affiche : état de la VM (étape, durée, RAM allouée), état du réseau (actif, filtrage OK, compteurs de refus), mises à jour (version de l'image, date de vérification, statut de signature) et isolation (backend WHP ou KVM, confinement du VMM actif oui/non).

---

## 8. UX et anti-spoofing

### 8.1 Écrans

1. **Accueil** : logo, « **Kaput** », un seul bouton primaire « **Naviguer en sécurité** », une ligne d'état discrète (« Image vérifiée le 12/11/2026 · v2026.11.2 »). Rien d'autre (pas de barre d'adresse côté hôte).
2. **Préparation** : liste des 7 étapes du brief avec coches progressives (« Vérification de l'environnement… », « Vérification des mises à jour… », « Vérification de l'intégrité… », « Création de l'environnement isolé… », « Démarrage… », « Lancement du navigateur… »). Bouton « Annuler », qui mène à `ABORTING` puis à la destruction.
3. **Session** : fenêtre de navigation entourée du **cadre Kaput** (§8.2).
4. **Fermeture** : surimpression hôte « Destruction de la session… » avec 6 étapes. Si l'escalade est atteinte : « L'environnement ne répondait pas — arrêt forcé effectué. »
5. **Confirmation** : « **Session détruite.** Aucune donnée de navigation n'a été conservée. » avec des détails vérifiables (processus arrêtés ✓, mémoire libérée ✓, fichiers temporaires supprimés ✓, durée). Boutons « Nouvelle session » et « Quitter ». Formulation honnête : ne pas promettre « 100 % effacé » (brief §33). Préciser au besoin « les téléchargements n'existent que dans la session ».

### 8.2 Cadre hôte anti-spoofing

**Menace :** une page en plein écran (Fullscreen API) dessine une fausse UI Kaput (« Session sécurisée ✓ », faux dialogue « Mise à jour requise, entrez votre mot de passe Windows »), voire un faux bureau Windows.

**Mesures :**

1. **Zone invitée strictement intérieure.**
   - Le cadre (bordure de 4 à 6 px plus une barre supérieure de 28 px) est dessiné **par l'hôte, hors du framebuffer invité**. L'invité ne peut écrire que dans son rectangle, et le plein écran du navigateur ne remplit que ce rectangle.
   - C'est l'approche de Qubes : les bordures colorées sont dessinées par le gestionnaire de fenêtres de confiance et ne peuvent pas être imitées par les applications ; aucune VM ne peut prendre tout l'écran ([doc Qubes](https://doc.qubes-os.org/en/r4.3/introduction/screenshots.html)).
2. **Pas de vrai plein écran par défaut.** « Plein écran Kaput » est une fenêtre maximisée sans décoration OS, mais **le cadre Kaput reste visible**. Le vrai plein écran est une option (décision §12) qui impose :
   - un bandeau hôte « Kaput — Contenu isolé — [touche hôte] pour quitter » de 3 s à l'entrée ;
   - un liseré permanent de 2 px.
3. **Motif de bordure distinctif** : une frise « tapis » (losanges indigo et or) que le web n'a aucune raison de reproduire, et une couleur d'état :
   - indigo : session active ;
   - ambre : invité ne répond pas ou mode diagnostic ;
   - rouge : arrêt forcé ou erreur.
   - Ne pas utiliser le vert pendant la navigation (pour ne pas suggérer que « tout est sûr »).
4. **Sceau d'installation (optionnel)** : variation de motif et de couleur de la frise générée aléatoirement à la première installation et affichée uniquement dans le cadre hôte. Le contenu invité ne voit jamais le cadre et ne peut donc pas le reproduire.
   - **Réserve :** l'efficacité des « images de sécurité » face au phishing est contestée dans la littérature d'utilisabilité (référence à retrouver ; non vérifiée ici). C'est un complément, pas un pilier.
5. **Règle simple, communiquée à l'utilisateur :** *« Kaput ne vous demandera jamais de mot de passe, ni de code, ni de télécharger quoi que ce soit. »* Les seuls dialogues hôte (fermeture, erreur, mise à jour) sont des fenêtres natives séparées, **hors de la zone invitée**, sans champ de saisie.
6. **Touche hôte** : elle met en évidence le cadre (pulsation) et ouvre le menu hôte. Le contenu invité ne peut pas la simuler, car elle n'est jamais transmise et l'invité ne reçoit pas d'événements synthétiques de l'hôte.
7. **Aucune notification OS, aucun son système, aucun changement d'icône ou de titre** ne peut être déclenché par l'invité.

### 8.3 Messages d'erreur

Format : **phrase claire, cause probable, action, code**. Exemple : « Impossible de démarrer l'environnement isolé. La virtualisation matérielle est désactivée. → Activez “Windows Hypervisor Platform” (instructions). Code KPT-E201 ». Familles de codes :

- E1xx : environnement ;
- E2xx : virtualisation ;
- E3xx : mise à jour ou intégrité ;
- E4xx : réseau ;
- E5xx : destruction (affichage rouge et bloquant si le nettoyage n'est pas confirmé).

Pour une **erreur d'intégrité** (E3xx) : ne jamais proposer « Continuer quand même ».

---

## 9. Concepts d'icône (K + tapis persan + protection + enclave)

Palette commune :

- garance `#8E1F2F` ;
- indigo `#1E2A5A` ;
- safran/or `#D6A23E` ;
- ivoire `#F2E8D0`.

En petite taille, deux couleurs suffisent (indigo + or), avec un contraste supérieur ou égal à 4,5:1.

Livrables :

- `.ico` multi-résolution (16, 20, 24, 32, 40, 48, 64, 256) ;
- PNG hicolor 16 à 512 et SVG ;
- variante **symbolique monochrome** pour la zone de notification, les notifications et les thèmes GNOME/KDE symboliques.

Chaque concept a **trois masters** : pixel-art 16–32, simplifié 48–64, détaillé 128–512.

### Concept A — « Médaillon-enclave »

- **Construction** : un carré arrondi (le tapis) avec une bordure épaisse (la frise, c'est-à-dire la protection) entoure un champ indigo. Au centre, le **médaillon** (*toranj*) losangé en or. Le K est formé par le médaillon lui-même : une hampe verticale à gauche, et deux bras diagonaux qui partent du centre du losange vers les coins droits, dessinés par l'espace négatif ivoire.
- **Sens** : le médaillon central gardé par la bordure, c'est l'enclave protégée.
- **16 px** : bordure or de 2 px, fond indigo, K ivoire en 3 traits de 2 px alignés sur la grille, sans ornement.
- **32 px** : la bordure gagne un pointillé de losanges de 1 px.
- **≥ 128 px** : frise de « boteh » stylisés, écoinçons (*lachak*) aux quatre coins, franges en bas.

### Concept B — « Kilim à degrés »

- **Construction** : un K tracé **en diagonales à degrés**, style kilim. Ces motifs suivent naturellement une grille de pixels, ce qui les rend nets à 16 px sans anticrénelage. Le K est enfermé dans un **losange à crochets** (motif *gul*), lui-même posé sur un rectangle (le tapis).
- **Sens** : le losange à crochets est un motif protecteur traditionnel ; le losange fermé est l'enclave.
- **16 px** : K en escalier de 1 px dans un losange de contour 1 px, deux couleurs.
- **≥ 64 px** : crochets sur le losange, et bordure à motif « chien courant » simplifié.
- **Point fort** : identité « pixel-native », très lisible dans la barre des tâches.
- **Point faible** : rendu plus « rustique » que luxueux.

### Concept C — « Mihrab-bouclier »

- **Construction** : la niche en arc d'un tapis de prière (*mihrab*), à la silhouette proche d'un bouclier. La hampe du K est la colonne gauche de la niche ; les deux bras sont l'arc brisé et sa réflexion vers le bas, ce qui ferme la niche.
- **Sens** : une porte fermée, un lieu protégé. L'enclave est l'intérieur de la niche, en indigo profond.
- **16 px** : silhouette bouclier/arc pleine en indigo et K or ; l'arc est réduit à 2 marches de pixels.
- **≥ 128 px** : remplissage par un champ fleuri (*hérati*) et bordure garance.
- **Point fort** : la « protection » est la plus lisible des trois concepts.
- **Risque** : le motif est religieux. Le *mihrab* est un élément du tapis de prière, ce qui pourrait être mal perçu. **Validation culturelle requise.**

**Recommandation** : partir de A comme icône principale, en lui empruntant la technique de construction à degrés de B pour les tailles 16–32. Écarter C, ou ne le retenir qu'après validation culturelle. La frise du cadre anti-spoofing (§8.2) reprend la bordure de A, ce qui donne une identité cohérente entre l'icône et la fenêtre.

**Tests** :

- rendu réel dans la barre des tâches Windows 10/11 en thème clair et sombre, GNOME, KDE, Alt+Tab, notifications ;
- test « flou » à 16 px (identifiable parmi 10 icônes voisines) ;
- simulation daltonisme ;
- pas de confusion possible avec les icônes de Windows Sandbox, VirtualBox, Tor Browser.

---

## 10. Risques

| ID | Risque | Gravité | Mitigation |
|---|---|---|---|
| R1 | Compromission du VMM par l'invité (bug d'émulation virtio) | Critique | VMM confiné (AppContainer/LPAC, seccomp/Landlock/namespaces) ; Kaput traite le VMM comme hostile ; fuzzing des périphériques ; minimiser le nombre de périphériques virtio |
| R2 | Supply chain crates.io (précédent `arrayref`, août 2026) | Élevée | Vendoring, `cargo-vet`, liste blanche de `build.rs`/proc-macros, builds hermétiques |
| R3 | La RAM invitée part dans le pagefile ou le swap de l'hôte (résidu forensique) | Élevée | `VirtualLock`/`mlock` dans la mesure du possible ; documenter ; recommander chiffrement disque et swap ; étudier l'alternative à `mlock` sous Linux (inconnue I3) |
| R4 | Spoofing de l'UI hôte par du contenu en plein écran | Moyenne | §8.2 (cadre hors zone invitée, pas de vrai plein écran par défaut, aucune saisie hôte) |
| R5 | winit 0.31 encore en bêta : rupture d'API, régressions Wayland | Moyenne | Épingler 0.30.x, migrer quand la 0.31 stable sort ; SDL3 en repli |
| R6 | Performances du blit CPU en 4K / multi-écrans | Moyenne | Rectangles de dommage, plafond de i/s, option wgpu mesurée |
| R7 | Session non détruite après crash (bug de récupération) | Élevée | Mort garantie par le noyau (Job/cgroup), journal + verrou, tests de crash automatisés (kill -9 de `kaput` à chaque état) |
| R8 | Les logs deviennent un canal de persistance ou d'exfiltration | Moyenne | Champs typés, pas de chaîne venant de l'invité, limitation de débit, rotation |
| R9 | Incompatibilité WHP / AppContainer : le VMM devrait tourner sans AppContainer | Élevée | Prototype précoce (I1) ; repli : jeton restreint, intégrité basse, Job avec restrictions UI, mitigations de processus |
| R10 | Limites d'accessibilité et d'IME : utilisateurs exclus | Faible à moyenne | IME dans l'invité ; documentation |

## 11. Inconnues (à lever avant l'implémentation)

- **I1** — Peut-on appeler WHP (`WHvCreatePartition`…) depuis un processus en **AppContainer / LPAC** ? Quelles capacités faut-il ? → Prototype Windows (agent Windows).
- **I2** — Le nettoyage de la partition WHP et de la VM KVM est-il garanti à la mort brutale du VMM (aucune fuite de ressources hyperviseur) ? → Tests de crash.
- **I3** — Comment empêcher la RAM invitée d'atteindre le swap ou le pagefile sans privilège (limites de `VirtualLock`, `RLIMIT_MEMLOCK`, `memfd_secret` incompatible avec le mapping KVM ?) → Agents Linux/Windows.
- **I4** — Le choix du VMM (OpenVMM, crosvm, Cloud Hypervisor, maison) détermine l'interface d'affichage (virtio-gpu 2D ? ramfb ?) et la frontière VMM/`kaput`. → Agent virtualisation.
- **I5** — Délégation cgroup v2 via systemd user : disponible sur toutes les distributions ciblées ? Quel repli sans systemd ?
- **I6** — `SetWindowDisplayAffinity(WDA_EXCLUDEFROMCAPTURE)` : compatibilité avec l'accessibilité et les captures légitimes.
- **I7** — Le budget de 10 s pour l'arrêt forcé est-il réaliste sur des machines lentes ? À mesurer.
- **I8** — Fonctionnement de winit + softbuffer sous **XWayland** et sur les compositeurs peu courants (Weston, Cage…) ; gestion de la souris relative (pointer lock) sans capture abusive.

## 12. Décisions nécessitant l'avis de l'utilisateur

1. **Plein écran réel** : l'autoriser, en option, avec bandeau et liseré, ou ne jamais l'autoriser (recommandation : option désactivée par défaut) ?
2. **Fonctionnement hors ligne** : si la vérification de mise à jour échoue, faut-il autoriser l'image locale vérifiée pendant N jours (par exemple 7) puis bloquer, ou bloquer tout de suite ? C'est un compromis entre sécurité et disponibilité.
3. **Presse-papiers** : totalement désactivé (recommandé en v1), ou collage hôte → invité unidirectionnel de texte brut sur action explicite (une touche dédiée, jamais l'inverse) ?
4. **Capture d'écran de la session** : faut-il bloquer les captures et miniatures OS (`WDA_EXCLUDEFROMCAPTURE`, ce qui gêne aussi l'utilisateur) ?
5. **Touche hôte par défaut** : Ctrl droit, ou une combinaison (par exemple Ctrl+Alt+K) ?
6. **Sceau d'installation personnalisé** (§8.2-4) : à inclure ou non ?
7. **Une seule session à la fois en v1** : acceptable ?
8. **Icône** : validation des concepts A, B ou C, et validation culturelle du concept C.
9. **Activation de WHP sous Windows** : elle nécessite une élévation UAC unique à l'installation (fonctionnalité optionnelle de Windows), peut-être un redémarrage. Ce privilège est à confirmer avec l'agent Windows et à annoncer.
10. **Licence** : si Slint est retenu pour les écrans, choisir entre GPLv3 et royalty-free avec mention obligatoire. Cela dépend de la licence choisie pour Kaput.

## 13. Sources

- Rust : [Releases](https://blog.rust-lang.org/releases) · [Rust 1.93.0](https://blog.rust-lang.org/2026/01/22/Rust-1.93.0/) · [ARM64 Windows tier 1 (1.91)](https://alternativeto.net/news/2025/10/rust-1-91-adds-tier-1-support-for-arm64-windows-platform-raw-pointer-warnings-and-more) · [Attaque supply chain arrayref (20/08/2026)](https://blog.rust-lang.org/2026/08/20/supply-chain-attack-on-arrayref/) · [Analyse Socket](https://www.socket.dev/blog/popular-rust-crates-compromised)
- Go : [Go 1.27 release notes](https://go.dev/doc/go1.27) · [Billet Go 1.27](https://go.googlesource.com/website/+/refs/heads/master/_content/blog/go1.27.md)
- .NET : [Get Ready for .NET Conf 2026](https://devblogs.microsoft.com/dotnet/?p=61166) · [.NET 11 RC1 go-live](https://visualstudiomagazine.com/articles/2026/09/14/net-11-rc1-gets-go-live-support-ahead-of-november-launch.aspx)
- VMM / WHP : [OpenVMM GitHub](https://github.com/microsoft/OpenVMM) · [The OpenVMM Project (Windows OS Platform Blog, relayé)](https://www.elevenforum.com/t/the-openvmm-project.48844/) · [The New Stack — OpenVMM](https://thenewstack.io/microsoft-open-sources-openvmm-rust-powered-vm-monitor/) · [crosvm — hyperviseurs](https://crosvm.dev/book/hypervisors.html) · [Windows Hypervisor Platform API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform) · [QEMU WHPX](https://www.qemu.org/docs/master/system/whpx.html)
- vsock : [virtio-vsock (lib.rs)](https://lib.rs/crates/virtio-vsock) · [tokio-vsock](https://github.com/fsyncd/tokio-vsock)
- GUI : [winit releases](https://www.github.com/rust-windowing/winit/releases) · [softbuffer 0.4.8](https://docs.rs/crate/softbuffer/latest) · [SDL 3.4.4](https://discourse.libsdl.org/t/sdl-updated-to-version-3-4-4-for-release/67068) · [Qt Releases](https://doc.qt.io/qt-6/qt-releases.html) · [Licence Slint 1.17](https://components.espressif.com/components/slint/slint/versions/1.17.0/license?language=en) · [egui 0.36](https://newreleases.io/project/github/emilk/egui/release/0.36.0) · [Tauri Isolation Pattern](https://v2.tauri.app/concept/inter-process-communication/isolation) · [Wayland keyboard-shortcuts-inhibit](https://wayland.app/protocols/keyboard-shortcuts-inhibit-unstable-v1)
- Processus / confinement : [Job Objects](https://learn.microsoft.com/nl-nl/windows/win32/procthread/job-objects) · [JOBOBJECT_EXTENDED_LIMIT_INFORMATION](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information) · [KILL_ON_JOB_CLOSE (exemple)](https://www.meziantou.net/killing-all-child-processes-when-the-parent-exits-job-object.htm) · [UpdateProcThreadAttribute](https://learn.microsoft.com/en-us/windows/desktop/api/processthreadsapi/nf-processthreadsapi-updateprocthreadattribute) · [CreateProcessInSandbox (expérimental)](https://learn.microsoft.com/en-us/windows/win32/secauthz/createprocessinsandbox) · [PR_SET_PDEATHSIG](https://www.man7.org/linux/man-pages/man2/PR_SET_PDEATHSIG.2const.html) · [cgroup.kill (patch)](https://lore.kernel.org/all/20210508121542.1269256-2-brauner@kernel.org/) · [Landlock](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)
- Résidus / logs : [WerRegisterExcludedMemoryBlock](https://learn.microsoft.com/en-us/windows/desktop/api/Werapi/nf-werapi-werregisterexcludedmemoryblock) · [XDG Base Directory](https://specifications.freedesktop.org/basedir/latest/)
- UX / anti-spoofing : [Qubes — bordures de confiance](https://doc.qubes-os.org/en/r4.3/introduction/screenshots.html) · [Dépréciation de Defender Application Guard](https://learn.microsoft.com/deployedge/microsoft-edge-security-windows-defender-application-guard)

> Note de méthode : le budget de recherche web de la session a été épuisé en fin d'étude. Certains points sont donc marqués « non vérifié » ou « déduction » : statut STS de .NET 11 ; nettoyage des partitions WHP au kill ; littérature sur les images de sécurité ; compatibilité `WDA_EXCLUDEFROMCAPTURE`. Ils devront être confirmés avant tout ADR.
