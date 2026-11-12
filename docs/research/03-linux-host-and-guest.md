# 03 — Hôte Linux et OS invité : confinement, prérequis, image minimale

> Auteur : Linux Security Engineer (équipe Kaput) — Phase 0 Discovery, recherche uniquement.
> Date de l'état de l'art : **12 novembre 2026**. Toutes les versions citées ont été vérifiées en ligne
> à cette date sauf mention **[non revérifié]** (budget de recherche web épuisé en cours d'étude ;
> ces points sont repris dans « Inconnues »).
> Ce document ne choisit pas le VMM (rôle du Virtualization Engineer) ni le navigateur (rôle du
> Browser Security Engineer) ; il en tire les conséquences côté hôte Linux et côté invité.

---

## 0. Résumé exécutif

1. **Hôte** : le processus VMM doit tourner **sans root**, dans un « jail » construit par Kaput (pas le jailer Firecracker, qui exige root et a eu une CVE d'écrasement de fichiers hôte en 2026) : user+mount+pid+net+ipc namespaces, `pivot_root` vers un répertoire vide, capabilities à zéro, `no_new_privs`, seccomp-bpf en liste blanche, Landlock (ABI ≥ 6 pour bloquer sockets abstraits et signaux), cgroup v2 délégué par systemd (mémoire, pids, CPU, **swap = 0**), `PR_SET_DUMPABLE=0`.
2. Ce socle **indépendant de la distribution** porte les garanties ; AppArmor/SELinux sont des couches additionnelles. Sur Ubuntu ≥ 24.04, un profil AppArmor installé (root, une fois) est requis pour autoriser les user namespaces au seul binaire de lancement.
3. La fenêtre hôte doit être un **processus séparé** du VMM, lui-même confiné ; **Wayland recommandé**, X11 toléré avec avertissement (X11 = pas d'isolation entre clients).
4. **Invité** : recommandation **Debian 13 « trixie » (glibc) assemblée par mkosi** en image **immuable** : noyau maison LTS durci sans modules, rootfs EROFS en lecture seule + **dm-verity sans initramfs**, état 100 % tmpfs, init minimal statique (pas de systemd), aucun shell/sshd/gestionnaire de paquets, compositeur kiosque (cage) en rendu logiciel, trames exportées par vsock.
5. Point critique n°1 : **le délai de correctif du navigateur**. Échantillon mesuré : Chromium 156.0.8078.79 publié en amont le 29/10/2026, disponible dans Debian trixie, Alpine 3.24 et Fedora 44 entre le 2 et le 4/11 ; au 12/11, Chrome 157 est stable en amont mais pas encore dans ces distributions stables. Avec le passage de Chrome à un cycle de 2 semaines, il faut une chaîne de rebuild automatisée et une mesure continue du délai.
6. Alpine/musl est rejeté comme base : Chromium et Firefox ne sont pas supportés en amont sur musl, et des correctifs de sandbox seccomp restent portés en aval.

---

## Partie A — Hôte Linux

### A.1 Prérequis KVM

| Prérequis | Vérification au lancement (fail-closed) | Remarque |
|---|---|---|
| CPU x86_64 avec VT-x/AMD-V + EPT/NPT (aarch64 : plus tard) | `/proc/cpuinfo` flags `vmx`/`svm`, `ioctl(KVM_GET_API_VERSION)==12`, `KVM_CHECK_EXTENSION` pour les capacités requises par le VMM | Virtualisation activée dans le firmware ; message d'aide explicite sinon |
| Modules `kvm` + `kvm_intel`/`kvm_amd` chargés | `open("/dev/kvm", O_RDWR)` | Hôte lui-même VM → virtualisation imbriquée : à signaler (frontière plus faible, perfs) |
| Accès à `/dev/kvm` sans root | droit `rw` effectif | voir A.2 |
| cgroup v2 unifié | `stat -f /sys/fs/cgroup` = `cgroup2fs` | défaut sur toutes les distributions visées (Ubuntu ≥ 21.10, Debian ≥ 11, Fedora ≥ 31, RHEL ≥ 9) [non revérifié pour les versions exactes] |
| Landlock actif | `landlock_create_ruleset(NULL,0,LANDLOCK_CREATE_RULESET_VERSION)` → ABI | ABI 6 minimale visée (scoping signaux / sockets abstraits) ; dégradation à définir (D-2) |
| User namespaces non privilégiés | test `unshare(CLONE_NEWUSER)` dans un processus jetable | Ubuntu ≥ 24.04 : restreint par AppArmor (A.4) |
| État des atténuations CPU | `/sys/devices/system/cpu/vulnerabilities/*`, SMT | afficher, ne pas bloquer (D-6) |

Recommandations de production issues de Firecracker, valables quel que soit le VMM : utiliser les filtres seccomp par défaut les plus restrictifs, lancer sous le jailer « ou sous des contraintes équivalentes ou plus strictes », **désactiver SMT** quand une séparation forte est requise, **désactiver KSM**, **désactiver le swap** (rémanence mémoire de l'invité), suivre la doc noyau sur les vulnérabilités matérielles, mémoire ECC/TRR contre rowhammer ([prod-host-setup.md](https://github.com/roypat/firecracker/blob/main/docs/prod-host-setup.md)). Kaput ne peut pas imposer SMT/KSM/swap sur un poste utilisateur : il doit **les mesurer et l'afficher** (diagnostic), et contourner le swap par cgroup (A.3).

### A.2 Exécution sans root : `/dev/kvm`, groupe `kvm`, udev

- Le noyau crée `/dev/kvm` en `0600` ; systemd-udev le passe au groupe `kvm`. Le commit systemd d'origine indique que les distributions utilisent « soit 0660 (ex. Debian) soit 0666 (ex. Fedora) », 0660 étant « l'option (légèrement) plus sûre » et la valeur par défaut amont ([commit systemd](https://git.alternativebit.fr/picnoir/Systemd/commits/commit/b2bb40ce9a4797728f384fa75e47829ab81303a1/rules/50-udev-default.rules.in)).
- Conséquences :
  - **Debian/Ubuntu (0660, groupe kvm)** : l'installeur ajoute l'utilisateur au groupe `kvm` (root, une fois ; reconnexion nécessaire). Alternative sans changement de groupe : ACL `uaccess` pour la session locale active — **non recommandé** de le généraliser à tous les utilisateurs.
  - **Fedora (0666)** : aucun réglage ; noter que tout processus local, y compris un processus compromis, peut déjà ouvrir KVM — ce n'est pas une régression due à Kaput.
- **Pas de règle udev élargissant les droits** (pas de `MODE="0666"` ajouté par Kaput).
- `/dev/net/tun` / TAP : créer une interface TAP exige `CAP_NET_ADMIN` dans le netns concerné. Deux voies sans root permanent : (a) TAP créé **dans le netns privé** du jail grâce aux capabilities du user namespace, relié à Internet par une pile utilisateur (passt/pasta, slirp4netns) ; (b) TAP persistant pré-créé par l'installeur. Choix détaillé = Network Security Engineer ; côté Linux, (a) est préféré (aucun privilège résiduel, rien dans le netns hôte).

### A.3 Confinement du processus VMM

#### A.3.1 Ce que fait le jailer Firecracker (référence)

D'après [docs/jailer.md (v1.16.1)](https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.16.1/docs/jailer.md) : le jailer **s'exécute en root**, valide chemins et ID, ferme les FD hérités, vide l'environnement, crée `<chroot_base>/<exec>/<id>/root`, **copie le binaire** dans le jail (pas de mémoire partagée entre instances), applique des `setrlimit` (`fsize`, `no-file`, défaut 2048), crée un cgroup (v1 par défaut, v2 supporté), `unshare` d'un mount namespace, mounts privés, bind du répertoire sur lui-même, `pivot_root` + `umount2` de l'ancienne racine + `chroot`, `mknod` de `/dev/kvm` et `/dev/net/tun` puis `chown` vers l'uid cible, `setns` dans un netns fourni, `setsid`, éventuel `CLONE_NEWPID`, **abandon uid/gid**, puis `exec`. Le seccomp est appliqué ensuite par Firecracker lui-même (filtres par thread, les plus restrictifs par défaut — [prod-host-setup](https://github.com/roypat/firecracker/blob/main/docs/prod-host-setup.md)).

Retours d'expérience 2026 à retenir :
- **CVE-2026-1386** : le jailer pouvait, sous certaines conditions, permettre l'**écrasement de fichiers arbitraires de l'hôte via un lien symbolique** ; corrigé en 1.14.1 / 1.13.2 (publié le 23/01/2026) ([bulletin AWS 2026-003](https://aws.amazon.com/security/security-bulletins/2026-003-AWS)). La 1.16.1 a ensuite **annulé** une partie du durcissement `O_NOFOLLOW` (cgroups/netns) ([notes v1.16.1](https://newreleases.io/project/github/firecracker-microvm/firecracker/release/v1.16.1)). Leçon : **tout composant root qui manipule des chemins contrôlables par l'utilisateur est une surface d'escalade** ; Kaput ne doit pas embarquer d'assistant root par session.
- **CVE-2026-5747** : écriture hors limites dans le transport virtio-PCI de Firecracker, déclenchable par un root invité (crash du VMM, exécution de code sur l'hôte possible sous conditions) ; corrigé en 1.14.4 / 1.15.1 ; le transport MMIO par défaut n'est pas affecté ([bulletin AWS 2026-015](https://aws.amazon.com/security/security-bulletins/2026-015-aws)). Leçon : le VMM est atteignable par un invité compromis ; **le confinement hôte du VMM n'est pas optionnel**, et chaque option de VMM (PCI, etc.) élargit la surface.
- Versions publiées constatées : 1.14.x, 1.15.x, 1.16.x, 1.17.0 ([releasealert](https://releasealert.dev/github/firecracker-microvm/firecracker), [v1.16.1](https://newreleases.io/project/github/firecracker-microvm/firecracker/release/v1.16.1)).

#### A.3.2 Modèle proposé : « kaput-jail » sans root

Un lanceur dédié (petit, mémoire-sûre, audité) reproduit le modèle du jailer **avec un user namespace au lieu de root** :

```text
kaput (UI, session utilisateur)
  └─ kaput-jail  (binaire root-owned dans /usr/lib/kaput, pas setuid)
       1. close_range(3,~0), environnement vidé, umask 077
       2. systemd : StartTransientUnit (scope utilisateur) → cgroup v2 dédié
            MemoryMax, MemorySwapMax=0, TasksMax, CPUQuota, IOWeight
       3. unshare(USER|MNT|PID|NET|IPC|UTS|CGROUP)   (uid_map 1:1 « moi→0 »)
       4. mount --make-rprivate / ; tmpfs vide (nosuid,nodev,noexec sauf binaire)
          y placer : copie RO du binaire VMM, kernel+rootfs invité (bind RO),
          socket(s) vsock/API, /dev/kvm (bind du nœud hôte), /dev/net/tun si TAP
          pivot_root ; umount2(old, MNT_DETACH) ; /proc monté hidepid=invisible
       5. TAP créé dans le netns privé (CAP_NET_ADMIN du userns), lo seul sinon
       6. setrlimit : CORE=0, NOFILE, FSIZE, MEMLOCK selon besoin
       7. prctl : PR_SET_DUMPABLE=0, PR_SET_NO_NEW_PRIVS=1,
          securebits NOROOT|NO_SETUID_FIXUP (verrouillés)
       8. capabilities : bounding, ambient, inheritable, permitted, effective = ∅
       9. Landlock (ABI max disponible) : FS en liste blanche (fichiers du jail),
          NET TCP/UDP refusé, SCOPE_ABSTRACT_UNIX_SOCKET + SCOPE_SIGNAL
      10. seccomp-bpf liste blanche (action par défaut KILL_PROCESS), ioctl
          filtrés par numéro (KVM_*, TUN*), pas de socket() hors AF_UNIX/AF_VSOCK
      11. execve(VMM)  — le VMM ajoute ses propres filtres seccomp par thread
```

Justifications point par point :
- **user namespace** : donne les capabilities nécessaires *à l'intérieur* (mount, netns, pivot_root) sans privilège hôte. Effet de bord à assumer : les user namespaces non privilégiés exposent davantage de code noyau (historique de LPE). On réduit l'exposition en ne les ouvrant qu'au lanceur et en abandonnant toutes les capabilities avant `execve`.
- **PID namespace** : le VMM ne peut pas nommer de PID hôte (donc ni `kill` ni `ptrace` vers eux) ; un processus d'un userns enfant ne peut pas `ptrace` des processus du userns parent.
- **net namespace** : point souvent négligé : les **sockets Unix abstraits** (ex. `@/tmp/.X11-unix/X0` du serveur X) sont **par netns**. Sans netns ni Landlock ABI 6, un VMM compromis pourrait se connecter au serveur X/Xwayland de la session et lire le clavier/l'écran.
- **mount ns + pivot_root** : rend invisibles `$HOME`, `/run/user/$UID/bus` (D-Bus), le socket Wayland, les sockets agent SSH/GPG.
- **Landlock** ([doc noyau 7.4-rc2](https://www.kernel.org/doc/html/latest/userspace-api/landlock.html)) : ABI 4 = TCP bind/connect ; 5 = ioctl sur périphériques ; **6 = scoping sockets abstraits et signaux** ; 7 = journalisation ; 8 = TSYNC (application à tous les threads) ; 9 = connexion aux sockets Unix nommés ; 10 = UDP ; 11 = no_new_privs conditionnel ; 12 = restriction des capabilities et des namespaces. Landlock est **non privilégié et indépendant de la distribution** : c'est la deuxième couche quand les namespaces sont indisponibles. Correspondance ABI → version noyau (d'après mes connaissances, [non revérifié]) : ABI 4 ≈ 6.7, ABI 5 ≈ 6.10, ABI 6 ≈ 6.12, ABI 7 ≈ 6.15. Donc Debian 13 (6.12) ≈ ABI 6 ; noyau GA d'Ubuntu 24.04 (6.8) ≈ ABI 4.
- **seccomp-bpf** : défense contre l'exploitation du noyau hôte *depuis le VMM compromis* (deuxième étape de l'évasion). La surface `ioctl(KVM_*)` reste large et incompressible : c'est un risque résiduel majeur (§ R-1).
- **cgroup v2** : limites de ressources (DoS) et surtout **`MemorySwapMax=0`** : la mémoire de l'invité (pages web, mots de passe saisis) ne doit pas finir dans le swap hôte. La délégation passe par le gestionnaire systemd utilisateur (unité transitoire) ; le jeu exact de contrôleurs délégués par défaut à `user@.service` est à vérifier par distribution [non revérifié].
- **`PR_SET_DUMPABLE=0` + `RLIMIT_CORE=0`** : empêche qu'un crash du VMM écrive un core dump (systemd-coredump) contenant **toute la RAM de l'invité** ; empêche aussi les processus de même UID de lire `/proc/<pid>/mem`.
- **Séparation des processus** : `kaput-ui` (fenêtre) ≠ `kaput-jail/VMM` ≠ éventuel `kaput-net` (pile réseau utilisateur). Chacun a son propre bac à sable ; seul `kaput-ui` voit le socket Wayland/X11 ; seul le VMM voit `/dev/kvm`.
- **Arrêt forcé** : le jail est le PID 1 de son PID namespace → `kill` du PID 1 du namespace = destruction de tous les processus ; en plus, `cgroup.kill` (cgroup v2) sur le scope dédié. Le mécanisme est fiable sans coopération de l'invité.

Mode dégradé si les user namespaces sont indisponibles : `no_new_privs` + seccomp + Landlock + rlimits + cgroup restent applicables sans aucun privilège. Mais **sans netns ni Landlock ≥ 6, l'accès aux sockets abstraits de la session reste possible** : ce mode doit être refusé par défaut (décision D-2).

### A.4 AppArmor vs SELinux, et restriction des user namespaces sur Ubuntu

| | AppArmor | SELinux |
|---|---|---|
| Distributions | Ubuntu, Debian (activé par défaut), openSUSE Leap 15.x / SLES 15 | Fedora, RHEL/Alma/Rocky, CentOS Stream ; **openSUSE Tumbleweed (nouvelles installations) et Leap 16 seraient passés à SELinux en 2025** [non revérifié — à confirmer, contredit l'hypothèse « openSUSE = AppArmor »] |
| Modèle | chemins ; profils par binaire | labels ; types + MCS |
| Confinement d'un VMM « maison » | profil statique livré dans `/etc/apparmor.d/kaput-*` (chargé par `apparmor_parser`, root à l'installation) | **aucun par défaut** : un VMM lancé par l'utilisateur hors libvirt tourne en `unconfined_t` ; sVirt (`svirt_t` + catégories MCS par VM) n'est appliqué que par libvirt. Il faut livrer un module de politique (`kaput.pp`) avec transition `kaput_vmm_exec_t → kaput_vmm_t` et catégories MCS par session |
| Coût de maintenance | modéré ; syntaxe ABI 4.0 pour `userns` | plus élevé (variations Fedora/RHEL, `selinux-policy-devel`, tests par version) |
| Rôle pour Kaput | couche additionnelle + **autorisation `userns` sur Ubuntu** | couche additionnelle |

**Restriction Ubuntu des user namespaces** : introduite en 23.10, **activée par défaut en 24.04** ([avis Qualys](https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt)). Avec `kernel.apparmor_restrict_unprivileged_userns=1`, un processus non confiné sans `CAP_SYS_ADMIN` ne peut créer de user namespace que si un profil l'autorise (`allow userns create,`) ; sinon, quand la création est permise par transition, les tâches du namespace sont confinées par le profil `unprivileged_userns` qui **refuse toute capability** ([wiki AppArmor](https://git.grimmauld.de/mirrors/apparmor/wiki/unprivileged_userns_restriction)). Conséquences :
- `kaput-jail` **ne peut pas** monter son jail sur Ubuntu ≥ 24.04 sans un profil livré par l'installeur : `profile kaput-jail /usr/lib/kaput/kaput-jail flags=(…) { userns, … }`. Le binaire doit être root-owned et non inscriptible par l'utilisateur (sinon contournement trivial, comme l'avertit la [doc Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md) pour les profils par répertoire).
- Ne **jamais** recommander `sysctl kernel.apparmor_restrict_unprivileged_userns=0` (désactive une protection de tout le système).
- Cette restriction est un **« tripwire », pas un mur** : Qualys a publié trois contournements (aa-exec, busybox, LD_PRELOAD dans nautilus) ; Ubuntu les considère comme non-vulnérabilités et propose `kernel.apparmor_restrict_unprivileged_unconfined=1` ([Ubuntu Discourse](https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007)). Kaput ne doit pas fonder de garantie sur elle.
- Rappel : cette restriction concerne l'**hôte**. Dans l'invité, le noyau est le nôtre (pas d'AppArmor Ubuntu) ; le sandbox du navigateur y fonctionne via user namespaces (B.6).

**libvirt ?** libvirt apporterait sVirt/AppArmor par VM automatiquement, mais impose `libvirtd` (démon root, grosse surface) ou le mode session (confinement réduit [non revérifié]). Recommandation : ne pas dépendre de libvirt ; s'inspirer de ses profils (`virt-aa-helper`, types sVirt).

### A.5 Wayland vs X11 côté hôte

- **X11** : tout client connecté au serveur peut lire les entrées clavier et capturer l'écran des autres clients. Corollaire : le processus qui détient la connexion X11 (`kaput-ui`) est très sensible ; s'il était compromis via le canal d'affichage (trames venant de l'invité), l'attaquant obtiendrait un keylogger sur toute la session.
- **Wayland** : isolation entre clients par conception ; `kaput-ui` ne voit que sa surface.
- Écosystème : GNOME 50 est **Wayland-only** (session X11 supprimée ; applis X11 via Xwayland) ; Fedora 44 le livre ; Ubuntu 26.04 le prévoyait ([The Register](https://www.theregister.com/2026/03/19/gnome_50/), [Fedora Change](https://fedoraproject.org/wiki/Changes/WaylandOnlyGNOME)). X11 reste présent sur KDE/XFCE/MATE et hôtes anciens.
- Recommandation : `kaput-ui` = client **Wayland natif** ; X11 supporté avec bandeau d'avertissement « isolation réduite côté hôte » (décision D-5). Le décodeur de trames de `kaput-ui` doit être minimal (format brut fixe, pas de codec complexe), écrit en langage mémoire-sûr, fuzzé, et `kaput-ui` lui-même sous seccomp + Landlock (pas d'accès FS, pas de réseau).
- Le presse-papiers et le glisser-déposer passent par `kaput-ui` ; désactivés par défaut (brief §8), toute ouverture relève de l'Application/Security Architect.

### A.6 Distributions hôtes à supporter et prérequis à documenter

| Niveau | Distributions | MAC | Points spécifiques |
|---|---|---|---|
| Tier 1 | Ubuntu 24.04 LTS, Ubuntu 26.04 LTS [26.04 non revérifié] | AppArmor | profil `userns` obligatoire ; groupe `kvm` ; Landlock ABI dépend du noyau (GA vs HWE) |
| Tier 1 | Debian 13 « trixie » | AppArmor | groupe `kvm` (0660) ; noyau 6.12 |
| Tier 1 | Fedora (2 dernières, 43/44) | SELinux | `/dev/kvm` 0666 ; module SELinux Kaput |
| Tier 2 | RHEL/Alma/Rocky 9 et 10 | SELinux | RHEL 9 = noyau 5.14 : disponibilité de Landlock à vérifier [inconnue] |
| Tier 2 | openSUSE Tumbleweed / Leap 16 | SELinux (?) | à confirmer |
| Best effort | Arch, autres | aucun par défaut | socle namespaces+seccomp+Landlock seul |

Prérequis documentés (`docs/linux.md`) : CPU/virtualisation activée, KVM, cgroup v2, systemd ≥ version à fixer (unités transitoires utilisateur), Landlock ≥ ABI 6 recommandé, user namespaces (profil livré sur Ubuntu), session Wayland recommandée, swap chiffré ou absent recommandé, hibernation déconseillée pendant une session (l'image d'hibernation contient la RAM de l'invité — `MemorySwapMax=0` ne la couvre pas). Le paquet (deb/rpm) est la seule étape root : profil MAC, groupe `kvm`, binaires dans `/usr/lib/kaput` root-owned. **Aucun service root permanent, aucun binaire setuid.**

---

## Partie B — OS invité

### B.1 Exigences dérivées

L'invité exécute du code hostile (pages, JS, exploits). On suppose qu'un attaquant obtient tôt ou tard root dans l'invité ; la frontière principale est le VMM/KVM. Le durcissement de l'invité est de la **défense en profondeur** : rendre plus coûteuse la chaîne navigateur → root invité → attaque des périphériques virtio, empêcher toute persistance, réduire ce qu'un attaquant peut manipuler. Exigences : glibc (compatibilité navigateur), correctifs navigateur en jours et non en semaines, image immuable vérifiable, aucun état persistant, aucun outil d'administration.

### B.2 Délai de correctif du navigateur (critère dominant)

Contexte amont : Chrome est passé à un **cycle majeur de 2 semaines depuis Chrome 153 (8/09/2026)** ; l'Extended Stable reçoit des correctifs hebdomadaires et une version majeure toutes les 8 semaines ([Chrome blog](https://developer.chrome.com/blog/chrome-two-week-start)). Chrome 156 stable le 27/10/2026, mise à jour 156.0.8078.79 le 29/10 ([Chrome Releases, oct. 2026](https://chromereleases.googleblog.com/2026/10/)) ; Chrome 157 (Linux 157.0.8103.78) le 11/11/2026 ; Extended Stable 156.0.8078.100 le 11/11 (Windows/Mac) ([Chrome Releases 2026](https://chromereleases.googleblog.com/2026/?hl=en)). Firefox : 153 et **ESR 153 (21/07/2026)** ([notes ESR 153](https://www.firefox.com/firefox/153.0esr/releasenotes/)).

Échantillon mesuré (un seul point, **à transformer en mesure continue**, cf. I-1) :

| Source | Version | Date de disponibilité | Délai vs amont (29/10) |
|---|---|---|---|
| Debian 13 trixie-security (DSA-6605-1) | 156.0.8078.79-1~deb13u1 | page publiée le 02/11/2026 ([LinuxSecurity](https://linuxsecurity.com/advisories/debian/debian-dsa-6605-1-chromium), [tracker DSA-6508-1](https://security-tracker.debian.org/tracker/DSA-6508-1)) | ≈ 4 j |
| Alpine 3.24 (community) | 156.0.8078.79-r0 | build 02/11/2026 ([pkgs](https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/chromium-angle)) | ≈ 4 j |
| Fedora 44 | 156.0.8078.79-1.fc44 | 04/11/2026 ([LWN](https://lwn.net/Articles/1105234/)) | ≈ 6 j |
| Alpine edge | 157.0.8103.50-r0 | build 10/11/2026 ([pkgs](https://pkgs.alpinelinux.org/package/edge/community/x86_64/chromium-angle)) | — |
| **Alpine 3.23** (branche encore listée) | **149.0.7827.53-r0** | build **06/06/2026** ([pkgs](https://pkgs.alpinelinux.org/package/v3.23/community/x86_64/chromium-common)) | **figée depuis 5 mois** |
| Mozilla APT (Firefox rapid release) | suit chaque release | jour J ([annonce](https://itsfoss.com/news/mozilla-firefox-deb/)) | ≈ 0 j |

Lecture : les distributions stables suivies tiennent un délai de quelques jours sur les correctifs d'une version majeure, mais **au 12/11 aucune n'avait encore Chrome 157** ; avec un cycle de 2 semaines, l'écart peut atteindre une version majeure complète. Chez Alpine, **seule la dernière branche stable** reçoit Chromium (3.23 figée en 149), avec **une seule mainteneuse** listée — risque de facteur bus. À ce délai s'ajoutent le rebuild de l'image Kaput, sa signature et la mise à jour chez l'utilisateur : la fenêtre d'exposition N-day totale est un **paramètre de sécurité de premier ordre** à piloter (SLO proposé : image publiée < 24 h après le paquet distribution, < 72 h après l'amont pour un correctif « exploité in the wild »).

### B.3 musl vs glibc

- Chromium n'est pas supporté en amont sur musl ; Alpine maintient des correctifs `musl-fixes` en aval ([aports](https://git-old.alpinelinux.org/aports/tree/community/chromium/musl-fixes.patch)).
- Firefox : le sandbox seccomp « trap » interagit mal avec musl (signaux bloqués → crash au lieu de `-EPERM`) ; le bug [Mozilla 1657849](https://bugzilla.mozilla.org/show_bug.cgi?id=1657849) est toujours **UNCONFIRMED** et Alpine porte un contournement ; historique de violations seccomp sous Alpine ([aports #7454](https://gitlab.alpinelinux.org/alpine/aports/issues/7454), [#12061](https://gitlab.alpinelinux.org/alpine/aports/-/issues/12061)).
- Risque de sécurité : les politiques seccomp des navigateurs sont calibrées sur les motifs d'appels système de glibc. Sur musl, soit le sandbox casse, soit l'empaqueteur l'**assouplit**. Pour Kaput, glibc est requis ; l'économie de taille de musl est marginale face à la taille du navigateur (centaines de Mo).

### B.4 Tableau comparatif des bases

Légende délai : « jours » = mesuré ou documenté ; « ? » = non mesuré.

| Base | libc | Navigateur disponible | Délai correctif navigateur | Taille / surface | Reproductibilité / vérifiabilité | Immutabilité native | Verdict |
|---|---|---|---|---|---|---|---|
| **Debian 13 (mmdebstrap/mkosi)** | glibc | Chromium (équipe sécurité Debian) ; Firefox ESR dans l'archive ; Firefox rapid release via APT Mozilla | ≈ 4 j (échantillon) ; Firefox ESR suit les ESR Mozilla ; APT Mozilla ≈ 0 j | moyenne ; minimisable (`--variant=essential`, suppression post-build) | Release signé OpenPGP, snapshot.debian.org, projet Reproducible Builds ; SBOM à générer par nous | non (mkosi la fournit) | **Recommandé** |
| Alpine 3.24 | **musl** | Chromium, Firefox (community) | ≈ 4 j sur la dernière branche ; branches précédentes figées | très petite base (quelques Mo), mais le navigateur domine | index apk signés ; pas de SBOM officiel ; reproductibilité partielle | non | Rejeté (musl, B.3 ; bus factor) |
| Ubuntu minimal / Ubuntu Core | glibc | Chromium **uniquement en snap** ([doc Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)) ; Firefox snap (ou APT Mozilla) | snap : rapide mais impose snapd + squashfs + AppArmor dans l'invité | grosse (snapd) | Core : images signées, mais modèle snap | Core oui | Rejeté (snapd = surface, aucun gain sur Debian) |
| Fedora (via mkosi) | glibc | Chromium, Firefox rapid release | ≈ 6 j (échantillon) | moyenne | RPM signés ; Koji ; reproductibilité partielle | non | **Alternative crédible** (cycle de 13 mois = rebases fréquents) |
| Fedora CoreOS | glibc | aucun (OS conteneur ; layering rpm-ostree possible) | n/a | grosse (~Go), Ignition, moteurs de conteneurs | images signées, ostree | oui | Rejeté (objectif différent) |
| Flatcar | glibc | aucun | n/a | moyenne | images signées | `/usr` A/B + dm-verity ([layout](https://www.flatcar.org/docs/latest/devguide/sdk-disk-partitions/)) | Rejeté ; **modèle d'inspiration** |
| Bottlerocket | glibc | aucun | n/a | petite ; pas de shell/interpréteur/gestionnaire de paquets | mises à jour d'image via **TUF** | root RO + dm-verity (panique si corruption), SELinux enforcing, lockdown ([AWS](https://aws.amazon.com/blogs/opensource/security-features-of-bottlerocket-an-open-source-linux-based-operating-system)) | Rejeté (variantes custom difficiles, « ne font plus confiance aux images officielles ») ; **modèle d'inspiration** |
| Wolfi / Chainguard | glibc | image `chromium` Chainguard **commerciale** (registre privé ; headless, sandbox désactivé par défaut) ([fiche](https://images.chainguard.dev/directory/image/chromium/overview)) ; paquet Chromium OSS Wolfi [non vérifié] | rebuild quotidien des images | petite ; pas de noyau ni d'init (orienté conteneur) | **SBOM au build pour chaque paquet**, apko/melange « bit-à-bit reproductibles », signatures Sigstore des images ([Chainguard](https://www.chainguard.dev/unchained/introducing-wolfi-the-first-linux-un-distro-designed-for-securing-the-software-supply-chain)) | non | À surveiller (excellent supply chain ; dépendance fournisseur, noyau/init à fournir) |
| NixOS / nixpkgs | glibc | Chromium, Firefox | ? ; délai lié aux builds Hydra ; nixpkgs « best effort », pas de garantie de rétroportage CVE ([Discourse, 07/2026](https://discourse.nixos.org/t/outdated-vulnerable-applications-in-the-official-repository/79021?page=2)) | grosse closure | forte (dérivations) ; caches signés | possible (images systemd-repart) | Alternative (courbe d'apprentissage, garanties sécurité faibles) |
| Arch | glibc | Chromium, Firefox | généralement très rapide [non mesuré] | moyenne | archive datée ; reproductibilité partielle | non | Possible comme « voie rapide » ; rolling = risque de régression |
| Buildroot | au choix | **pas de navigateur maintenu** [non revérifié] | nous serions le mainteneur | minuscule | très bonne | oui | Rejeté (coût de maintenance navigateur) |
| Yocto (meta-browser) | glibc | Chromium/Firefox via couche communautaire | dépend de la couche ; souvent en retard [non mesuré] | minuscule possible | très bonne, SBOM SPDX natif | oui | Rejeté pour la v1 (infrastructure lourde, nous devenons distributeur) |
| Image mkosi | (selon distro source) | (selon distro source) | (selon distro source) | contrôle fin | sorties reproductibles, verity signé/différé, UKI ([releases mkosi](https://github.com/systemd/mkosi/releases)) | **oui** | **Outil d'assemblage recommandé** (pas une distro) |

Autre référence pertinente : les **DisposableVM de Qubes OS** (précédent conceptuel direct ; leur modèle de rendu/presse-papiers est à étudier par l'Application Engineer).

### B.5 Recommandation argumentée

**Base : paquets Debian 13 « trixie » (glibc), assemblés par mkosi en image immuable signée, avec noyau Kaput.**

Arguments :
1. **Correctifs navigateur** : l'équipe sécurité Debian publie Chromium dans `trixie-security` en quelques jours (échantillon ≈ 4 j) ; pour Firefox, l'APT officiel Mozilla est disponible jour J et signé (empreinte `35BAA0B3…15A3`). Le choix final du navigateur (Browser Engineer) n'impose donc pas de changer de base.
2. **glibc** : configuration supportée en amont par les deux navigateurs et par leurs sandboxes.
3. **Chaîne d'approvisionnement** : Release signé, `snapshot.debian.org` (figer l'état exact de chaque build), Reproducible Builds, cycle de vie long (pas de rebase tous les 13 mois). L'image est reconstructible bit à bit à partir d'un horodatage de snapshot + config mkosi versionnée → vérification indépendante possible.
4. **Immutabilité et minimisation** apportées par mkosi + post-traitement, pas par la distribution : on obtient le modèle Bottlerocket/Flatcar (RO + verity, pas de shell) tout en gardant les paquets navigateur maintenus.
5. **Plan B documenté** : Fedora via la même config mkosi (mkosi est multi-distribution), si le délai Debian se dégradait. La mesure continue des délais (I-1) déclenche la bascule.

Contre-arguments assumés : la base Debian est plus grosse qu'Alpine ; les correctifs « exploités in the wild » arrivent avec quelques jours de retard sur l'amont (risque R-4) ; la minimisation post-build (suppression de `/bin/sh`, dpkg…) sort du cadre supporté par Debian et doit être testée.

### B.6 Conception de l'invité durci

#### B.6.1 Noyau invité (construit par Kaput)

- Base : branche **LTS kernel.org 6.18** (EOL projetée déc. 2028 ; 6.12 aussi jusqu'à déc. 2028) ([GamingOnLinux / kernel.org](https://www.gamingonlinux.com/2026/02/longterm-supported-linux-kernels-get-a-longer-life/page=1/)). Suivi automatisé des versions stables (hebdomadaires), build reproductible.
- Justification d'un noyau maison plutôt que celui de Debian : le noyau Debian est générique et modulaire (milliers de pilotes) ; pour un matériel virtuel fixe (virtio), une configuration fermée supprime l'essentiel de la surface. Coût : nous devenons responsables de son suivi de sécurité (D-4).
- Configuration (liste blanche, `allnoconfig` + ajouts) :
  - **`CONFIG_MODULES=n`** (aucun chargement de code noyau à l'exécution) ; `CONFIG_KEXEC=n`, `HIBERNATION=n`, `DEVMEM=n`, `DEVPORT=n`, `PROC_KCORE=n`, `DEBUG_FS=n`, `KPROBES=n`, `FTRACE=n` (prod), `MAGIC_SYSRQ=n`, `LEGACY_TIOCSTI=n`, `USERFAULTFD=n`, **`IO_URING=n`** (surface historiquement très exploitée, inutile au navigateur), `BPF_SYSCALL` minimal avec `BPF_UNPRIV_DEFAULT_OFF=y` (seccomp n'en dépend pas), `PERF_EVENTS=n` si compatible.
  - Matériel : virtio (mmio et/ou pci selon VMM), virtio-blk, virtio-net, **virtio-vsock**, virtio-rng ; **pas** d'USB, son (sauf décision audio), Bluetooth, Wi-Fi, DRM/GPU (rendu logiciel, B.6.6), entrées physiques, NFS/9p/virtiofs (aucun partage hôte).
  - Systèmes de fichiers : EROFS, tmpfs, proc, sysfs, devtmpfs ; **`DM_VERITY` + `DM_INIT`** (création de la cible verity par paramètre noyau, sans initramfs).
  - Sécurité : `SECURITY_LOCKDOWN_LSM` + `LOCK_DOWN_KERNEL_FORCE_CONFIDENTIALITY`, `SECURITY_LANDLOCK`, `SECURITY_YAMA`, `SECCOMP_FILTER`, `USER_NS`/`PID_NS`/`NET_NS` (requis par le sandbox des navigateurs), `STATIC_USERMODEHELPER`, `STACKPROTECTOR_STRONG`, `HARDENED_USERCOPY`, `FORTIFY_SOURCE`, `INIT_ON_ALLOC_DEFAULT_ON`, `INIT_ON_FREE_DEFAULT_ON`, `RANDOMIZE_KSTACK_OFFSET_DEFAULT`, `SLAB_FREELIST_HARDENED/RANDOM`, `SHUFFLE_PAGE_ALLOCATOR`, `LIST_HARDENED`, `BUG_ON_DATA_CORRUPTION`, CFI (`CFI_CLANG` si build clang), atténuations Spectre/Meltdown actives (le site isolation du navigateur en dépend *dans* l'invité). Référence : recommandations KSPP (la page wiki kernsec a migré vers le site du projet KSPP — liste à reprendre de la version actuelle, [kernsec](https://kernsec.org/wiki/Kernel_Self_Protection_Project/Recommended_Settings)).
  - Ligne de commande (fixée par l'hôte) : `lockdown=confidentiality slab_nomerge page_alloc.shuffle=1 init_on_alloc=1 init_on_free=1 randomize_kstack_offset=on vsyscall=none debugfs=off oops=panic panic=-1 module.sig_enforce=1 (sans effet si MODULES=n) ro rootfstype=erofs dm-mod.create=… root=/dev/dm-0`.
  - sysctls (appliqués par l'init) : `kernel.kptr_restrict=2`, `kernel.dmesg_restrict=1`, `kernel.yama.ptrace_scope=2` (ou 3), `kernel.unprivileged_bpf_disabled=2`, `kernel.perf_event_paranoid=3`, `vm.unprivileged_userfaultfd=0`, `fs.protected_*=1/2`, `vm.memfd_noexec` (valeur 1 ou 2 à valider avec le navigateur, I-4), `user.max_user_namespaces` borné au besoin du sandbox (I-3), `net.*` (pas de forwarding, pas de redirects ; détail réseau = Network Engineer).

#### B.6.2 Rootfs en lecture seule + dm-verity, sans initramfs

- Rootfs **EROFS** (lecture seule native, compact, compressé LZ4/LZMA) ; arbre de hachage dm-verity dans une partition ou un fichier séparé.
- Le **root hash** est inclus dans le manifeste signé de l'image ; l'hôte vérifie la signature (chaîne de confiance = Update/Supply-Chain Engineer), la non-régression de version, puis passe le root hash au noyau via `dm-mod.create="vroot,,,ro,0 <secteurs> verity 1 /dev/vda /dev/vdb 4096 4096 <n> <n> sha256 <roothash> <salt> 1 panic_on_corruption"`.
- Le disque est en plus présenté **en lecture seule par le VMM**. dm-verity apporte : vérification continue de chaque bloc lu (protège contre une altération du fichier image sur l'hôte entre vérification et lecture, TOCTOU), démarrage sans relire tout l'image, échec fermé (panique) en cas de corruption.
- Pas de firmware/BIOS ni de chargeur d'amorçage dans l'invité (boot noyau direct par le VMM) → pas de Secure Boot invité ; la racine de confiance est la vérification côté hôte.

#### B.6.3 État éphémère

- Aucun disque inscriptible attaché. Montages : `/tmp`, `/run`, `/var/tmp`, `/home/browser` en **tmpfs `nosuid,nodev,noexec`** avec `size=` borné ; `/proc` en `hidepid=invisible` ; `/sys` en lecture seule ; `/dev` minimal.
- Pas de swap dans l'invité. Journaux : aucun fichier ; éventuels diagnostics vers l'agent vsock, filtrés (brief §19).
- Profil navigateur, cache, téléchargements : en tmpfs → détruits avec la VM. Côté hôte, la mémoire de l'invité est libérée par le noyau hôte avec le processus VMM (voir R-7 pour swap/hibernation hôte).
- Exécution de nouveau code natif : rootfs RO + tmpfs `noexec` + `vm.memfd_noexec` + absence d'interpréteurs → un attaquant ne peut ni déposer ni exécuter de nouveau binaire par les voies classiques ; il reste l'exécution en mémoire dans un processus déjà compromis (JIT, ROP), que ces mesures ne couvrent pas.

#### B.6.4 Init minimal : systemd complet ou non ?

| Option | Pour | Contre |
|---|---|---|
| systemd complet | robuste, primitives de durcissement par unité, connu | ~1 M lignes, journald/udev/logind/dbus inutiles ici, surface et non-déterminisme |
| busybox init / runit / s6-linux-init / dinit | petits, éprouvés | busybox apporte un shell et des applets ; scripts shell |
| **init Kaput statique (mémoire-sûr)** | ~quelques centaines de lignes, déterministe, aucune dépendance, applique lui-même uid/seccomp/Landlock par service | code à écrire, auditer et fuzzer |

Recommandation : **init Kaput statique** (PID 1) qui : monte les FS, applique les sysctls, configure le réseau en statique depuis la ligne de commande (pas de DHCP client), lance et supervise 3 services (agent vsock, compositeur, navigateur) chacun sous uid distinct, sans capabilities, `no_new_privs`, avec seccomp/Landlock propres ; récolte les zombies ; **sur sortie du navigateur ou de l'agent : `reboot(LINUX_REBOOT_CMD_POWER_OFF)`** (l'hôte détruit ensuite la VM). Repli acceptable : s6-linux-init sans shell.

#### B.6.5 Utilisateurs et privilèges dans l'invité

- `browser` (uid 1000), `compositor` (uid 1001), `agent` (uid 1002) ; aucun groupe supplémentaire ; pas de `sudo`/`su`/`polkit`/`dbus-daemon` système.
- **Aucun binaire setuid/setgid** (tous les montages `nosuid`). Le sandbox du navigateur utilise les user namespaces du noyau invité (pas le helper SUID `chrome-sandbox`, que la doc Chromium décrit comme une ancienne voie « peut-être légèrement plus faible » — [doc Chromium](https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md)).
- **Jamais `--no-sandbox`** : la doc Chromium rappelle que cela « désactive des fonctions de sécurité critiques ». (À noter : l'image Chromium Chainguard désactive le sandbox par défaut, autre raison de ne pas la reprendre telle quelle.)
- Lancer directement le binaire (`/usr/lib/chromium/chromium` ou `/usr/lib/firefox/firefox`) et pas les scripts shell d'enrobage Debian, ce qui permet de supprimer `/bin/sh`.

#### B.6.6 Affichage : compositeur kiosque, rendu logiciel, trames par vsock

- Firefox et Chromium de bureau ont besoin d'un serveur Wayland (ou X11) : le « rendu direct » DRM/KMS sans compositeur n'est pas une option sur les builds bureau [non revérifié pour Ozone/DRM].
- **cage** (kiosque wlroots, une seule application plein écran) : version 0.3.1 (30/06), 0.3.0 passée à wlroots 0.20 ([releases cage](https://github.com/Hjdskes/cage/releases)). Backend `headless` ; un agent client capture les trames (protocole `ext-image-copy-capture`) ou, mieux à terme, compositeur Kaput dédié (wlroots/smithay) qui écrit directement les trames.
- Weston kiosk-shell : fonctionnel mais plus gros ; ses backends VNC/RDP imposeraient un **parseur RFB/RDP côté hôte**, surface inutile.
- Transport recommandé (à arbitrer avec le Virtualization Engineer) : **trames brutes (format pixel fixe, rectangles de dommage bornés) + événements d'entrée typés, sur virtio-vsock**. Avantages : indépendant du VMM (Firecracker n'émule pas de GPU ; vsock existe aussi sous Hyper-V via hvsock, ce qui facilite la parité Windows), aucune émulation GPU côté hôte, parseur hôte trivial. À rejeter : virgl/venus (accélération 3D = énorme surface hôte), transfert du protocole Wayland vers l'hôte (cross-domain/waypipe).
- Coût : pas d'accélération GPU (vidéo HD/WebGL lents) → décision D-7 ; débit vsock à mesurer (I-2).

#### B.6.7 Suppression de l'inutile (vérifiée en CI)

Absents de l'image finale : shell (`/bin/sh`, bash, dash, busybox), sshd/getty/console de connexion (console série en sortie seule ou désactivée en production), dpkg/apt/apk (base dpkg supprimée après génération du SBOM), interpréteurs (perl, python), outils réseau (curl, wget, nc), compilateurs, `su`/`sudo`/`mount`/`setcap`, pages de manuel, locales non utilisées, pilotes Mesa matériels, D-Bus. Contrôle CI : liste des ELF exécutables du rootfs comparée à une liste blanche signée ; échec si un nouveau binaire apparaît ; recherche `find -perm /6000` vide ; recherche d'interpréteurs.

### B.7 Schéma de l'image invitée proposée

```text
ARTEFACTS PUBLIÉS (vérifiés par l'hôte avant tout boot)
┌──────────────────────────────────────────────────────────────────┐
│ kaput-guest-<version>.manifest   (signé ; version monotone)      │
│   - sha256(vmlinux), sha256(rootfs.erofs), sha256(rootfs.verity) │
│   - roothash + salt dm-verity, ligne de commande noyau figée     │
│   - SBOM (SPDX/CycloneDX) + provenance de build (snapshot Debian)│
├──────────────────────────────────────────────────────────────────┤
│ vmlinux            noyau LTS Kaput, sans modules, sans initramfs │
│ rootfs.erofs       /usr, /etc figé, navigateur, cage, init, agent│
│ rootfs.verity      arbre de hachage dm-verity                    │
└──────────────────────────────────────────────────────────────────┘

BOOT
 hôte: vérif signature + anti-rollback + hash ─► jail sans root ─► VMM
   VMM: boot noyau direct, disques RO (vda=erofs, vdb=verity),
        virtio-net (→ politique réseau), virtio-vsock (affichage/entrées), rng
 noyau: dm-init crée /dev/dm-0 (verity, panic_on_corruption) ─► mount / (ro)
 PID1 kaput-init (statique):
   ├─ tmpfs nosuid,nodev,noexec : /tmp /run /var/tmp /home/browser (taille bornée)
   ├─ proc hidepid=invisible, sysfs ro, sysctls durcis, réseau statique
   ├─ agent   (uid 1002) : vsock ⇄ hôte (trames sortantes, entrées entrantes)
   ├─ cage    (uid 1001) : Wayland headless, rendu logiciel
   └─ browser (uid 1000) : Chromium|Firefox, sandbox userns+seccomp actif
 fin: sortie navigateur ─► PID1 poweroff ─► VMM termine ─► l'hôte tue le
      scope cgroup (cgroup.kill), supprime le jail dans $XDG_RUNTIME_DIR
      (tmpfs) ─► mémoire libérée ; aucun fichier de session sur disque hôte

DISPOSITION DISQUE (option « un seul fichier » via systemd-repart/mkosi)
 GPT: [p1 root-x86-64 (EROFS)] [p2 root-x86-64-verity] [p3 root-verity-sig*]
 * signature optionnelle si la vérification est faite par le manifeste hôte
```

Estimation de taille (à mesurer, I-5) : 250–450 Mo non compressé, dominé par le navigateur et les polices.

---

## Risques résiduels

- **R-1 Hyperviseur/KVM** : un invité root malveillant attaque le VMM (ex. CVE-2026-5747) puis, depuis le VMM confiné, le noyau hôte via les `ioctl` KVM et les appels système autorisés. Le confinement réduit l'impact d'une compromission du VMM ; il ne supprime pas les bugs KVM du noyau hôte, qui restent atteignables par conception.
- **R-2 Canal d'affichage/entrées** : seul flux riche invité→hôte ; un bug du décodeur dans `kaput-ui` donnerait l'accès à la session graphique (critique sous X11).
- **R-3 Canaux auxiliaires** : Spectre-like, SMT, rowhammer, cache partagé ; Kaput détecte et signale mais ne contrôle pas le matériel.
- **R-4 Fenêtre N-day navigateur** : quelques jours (distribution) + pipeline Kaput + adoption par l'utilisateur ; aggravée par le cycle de 2 semaines de Chrome.
- **R-5 Noyau invité maison** : suivi de sécurité à notre charge ; un retard ouvre une escalade locale dans l'invité (impact limité par l'éphémérité, mais étape de chaîne).
- **R-6 User namespaces sur l'hôte** : nécessaires au jail, ils exposent du code noyau supplémentaire au lanceur avant l'abandon des capabilities. La restriction Ubuntu est contournable (Qualys) et ne doit pas être considérée comme une garantie.
- **R-7 Rémanence hôte** : hibernation, crash du noyau hôte (kdump), swap non couvert par le cgroup (ex. zswap/zram selon config), journaux du compositeur hôte. Documenter ; recommander le chiffrement du disque.
- **R-8 Hétérogénéité des distributions** : un hôte sans Landlock ≥ 6 ou sans user namespaces offre moins de couches ; le mode dégradé doit être explicite.
- **R-9 Supply chain** : compromission de l'archive Debian, de l'APT Mozilla, de notre CI ou de notre clé de signature. Atténuations côté Supply-Chain Engineer (reproductibilité, builds indépendants, TUF façon Bottlerocket).
- **R-10 Minimisation hors cadre** : retirer shell/dpkg peut casser des chemins rares du navigateur (crash handler, `xdg-open`, impression) ; à couvrir par des tests.

## Inconnues (à réduire avant implémentation)

- **I-1** Distribution réelle des délais de correctif (Debian, Fedora, Arch, APT Mozilla, ESR) : instrumenter un relevé automatique sur 8–12 semaines (dates amont vs dates de publication des paquets).
- **I-2** Débit/latence des trames brutes sur vsock (1080p/1440p, 30–60 i/s) selon le VMM retenu ; besoin éventuel de compression (et donc d'un décodeur supplémentaire côté hôte).
- **I-3** Nombre de user namespaces et appels système exacts requis par le sandbox de Chromium/Firefox dans l'invité (pour borner `user.max_user_namespaces` et écrire les profils seccomp des services).
- **I-4** Compatibilité navigateur avec `vm.memfd_noexec=1/2`, `IO_URING=n`, absence de `/bin/sh`, `PERF_EVENTS=n`.
- **I-5** Taille réelle de l'image, temps de boot, empreinte RAM.
- **I-6** Landlock activé (et ABI) par défaut sur : noyau GA Ubuntu 24.04, RHEL 9/10, openSUSE ; correspondance ABI→noyau à confirmer.
- **I-7** Bascule SELinux d'openSUSE Tumbleweed/Leap 16 (à confirmer).
- **I-8** Contrôleurs cgroup v2 délégués par défaut au gestionnaire utilisateur systemd selon la distribution (`MemorySwapMax` exige le contrôleur mémoire).
- **I-9** Disponibilité et licence d'un paquet Chromium dans le dépôt Wolfi OSS (pour une éventuelle bascule supply chain).
- **I-10** Matrice des noyaux hôtes supportés par le VMM retenu, et son fonctionnement sans jailer (non-root) avec TAP créé dans un netns privé.
- **I-11** Statut exact d'Ubuntu 26.04 LTS (noyau, session X11) — non revérifié.

## Décisions nécessitant l'avis de l'utilisateur

- **D-1 Provenance du binaire navigateur** : Chromium compilé par Debian (libre, quelques jours de retard) vs Google Chrome (binaire propriétaire, jour J, **licence de redistribution dans une image à examiner**) vs Firefox via APT Mozilla (jour J). La base Debian supporte les trois.
- **D-2 Politique sur hôte incomplet** : refus strict (fail-closed) si user namespaces/Landlock ≥ 6 indisponibles, ou mode « isolation réduite » avec consentement explicite. Recommandation : refus par défaut.
- **D-3 Privilège à l'installation** : un paquet installé en root (profil AppArmor/module SELinux, groupe `kvm`) est nécessaire sur Ubuntu ≥ 24.04 et souhaitable ailleurs. Aucun privilège à l'exécution. Valider ce compromis.
- **D-4 Noyau invité maison** (surface minimale, maintenance à notre charge) vs noyau Debian (maintenu par Debian, surface bien plus grande). Recommandation : noyau maison avec pipeline automatisé.
- **D-5 Hôtes X11** : supportés avec avertissement, ou Wayland exigé.
- **D-6 Atténuations CPU hôte** (SMT actif, KSM, swap) : simple avertissement ou blocage.
- **D-7 Pas d'accélération GPU** dans l'invité (rendu logiciel) : sécurité nettement meilleure, UX vidéo/WebGL dégradée.
- **D-8 Matrice de distributions Tier 1** proposée en A.6.

## Sources

Hôte / VMM
- Firecracker jailer (v1.16.1) : https://raw.githubusercontent.com/firecracker-microvm/firecracker/v1.16.1/docs/jailer.md
- Firecracker, recommandations hôte de production : https://github.com/roypat/firecracker/blob/main/docs/prod-host-setup.md
- CVE-2026-1386 (jailer, symlink) : https://aws.amazon.com/security/security-bulletins/2026-003-AWS
- CVE-2026-5747 (virtio-pci) : https://aws.amazon.com/security/security-bulletins/2026-015-aws
- Firecracker v1.16.1 : https://newreleases.io/project/github/firecracker-microvm/firecracker/release/v1.16.1 ; versions : https://releasealert.dev/github/firecracker-microvm/firecracker
- Landlock (doc noyau) : https://www.kernel.org/doc/html/latest/userspace-api/landlock.html
- Permissions `/dev/kvm` (commit systemd) : https://git.alternativebit.fr/picnoir/Systemd/commits/commit/b2bb40ce9a4797728f384fa75e47829ab81303a1/rules/50-udev-default.rules.in
- Restriction userns AppArmor : https://git.grimmauld.de/mirrors/apparmor/wiki/unprivileged_userns_restriction ; https://discourse.ubuntu.com/t/understanding-apparmor-user-namespace-restriction/58007 ; spec : https://discourse.ubuntu.com/t/spec-unprivileged-user-namespace-restrictions-via-apparmor-in-ubuntu-23-10/37626
- Contournements Qualys : https://www.qualys.com/2025/three-bypasses-of-Ubuntu-unprivileged-user-namespace-restrictions.txt
- Chromium et restrictions AppArmor : https://chromium.googlesource.com/chromium/src/+/main/docs/security/apparmor-userns-restrictions.md
- GNOME 50 Wayland-only : https://www.theregister.com/2026/03/19/gnome_50/ ; https://fedoraproject.org/wiki/Changes/WaylandOnlyGNOME

Navigateurs et cadence
- Cycle de 2 semaines Chrome : https://developer.chrome.com/blog/chrome-two-week-start
- Chrome Releases oct. 2026 : https://chromereleases.googleblog.com/2026/10/ ; 2026 : https://chromereleases.googleblog.com/2026/?hl=en ; 09/2026 : https://chromereleases.googleblog.com/2026/09/stable-channel-update-for-desktop.html
- Firefox ESR 153 : https://www.firefox.com/firefox/153.0esr/releasenotes/
- APT Mozilla : https://itsfoss.com/news/mozilla-firefox-deb/
- Debian DSA-6605-1 : https://linuxsecurity.com/advisories/debian/debian-dsa-6605-1-chromium ; DSA-6508-1 : https://security-tracker.debian.org/tracker/DSA-6508-1
- Fedora 44 chromium : https://lwn.net/Articles/1105234/
- Alpine chromium : https://pkgs.alpinelinux.org/package/v3.24/community/x86_64/chromium-angle ; https://pkgs.alpinelinux.org/package/edge/community/x86_64/chromium-angle ; https://pkgs.alpinelinux.org/package/v3.23/community/x86_64/chromium-common ; Snyk : https://security.snyk.io/vuln/SNYK-ALPINE323-CHROMIUM-15426681
- musl : https://bugzilla.mozilla.org/show_bug.cgi?id=1657849 ; https://gitlab.alpinelinux.org/alpine/aports/issues/7454 ; https://gitlab.alpinelinux.org/alpine/aports/-/issues/12061 ; https://git-old.alpinelinux.org/aports/tree/community/chromium/musl-fixes.patch

Distributions / outillage invité
- Bottlerocket : https://aws.amazon.com/blogs/opensource/security-features-of-bottlerocket-an-open-source-linux-based-operating-system
- Flatcar : https://www.flatcar.org/docs/latest/devguide/sdk-disk-partitions/
- Wolfi : https://www.chainguard.dev/unchained/introducing-wolfi-the-first-linux-un-distro-designed-for-securing-the-software-supply-chain ; image chromium : https://images.chainguard.dev/directory/image/chromium/overview
- nixpkgs (maintenance) : https://discourse.nixos.org/t/outdated-vulnerable-applications-in-the-official-repository/79021?page=2
- mkosi : https://github.com/systemd/mkosi/releases
- Noyaux LTS : https://www.gamingonlinux.com/2026/02/longterm-supported-linux-kernels-get-a-longer-life/page=1/ ; https://linuxiac.com/linux-6-18-is-now-listed-as-the-new-long-term-support-kernel/
- KSPP : https://kernsec.org/wiki/Kernel_Self_Protection_Project/Recommended_Settings (renvoie vers le site du projet KSPP)
- cage : https://github.com/Hjdskes/cage/releases
