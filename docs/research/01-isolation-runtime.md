# 01 — Runtime d'isolation : comparaison et recommandation

> Rôle : Virtualization / Security Architect — Phase 0 (Discovery), recherche uniquement.
> Date : 12 novembre 2026. Rien n'a été prototypé : le conteneur de recherche n'a ni KVM ni WHP.
> Toutes les affirmations marquées **[À VÉRIFIER-PoC]** doivent être confirmées par un prototype avant l'ADR 0001.
> Limite de méthode : le budget de recherche web partagé s'est épuisé en cours de travail. Quelques points
> (édition Home de Hyper-V/HCS, détails internes d'OpenVMM) reposent donc sur la documentation déjà
> collectée ou sur des connaissances antérieures. Ils sont signalés comme tels.

---

## 1. Résumé exécutif

1. Seule la **virtualisation matérielle** (VT-x/AMD-V via KVM ou l'hyperviseur Microsoft) offre une frontière où le noyau hôte n'est pas partagé avec le contenu hostile. Les conteneurs, AppContainer, gVisor et la sandbox du navigateur seule sont écartés comme frontière **principale**. On les garde comme couches **secondaires**.
2. **Question centrale.** Un VMM unique, écrit en Rust, maintenu et couvrant WHP et KVM existe : **OpenVMM** (Microsoft, licence MIT). Mais il n'est pas présenté comme prêt pour la production en VMM autonome, il ne publie pas de releases, et sa base de code est vaste. crosvm couvre aussi les deux plateformes, mais son backend WHPX n'est **pas testé en amont**. QEMU couvre les deux, mais il est écrit en C, très étendu, et a connu des évasions en 2026.
3. **Recommandation : un contrat invité unique et deux backends VMM.** Sous Linux, **Firecracker** sur KVM, confiné sans root. Sous Windows, **OpenVMM** sur WHP, confiné par AppContainer ou un token restreint. crosvm/WHPX sert de candidat de repli Windows. Une convergence sur OpenVMM seul reste à réévaluer après le PoC.
4. **Jeu de périphériques minimal :** `virtio-vsock` + `virtio-blk` en lecture seule (image raw signée), boot direct du noyau, irqchip dans l'hyperviseur. Pas de `virtio-net`, pas de `virtio-gpu` (même en 2D), pas de virtio-fs, son ni USB. Le VMM devient un simple relais d'octets.
5. **Réseau, affichage, entrées, audio éventuel :** des protocoles minimaux passent par vsock. Ils sont analysés par des **brokers hôte séparés**, chacun confiné dans son propre bac à sable. Une évasion du VMM n'obtient ni fichiers, ni réseau, ni accès aux processus de l'utilisateur.
6. **Risque résiduel principal :** vulnérabilités de l'hyperviseur et du noyau hôte, canaux auxiliaires CPU, et parseurs de nos propres brokers. Aucune de ces couches n'est présentée comme infaillible.

---

## 2. Tableau comparatif

Légende pour la colonne « Langage » : **MS** = mémoire-sûr (Rust/Go, avec du code `unsafe` résiduel) ; **C** = C/C++.
Les tailles de code sont des **ordres de grandeur** à mesurer (`tokei`, `cargo tree`) au PoC.

| Option | Frontière principale | Surface exposée à l'invité (côté hôte) | Lang. | Windows | Linux | Maturité / maintenance | Verdict Kaput |
|---|---|---|---|---|---|---|---|
| **QEMU/KVM** | VM matérielle | Très large (centaines de modèles de périphériques). Code ~10⁶ lignes. | C | via WHPX (cf. ligne suivante) | Oui, référence | Très mature, CVE fréquentes (2026 : virtio-gpu, virtio-blk) | Repli seulement, en profil réduit |
| **QEMU + WHPX** | VM (hyperviseur MS) | Idem, plus l'accélérateur WHPX | C | Oui (Home inclus via WHP) | — | WHPX relancé en 2025-26 par la communauté (x86 + arm64) | Repli Windows uniquement |
| **Hyper-V / HCS** | VM (hyperviseur MS) | Pile Hyper-V complète : VSP VMBus, dont certains en **noyau root** (vmswitch, storvsp), plus vmwp | C/C++ | Pro/Ent/Edu (Hyper-V). HCS sur Home via « Virtual Machine Platform » **[À VÉRIFIER]** | — | Très mature. Plusieurs CVE « Hyper-V RCE » guest→host en 2026 | Non : surface noyau root trop large, peu de contrôle |
| **WHP (API seule)** | VM (hyperviseur MS) | Hyperviseur + vid.sys. **Toute l'émulation dans notre processus user-mode** | — | Oui, Win10 1803+, Home inclus | — | API stable, documentée | **Oui : socle Windows** |
| **Firecracker** | VM KVM | virtio-net/blk/vsock (MMIO), serial, i8042 partiel, MMDS. Code ~10⁵ lignes | MS | Non | Oui | Production AWS. CVE-2026-5747 (transport PCI, opt-in) | **Oui : backend Linux** |
| **Cloud Hypervisor** | VM KVM/MSHV | Plus large que Firecracker (PCI, hotplug, vhost-user, qcow2…) | MS | Non (MSHV = Linux en partition root, pas un hôte Windows) | Oui | Actif. CVE 2026 : exfiltration de fichiers hôte (qcow2) et UAF virtio-blk | Alternative Linux n°2 |
| **crosvm** | VM | Processus par périphérique + minijail/seccomp sous Linux. Broker style Chromium sous Windows | MS | WHPX/HAXM **non testés en amont** | Oui (ChromeOS, Android) | Mature sous Linux, incertain sous Windows | Repli Windows à évaluer |
| **OpenVMM** | VM | Très riche (VMBus, virtio, NVMe, vTPM, chipset legacy, VGA…). Base **vaste**, mais configurable | MS | Oui (WHP, x64/arm64, Win11 récent) | Oui (KVM, MSHV) | Actif, ~100 contributeurs, Intel/Arm. **Pas de releases. Interfaces « évolutives »** | **Oui : backend Windows** (candidat à l'unification) |
| **libkrun** | VM | virtio-console/blk/fs/net/vsock/gpu, TSI | MS | WHP « à venir » en amont ; fork précoce (1 vCPU) | Oui | Actif (Podman/krun) | Non pour v1 |
| **Hyperlight** | Micro-VM sans OS | Minimale | MS | WHP | KVM/MSHV | CNCF Sandbox (expérimental) | Non : n'exécute pas un navigateur graphique |
| **gVisor** | Noyau applicatif en espace utilisateur | Sentry (Go) + noyau hôte filtré | MS | Non | Oui | Production Google | Non comme frontière principale |
| **Kata Containers** | VM (QEMU/CH/FC) + agent | VMM sous-jacent + agent + runtime conteneur | mixte | Non | Oui | Mature | Non : orchestration inutile pour un poste de travail |
| **Conteneurs** (ns/cgroups/seccomp/Landlock/AA/SELinux) | Noyau hôte **partagé** | Noyau Linux entier (filtré) | C | Non | Oui | Mature | **Couche de confinement du VMM**, pas une frontière |
| **Windows Sandbox** | VM Hyper-V jetable | Pile Hyper-V + invité Windows | C/C++ | Pro/Ent/Edu, **pas Home** | — | Mature | Non : invité Windows, peu configurable |
| **AppContainer / LPAC** | Noyau Windows **partagé** | Noyau NT + win32k (sauf lockdown) | C | Oui | — | Mature | **Couche de confinement du VMM et des brokers** |
| **Sandbox navigateur seule** | Processus du navigateur | Noyau hôte + IPC du navigateur | C++ | Oui | Oui | Mature, évasions régulières (Pwn2Own 2026) | Couche interne (dans l'invité) |
| **Combinaison recommandée** | VM + VMM confiné + sandbox navigateur | Voir §5 | MS (hôte) | WHP | KVM | — | **Retenue** |

### 2.1 Axes complémentaires (synthèse)

| Axe | Conséquence pour Kaput |
|---|---|
| Performance | Les micro-VM démarrent en une fraction de seconde. Le coût dominant vient du **rendu logiciel** dans l'invité (pas de GPU) et du transport des images (§4.5). |
| GPU | Aucune accélération GPU en v1. Les chemins virtio-gpu, virgl, venus et vGPU multiplient la surface hôte (exemple : CVE-2026-3886 dans QEMU). |
| Audio | Désactivé par défaut. Option : flux PCM sortant en format fixe, via vsock vers un broker audio. Micro et caméra : jamais en v1. |
| Clipboard / drag & drop | Désactivés. Option ultérieure : hôte→invité, texte UTF-8 seul, taille plafonnée, sur action explicite de l'utilisateur. |
| Fichiers | Aucun dossier partagé, aucun virtio-fs. Les téléchargements restent dans l'invité. Un export éventuel passerait par un canal dédié avec quarantaine (Mark-of-the-Web sous Windows). |
| Périphériques | Aucun passthrough (USB, PCI, caméra, carte à puce). |
| Persistance | Aucun disque inscriptible côté hôte. L'écriture se fait dans un tmpfs en RAM invitée. La destruction se fait en tuant le processus et en libérant sa mémoire. |
| Résidus forensiques | Pagefile/swap, hiberfil, dumps de crash du VMM (WER, core), cache DNS de l'hôte (si l'OS résout), Prefetch/ETW (lancement de Kaput visible). Détail en §7. |
| Supply chain | Les VMM sont construits **depuis les sources, à un commit épinglé**, avec dépendances vendorisées, `cargo-vet`/`cargo-deny` et build reproductible. OpenVMM n'a pas de releases : nous en sommes de fait les intégrateurs. |

---

## 3. Analyse par famille (synthèse)

### 3.1 Pourquoi pas une frontière à noyau partagé

- **Conteneurs Linux.** L'invité hostile parle directement au noyau hôte, et toute LPE noyau franchit la frontière. seccomp, Landlock et les MAC réduisent la surface sans la supprimer. Ces mécanismes sont utilisés en §5 pour **confiner le VMM**, ce qui est leur bon emploi.
- **gVisor.** C'est une vraie réduction de surface : le Sentry, écrit en Go, réimplémente l'ABI Linux et, selon la documentation, il « never passes through any system call to the host » ([gVisor security](https://gvisor.dev/docs/architecture_guide/intro/)). Mais gVisor ne fonctionne que sous Linux, sa compatibilité graphique et avec la sandbox Chromium est partielle, et la documentation exclut explicitement les canaux auxiliaires de type Spectre. Il ne règle pas Windows.
- **AppContainer / LPAC.** Ce sont d'excellents réducteurs de privilèges ([Chromium sandbox design](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md)). Mais un navigateur natif en AppContainer partage le noyau NT et win32k. Nous les retenons pour confiner VMM et brokers.
- **Sandbox navigateur seule.** Les chaînes d'évasion de sandbox restent courantes. À Pwn2Own Berlin 2026, une évasion de sandbox de Microsoft Edge par chaîne de quatre bogues logiques a été démontrée ([Trend Micro/ZDI](https://www.trendmicro.com/en/research/26/f/pwn2own-berlin-2026.html)). Pour Kaput, c'est la couche la plus interne, pas la frontière hôte.

### 3.2 Pourquoi pas Hyper-V/HCS ni Windows Sandbox

- Avec Hyper-V classique, une partie des fournisseurs de services VMBus (stockage, commutateur réseau) s'exécute dans le **noyau de la partition root**. Une évasion à travers ces composants atterrit directement en noyau Windows, sans couche de confinement intermédiaire. 2026 a connu plusieurs CVE « Windows Hyper-V Remote Code Execution » guest→host. Exemple : CVE-2026-45607, lecture hors limites, CVSS 8.4, Windows 10/11/Server 2016-2025 ([Action1](https://www.action1.com/vulnerabilities/cve-2026-45607/), voir aussi [CVE-2026-45641](https://www.action1.com/vulnerabilities/cve-2026-45641/)).
- Le processus utilisateur vmwp est durci (CFG, ACG, CIG, retrait de SeImpersonatePrivilege). Microsoft lui-même conclut que « given strong primitives, exploitation will always be possible (with hard work) » ([MSRC, Attacking the VM Worker Process](https://www.microsoft.com/en-us/msrc/blog/2019/09/attacking-the-vm-worker-process)).
- Windows Sandbox n'est **pas disponible sous Windows Home**. Son invité est Windows, ce qui contredit l'image Linux minimale du brief. Le réseau y est activé par défaut ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview)).
- **WHP** n'expose que partitions, vCPU et mappage mémoire. L'émulation des périphériques est faite par le processus user-mode appelant ([WHP API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform)). C'est précisément ce qu'il nous faut : la surface d'émulation est dans **notre** processus, écrit en Rust, et confinable.
- WHP est disponible depuis Windows 10 1803. L'aide Google mentionne l'option sur **Windows 10 Home** ([Google Play Games, WHP](https://support.google.com/googleplay/answer/11913190?hl=en)). L'activation exige un administrateur et un redémarrage ([ElevenForum](https://www.elevenforum.com/t/enable-or-disable-windows-hypervisor-platform-in-windows-11.38917/latest)).

### 3.3 QEMU (KVM et WHPX)

- C'est le seul VMM « universel » éprouvé sur les deux plateformes. Le backend WHPX a reçu en 2025-2026 un important travail (support Arm, séries de mises à jour x86, documentation, ajout de mainteneurs) ([patchew, docs WHPX](https://patchew.org/QEMU/20260327011152.4126-1-mohamed@unpredictable.fr/20260327011152.4126-3-mohamed@unpredictable.fr), [WHPX x86 updates 2026-02](https://patchew.org/QEMU/20260223083734.48533-1-mohamed@unpredictable.fr)).
- La surface reste problématique. Exemples 2026 :
  - CVE-2026-3886 / ZDI-26-332 : dépassement d'entier dans `calc_image_hostmem` de **virtio-gpu**, guest→host, CVSS 8.8 ([ZDI](https://zerodayinitiative.com/advisories/ZDI-26-332), [Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-3886)). Ce chemin sert aussi à la création de ressources 2D, d'où l'exclusion de virtio-gpu « même 2D ».
  - CVE-2026-48914 : écriture hors limites dans le tas via **virtio-blk** ([Tenable](https://www.tenable.com/cve/CVE-2026-48914)).
- Verdict : repli uniquement, avec `-nodefaults`, machine `microvm`, sandbox `-sandbox on` sous Linux, et un confinement externe identique au §5.

### 3.4 libkrun, Hyperlight, Kata

- **libkrun** : en amont, WHP est listé comme « upcoming ». La documentation avertit que « The VM boundary does not restrict host resources exposed through devices » ([libkrun](https://github.com/containers/libkrun)). Un backend WHPX existe hors amont : 1 vCPU, virtio-gpu absent, publié le 2026-03-05 ([A3S Lab](https://a3s-lab.github.io/a3s/blog/en/libkrun-libkrunfw-whpx)). Le mécanisme TSI fait transiter les sockets de l'invité par le VMM, qui obtient donc le réseau de l'hôte. C'est l'inverse de notre principe « VMM sans réseau ».
- **Hyperlight** couvre WHP, KVM et MSHV et sait désormais exécuter des binaires Linux via Unikraft ([CNCF, 2026-11-09](https://www.cncf.io/blog/2026/11/09/run-linux-applications-in-hypervisor-isolated-micro-vms-with-hyperlight/)). C'est un projet CNCF Sandbox, orienté fonctions, et rien n'indique qu'il supporte une pile graphique ou un navigateur. À surveiller, sans plus.
- **Kata** n'apporte que l'intégration OCI et Kubernetes, qui ne nous sert pas.

---

## 4. Analyse détaillée des meilleurs candidats

### 4.1 Firecracker (backend Linux recommandé)

**Isolation et modèle de menace.**
- Le document de conception considère tous les threads vCPU comme exécutant du code malveillant dès leur démarrage. Il organise des zones de confiance imbriquées et recommande le **jailer** en production ([design.md](https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/design.md)).
- Des filtres seccomp sont chargés **par thread** avant l'exécution de code invité.
- Firecracker ne filtre pas le trafic sortant : le filtrage revient à l'hôte. Cela confirme notre choix d'un broker réseau séparé.

**Surface.**
- Périphériques : virtio-net, virtio-blk, virtio-vsock, serial (absent en production), i8042 partiel (reset) et MMDS. Le transport par défaut est **MMIO**. Pas de PCI par défaut, pas de BIOS, pas d'affichage.
- Kaput n'activerait que **blk (ro) + vsock**. MMDS, net, balloon et serial seraient désactivés en build release.

**CVE.**
- CVE-2026-5747 : écriture hors limites dans le **transport virtio PCI**. Le crash est possible depuis un root invité, et l'exécution de code sous conditions supplémentaires. Versions affectées : 1.13.0–1.14.3 et 1.15.0, corrigées en 1.14.4/1.15.1. **Le transport MMIO par défaut n'est pas affecté** ([AWS 2026-015](https://aws.amazon.com/security/security-bulletins/2026-015-aws)).
- Leçon : chaque option activée (`--enable-pci`) ajoute de la surface. Kaput reste en MMIO.

**Confinement.**
- Le jailer fait chroot/pivot_root, namespaces mount/PID/net, cgroups, changement d'uid/gid, rlimits et fermeture des descripteurs. Mais **il s'exécute en root** ([jailer.md](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)).
- Pour une application de bureau, nous proposons de **réimplémenter l'équivalent sans root** (§5.3) à partir d'un utilisateur ayant accès à `/dev/kvm`.

**vsock.** Les ports vsock invités sont exposés côté hôte comme des sockets **AF_UNIX** dans le chroot. Le pont vers des brokers confinés se fait donc naturellement, sans pile réseau dans le VMM.

**Limites.**
- Pas de Windows.
- Pas d'affichage natif : c'est voulu, l'affichage passe par vsock (§4.5).
- Le débit vsock pour l'affichage est à mesurer **[À VÉRIFIER-PoC]**.

### 4.2 OpenVMM (backend Windows recommandé, candidat à l'unification)

**Faits établis.**
- VMM modulaire en Rust, licence MIT. Le développement actuel est centré sur le rôle de paravisor OpenHCL ([GitHub](https://github.com/microsoft/OpenVMM)).
- Plateformes : Windows x64/arm64 via **WHP**, Linux x64/arm64 via **KVM** et **MSHV**, macOS arm64 via Hypervisor.framework ([Guide utilisateur](https://github.com/microsoft/openvmm/blob/main/Guide/src/user_guide/openvmm.md), [blog Windows OS Platform](https://www.elevenforum.com/t/the-openvmm-project.48844/)).
- Boot UEFI, BIOS ou **Linux Direct Boot**. Périphériques paravirtualisés virtio et VMBus. Émulés : vTPM, NVMe, UART, chipset i440BX/PIIX4, IDE, VGA (expérimental).
- Développement sous Windows : « recent version of Windows 11 ». Windows 10 n'est plus supporté comme plateforme de développement à cause des API WHP requises ([guide Windows](https://github.stwitter.workers.dev/microsoft/openvmm/blob/main/Guide/src/dev_guide/getting_started/windows.md)).
- Gouvernance : environ 100 contributeurs, contributions d'Intel et d'Arm (août 2026) ([OSFY](https://www.opensourceforu.com/2026/08/microsofts-openvmm-gains-intel-arm-contributions/)).

**Points de vigilance (bloquants potentiels).**
- **Maturité en VMM autonome.**
  - En 2024, Microsoft le décrivait comme « not yet ready for production use » et « more akin to a development platform », sans garantie de stabilité d'API ([The New Stack](https://thenewstack.io/microsoft-open-sources-openvmm-rust-powered-vm-monitor/)).
  - Le guide 2026 ne reprend pas ce texte, mais qualifie les interfaces de gestion d'« evolving ». La section Releases du dépôt est vide.
  - Kaput serait donc **intégrateur et mainteneur d'un commit épinglé**, avec la veille sécurité à sa charge.
- **Taille de la TCB.** Le dépôt contient OpenHCL, UEFI, l'émulation Hyper-V complète, etc. Il faut prouver qu'un build par *features* Cargo exclut tout sauf partition, vCPU, irqchip, boot direct, virtio-blk et vsock **[À VÉRIFIER-PoC : mesurer lignes et crates réellement liées]**.
- **vsock côté Windows.** Il faut confirmer le chemin : virtio-vsock ou hvsocket sur VMBus, et le point de sortie côté hôte (named pipe ? socket ?). Ce choix détermine le contrat invité. Si OpenVMM n'expose que hvsocket/VMBus, le noyau invité devra embarquer `hv_vmbus` + `hv_sock`, ce qui fait **deux noyaux invités ou deux configurations** **[À VÉRIFIER-PoC]**.
- **Confinement.** Rien de documenté n'indique un mode « sandboxé » prêt à l'emploi sous Windows. À notre connaissance, OpenVMM a une architecture multi-processus (« mesh »), non vérifiée faute de budget de recherche. Nous appliquerons notre propre confinement (§5.4).
- **Processus de sécurité.** Il faut confirmer si les vulnérabilités OpenVMM font l'objet d'avis (MSRC/GHSA) **[INCONNU]**.

**Pourquoi malgré tout.**
- C'est le **seul** VMM mémoire-sûr dont le backend WHP est développé et testé par le fournisseur de l'hyperviseur.
- L'alternative crosvm/WHPX n'est explicitement pas testée en amont (§4.3), et QEMU/WHPX est en C.

### 4.3 crosvm (repli Windows ; alternative Linux)

- Sous Linux, l'architecture est exemplaire : chaque périphérique tourne dans un **processus séparé**, forké et emprisonné via minijail, avec des politiques seccomp par périphérique et des sockets de contrôle séparés par type de requête ([ARCHITECTURE.md](https://android.googlesource.com/platform/external/crosvm/+/052742a1a/ARCHITECTURE.md)).
- Sous Windows, il existe une couche broker/target de type Chromium : tokens restreints, job objects, niveaux d'intégrité, AppContainer/LowBox, politiques de mitigation ([sandbox/src/lib.rs](https://android.googlesource.com/platform/external/crosvm/+/44e40e1560890dbf34a731e19bab24b7f2c72b8a/sandbox/src/lib.rs)). C'est **un atout majeur pour le confinement**.
- Mais WHPX et HAXM ne sont « pas testés en amont ». Leurs mainteneurs doivent tester en aval et fournir eux-mêmes les correctifs en cas de casse ([crosvm book, Hypervisors](https://crosvm.dev/book/hypervisors.html)). HAXM est par ailleurs déprécié par Intel ([Android Developers](https://developer.android.com/studio/run/emulator-acceleration)).
- Verdict : candidat sérieux **si** le PoC OpenVMM échoue sur la TCB ou le confinement. Le risque de maintenance doit être assumé et documenté.

### 4.4 Cloud Hypervisor (alternative Linux)

- Rust, seccomp, support **Landlock** (utilisé par exemple par Spectrum OS depuis novembre 2025, [patch](https://inbox.spectrum-os.org/spectrum-devel/20251110184907.346511-1-hi@alyssa.is/t)).
- Surface plus large que Firecracker. Ses CVE 2026 sont instructives pour la notion de « mémoire-sûr » :
  - CVE-2026-27211 : un invité réécrit l'en-tête de son disque raw en QCOW2 pointant vers un fichier hôte ; l'auto-détection de format sert ensuite ce fichier à l'invité. CVSS 3.1 de 10.0, corrigé en 50.1. Les images en lecture seule et de confiance ne sont pas affectées ; Landlock est cité comme mitigation ([CVELogic](https://www.cvelogic.com/cve/CVE-2026-27211)).
  - CVE-2026-45782 : **use-after-free** dans virtio-blk avec E/S asynchrones (io_uring/aio), corrigé en 51.2 ([Tenable](https://www.tenable.com/cve/CVE-2026-45782)).
- Leçon pour Kaput :
  - Rust réduit fortement les classes de bogues sans les éliminer (code `unsafe`, interactions noyau, bogues **logiques**).
  - Règles : **format raw imposé, pas d'auto-détection, lecture seule, pas d'E/S asynchrones exotiques, confinement du système de fichiers**.
- MSHV n'est pas un chemin vers Windows. Il s'agit de Linux en partition root sur l'hyperviseur Microsoft ([The Register](https://www.theregister.com/2021/02/17/linux_as_root_partition_on_hyper_v/)), sans rapport avec un poste Windows grand public.

### 4.5 Jeu minimal de périphériques virtuels (contrat invité commun)

| Composant | Décision | Justification |
|---|---|---|
| Boot | **Direct kernel boot** (bzImage/Image + initramfs), pas de firmware UEFI/BIOS | Supprime firmware, SMM, variables NVRAM et ACPI complexe (à minimiser selon le backend). |
| CPU / IRQ | irqchip et APIC **dans l'hyperviseur** (KVM in-kernel, émulation LAPIC WHP) ; 2-4 vCPU | Pas d'émulation PIC/IOAPIC en user-mode lorsque c'est évitable. |
| `virtio-blk` | **1 disque, lecture seule, image raw** signée et vérifiée avant lancement. Fichier ouvert par le superviseur, **descripteur ou handle transmis**. dm-verity dans l'invité. | Protège l'intégrité invitée. Évite la classe CVE-2026-27211. Côté hôte, seul le chemin lecture est utilisé. |
| Écriture invitée | **tmpfs en RAM invitée** uniquement | Aucun octet de session sur le disque hôte (hors pagination de l'hôte, §7). |
| `virtio-vsock` | **Canal unique multiplexé par ports** : contrôle, affichage, entrées, réseau (proxy), audio optionnel | Le VMM ne fait que relayer des octets. Toute l'analyse protocolaire se fait dans des brokers séparés. |
| `virtio-net` | **Absent** | Pas de pile TCP/IP ni de NAT dans le VMM ou l'hôte. Le réseau passe par un proxy de sortie via vsock (§6). |
| `virtio-gpu` (même 2D) | **Absent** | Évasions récentes dans ce code (CVE-2026-3886). Cadres d'image via vsock vers un *viewer* confiné. |
| `virtio-rng` | Optionnel (préférer RDRAND/RDSEED + jitterentropy) | Petite surface. À décider selon l'entropie mesurée au boot. |
| Serial / console | **Builds de développement uniquement** | Le brief exige qu'il n'y ait pas d'interface inutile. |
| balloon, fs, snd, input, USB, PCI passthrough, TPM | **Absents** | Pas de besoin justifié. |

**Affichage.** Le navigateur rend en logiciel dans l'invité. Un agent invité minimal envoie des rectangles modifiés (format brut, dimensions bornées, en-tête de taille fixe) au viewer hôte. C'est l'approche du protocole GUI de Qubes, ici sur vsock.
- Variante à évaluer : une **région de mémoire invitée fixe** (framebuffer brut) mappée en lecture seule dans le viewer. La surface d'analyse est quasi nulle, mais cela demande une modification du VMM **[À VÉRIFIER-PoC : débit vsock 1080p/60 vs framebuffer partagé]**.
- Tout codec compressé (H.264, PNG…) côté hôte est exclu en v1, car ce serait un parseur complexe exposé à l'invité.

---

## 5. Recommandation et architecture en couches

### 5.1 Décision proposée (pour l'ADR 0001)

> **Contrat invité unique, deux backends VMM mémoire-sûrs :**
> - Linux : **Firecracker** (KVM), transport MMIO, blk ro + vsock, confiné sans root.
> - Windows : **OpenVMM** (WHP), build minimal par *features*, blk ro + vsock, confiné AppContainer/LPAC.
> - Repli Windows : **crosvm/WHPX** si OpenVMM échoue aux critères du PoC. Repli ultime : QEMU microvm durci (non souhaité).
> - **Convergence** OpenVMM sur KVM : à réévaluer quand OpenVMM publiera des releases et un processus d'avis de sécurité.

**Pourquoi c'est la meilleure frontière pour Kaput.**
1. **Le noyau hôte n'est pas partagé.** L'invité hostile ne voit que l'interface de virtualisation matérielle, plus deux périphériques virtio.
2. **La surface d'émulation est minimale et écrite dans un langage mémoire-sûr :** environ deux périphériques, sans firmware, sans GPU, sans pile réseau. Comparée à QEMU ou Hyper-V, la surface exposée baisse de plusieurs ordres de grandeur.
3. **L'émulation est en user-mode et confinée.** Contrairement aux VSP Hyper-V en noyau root, une évasion du VMM atterrit dans un processus **sans fichiers, sans réseau et sans vue sur les processus de l'utilisateur**. Il lui faut ensuite une seconde vulnérabilité (noyau hôte ou broker).
4. **La disponibilité correspond au brief.** WHP fonctionne sous Windows Home et Pro sans Hyper-V complet. KVM est présent sur toutes les distributions modernes.
5. **Le meilleur de chaque plateforme.** Firecracker est le VMM minimal le plus éprouvé en production sous KVM. Sous WHP, OpenVMM est le seul VMM mémoire-sûr porté par Microsoft. Le coût de deux backends est contenu par un contrat invité commun et une même suite de tests d'évasion.

### 5.2 Architecture en couches

```text
 HÔTE (Windows / Linux) ── trust boundary T0 : noyau hôte + hyperviseur (TCB non réductible)
 │
 ├─ Kaput Supervisor (privilèges utilisateur ; aucun parseur de données invitées)
 │     vérifie l'image signée, ouvre les fichiers, crée les sandboxes, tue tout à la fermeture
 │
 ├─ [S1] Processus VMM      ── sandbox : pas de FS (handles hérités), PAS de réseau,
 │        Firecracker | OpenVMM     pas de vue processus, pas de GUI, job/cgroup, kill-on-close
 │        relais vsock ──────────────┐
 ├─ [S2] Broker réseau      ── réseau sortant uniquement ; politique d'égress + DNS (DoH)
 ├─ [S3] Viewer / entrées   ── GUI uniquement ; analyse des cadres (format fixe)
 ├─ [S4] Broker audio (opt.)── sortie audio uniquement ; PCM format fixe
 │                                   │ (sockets AF_UNIX / named pipes, une par service)
 ════════════ trust boundary T1 : virtualisation matérielle (VT-x/AMD-V, EPT/NPT) ════════════
 │
 └─ INVITÉ Linux minimal (rootfs ro + dm-verity, tmpfs, pas de shell interactif)
       ├─ agent Kaput (uid dédié, seul autorisé à ouvrir AF_VSOCK)
       └─ navigateur (uid non privilégié) ── trust boundary T2 : sandbox du navigateur
             └─ renderers (seccomp-bpf + namespaces)
```

**Chaîne d'attaque minimale pour atteindre l'utilisateur hôte :**
1. RCE dans le renderer.
2. Évasion de la sandbox du navigateur.
3. LPE noyau invité (vsock et virtqueues réservés à root ou à l'uid agent).
4. Bogue dans le VMM **ou** dans un broker.
5. Évasion du sandbox S1 ou Sx (LPE noyau hôte ou bogue de l'hyperviseur).

L'objectif de défense en profondeur est d'exiger **au moins trois vulnérabilités indépendantes** après la compromission du renderer.

### 5.3 Confinement du VMM — Linux (sans root)

- **Prérequis.** L'utilisateur a accès à `/dev/kvm` (groupe `kvm`, ou `uaccess` selon la distribution). Ce point dépend de la distribution et doit être documenté.
- **Namespaces.** user, mount (racine tmpfs + `pivot_root`, ne contenant que le binaire, `/dev/kvm` et les descripteurs hérités), **PID** (aucun processus de l'utilisateur adressable par ptrace ou kill), **net vide** (pas d'interface ; cela isole aussi les sockets Unix *abstraits*, par exemple X11 ou D-Bus), IPC, UTS.
- **Ubuntu ≥ 24.04** restreint les user namespaces non privilégiés via AppArmor : le paquet doit fournir un profil dédié **[À VÉRIFIER par l'agent Linux]**.
- **Filtrage.** seccomp de Firecracker par thread, à conserver par défaut, plus un filtre externe empilé : interdiction de `ptrace`, `process_vm_*`, `execve` après démarrage, `socket` hors `AF_UNIX`. Plus `PR_SET_NO_NEW_PRIVS` et **Landlock** (FS en lecture seule sur l'image ; ABI récentes pour TCP et le scoping signaux/sockets abstraits, selon la version du noyau).
- **Ressources.** cgroup v2 via un scope systemd utilisateur (`memory.max`, `pids.max`, `cpu.max`). `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` (pas de core contenant la RAM invitée).
- **MAC optionnel.** Profil AppArmor ou SELinux livré quand la distribution l'active. On ne compte pas dessus comme unique couche (le comportement varie selon la distribution, comme le souligne le brief §11).
- **Variante plus forte.** Un uid dédié distinct de l'utilisateur via un helper privilégié installé, comme le jailer. Cela demande un privilège à l'installation : **décision utilisateur** (§9).

### 5.4 Confinement du VMM — Windows

- **Token.** Processus lancé par le superviseur avec un token **AppContainer, de préférence LPAC**, **sans capability** (`internetClient` absent, donc aucun réseau). Repli : token restreint + intégrité *Low/Untrusted* + SIDs *deny-only* (modèle Chromium/crosvm).
- **Job object.** `KILL_ON_JOB_CLOSE` (garantit l'arrêt forcé), pas de processus enfant, plafond mémoire, restrictions UI (pas de presse-papier, pas de hooks globaux).
- **Mitigations.** CFG, ACG (pas de code dynamique), *strict handle checks*, **lockdown win32k** (le VMM n'a pas de fenêtre ; le viewer est un autre processus), *image load* limité aux binaires signés Kaput/Microsoft, blocage des points d'extension legacy, `SeImpersonatePrivilege` retiré. Ces durcissements reprennent ceux de vmwp ([MSRC](https://www.microsoft.com/en-us/msrc/blog/2019/09/attacking-the-vm-worker-process)).
- **Ressources.** Seuls des handles dupliqués explicitement : image en lecture seule, pipes vers les brokers. Aucun chemin de fichier n'est accessible.
- **Inconnue critique.** `WHvCreatePartition` et `WHvSetupPartition` fonctionnent-ils depuis un AppContainer ou LPAC ? Faut-il une ACL sur les objets VID ? **[À VÉRIFIER-PoC, bloquant]**. Si non : restricted token + Low IL, ou compte de service virtuel dédié, ce qui suppose un privilège à l'installation.
- **WER.** Exclure le VMM des rapports et dumps WER (sinon la RAM invitée finit dans `%LOCALAPPDATA%\CrashDumps` ou dans les rapports).

### 5.5 Brokers

- Mêmes primitives que le VMM, avec **un seul privilège chacun** : réseau pour S2, GUI pour S3, audio pour S4.
- Protocoles à trames de taille plafonnée, sans sérialiseur générique. Code Rust, `#![forbid(unsafe_code)]` hors FFI. Fuzzing continu (cargo-fuzz) dans la CI. Ces brokers sont **notre propre surface d'attaque** et doivent recevoir le même niveau d'audit qu'un VMM.

---

## 6. Réseau (vue runtime ; politique détaillée par l'agent Réseau)

- **Pas de NIC invitée.** Le navigateur est configuré avec un proxy SOCKS5 ou HTTP CONNECT exposé par l'agent invité, relayé par vsock vers **S2**.
- S2 résout lui-même le DNS (DoH vers un résolveur choisi), **après** quoi il applique la politique : refus de loopback, RFC1918, CGNAT, link-local, ULA/fe80::/10, multicast et adresses de l'hôte. Le contrôle **sur l'IP résolue** protège contre le DNS rebinding. Le cache DNS de l'OS hôte n'est pas utilisé (pas d'artefact).
- Avec cette architecture, le VMM **n'a aucun accès réseau**. C'est le contraire de libkrun/TSI ou de slirp intégré au VMM.
- **Compromis à valider (§9) :** TCP uniquement, donc pas de QUIC (le repli vers TCP est automatique dans les navigateurs) et pas de WebRTC UDP direct (seulement TURN/TCP, ou WebRTC désactivé).
- Alternative : `virtio-net` + NAT userspace mémoire-sûr dans un processus dédié. À notre connaissance, OpenVMM inclut un NAT userspace en Rust (« consomme »), non vérifié faute de budget de recherche. Cette alternative ajoute un périphérique et une pile TCP/IP exposée.

---

## 7. Persistance et résidus forensiques (périmètre runtime)

| Résidu | Linux | Windows | Mesure |
|---|---|---|---|
| Disque de session | aucun (tmpfs invité) | aucun | Conception |
| RAM invitée paginée | swap hôte | pagefile, *memory compression store* | Documenter ; recommander swap chiffré / BitLocker. `mlock` impossible à grande échelle sans privilège. **Risque résiduel** |
| Hibernation | image d'hibernation | `hiberfil.sys` | Documenter ; détecter et avertir |
| Dumps de crash du VMM | core dumps, systemd-coredump | WER LocalDumps | `RLIMIT_CORE=0`, `PR_SET_DUMPABLE=0` ; exclusion WER |
| Cache DNS hôte | systemd-resolved | service DNS Client | Résolution dans S2 (DoH), jamais par l'OS |
| Journaux | journald | ETW / journal d'événements | Logs Kaput sans URL ni contenu ; pas de console série en release |
| Traces de lancement | historique du shell, .desktop | Prefetch, Amcache | Révèlent l'**usage** de Kaput, pas le contenu : risque accepté |
| Fichiers temporaires du VMM | aucun (racine tmpfs dans un mount ns) | répertoire AppContainer | Purge au démarrage et à l'arrêt |

La destruction se fait ainsi : arrêt de l'agent, puis kill du processus VMM (job ou cgroup), puis libération de la mémoire par l'OS. Le contenu de la RAM n'est **pas** garanti effacé physiquement avant réallocation. En pratique, le noyau met à zéro les pages avant de les donner à un autre processus, mais elles restent lisibles à froid ou dans une image d'hibernation.

---

## 8. Risques résiduels

1. **Hyperviseur et noyau hôte (T0).** Une vulnérabilité KVM, Hyper-V ou vid.sys contourne toutes les couches. Mitigation : mises à jour de l'OS (hors de notre contrôle), surface minimale exposée, évasion du VMM confiné nécessaire pour la plupart des chemins.
2. **Canaux auxiliaires CPU** (famille Spectre/MDS/L1TF/Retbleed). Ils dépendent du microcode et des mitigations de l'hyperviseur. Kaput peut vérifier et avertir, pas corriger.
3. **Bogues logiques ou `unsafe` dans des VMM Rust** : déjà observés en 2026 chez Firecracker et Cloud Hypervisor. Mitigation : features minimales, fuzzing, mise à jour rapide des commits épinglés, confinement.
4. **Brokers Kaput** : code nouveau et peu audité. Mitigation : protocoles triviaux, fuzzing, audit offensif indépendant (brief §16).
5. **Deux backends** : deux TCB à suivre, avec des divergences comportementales possibles. Mitigation : contrat invité unique, suite d'évasion identique sur les deux.
6. **OpenVMM** : absence de releases et de processus d'avis connu, donc dépendance à notre veille.
7. **Résidus mémoire** (pagefile, swap, hibernation) : non éliminables sans privilèges ou configuration de l'hôte.
8. **Exposition de vsock dans l'invité** : sans restriction, tout processus invité pourrait parler aux brokers. Mitigation : seul l'uid agent est autorisé (LSM ou seccomp invité) et la sandbox du navigateur interdit les sockets.

---

## 9. Décisions nécessitant l'avis de l'utilisateur

1. **Deux backends** (Firecracker Linux + OpenVMM Windows), recommandé, **ou** un VMM unique OpenVMM (maintenance plus simple, mais Linux moins éprouvé) ?
2. **Fail-closed sans virtualisation matérielle.** Kaput refuse de démarrer sans KVM/WHP, au lieu de se replier sur des conteneurs ou gVisor. Recommandé : refuser.
3. **Privilège exceptionnel à l'installation sous Windows** : administrateur une fois pour activer WHP (avec redémarrage), plus éventuellement la création d'un compte de service virtuel si l'AppContainer est incompatible avec WHP.
4. **Linux** : ajout de l'utilisateur au groupe `kvm` et profil AppArmor userns (privilège à l'installation). Faut-il aussi un helper privilégié pour un uid VMM distinct ?
5. **Réseau TCP-only via proxy** : pas de WebRTC UDP ni de QUIC natif. Acceptable pour la v1 ?
6. **Pas d'accélération GPU** : rendu logiciel, donc vidéo HD et WebGL dégradés.
7. **Audio** désactivé par défaut (activable, sortie seule) ; micro et caméra exclus en v1.
8. **Presse-papier et export de téléchargements** désactivés. Faut-il un mode opt-in unidirectionnel en v1 ou plus tard ?
9. **Périmètre matériel** : x86_64 seul en v1, ou aussi Windows on ARM / Linux arm64 ?
10. **Version minimale de Windows** : Windows 11 récent seulement, aligné sur les prérequis WHP d'OpenVMM, ou maintien de Windows 10 (fin de support grand public en 2025, ESU) ?

---

## 10. Inconnues (à lever par PoC avant l'ADR 0001)

| # | Inconnue | Bloquant ? | Méthode |
|---|---|---|---|
| U1 | Un build OpenVMM minimal (features) : taille réelle de la TCB, crates liées | Oui (Windows) | Build et mesure `cargo tree` / `tokei` |
| U2 | OpenVMM sur WHP : virtio-vsock ou hvsocket ? Point de sortie côté hôte ? virtio-blk via MMIO ou PCI ? | Oui | PoC boot direct d'un noyau Linux |
| U3 | WHP utilisable depuis un AppContainer/LPAC, ou au minimum depuis un token restreint Low IL | Oui | PoC Windows 11 Home et Pro |
| U4 | Débit et latence de l'affichage sur vsock (1080p, 60 Hz, damage rects) vs framebuffer partagé | Oui (UX) | Benchmark sur les deux backends |
| U5 | Firecracker sans root sur Debian, Ubuntu, Fedora et Arch (permissions `/dev/kvm`, userns, AppArmor) | Non | Matrice CI |
| U6 | Coexistence avec VBS/HVCI, VirtualBox, VMware et WSL2 sur le même hôte ; virtualisation imbriquée | Non | Matrice de tests |
| U7 | Processus de publication des vulnérabilités OpenVMM (MSRC, GHSA ?) | Non | Contact et veille |
| U8 | État réel du support Windows de crosvm en aval (qui le teste, à quel rythme) | Repli | Analyse du dépôt et des builds |
| U9 | Disponibilité de HCS/Hyper-V sur Windows Home (comparaison seulement) | Non | Doc Microsoft (non vérifiée ici, budget de recherche épuisé) |

**Critères de validation du PoC pour OpenVMM :**
- U1 : TCB liée raisonnable, sans VMBus, UEFI ni chipset legacy si c'est évitable.
- U2 : contrat invité identique à Firecracker, ou un écart justifié.
- U3 : sandbox équivalente au §5.4.

Si ces critères échouent, le PoC passe à crosvm/WHPX.

---

## 11. Sources

- Brief produit : `docs/product-brief.md`
- OpenVMM :
  - [dépôt GitHub](https://github.com/microsoft/OpenVMM)
  - [guide utilisateur](https://github.com/microsoft/openvmm/blob/main/Guide/src/user_guide/openvmm.md)
  - [guide dev Windows (miroir)](https://github.stwitter.workers.dev/microsoft/openvmm/blob/main/Guide/src/dev_guide/getting_started/windows.md)
  - [Windows OS Platform Blog, The OpenVMM project](https://www.elevenforum.com/t/the-openvmm-project.48844/)
  - [The New Stack (2024)](https://thenewstack.io/microsoft-open-sources-openvmm-rust-powered-vm-monitor/)
  - [HostZealot (2024)](https://www.hostzealot.com/blog/news/next-generation-virtualization-microsoft-introduces-openvmm-in-rust)
  - [OSFY (août 2026)](https://www.opensourceforu.com/2026/08/microsofts-openvmm-gains-intel-arm-contributions/)
  - [OpenHCL announcement](https://techcommunity.microsoft.com/blog/windowsosplatform/openhcl-the-new-open-source-paravisor/4273172)
- crosvm :
  - [Hypervisor support](https://crosvm.dev/book/hypervisors.html)
  - [Build Windows](https://crosvm.dev/book/building_crosvm/windows.html)
  - [ARCHITECTURE.md](https://android.googlesource.com/platform/external/crosvm/+/052742a1a/ARCHITECTURE.md)
  - [sandbox Windows](https://android.googlesource.com/platform/external/crosvm/+/44e40e1560890dbf34a731e19bab24b7f2c72b8a/sandbox/src/lib.rs)
- Firecracker :
  - [design.md](https://raw.githubusercontent.com/firecracker-microvm/firecracker/main/docs/design.md)
  - [jailer.md](https://github.com/firecracker-microvm/firecracker/blob/main/docs/jailer.md)
  - [AWS bulletin 2026-015 / CVE-2026-5747](https://aws.amazon.com/security/security-bulletins/2026-015-aws)
- Cloud Hypervisor :
  - [CVE-2026-27211](https://www.cvelogic.com/cve/CVE-2026-27211)
  - [CVE-2026-45782](https://www.tenable.com/cve/CVE-2026-45782)
  - [Spectrum OS, Landlock](https://inbox.spectrum-os.org/spectrum-devel/20251110184907.346511-1-hi@alyssa.is/t)
  - [MSHV / Linux root partition](https://www.theregister.com/2021/02/17/linux_as_root_partition_on_hyper_v/)
- QEMU :
  - [docs WHPX (patch 2026)](https://patchew.org/QEMU/20260327011152.4126-1-mohamed@unpredictable.fr/20260327011152.4126-3-mohamed@unpredictable.fr)
  - [WHPX x86 updates 2026-02](https://patchew.org/QEMU/20260223083734.48533-1-mohamed@unpredictable.fr)
  - [WHPX support for Arm](https://patchew.org/QEMU/20260115001505.57237-1-mohamed@unpredictable.fr)
  - [ZDI-26-332 / CVE-2026-3886](https://zerodayinitiative.com/advisories/ZDI-26-332)
  - [Wiz CVE-2026-3886](https://www.wiz.io/vulnerability-database/cve/cve-2026-3886)
  - [CVE-2026-48914](https://www.tenable.com/cve/CVE-2026-48914)
- libkrun : [dépôt](https://github.com/containers/libkrun), [A3S Lab, backend WHPX (2026-03)](https://a3s-lab.github.io/a3s/blog/en/libkrun-libkrunfw-whpx)
- Hyperlight : [CNCF blog 2026-11-09](https://www.cncf.io/blog/2026/11/09/run-linux-applications-in-hypervisor-isolated-micro-vms-with-hyperlight/)
- gVisor : [Introduction to gVisor security](https://gvisor.dev/docs/architecture_guide/intro/)
- Windows :
  - [WHP API](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform)
  - [Windows Sandbox](https://learn.microsoft.com/en-us/windows/security/application-security/application-isolation/windows-sandbox/windows-sandbox-overview)
  - [Activer WHP (ElevenForum)](https://www.elevenforum.com/t/enable-or-disable-windows-hypervisor-platform-in-windows-11.38917/latest)
  - [Google Play Games, WHP (mention Win10 Home)](https://support.google.com/googleplay/answer/11913190?hl=en)
  - [Android Emulator acceleration (WHPX, HAXM déprécié, AEHD fin 2026)](https://developer.android.com/studio/run/emulator-acceleration)
  - [MSRC, Attacking the VM Worker Process](https://www.microsoft.com/en-us/msrc/blog/2019/09/attacking-the-vm-worker-process)
  - [CVE-2026-45607](https://www.action1.com/vulnerabilities/cve-2026-45607/)
  - [CVE-2026-45641](https://www.action1.com/vulnerabilities/cve-2026-45641/)
- Chromium : [Sandbox design](https://chromium.googlesource.com/chromium/src/+/refs/heads/lkgr/docs/design/sandbox.md)
- Pwn2Own Berlin 2026 : [Trend Micro / ZDI](https://www.trendmicro.com/en/research/26/f/pwn2own-berlin-2026.html)
