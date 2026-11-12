# 02 — Hôte Windows : frontière d'isolation et privilèges minimaux

| Champ | Valeur |
|---|---|
| Rôle | Windows Security Engineer (phase 0, Discovery) |
| Date de l'état de l'art | 12 novembre 2026 |
| Statut | Recherche. Aucune décision définitive : à arbitrer dans `PROJECT_ANALYSIS.md` et dans les ADR |
| Périmètre | Côté **hôte Windows** uniquement : hyperviseur, confinement du VMM, privilèges, réseau hôte, disques, packaging, signature, artefacts. Le choix du VMM, de l'image invitée et du navigateur relève d'autres agents |

> Note de méthode. Les faits datés (versions, prix, éligibilité) ont été vérifiés en ligne le 12/11/2026 (liens en §12). Le budget de recherche web de la session a été épuisé avant la fin : les points marqués **[non revérifié]** viennent de connaissances antérieures et doivent être confirmés. Les points marqués **[PoC]** ne peuvent être tranchés que par un test sur une machine réelle.

---

## 1. Résumé exécutif

1. Toutes les options Windows sérieuses (Hyper-V, HCS, WHP, Windows Sandbox, VBS) reposent sur **le même hyperviseur Microsoft** ; la frontière « VM » est une frontière de sécurité officiellement maintenue par Microsoft (avec bug bounty). La différence se joue sur **ce qui tourne côté hôte** (VMM, services, réseau) et sur **les privilèges requis**.
2. Recommandation : **Windows Hypervisor Platform (WHP)** + un **VMM en mode utilisateur, minimal, lancé en utilisateur standard et confiné en AppContainer/LPAC** (ou, à défaut, jeton restreint + Job object), sans service système, sans pilote, sans vSwitch.
3. Le réseau passe par une **pile réseau en espace utilisateur dans un processus « broker » séparé** qui applique une politique deny-by-default (pas de LAN, pas de loopback, pas de RFC1918/ULA/link-local, DNS chiffré géré par Kaput). Pas de HNS/WinNAT/Default Switch.
4. Aucun disque invité inscriptible sur le disque hôte : image en lecture seule vérifiée, état de session en RAM.
5. Privilèges : **administrateur une seule fois à l'installation** (activer la fonctionnalité `HypervisorPlatform`, reboot, installation per-machine) ; **exécution sans élévation**. Ne jamais ajouter l'utilisateur au groupe « Hyper-V Administrators » (non-frontière selon Microsoft).
6. WHP est utilisable sur **Windows 11 Home** (forte confiance, à confirmer [PoC]) ; Hyper-V, HCS « officiel » et Windows Sandbox ne le sont pas. Exclure Home n'est donc pas nécessaire avec cette architecture.
7. Points critiques non résolus : fonctionnement de WHP **dans un AppContainer** [PoC], maturité du VMM (QEMU-WHPX vs OpenVMM vs VMM dédié), pagination/dumps de la RAM invitée (qui vit dans un processus hôte), et **signature** (un particulier belge n'est pas éligible à Azure Artifact Signing).

---

## 2. Contexte plateforme (novembre 2026)

### 2.1 Versions supportées

| Produit | Version | Fin de support | Remarque |
|---|---|---|---|
| Windows 11 Home/Pro | 24H2 (build 26100) | **14/10/2026 — terminé** | Toujours supporté en Enterprise/Education [non revérifié : 36 mois pour les versions H2] |
| Windows 11 Home/Pro | 25H2 (26200) | 13/10/2027 | Même base de code que 24H2 |
| Windows 11 Home/Pro | 26H1 | 15/03/2028 | Réservée à de nouveaux appareils (Snapdragon X2), pas une mise à jour générale |
| Windows 11 Home/Pro | 26H2 | 10/10/2028 | Publiée le 29/09/2026 |
| Windows 10 | 22H2 | Fin de support 14/10/2025 ; **ESU grand public prolongé jusqu'au 12/10/2027** | Inscription gratuite (sauvegarde Windows / points Rewards) ou 30 USD |

Sources : [cycle de vie Windows 11 Home/Pro](https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro), [26H1 réservé aux nouveaux appareils](https://www.windowscentral.com/microsoft/windows-11/microsoft-confirms-windows-11-version-26h1-support-lifecycle-dates-heres-how-long-your-new-snapdragon-x2-laptop-will-be-supported-on-26h1), [prolongation ESU Windows 10](https://www.helpnetsecurity.com/2026/06/26/microsoft-windows-10-free-security-updates-esu-program/).

**Proposition de cible** : Windows 11, build 26100 ou plus (24H2 Enterprise/Education, 25H2, 26H1, 26H2), x64 et ARM64, version encore en support. Justification :
- QEMU-WHPX sur ARM64 exige 24H2 avec les mises à jour d'avril/mai 2025 (API WHP ARM64 définitive) ([doc QEMU WHPX](https://qemu.readthedocs.io/en/master/system/whpx.html)).
- OpenVMM et Hyperlight (deux VMM Microsoft basés sur WHP) exigent Windows 11 ([OpenVMM, Windows](https://github.stwitter.workers.dev/microsoft/openvmm/blob/main/Guide/src/dev_guide/getting_started/windows.md), [Hyperlight README](https://docs.rs/crate/hyperlight-host/0.9.0/source/README.md)).
- Windows 10 sous ESU reçoit des correctifs de sécurité mais plus d'évolutions de l'API WHP ; le supporter doublerait la matrice de test. Voir décision D-2.

### 2.2 Fait structurant : VBS est souvent déjà actif

Sur les installations récentes de Windows 11 24H2+, **VBS est activé par défaut** ; l'hyperviseur Microsoft est donc déjà chargé sous Windows, et tout hyperviseur tiers doit passer par WHP (mode imbriqué/« nested » sinon) ([KB Broadcom 417896](https://knowledge.broadcom.com/external/article/417896/after-the-host-os-upgrade-to-version-win.html)). Conséquence directe : **Kaput ne doit jamais demander de désactiver VBS/HVCI/Credential Guard** ni `hypervisorlaunchtype` — ce serait une régression de sécurité de l'hôte. Une architecture WHP coexiste nativement avec VBS.

---

## 3. Analyse par mécanisme

### 3.1 Base commune : l'hyperviseur Microsoft et ses frontières officielles

Les [critères de servicing sécurité de Microsoft](https://microsoft.com/msrc/windows-security-servicing-criteria) définissent ce qui est une frontière de sécurité (correctif + bounty) :

| Frontière | Servicée | Pertinence Kaput |
|---|---|---|
| Virtual machine boundary (« un invité non autorisé ne peut accéder au code/données d'un autre invité » ; l'hôte inclus de fait) | Oui | Frontière principale invité → hôte |
| AppContainer sandbox boundary | Oui | Confinement du VMM et du broker réseau (défense en profondeur) |
| User boundary | Oui | Isolation entre utilisateurs Windows |
| VBS boundary | Oui | Protège l'hôte (secrets LSA, intégrité noyau), pas l'invité |
| Administrator-to-kernel | **Non** | Tout composant Kaput admin ≈ noyau |
| **Hyper-V Administrators** | **Non** (non-frontière vis-à-vis d'Administrators) | Ajouter l'utilisateur à ce groupe équivaut à le rendre administrateur |

Trust boundaries à retenir côté Windows :
- **TB-1** invité ↔ hyperviseur (le noyau Microsoft, hors de notre contrôle) ;
- **TB-2** invité ↔ VMM utilisateur (émulation de périphériques, l'essentiel de la surface d'attaque de Kaput) ;
- **TB-3** VMM ↔ reste de la session utilisateur (AppContainer/jeton restreint) ;
- **TB-4** broker réseau ↔ réseau local/hôte (politique réseau) ;
- **TB-5** utilisateur ↔ administrateur/SYSTEM (ne doit **pas** être traversée à l'exécution).

### 3.2 Hyper-V « complet » (VMMS, WMI, PowerShell)

- **Éditions** : Pro, Enterprise, Education (pas Home).
- **Privilèges** : administrateur ou membre de « Hyper-V Administrators ». Ce groupe n'est pas une frontière ([MSRC](https://microsoft.com/msrc/windows-security-servicing-criteria)) : un membre peut créer une VM attachée à un disque physique de l'hôte ou monter des VHD arbitraires, ce qui mène à l'administrateur.
- **Atouts** : pile mûre, bounty, processus de travail par VM sous un compte virtuel dédié [non revérifié], périphériques synthétiques VMBus.
- **Problèmes pour Kaput** : service VMMS (SYSTEM), configuration persistante des VM (inventaire, journaux, fichiers `.vmcx/.vmrs`), réseau via vSwitch, console via VMConnect/RDP (surface d'attaque large), indisponible sur Home.
- **Verdict** : non retenu comme runtime.

### 3.3 Host Compute Service (HCS) et Host Compute Network (HCN)

- **HCS** (`computecore.dll`) crée et contrôle VM et conteneurs à partir de documents JSON ; les compute systems sont **éphémères** (nettoyés à l'arrêt), mais le client doit préparer lui-même le VHD, le réseau (HCN) et les sockets Hyper-V ([vue d'ensemble HCS](https://learn.microsoft.com/fr-fr/virtualization/api/hcs/overview)). C'est la couche utilisée par WSL2, les conteneurs Windows et Windows Sandbox.
- **HCN** est hébergé par le service **HNS** ; il gère réseaux, endpoints et politiques ([HCN API](https://learn.microsoft.com/en-us/windows-server/networking/technologies/hcn/hcn-top)). La documentation n'est formellement « applicable » qu'à Windows Server.
- **Privilèges** : dans la pratique, un administrateur **et** l'appartenance à « Hyper-V Administrators » ; Lima (driver HCS expérimental) l'exige explicitement, avec une seule instance à la fois et un sous-réseau HCN fixe ([Lima HCS](https://lima-vm.io/docs/config/vmtype/hcs/)). WSL contourne cela avec un **service SYSTEM** (`wslservice.exe`) qui appelle HCS pour l'utilisateur.
- **Home** : HCS est présent via « Virtual Machine Platform » (WSL2 fonctionne sur Home), mais son usage direct par un tiers sur Home n'est pas documenté [PoC / non supporté].
- **Sockets Hyper-V (hvsocket)** : l'enregistrement d'un service GUID se fait sous `HKLM\...\Virtualization\GuestCommunicationServices` et **exige l'administrateur** ([intégration services](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service)).
- **Verdict** : techniquement solide (périphériques Microsoft), mais impose soit l'exécution en admin, soit un **service broker SYSTEM** livré par Kaput — un nouveau composant privilégié exposé à tous les processus de l'utilisateur, et donc une cible d'élévation locale. Conserver comme **alternative documentée** (ADR) si le PoC WHP échoue.

### 3.4 Windows Hypervisor Platform (WHP) — option recommandée

- **Nature** : API C (`WinHvPlatform.dll`) qui permet à un VMM en mode utilisateur de créer une partition, mapper la mémoire, exécuter des vCPU et traiter les sorties (I/O, MMIO). **La mémoire invitée est de la mémoire du processus VMM** (`VirtualAlloc` ou fichier mappé) ([API WHP](https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform)). Disponible depuis Windows 10 1803 ; support ARM64 détectable via `WHvGetCapability`.
- **Activation** : fonctionnalité optionnelle `HypervisorPlatform` ; **admin + redémarrage** requis ([Eleven Forum](https://www.elevenforum.com/t/enable-or-disable-windows-hypervisor-platform-in-windows-11.38917/latest)). Le statut peut être vérifié **sans élévation** via `WHvGetCapability` plutôt que `Get-WindowsOptionalFeature` (qui exige l'élévation) ([pvm PR #1](https://github.com/huangzheng2016/pvm/pull/1)).
- **Exécution en utilisateur standard** : forte indication (aucune mention d'élévation dans les docs Microsoft, QEMU ou pywinhv ; un projet rapporte WHPX détecté en utilisateur standard ([pvm PR #1](https://github.com/huangzheng2016/pvm/pull/1), [pywinhv](https://github.com/0vercl0k/pywinhv))). **À confirmer [PoC-1]**, y compris sur Home.
- **Coexistence VBS/HVCI** : native (WHP est l'interface officielle vers l'hyperviseur déjà chargé).
- **Surface côté hôte** : tout ce que le VMM émule (virtio, horloge, interruptions) tourne dans **un processus utilisateur que nous contrôlons et pouvons confiner**. C'est à la fois l'avantage (pas de service privilégié, confinement possible) et le risque (la qualité du VMM détermine TB-2).
- **Fonctions WHP à ne jamais utiliser** : assignation de périphériques VPCI (passthrough), mémoire partagée avec d'autres processus.

Choix du VMM (à trancher par le Virtualization Engineer) :

| VMM | Langage | Maturité sur WHP | Remarques sécurité |
|---|---|---|---|
| QEMU + `-accel whpx` | C | Testé depuis Windows 10 2004 ; ARM64 depuis 24H2 | Énorme surface si non restreinte : compiler avec un jeu minimal de périphériques, machine `microvm`/`virt`. Option `ssd` (« separate security domain ») à **laisser activée** : la désactiver améliore les perfs MMIO mais affaiblit les mitigations ([doc](https://qemu.readthedocs.io/en/master/system/whpx.html)) |
| OpenVMM (Microsoft) | Rust | Supporte WHP x64/ARM64, mais **« pas encore prêt pour des charges utilisateurs » sur l'hôte**, pas de stabilité d'API ([The Register](https://www.theregister.com/2024/10/17/microsoft_preps_rust_hypervisor_for/), [blog OpenVMM](https://www.elevenforum.com/t/the-openvmm-project.48844/)) | Architecture pensée pour la séparation en processus et la sûreté mémoire ; candidat sérieux à moyen terme |
| Hyperlight (Microsoft) | Rust | Micro-VM pour fonctions, pas pour un OS complet | Non adapté à un Linux + navigateur |
| VMM dédié Kaput | Rust | À construire | Surface minimale (virtio-blk ro, virtio-net ou vsock, virtio-gpu 2D/framebuffer, input, RNG), coût de développement et d'audit élevé |

### 3.5 Virtual Machine Platform et WSL2

- « Virtual Machine Platform » fournit la base de WSL2 et est disponible sur Home ([pureinfotech](https://pureinfotech.com/hyperv-virtual-machine-platform-windows-hypervisor-platform/)).
- **WSL2 est exclu comme runtime Kaput** : un serveur plan9 lancé par `wslservice.exe` expose les lecteurs Windows à l'invité, et un processus invité peut monter un lecteur par simple `mount -t drvfs C: ...` tant que ce serveur tourne ([wsl.dev drvfs](https://wsl.dev/technical-documentation/drvfs/)) ; Canonical rappelle qu'une instance WSL est « aussi sûre qu'un programme arbitraire du compte utilisateur » ([sécurité Ubuntu WSL](https://documentation.ubuntu.com/wsl/en/stable/_sources/explanation/security-overview.md.txt)). Les options `wsl.conf` (interop, automount) sont appliquées **dans l'invité**, donc contournables par un invité compromis. Toutes les distributions partagent en outre une même VM utilitaire et un même noyau.

### 3.6 Windows Sandbox

- **Éditions** : Pro, Enterprise, Education ; **pas Home**. Une seule instance à la fois. Invité **Windows** uniquement (pas de Linux), ce qui ne correspond pas à l'architecture cible du brief. Les données persistent à travers un redémarrage initié dans la sandbox (Windows 11 22H2+) ; tout est supprimé à la fermeture ([vue d'ensemble](https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox)).
- **Configuration `.wsb`** ([doc](https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file)) : réseau **activé par défaut via le Default Switch** (Microsoft avertit d'une exposition possible du réseau interne), vGPU activé par défaut (Microsoft note que cela augmente la surface d'attaque), presse-papiers activé par défaut, entrée audio activée par défaut, `ProtectedClient` (client en AppContainer) **désactivé par défaut**. Ce sont des défauts orientés confort, opposés à ceux de Kaput.
- **Précédent utile** : `ProtectedClient` montre que Microsoft confine lui-même le client d'affichage d'une VM en AppContainer — même logique que celle proposée ici pour le VMM et l'UI.
- **Précédent d'alerte** : Microsoft Defender Application Guard (navigation Edge isolée par Hyper-V) a été **retiré de Windows 11 24H2** ([Neowin](https://www.neowin.net/news/microsoft-windows-11-24h2-ditches-defender-application-guard-and-browser-extensions-on-edge/)). Dépendre d'un produit d'isolation Microsoft de haut niveau expose Kaput à un retrait unilatéral ; WHP (API bas niveau utilisée par VMware, VirtualBox, QEMU, Android Emulator) est un pari plus stable.
- **Verdict** : non retenu.

### 3.7 AppContainer / LPAC pour confiner le VMM côté hôte

AppContainer est une frontière servicée ([MSRC](https://microsoft.com/msrc/windows-security-servicing-criteria)). Pour Kaput, l'intérêt est de limiter l'impact d'une évasion **TB-2** (invité → VMM) : un attaquant qui exécute du code dans le VMM ne doit obtenir ni les fichiers de l'utilisateur, ni le réseau, ni les autres processus.

Proposition de découpage (à valider par le Security Architect) :

| Processus | Jeton | Capacités | Rôle |
|---|---|---|---|
| `kaput.exe` (launcher/UI) | Utilisateur standard, intégrité moyenne | — | UI, vérification d'image, orchestration, kill switch. **Ne parse aucune donnée invitée complexe** |
| `kaput-vmm.exe` | **LPAC** (Less Privileged AppContainer), aucune capacité réseau | Accès lecture seule à l'image invitée (ACL par SID de package) | Partition WHP, émulation virtio. Reçoit ses handles (image, canal vers broker, mémoire partagée framebuffer) par héritage/duplication depuis le launcher |
| `kaput-net.exe` | AppContainer avec `internetClient` uniquement | Pas de `privateNetworkClientServer`, pas d'exemption loopback | Pile TCP/IP utilisateur + politique réseau + DNS chiffré |
| (optionnel) `kaput-display` | AppContainer, Win32k nécessaire | — | Rendu du framebuffer invité, séparé du launcher |

Mitigations de processus à appliquer au VMM et au broker (`SetProcessMitigationPolicy` / `PROC_THREAD_ATTRIBUTE_MITIGATION_POLICY`) : signature du code exigée (CIG, binaires Microsoft/Kaput seulement), ACG (pas de JIT dans un VMM matériel), interdiction des processus enfants, désactivation des appels système Win32k pour les processus sans fenêtre, désactivation des points d'extension, CET/shadow stacks, CFG, Job object avec `KILL_ON_JOB_CLOSE` et limites mémoire/processus.

Points ouverts :
- **[PoC-2, critique]** Les appels WHP (`WHvCreatePartition` et l'accès au pilote de virtualisation sous-jacent) fonctionnent-ils depuis un AppContainer/LPAC ? Aucune source publique trouvée. Repli : jeton restreint + intégrité basse + Job object (modèle de la sandbox Chromium), moins fort mais toujours utile.
- La notion de « réseau privé » de l'isolation réseau AppContainer repose sur une détection des sous-réseaux par Windows : c'est une **défense en profondeur**, jamais la politique réseau principale (qui doit être codée dans le broker).
- Un processus malveillant de **la même session utilisateur** peut probablement ouvrir les processus AppContainer de cet utilisateur : Kaput **ne protège pas la session contre un hôte déjà compromis** (hors modèle de menace, à écrire explicitement).

### 3.8 VBS, HVCI, Credential Guard

- Activés par défaut sur beaucoup de machines 24H2+ (§2.2). Ils durcissent **l'hôte** (intégrité du code noyau, isolation des secrets LSA) et réduisent l'impact d'une évasion suivie d'une élévation, mais ne protègent pas l'invité.
- Exigences pour Kaput : aucun pilote noyau (sinon : compatibilité HVCI, signature attestée Microsoft, surface noyau) ; aucune demande de désactivation ; détecter et **signaler** (sans bloquer) l'état HVCI/VBS dans le contrôle d'environnement.
- Les hyperviseurs tiers qui ne passent pas par WHP (anciens VMware/VirtualBox) tombent en mode imbriqué lent ([Broadcom](https://knowledge.broadcom.com/external/article/417896/after-the-host-os-upgrade-to-version-win.html)) : argument de plus pour WHP.

### 3.9 Droits administrateur et UAC

| Action | Admin requis ? | Source / statut |
|---|---|---|
| Activer `HypervisorPlatform` | Oui + reboot | [Eleven Forum](https://www.elevenforum.com/t/enable-or-disable-windows-hypervisor-platform-in-windows-11.38917/latest) |
| Vérifier la disponibilité WHP | Non (`WHvGetCapability`) | [pvm PR #1](https://github.com/huangzheng2016/pvm/pull/1) |
| Créer/exécuter une partition WHP | Non (attendu) | [PoC-1] |
| HCS / Hyper-V VM | Oui (ou groupe Hyper-V Administrators, ≈ admin) | [Lima](https://lima-vm.io/docs/config/vmtype/hcs/), [MSRC](https://microsoft.com/msrc/windows-security-servicing-criteria) |
| Enregistrer un service hvsocket | Oui | [doc Microsoft](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service) |
| Créer un réseau HCN/NAT, règles pare-feu Hyper-V | Oui (attendu) | [Hyper-V firewall](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall) |
| Installer dans `Program Files` | Oui | — |
| `ClearPageFileAtShutdown`, config WER machine | Oui | §7 |

### 3.10 Services système

- **Architecture WHP** : aucun service Kaput. Dépendances Windows : l'hyperviseur et la pile de virtualisation intégrée (aucun service tiers).
- **Architecture HCS** : `vmcompute` (HCS) + `hns` (HNS) + un service broker Kaput SYSTEM. À éviter.
- **Mises à jour** : pas de service de mise à jour SYSTEM (cf. §5.3).

### 3.11 Disques virtuels et stockage éphémère

Recommandation :
1. **Image invitée en lecture seule** (format choisi par le Linux Security Engineer, p. ex. erofs/squashfs + dm-verity), stockée sous `Program Files` (non inscriptible par l'utilisateur), **hachée et vérifiée par le launcher avant chaque démarrage**, puis exposée en virtio-blk **read-only** au VMM via un handle ouvert en lecture seule.
2. **Aucun fichier inscriptible côté hôte** pour la session : état du navigateur en tmpfs/zram **dans l'invité**, donc dans la RAM de la partition.
3. Si un disque de travail est indispensable (téléchargements volumineux) : volume adossé à la RAM du VMM, ou fichier temporaire **chiffré dans l'invité avec une clé éphémère jamais écrite sur disque** (effacement cryptographique), créé avec `FILE_FLAG_DELETE_ON_CLOSE` et nettoyé au démarrage suivant s'il survit à un crash.
4. **VHDX différentiels** : pertinents uniquement en voie HCS ; ils laissent des fichiers sur disque après crash et sont scannés (et potentiellement soumis comme échantillons) par Defender. À éviter.

### 3.12 Réseau virtuel et exposition du LAN

| Option | Admin | Risque LAN/hôte | Contrôle de politique | Verdict |
|---|---|---|---|---|
| vSwitch « Default Switch » / NAT HNS / WinNAT | Oui | L'invité obtient une adresse sur un réseau routé par l'hôte : accès potentiel aux services de l'hôte (passerelle, proxy DNS) et au LAN par NAT | Règles pare-feu hôte (admin) ; le [pare-feu Hyper-V](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall) (Win11 22H2+) cible les VM par `VMCreatorId` (exemples WSL) ; applicabilité à une VM tierce non documentée | Rejeté |
| Réseau externe (bridge) | Oui | Invité directement sur le LAN | Aucun côté hôte | Rejeté |
| **Pile réseau utilisateur dans un broker** (virtio-net ou vsock vers `kaput-net.exe`) | Non | L'invité n'a aucune interface sur un réseau hôte ; seules sortent les connexions que le broker accepte d'ouvrir | Politique codée, testable, fail-closed | **Recommandé** |

Politique minimale du broker (détail : Network Security Engineer) : refuser loopback (127/8, ::1), RFC1918, CGNAT 100.64/10, link-local (169.254/16, fe80::/10), ULA fc00::/7, multicast/broadcast, adresses des interfaces de l'hôte, métadonnées cloud (169.254.169.254) ; **résoudre le DNS lui-même en DoH/DoT** puis vérifier l'IP résolue contre la politique (anti-DNS-rebinding) ; ne **jamais** passer par le résolveur Windows (fuite et cache DNS de l'hôte, cf. §7). Le broker parse des données contrôlées par l'invité : il est une surface d'attaque (TB-2bis) et doit être en langage sûr, fuzzé, et confiné (§3.7).

### 3.13 Defender et contrôles Windows

- **Ne demander aucune exclusion Defender** par défaut (régression de sécurité, et exclusion exploitable par un malware de la session). L'architecture RAM-only rend les exclusions inutiles.
- Defender scannera l'image invitée et les binaires à l'installation/mise à jour (coût de démarrage à mesurer [PoC-6]) ; risques de faux positifs sur un VMM non réputé : mitigé par la signature et la réputation SmartScreen.
- **Smart App Control (SAC)** : vérifie **tout code chargé** (EXE, DLL, scripts) ; le code signé doit chaîner à une racine du **Microsoft Trusted Root Program** (un certificat ajouté localement ne compte pas) ; le code non signé n'est accepté que s'il est connu du cloud ; les fichiers MotW à extension dangereuse (dont `.msi`) peuvent être bloqués sans contournement. Depuis Windows 11 25H2, SAC peut être réactivé sans réinstallation, donc la base installée avec SAC actif va croître ([Eric Lawrence, 04/2026](https://textslashplain.com/2026/04/28/smart-app-control/), [CIAOPS](https://blog.ciaops.com/2026/04/16/existing-systems-can-now-enable-windows-smart-app-control-and-you-should/)). Conséquence : **chaque binaire et DLL Kaput doit être signé** (SHA-256, RSA recommandé).

---

## 4. Matrice éditions × options

| Option | Home | Pro | Enterprise | Education | Admin install | Admin exécution | Invité Linux | Verdict |
|---|---|---|---|---|---|---|---|---|
| Hyper-V (VMMS) | Non | Oui | Oui | Oui | Oui | Oui (ou groupe ≈ admin) | Oui | Rejeté |
| HCS/HCN direct | Non documenté | Oui | Oui | Oui | Oui | Oui + broker SYSTEM | Oui | Alternative de repli |
| Virtual Machine Platform / WSL2 | Oui | Oui | Oui | Oui | Oui | Non | Oui | Rejeté (exposition fichiers hôte) |
| Windows Sandbox | Non | Oui | Oui | Oui | Oui | Non | **Non** | Rejeté |
| **WHP + VMM utilisateur** | **Oui (forte confiance, [PoC-1])** | Oui | Oui | Oui | **Oui, une fois** | **Non (attendu)** | Oui | **Recommandé** |
| VBS/HVCI | Oui (selon matériel) | Oui | Oui | Oui | — | — | — | Préalable conseillé, jamais désactivé |
| AppContainer/LPAC | Oui | Oui | Oui | Oui | Non | Non | — | Confinement VMM/broker |

Avec WHP, **l'exclusion de Windows Home n'est pas nécessaire** ; elle ne le deviendrait que si le PoC-1 échoue sur Home ou si l'on choisit HCS.

Prérequis matériels communs : CPU 64 bits avec VT-x/AMD-V (ou virtualisation ARM64) + SLAT activés dans le firmware, 8 Go de RAM conseillés (l'invité + navigateur réservent de la RAM non partagée).

---

## 5. Modèle de privilèges recommandé

### 5.1 Installation (une élévation UAC)

1. Installateur MSI **per-machine**, signé, élévation UAC unique.
2. Copie des binaires et de l'image invitée signée dans `%ProgramFiles%\Kaput\` (ACL par défaut : non inscriptible par l'utilisateur).
3. Activation de `HypervisorPlatform` si absente (DISM/API), puis **redémarrage demandé** (jamais forcé).
4. Option explicite (case non cochée par défaut, décision D-5) : durcissements machine `ClearPageFileAtShutdown`, exclusion WER des processus Kaput.
5. **Ne fait pas** : création de service, pilote, tâche planifiée SYSTEM, ajout à « Hyper-V Administrators », règle pare-feu, exclusion Defender, désactivation de VBS.

### 5.2 Exécution (aucune élévation)

```text
Utilisateur standard (intégrité moyenne)
 └─ kaput.exe  ── vérifie WHP (WHvGetCapability), HVCI, version Windows, hash/signature image
     │            crée un Job object (KILL_ON_JOB_CLOSE, limites mémoire/processus)
     ├─ kaput-vmm.exe  [LPAC, aucune capacité réseau, mitigations CIG/ACG/no-child]
     │     └─ partition WHP ── Linux invité ── navigateur
     ├─ kaput-net.exe  [AppContainer, internetClient seul] ── Internet (politique deny-by-default)
     └─ affichage : mémoire partagée framebuffer en lecture seule pour l'UI
```

Arrêt : fermeture → arrêt propre de l'invité avec délai court → `WHvDeletePartition` → effacement explicite de la RAM invitée par le VMM → fin des processus ; **arrêt forcé** = `TerminateJobObject` (la partition appartenant au processus VMM, sa destruction est attendue à la mort du processus [PoC-3]). Au lancement suivant : nettoyage de tout résidu (fichiers temporaires, minidumps Kaput).

### 5.3 Mises à jour

- Binaires dans `Program Files` ⇒ leur mise à jour exige une **élévation UAC** à chaque version (MSI signé, vérifié avant exécution). C'est le prix d'une installation non altérable par l'utilisateur ; préférable à un service de mise à jour SYSTEM permanent (cible d'élévation).
- Variante à évaluer (D-4) : image invitée mise à jour **sans élévation** dans `%LOCALAPPDATA%` ; elle est alors modifiable par tout processus de l'utilisateur, donc **vérification de signature + anti-rollback obligatoire à chaque lancement** (chaîne de confiance : Update/Supply Chain Engineer).

---

## 6. Packaging et signature

### 6.1 Packaging

| Format | Pour | Contre | Verdict |
|---|---|---|---|
| **MSI (WiX)** | Per-machine, actions personnalisées n'importe où dans la séquence, contrôle des ACL, déploiement entreprise (Intune/GPO) | Signature MSI + binaires, SAC/MotW peut bloquer un `.msi` téléchargé non réputé | **Recommandé** |
| MSIX | Installation propre, désinstallation complète, Store re-signe gratuitement | Pas de pilotes, actions personnalisées limitées (avant/après lancement), registre virtualisé ; services seulement depuis Windows 2004 ([Advanced Installer](https://www.advancedinstaller.com/msix-limitations.html)) ; ne peut pas activer de fonctionnalité optionnelle Windows | Possible plus tard, avec étape d'activation WHP séparée |
| WinGet | Canal de distribution, mises à jour en ligne de commande | Pointe vers un installateur ; n'apporte pas de signature | Canal complémentaire pointant vers le MSI signé |
| EXE bootstrapper | — | Surface et réputation supplémentaires | À éviter |

Le packaging doit être **reproductible** (même source → mêmes octets avant signature) et accompagné d'un SBOM (Release/Supply Chain Engineers).

### 6.2 Signature de code (état au 12/11/2026)

| Option | Coût | Éligibilité | Remarques |
|---|---|---|---|
| **Azure Artifact Signing** (ex-Trusted Signing), GA janvier 2026 | 9,99 USD/mois (5 000 signatures) ; 99,99 USD/mois (100 000) | Organisations : US, Canada, UE, UK, Australie, NZ, Japon, Corée du Sud, Singapour, Suisse, Norvège, Israël. **Particuliers : US/Canada uniquement** | Certificats de 24 h renouvelés automatiquement, horodatage, intégration CI (GitHub Actions), pas d'EV, pas de token matériel ; CN = nom légal validé ([quickstart](https://learn.microsoft.com/azure/artifact-signing/quickstart), [DevClass](https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554)) |
| Certificat OV (DigiCert, Sectigo…) | ≈150–300 USD/an | Mondial, particuliers inclus | Clé sur HSM/token obligatoire depuis 2023 ; durée max **460 jours** depuis le 1/3/2026 ; même traitement SmartScreen qu'Artifact Signing ([options de signature](https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options)) |
| Certificat EV | ≥400 USD/an | — | **Ne contourne plus SmartScreen depuis 2024** : surcoût injustifié |
| SignPath Foundation | Gratuit | Projets open source qualifiés | Signature OV par une fondation (le nom affiché est celui de la fondation) |
| Store (MSIX) | Gratuit | Compte développeur | Microsoft re-signe ; inadapté au MSI per-machine |
| Auto-signé | Gratuit | — | Bloqué par SmartScreen/SAC ; tests uniquement |

Aucune option ne donne une réputation SmartScreen immédiate ; elle s'accumule en signant chaque version avec la **même identité d'éditeur**. La signature Authenticode Windows est **distincte** de la signature des images invitées et des métadonnées de mise à jour (qui doivent rester sous contrôle de Kaput, clé hors ligne, cf. agent Supply Chain).

---

## 7. Artefacts forensiques Windows et mitigations

Principe : le contenu de navigation vit dans la RAM de la partition, qui est **de la mémoire du processus VMM**. Toute voie par laquelle Windows copie la mémoire d'un processus sur disque est une voie de fuite. Les artefacts d'exécution « Kaput a été lancé » sont, eux, en grande partie inévitables pour un utilisateur standard et doivent être documentés honnêtement.

| Artefact | Ce qui peut fuir | Mitigation proposée | Risque résiduel |
|---|---|---|---|
| **pagefile.sys** | Pages de RAM invitée paginées | Réserver la RAM invitée et tenter `VirtualLock` (plafonné par le working set ; grandes pages = privilège `SeLockMemoryPrivilege`, donc admin) [PoC-4] ; chiffrement des données sensibles **dans l'invité** n'aide pas (l'invité voit du clair) ; option machine `ClearPageFileAtShutdown` (admin, ralentit l'arrêt) ; BitLocker/chiffrement de l'appareil | Élevé sans BitLocker |
| **hiberfil.sys** / veille prolongée | Toute la RAM, y compris l'invité | Détecter la mise en veille (`PowerRegisterSuspendResumeNotification`) et **détruire la session avant suspension** ; `SetThreadExecutionState` contre la veille sur inactivité ; recommander BitLocker | Moyen (veille forcée, coupure brutale) |
| **Dumps WER / LocalDumps** du VMM | Toute la RAM invitée | `WerAddExcludedApplication` (par utilisateur), `WerRegisterExcludedMemoryBlock` sur la RAM invitée (Windows 10 1703+, nombre de blocs limité par `WER_MAX_REGISTERED_ENTRIES`) ([doc](https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock)) ; aucun dump interne non chiffré | Faible-moyen (politique LocalDumps imposée par un admin) |
| **MEMORY.DMP** (BSOD) | Par défaut mémoire noyau ; une configuration « vidage complet » inclurait la RAM utilisateur | Détecter et signaler une configuration de vidage complet | Faible |
| Résidus en RAM physique après arrêt | Pages libérées non encore remises à zéro | Effacement explicite de la RAM invitée par le VMM avant libération | Faible (impossible si crash) |
| **Cache DNS Windows** | Domaines visités | Broker résout en DoH lui-même, jamais via `getaddrinfo`/client DNS Windows | Faible |
| **SRUM** | Octets réseau par application et horaires | Inévitable sans admin ; documenter | Moyen (métadonnées) |
| Prefetch, Amcache, ShimCache, BAM, UserAssist | Exécution de Kaput et horodatage | Inévitable ; documenter | Faible (révèle l'usage de Kaput, pas le contenu) |
| Jump lists, éléments récents, miniatures (`thumbcache`) | Fichiers ouverts via le shell | UI sans boîtes de dialogue shell ni `SHAddToRecentDocs` ; pas d'export de fichiers par défaut ; tout export futur = flux explicite documenté | Faible |
| Journaux d'événements Hyper-V/HCS/VMMS | Création/arrêt de VM, noms, chemins | Inexistants ou réduits en voie WHP [PoC-5 : recenser les canaux ETW/journaux réellement écrits] | Faible |
| Fichiers temporaires `%TEMP%` | Selon l'implémentation | Aucune écriture disque par conception ; nettoyage au démarrage | Faible |
| VHDX résiduels, `.vmrs` | Disque/état invité | Évités par conception (pas de disque inscriptible hôte) | Faible |
| Soumission d'échantillons Defender | Fichiers invités écrits sur l'hôte | Évitée par conception | Faible |
| Journaux Kaput | Ce que l'on y écrit | Jamais d'URL, de domaine, de titre ; niveaux minimaux par défaut | Dépend de l'implémentation |
| Presse-papiers Windows (historique, synchronisation cloud) | Contenu copié | Presse-papiers désactivé par défaut ; si activé un jour : texte seul, sur action explicite | Nul par défaut |

---

## 8. Prérequis minimaux à documenter (`docs/windows.md`)

1. Windows 11 x64 ou ARM64, build 26100+, version encore en support ; Home, Pro, Enterprise, Education (sous réserve PoC-1).
2. Virtualisation matérielle (VT-x/AMD-V/ARM) et SLAT activées dans le firmware.
3. Fonctionnalité `HypervisorPlatform` activée (par l'installateur, admin + reboot).
4. Un compte administrateur pour l'installation et chaque mise à jour des binaires ; exécution en compte standard.
5. Recommandés, signalés mais non bloquants : VBS/HVCI actifs, BitLocker/chiffrement de l'appareil, Secure Boot, mises à jour Windows à jour.
6. Incompatibilités attendues à tester : hyperviseurs tiers sans WHP, logiciels anti-triche/EDR bloquant WHP, politiques WDAC/AppLocker d'entreprise.
7. Ressources : RAM libre suffisante (valeur à fixer après mesure).

---

## 9. Risques résiduels

| ID | Risque | Gravité | Commentaire |
|---|---|---|---|
| R-1 | Vulnérabilité dans le VMM utilisateur (émulation virtio, parsing) → exécution dans le processus VMM | Élevée | Confinement LPAC + VMM minimal en langage sûr + fuzzing ; reste la surface principale |
| R-2 | Évasion de l'hyperviseur Microsoft ou du noyau hôte via les sorties WHP | Critique, probabilité faible | Hors de notre contrôle ; dépend des correctifs Windows ; exiger un Windows à jour |
| R-3 | Évasion AppContainer depuis le VMM compromis (bug noyau/Win32k) | Élevée | Désactiver Win32k dans le VMM réduit fortement la surface |
| R-4 | Broker réseau compromis ou erreur de politique → accès LAN/localhost | Élevée | Tests négatifs systématiques (laboratoire d'évasion) |
| R-5 | RAM invitée écrite sur disque (pagefile, hiberfil, dumps) | Moyenne | §7 ; dépend de BitLocker et des politiques de la machine |
| R-6 | Hôte déjà compromis lisant la session | Hors modèle | À écrire explicitement dans le threat model |
| R-7 | Retrait/changement de l'API WHP ou des comportements de privilèges par Microsoft | Moyenne | WHP est massivement utilisé (VMware, VirtualBox, QEMU, Android) ; garder HCS comme repli documenté |
| R-8 | Compromission de la clé de signature ou du pipeline | Critique | Signature en CI isolée, identités distinctes binaires / images |
| R-9 | SAC/SmartScreen bloquant les premières versions | Moyenne (UX) | Signature systématique, réputation progressive |

---

## 10. Inconnues et PoC à réaliser

| ID | Question | Méthode |
|---|---|---|
| PoC-1 | `WHvCreatePartition` + exécution d'un vCPU en **utilisateur standard**, sur Home, Pro, Enterprise, x64 et ARM64 | Programme minimal Rust/C, matrice de VM de test |
| PoC-2 | Les mêmes appels depuis un **AppContainer** puis un **LPAC** ; capacités éventuellement requises | Lanceur AppContainer minimal ; lister les objets/pilotes ouverts (Process Monitor) |
| PoC-3 | Destruction garantie de la partition et libération mémoire à la mort du processus (`TerminateJobObject`, crash) | Test de crash + inspection |
| PoC-4 | Pagination de la RAM invitée : effet de `VirtualLock`, limites de working set, alternatives sans privilège | Mesure sous pression mémoire, analyse du pagefile en lab |
| PoC-5 | Inventaire réel des journaux/ETW/registres écrits par une session WHP | Diff de l'état disque/registre avant/après |
| PoC-6 | Coût Defender/SAC au démarrage et à la mise à jour | Mesure |
| PoC-7 | Le pare-feu Hyper-V s'applique-t-il à une VM WHP (utile seulement en repli) | Test |
| I-8 | Disponibilité officielle de WHP sur Home : aucune page Microsoft explicite trouvée | Test + recherche complémentaire |

---

## 11. Décisions nécessitant l'avis de l'utilisateur

| ID | Décision | Options | Recommandation |
|---|---|---|---|
| D-1 | **Signature de code (coût, identité légale)** | (a) Créer une entité légale UE (p. ex. société belge) → Artifact Signing ≈120 USD/an ; (b) certificat OV au nom d'un particulier ≈150–300 USD/an + HSM/token ; (c) SignPath Foundation si projet open source qualifié (gratuit) ; (d) aucune signature (inacceptable pour SAC) | (c) si Kaput est open source, sinon (a) ou (b). Un particulier belge **n'est pas éligible** à Artifact Signing |
| D-2 | Support de Windows 10 22H2 sous ESU (jusqu'au 12/10/2027) | Inclure / exclure | Exclure (matrice de test, API WHP récentes) |
| D-3 | Support de Windows Home | Inclure (WHP) / exclure | Inclure si PoC-1 réussit sur Home |
| D-4 | Mises à jour de l'image invitée sans élévation (dans le profil utilisateur) | Oui avec vérification stricte / non (élévation à chaque mise à jour) | Oui, avec signature + anti-rollback à chaque lancement |
| D-5 | Durcissements machine optionnels à l'installation (`ClearPageFileAtShutdown`, WER) | Proposer / ne pas toucher | Proposer, non coché par défaut (impact sur toute la machine) |
| D-6 | Repli HCS avec service SYSTEM si WHP en AppContainer échoue | Accepter un service privilégié / accepter un VMM non-AppContainer | À décider après PoC-2 : un service SYSTEM est un « privilège système exceptionnel » au sens du brief |
| D-7 | Choix du VMM (QEMU-WHPX vs OpenVMM vs VMM dédié) | — | Décision du Virtualization Engineer, avec revue sécurité ; impact fort sur le coût |

---

## 12. Sources

Consultées le 12/11/2026.

- Microsoft — Cycle de vie Windows 11 Home/Pro : https://learn.microsoft.com/en-us/lifecycle/products/windows-11-home-and-pro
- Windows Central — 26H1 réservé aux nouveaux appareils : https://www.windowscentral.com/microsoft/windows-11/microsoft-confirms-windows-11-version-26h1-support-lifecycle-dates-heres-how-long-your-new-snapdragon-x2-laptop-will-be-supported-on-26h1
- Help Net Security — ESU Windows 10 prolongé au 12/10/2027 : https://www.helpnetsecurity.com/2026/06/26/microsoft-windows-10-free-security-updates-esu-program/
- Microsoft MSRC — Security Servicing Criteria for Windows : https://microsoft.com/msrc/windows-security-servicing-criteria
- Microsoft — API Windows Hypervisor Platform : https://learn.microsoft.com/en-us/virtualization/api/hypervisor-platform/hypervisor-platform
- Microsoft — Vue d'ensemble HCS : https://learn.microsoft.com/fr-fr/virtualization/api/hcs/overview
- Microsoft — HCN API : https://learn.microsoft.com/en-us/windows-server/networking/technologies/hcn/hcn-top
- Microsoft — Hyper-V sockets / intégration services : https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
- Microsoft — Pare-feu Hyper-V : https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall
- Microsoft — Windows Sandbox : https://learn.microsoft.com/windows/security/application-security/application-isolation/windows-sandbox
- Microsoft — Configuration `.wsb` : https://learn.microsoft.com/en-us/windows/security/threat-protection/windows-sandbox/windows-sandbox-configure-using-wsb-file
- Microsoft — `WerRegisterExcludedMemoryBlock` : https://learn.microsoft.com/windows/win32/api/werapi/nf-werapi-werregisterexcludedmemoryblock
- Microsoft — Options de signature de code : https://learn.microsoft.com/windows/apps/package-and-deploy/code-signing-options
- Microsoft — Artifact Signing quickstart (éligibilité) : https://learn.microsoft.com/azure/artifact-signing/quickstart
- Microsoft Q&A — Éligibilité d'un entrepreneur individuel UE : https://learn.microsoft.com/en-us/answers/questions/5915697/can-an-irish-sole-trader-(non-incorporated)-qualif
- DevClass — GA d'Azure Artifact Signing, prix, validité 460 jours : https://www.devclass.com/security/2026/01/14/code-signing-windows-apps-may-be-easier-and-more-secure-with-new-azure-artifact-service/4079554
- Eric Lawrence — Smart App Control (04/2026) : https://textslashplain.com/2026/04/28/smart-app-control/
- CIAOPS — Réactivation de SAC sans réinstallation : https://blog.ciaops.com/2026/04/16/existing-systems-can-now-enable-windows-smart-app-control-and-you-should/
- QEMU — WHPX : https://qemu.readthedocs.io/en/master/system/whpx.html
- OpenVMM — dépôt et guide Windows : https://github.com/microsoft/OpenVMM , https://github.stwitter.workers.dev/microsoft/openvmm/blob/main/Guide/src/dev_guide/getting_started/windows.md
- The Register — OpenVMM pas prêt pour l'hôte : https://www.theregister.com/2024/10/17/microsoft_preps_rust_hypervisor_for/
- Blog Windows OS Platform (relayé) — projet OpenVMM : https://www.elevenforum.com/t/the-openvmm-project.48844/
- Hyperlight README : https://docs.rs/crate/hyperlight-host/0.9.0/source/README.md
- pvm PR #1 — détection WHPX sans élévation : https://github.com/huangzheng2016/pvm/pull/1
- pywinhv : https://github.com/0vercl0k/pywinhv
- Lima — driver HCS : https://lima-vm.io/docs/config/vmtype/hcs/
- Eleven Forum — activation `HypervisorPlatform` : https://www.elevenforum.com/t/enable-or-disable-windows-hypervisor-platform-in-windows-11.38917/latest
- Pureinfotech — Hyper-V vs VMP vs WHP : https://pureinfotech.com/hyperv-virtual-machine-platform-windows-hypervisor-platform/
- Broadcom KB 417896 — VBS par défaut sur 24H2 et VMware : https://knowledge.broadcom.com/external/article/417896/after-the-host-os-upgrade-to-version-win.html
- wsl.dev — drvfs : https://wsl.dev/technical-documentation/drvfs/
- Canonical — sécurité Ubuntu sur WSL : https://documentation.ubuntu.com/wsl/en/stable/_sources/explanation/security-overview.md.txt
- Neowin — retrait de MDAG dans 24H2 : https://www.neowin.net/news/microsoft-windows-11-24h2-ditches-defender-application-guard-and-browser-extensions-on-edge/
- Advanced Installer — limites MSIX : https://www.advancedinstaller.com/msix-limitations.html
