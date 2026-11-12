# 04 — Navigateur invité et transport affichage/entrée hôte ↔ invité

- **Auteur** : Browser Security Engineer (équipe Kaput)
- **Date** : 12 novembre 2026
- **Statut** : RECHERCHE, pas encore une décision. Les décisions finales passent par des ADR.
- **Périmètre** : (A) choix et durcissement du navigateur exécuté dans le Linux invité ; (B) protocole qui transporte les pixels, les entrées, et éventuellement l'audio et le presse-papiers entre l'invité et l'hôte.
- **Convention** : `[non revérifié]` signale une affirmation tirée de connaissances antérieures, que je n'ai pas pu revérifier le 12/11/2026 (budget de recherche web épuisé). Les chiffres sur les 0-days viennent surtout de la presse spécialisée (sources secondaires). Il faut les recouper avec les bulletins primaires (chromereleases.googleblog.com, MFSA) avant de les citer dans un ADR.

---

## 0. Résumé exécutif

1. **Navigateur** : je recommande un navigateur de la **famille Chromium**. Ses atouts : sandbox Linux à deux couches (namespaces + seccomp-bpf), isolation de sites stricte, V8 heap sandbox, catalogue de politiques d'entreprise très complet, cadence de correctifs la plus rapide du marché (version tous les 14 jours depuis Chrome 153, plus des correctifs de sécurité hebdomadaires).
2. **Provenance du binaire** : à arbitrer avec l'utilisateur et l'agent Supply Chain. Trois options : Google Chrome Stable officiel (le plus rapide et le plus durci, mais licence propriétaire et redistribution à valider), Chromium d'une distribution (ouvert, mais délai variable), ou Chromium compilé par Kaput (provenance maîtrisée, mais coût d'infrastructure élevé).
3. Le **navigateur reste la surface la plus attaquée** : au moins 7 0-days Chrome exploités in the wild entre février et septembre 2026, dont 5 dans V8. Je recommande par défaut un **JIT désactivé ou restreint**, l'absence de GPU, de WebUSB/HID/Serial/Bluetooth, d'extensions et de synchronisation, et une vérification stricte de l'âge de l'image (fail closed).
4. **Affichage** : je recommande un **protocole maison minimal (« KDP »)** : framebuffer XRGB8888 en tuiles bornées, transporté par vsock (KVM) ou hvsocket (Hyper-V), avec option de mémoire partagée. Le parseur côté hôte fait quelques centaines de lignes de Rust, il est fuzzé et tourne dans un processus hôte sandboxé. La moindre violation du protocole entraîne la destruction de la session.
5. **À rejeter** : virtio-gpu 3D (virgl/Venus/gfxstream/native context), SPICE, RDP, VNC générique, et le transfert Wayland vers le compositeur hôte. Chacune de ces options expose un gros parseur en C/C++ côté hôte, voire le pilote GPU hôte. Des CVE client ou hôte publiées en 2026 l'illustrent.
6. **Défauts proposés** : audio coupé (PCM brut en option), presse-papiers hôte→invité sur geste explicite seulement, invité→hôte désactivé, téléchargements bloqués, aucun transfert de fichier vers l'hôte en v1.

---

## Partie A — Navigateur

### A.1 État au 12 novembre 2026 (vérifié)

**Chrome / Chromium**
- Chrome est passé d'un cycle de 4 semaines à un **cycle de 2 semaines** à partir de Chrome 153 (stable le 8 septembre 2026). Extended Stable garde un cycle de 8 semaines. Des mises à jour de sécurité hebdomadaires existent depuis 2023 ([Chrome for Developers](https://developer.chrome.com/blog/chrome-two-week-release?hl=en)).
- Chrome 157 stable a été annoncé le 3 novembre 2026 (157.0.8103.38 pour Linux), avec 213 correctifs de sécurité dont 7 critiques ([SmartScope](https://smartscope.blog/en/blog/chrome-157-stable-released-213-security-fixes-7-2026/)). Extended Stable 156.0.8078.100 est sorti le 11 novembre 2026 avec 72 correctifs ([Chrome Releases](https://chromereleases.googleblog.com/2026/?hl=en)).
- **0-days Chrome exploités in the wild en 2026**, d'après la liste compilée par [Security Affairs](https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html) :

| # | CVE | Mois | Composant | Type |
|---|---|---|---|---|
| 1 | CVE-2026-2441 | févr. | CSS | UAF |
| 2 | CVE-2026-3909 | mars | Skia | OOB write |
| 3 | CVE-2026-3910 | mars | V8 | implémentation |
| 4 | CVE-2026-5281 | avr. | Dawn (WebGPU) | UAF |
| 5 | CVE-2026-11645 | juin | V8 | OOB access |
| 6 | CVE-2026-85046 | sept. | V8 | type confusion ([eSecurityPlanet](https://esecurityplanet.com/threats/news-google-chrome-cve-2026-85046-zero-day)) |
| 7 | CVE-2026-87491 | sept. | V8 | OOB write, corrigé dans 153.0.8010.36 ([Help Net Security](https://www.helpnetsecurity.com/2026/09/09/google-chrome-cve-2026-87491-zero-day-flaw/)) |

  Je n'ai pas trouvé de 0-day Chrome in the wild publié en octobre ou novembre 2026 (recherche limitée). Pour référence, 2025 en a compté au moins 8 ([cybersecurity-help.cz](https://www.cybersecurity-help.cz/blog/5124.html)).
  **Lecture sécurité** : 5 des 7 visent V8 et 1 vise WebGPU. Les sources ne disent pas si une évasion de sandbox était chaînée. Il faut supposer que des chaînes complètes (RCE renderer + évasion de sandbox) existent chez les attaquants.
- **V8 sandbox** (heap sandbox) : activé par défaut sur les builds 64 bits de toutes les plateformes, inclus dans le VRP depuis avril 2024. Surcoût d'environ 1 % ou moins. Google ne le présente **pas encore** comme une frontière forte : « still a number of issues to resolve before it becomes a strong security boundary » ([v8.dev](https://v8.dev/blog/sandbox), [SecurityWeek](https://www.securityweek.com/google-adds-v8-sandbox-to-chrome/amp/)). En 2026, il est décrit comme « a practical defense mechanism deployed in Chromium » ([PriSC 2026](https://popl26.sigplan.org/details/prisc-2026-papers/1/The-V8-Sandbox-From-Compiler-Correctness-to-Runtime-Containment)).
- **Wayland** : depuis Chrome 140, `--ozone-platform-hint` vaut `auto` par défaut (Wayland si disponible) ([OMG! Ubuntu](https://omgubuntu.co.uk/2025/08/chrome-140-wayland-auto-detection-linux)).

**Firefox**
- Firefox est lui aussi passé à un **cycle de 2 semaines** depuis Firefox 155 (1er septembre 2026). Des « dot releases » de sécurité sont publiées chaque semaine depuis Firefox 151 ([Mozilla SUMO](https://blog.mozilla.org/sumo/2026/08/19/firefox-new-release-cadence-and-what-to-expect/), [PC-WELT](https://www.pcwelt.de/article/3138190/firefox-150-0-3-schnelles-update-kontert-exploit-kette-vor-pwn2own.html)).
- Firefox 158 (13 octobre 2026) a corrigé 77 vulnérabilités, dont au moins 8 évasions de sandbox ([eSecurityPlanet](https://www.esecurityplanet.com/vulnerabilities/news-firefox-158-security-vulnerabilities-sandbox-escapes/)). Firefox 159 (vers le 28 octobre 2026) en a corrigé 167, dont **13 évasions de sandbox exploitables seules**. ESR 153.6.0 est sorti en même temps ([PCWorld](https://www.pcworld.com/article/3271386/firefox-159-fixes-167-security-flaws-including-13-sandbox-escapes.html)).
- Firefox 150.0.3 (mai 2026) a corrigé une chaîne complète page HTML → évasion de sandbox (CVE-2026-8401) préparée pour Pwn2Own Berlin ([PC-WELT](https://www.pcwelt.de/article/3138190/firefox-150-0-3-schnelles-update-kontert-exploit-kette-vor-pwn2own.html)).
- CVE-2026-15718 (Wasm) et CVE-2026-15719 (contournement de l'isolation de sites) ont été corrigées dans 152.0.6. Un exploit public existe, mais **pas d'exploitation in the wild confirmée** ([Qualys](https://threatprotect.qualys.com/2026/07/15/mozilla-firefox-zero-day-vulnerabilities-exploited-in-attacks-cve-2026-15718-cve-2026-15719/)).
- Sandbox du processus de contenu sous Linux : niveau 4 (seccomp-bpf, user namespaces si disponibles, chroot) ([wiki Mozilla, mis à jour en octobre 2024](https://wiki.mozilla.org/Security/Sandbox)). seccomp-bpf ne peut pas filtrer les arguments pointeurs (chemins) : ces appels passent par un broker non sandboxé ([wiki Mozilla, Specifics](https://wiki.mozilla.org/Security/Sandbox/Specifics)).

### A.2 Architecture de sécurité comparée (Linux)

**Chromium sous Linux** ([docs Chromium](https://chromium.googlesource.com/chromium/src/+/404ca6f/docs/linux_sandboxing.md))
- Couche 1 : sandbox par user namespaces (PID, réseau, vue FS vide). Le sandbox setuid sert de solution de repli sur les vieux noyaux. Couche 2 : seccomp-bpf par type de processus.
- Les renderers ont les deux couches. Le processus GPU n'a **que seccomp-bpf**, qui lui sert de couche 1 : il est plus faible.
- Sous Linux, le Network Service, le service audio et le GPU ne sont pas sandboxés au même niveau que les renderers par défaut. Trivalent ajoute des patches qui activent leur sandboxing ([discussion Privacy Guides](https://discuss.privacyguides.net/t/brave-vs-trivalent-security/25880), [secureblue/Trivalent](https://github.com/secureblue/hardened-chromium)). → Il faut tester les feature flags équivalents dans le build retenu `[non revérifié]`.
- Isolation de sites stricte sur desktop. PartitionAlloc et MiraclePtr/BackupRefPtr (mitigation des UAF). CFI Clang dans les builds officiels `[non revérifié]`.
- **Contrainte critique pour l'image invitée** : le sandbox de couche 1 exige des **user namespaces non privilégiés** dans l'invité, ou le binaire setuid. `--no-sandbox` est réservé aux tests et **interdit dans Kaput**. À coordonner avec le Linux Security Engineer, dont le durcissement pourrait désactiver userns.

**Firefox sous Linux**
- Fission (isolation de sites), RLBox (bibliothèques tierces compilées en Wasm et sandboxées, par exemple polices et parseurs) `[non revérifié pour 2026]`.
- Pas d'équivalent public du V8 heap sandbox pour SpiderMonkey `[non revérifié]`.
- Le processus GPU/compositeur sous Linux est à vérifier : s'il est désactivé, le rendu WebRender tourne dans le processus parent non sandboxé `[inconnue]`.
- Le nombre d'évasions de sandbox corrigées par version (8 dans Fx158, 13 dans Fx159) montre une surface IPC parent importante. Ce n'est pas une mesure directe de faiblesse : Chrome corrige aussi des évasions, et ces chiffres reflètent en partie l'intensité de l'audit, y compris par IA.

**Interprétation honnête** : Chrome subit plus de 0-days in the wild parce qu'il est la cible principale (part de marché), pas parce qu'il est intrinsèquement plus faible. À configuration égale, l'architecture de Chromium sous Linux offre davantage de couches (V8 sandbox, renderers à double couche). Firefox reste un second choix crédible.

### A.3 Tableau comparatif

| Candidat | Sandbox Linux | Isolation sites / heap sandbox | Délai de correctif | Provenance binaire | Politiques entreprise | Surface ajoutée | Verdict |
|---|---|---|---|---|---|---|---|
| **Google Chrome Stable** (officiel) | userns + seccomp-bpf ; GPU seccomp seul | Site isolation stricte + V8 sandbox | Référence (J0), cycle 14 j + hebdo | Dépôt Google signé ; build officiel (PGO/CFI) ; **licence propriétaire** | Très complètes (JSON `/etc/opt/chrome/policies/managed`) | Services Google (désactivables), Widevine | **Recommandé si la licence le permet** |
| **Chromium distro** (Debian/Fedora) | idem (selon les flags du packageur) | idem | J+0 à J+plusieurs jours selon la distro `[non revérifié]` | Signé par la distro, open source | Mêmes politiques (`/etc/chromium/policies/managed`) | Patches distro | **Alternative recommandée**, avec SLA d'âge strict |
| **Chromium compilé par Kaput** | idem, flags maîtrisés | idem | Notre CI : ≥ 1 build/semaine, plusieurs heures de compilation | Provenance maximale (SLSA, reproductibilité partielle) | idem | Aucune | **Cible long terme** (coût élevé) |
| ungoogled-chromium | idem | idem | Variable ; patchs par scripts susceptibles de conflits silencieux | Binaires construits par des tiers non vérifiés selon Privacy Guides ([fil](https://discuss.privacyguides.net/t/ungoogled-chromium/15781.md)) | idem | Moins de services Google | Rejeté (provenance) |
| Brave | Chromium ; le Flatpak via zypak affaiblit la couche 1 ([fil](https://discuss.privacyguides.net/t/brave-vs-trivalent-security/25880)) | idem | Rapide (typiquement quelques jours) `[non revérifié]` | Dépôt Brave signé | Chromium + politiques Brave | Wallet, Tor, IA, récompenses | Alternative acceptable, sinon rejeté (surface) |
| Trivalent (secureblue, inspiré de Vanadium) | Chromium + sandbox réseau/audio/GPU sous Linux | idem + patches restreignant le JIT | Dépend d'une petite équipe | Dépôt secureblue (Fedora) | idem | Faible | Source de patches à étudier, dépendance risquée (bus factor) |
| Vanadium (GrapheneOS) | Android uniquement | — | — | — | — | — | Hors périmètre ; garder ses idées (hardened_malloc, JIT off) |
| Firefox (Mozilla) | seccomp + userns + chroot (niveau 4) | Fission ; pas de heap sandbox JS | Rapide, cycle 14 j + hebdo | Tarball/dépôt APT Mozilla signé | `policies.json` complet | Faible | Second choix crédible |
| Firefox ESR | idem | idem | Correctifs rétroportés | idem | idem | Faible | Inutile (l'invité est jetable, pas besoin de stabilité de fonctionnalités) |
| Tor Browser / Mullvad Browser | Firefox ESR | idem | Retard possible de quelques jours après MFSA `[non revérifié]` | Signés par Tor Project / Mullvad | Limitées | — | Mode « Safest » (JS off) intéressant ; anti-empreinte, pas anti-exploit |
| LibreWolf | Firefox | idem | Communautaire | Communautaire | Limitées | — | Rejeté (provenance, délai) |
| WebKitGTK (Epiphany) | bubblewrap + seccomp `[non revérifié]` | Isolation de sites partielle | Plus lent, moins de ressources | Distro | Quasi inexistantes | — | Rejeté |
| Ladybird / Servo | Immature | — | — | — | — | — | Rejeté (maturité) |

### A.4 Recommandation A

1. **Moteur** : Chromium. **Binaire** : Google Chrome Stable pour Linux (x86-64), à condition que les conditions de redistribution dans une image Kaput soient validées (décision utilisateur et juridique). Sinon, Chromium d'une distribution à glibc (Debian ou Fedora, selon le choix de distribution invitée), avec contrôle d'âge strict. Objectif à moyen terme : build Kaput reproductible depuis les tags upstream.
   - Pas d'Alpine/musl pour le navigateur : Chromium sur musl n'est pas supporté upstream et dépend de patches distro `[non revérifié]`.
   - Pas de Flatpak ni de Snap dans l'invité (zypak remplace la couche 1, la confinement se superpose mal).
2. **Mises à jour** : le navigateur ne se met **jamais** à jour seul dans l'invité. Chrome Linux n'a d'ailleurs pas d'auto-updater et l'invité est jetable. La seule voie est la chaîne d'images signées Kaput (agent Supply Chain). Il faut viser :
   - une reconstruction de l'image à **chaque** release stable ou de sécurité (au minimum hebdomadaire) ;
   - un **SLA ≤ 48 h** pour un 0-day in the wild annoncé ;
   - au lancement : **refus de démarrer, ou avertissement bloquant**, si la version du navigateur a plus de N jours (proposition : 14 jours) ou figure dans une liste signée de versions à 0-day exploité. Fail closed, à valider avec l'utilisateur.
3. **Exécution** :
   - utilisateur dédié non privilégié (uid ≠ 0, aucune capability) ;
   - pas de `--no-sandbox`, et une vérification au démarrage (via `chrome://sandbox`, ou par l'introspection `/proc/<pid>/status` → `Seccomp: 2` et des namespaces distincts) qui tue la session si la sandbox n'est pas active ;
   - profil sur tmpfs ;
   - pas de serveur X : Wayland seulement (`--ozone-platform=wayland`) dans un compositeur kiosque invité ;
   - **aucun GPU** dans l'invité (voir partie B) → rendu logiciel.
4. **JIT** : par défaut, je recommande `DefaultJavaScriptJitSetting=2` (V8 sans JIT). Le JIT est la classe de bugs dominante dans les 0-days de 2026.
   - **Impact** : JavaScript plus lent sur les sites lourds, et **WebAssembly possiblement désactivé** en mode jitless `[non revérifié]`.
   - Microsoft (Edge « Super Duper Secure Mode », 2021) rapportait qu'environ 45 % des CVE V8 étaient liées au JIT, avec un impact jugé modéré sur la navigation courante `[non revérifié]`.
   - Alternative moins stricte : `DefaultJavaScriptOptimizerSetting=2` (désactive seulement les compilateurs optimisants) `[nom et sémantique à vérifier]`.
   - → **Décision utilisateur** (voir D).
5. **WebGPU / WebGL** : sans GPU invité, WebGPU doit être désactivé explicitement (0-day Dawn CVE-2026-5281). Le repli WebGL sur SwiftShader a été restreint récemment `[non revérifié]`. Il faut accepter que WebGL soit indisponible ou purement logiciel, ce qui affecte la cartographie 3D et certains jeux.

### A.5 Politiques navigateur proposées (Chrome/Chromium)

Le fichier `/etc/opt/chrome/policies/managed/kaput.json` (ou `/etc/chromium/policies/managed/`) se trouve dans l'image en lecture seule. **Tous les noms et valeurs doivent être validés contre https://chromeenterprise.google/policies/ pour la version figée**, avec un test automatisé qui lit `chrome://policy` et échoue en cas de politique inconnue ou en erreur.

| Domaine | Politique | Valeur | Justification / impact |
|---|---|---|---|
| Périphériques | `DefaultWebUsbGuardSetting` | 2 (bloquer) | Pas de périphérique dans l'invité ; surface inutile |
| | `DefaultWebBluetoothGuardSetting` | 2 | idem |
| | `DefaultSerialGuardSetting` | 2 | idem |
| | `DefaultWebHidGuardSetting` | 2 | idem |
| | `DefaultSensorsSetting` | 2 | idem |
| | `AudioCaptureAllowed`, `VideoCaptureAllowed` | false | Pas de micro ni de caméra ; casse la visio |
| | `ScreenCaptureAllowed` | false | idem |
| Fichiers | `DefaultFileSystemReadGuardSetting`, `DefaultFileSystemWriteGuardSetting` | 2 | File System Access API |
| | `DownloadRestrictions` | 3 (tout bloquer) | Voir B.6 / décision ; 1 ou 4 si les téléchargements dans l'invité sont autorisés |
| | `AlwaysOpenPdfExternally` | false | PDFium reste dans le renderer sandboxé ; `true` + téléchargements bloqués = PDF illisibles |
| | `PrintingEnabled` | false | Pas d'imprimante |
| | `AllowFileSelectionDialogs` | false (si upload refusé) | Empêche l'upload ; **décision** |
| Comptes / données | `SyncDisabled` | true | |
| | `BrowserSignin` | 0 | |
| | `PasswordManagerEnabled` | false | Session jetable ; évite de stocker des secrets dans un invité potentiellement compromis |
| | `AutofillAddressEnabled`, `AutofillCreditCardEnabled` | false | |
| | `BrowserGuestModeEnabled`, `BrowserAddPersonEnabled` | false | |
| Extensions | `ExtensionInstallBlocklist` | `["*"]` | Option : liste blanche d'un bloqueur (uBlock Origin Lite) via `ExtensionInstallForcelist` (**décision**) |
| | `BlockExternalExtensions` | true | |
| Réseau | `WebRtcIPHandling` | `disable_non_proxied_udp` (si proxy) ou `default_public_interface_only` | À aligner avec l'agent Réseau ; le premier casse une partie de la visio |
| | `WebRtcEventLogCollectionAllowed` | false | |
| | `HttpsOnlyMode` | `force_enabled` | Interstitiel sur les sites HTTP |
| | `DnsOverHttpsMode`, `BuiltInDnsClientEnabled`, `QuicAllowed` | selon l'agent Réseau | La politique DNS est imposée par la couche réseau Kaput |
| | `LocalNetworkAccessRestrictionsEnabled` | true `[à vérifier]` | Défense en profondeur contre l'accès LAN/localhost depuis des pages |
| Contenu | `DefaultJavaScriptJitSetting` | 2 | **Décision** (voir A.4) |
| | `DefaultPopupsSetting` | 2 | |
| | `DefaultInsecureContentSetting` | 2 | |
| | `DefaultNotificationsSetting`, `DefaultGeolocationSetting` | 2 | |
| | `DefaultLocalFontsSetting`, `DefaultWindowManagementSetting` | 2 | Empreinte et API multi-écran |
| | `DefaultClipboardSetting` | 2 | API async clipboard (lecture JS) ; n'empêche pas Ctrl+V |
| | `BlockThirdPartyCookies` | true | |
| Télémétrie / IA | `MetricsReportingEnabled`, `UrlKeyedAnonymizedDataCollectionEnabled`, `SpellCheckServiceEnabled`, `TranslateEnabled` | false | Confidentialité |
| | `GenAILocalFoundationalModelSettings` / politiques Gemini | désactiver `[noms à vérifier]` | Surface et données |
| | `SafeBrowsingProtectionLevel` | 1 (standard) | **Décision** : 2 (Enhanced) protège mieux mais envoie des URL à Google |
| Divers | `RemoteDebuggingAllowed` | false | Pas de port DevTools exposé |
| | `DeveloperToolsAvailability` | 1 ou 2 | **Décision** (analyse de sites malveillants ou non) |
| | `BackgroundModeEnabled` | false | |
| | `HardwareAccelerationModeEnabled` | false | Pas de GPU invité |
| | `ComponentUpdatesEnabled` | true (CRLSet, listes Safe Browsing) | Widevine passe aussi par ce canal : voir **décision DRM** |
| | `CommandLineFlagSecurityWarningsEnabled` | true | Détecte un `--no-sandbox` injecté |

Drapeaux de ligne de commande, à vérifier pour chaque version :
- `--ozone-platform=wayland` ;
- désactivation de WebGPU (feature `WebGPU`/`WebGPUService`, nom exact à vérifier) ;
- activation du sandbox du Network Service sous Linux si le flag existe (`NetworkServiceSandbox`) `[à vérifier]` ;
- `--js-flags=--jitless` seulement comme repli si la politique est insuffisante.

Si Firefox était retenu, les équivalents se trouvent dans `policies.json` :
- `DisableFirefoxAccounts`, `DisableTelemetry` ;
- `ExtensionSettings` avec `"*": {"installation_mode":"blocked"}` ;
- `Permissions` ;
- les préférences `javascript.options.ion`, `javascript.options.baselinejit`, `javascript.options.wasm` ;
- `media.peerconnection.ice.proxy_only` ;
- `dom.webgpu.enabled=false`.

---

## Partie B — Transport d'affichage et d'entrée hôte ↔ invité

### B.1 Modèle de menace spécifique

On suppose l'invité **entièrement compromis** (root dans l'invité, noyau invité compromis). Tout octet reçu de l'invité est donc hostile : valeurs, tailles, ordre, cadence, contenu de la mémoire partagée qui peut changer pendant la lecture (TOCTOU / double fetch).

Il faut aussi considérer :
- l'usurpation d'interface : l'invité dessine une fausse boîte de dialogue Windows ou une fausse invite UAC ;
- l'exfiltration par les canaux autorisés (presse-papiers, audio, fichiers) ;
- le déni de service sur l'hôte (CPU, mémoire, inondation de messages).

Après l'hyperviseur, le composant hôte qui décode le flux d'affichage est **la surface la plus exposée** : il s'exécute dans la session de l'utilisateur, a accès à ses fichiers, et consomme un flux à haut débit contrôlé par l'attaquant.

### B.2 Faits récents qui orientent le choix

- **QEMU virtio-gpu** : CVE-2026-3886, dépassement d'entier → évasion invité→hôte, CVSS 8.8, divulguée par ZDI en juin 2026 ([Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-3886)). Même le périphérique virtio-gpu « simple » de QEMU (en C) reste une surface réelle.
- **virglrenderer** : environ 20 CVE (débordements, OOB write, UAF), dont un OOB write via un `VIRTGPU_EXECBUFFER` forgé ([CVE Details](https://www.cvedetails.com/vulnerability-list/vendor_id-16205/Virglrenderer-Project.html)). Les shaders de l'invité sont recompilés par le pilote GL de l'hôte. Seul Venus tourne dans un processus isolé côté hôte ([Collabora 2025](https://www.collabora.com/news-and-blog/blog/2025/01/15/the-state-of-gfx-virtualization-using-virglrenderer/)). Les bibliothèques virgl et gfxstream tournent en espace utilisateur hôte, sans analyse de menace détaillée publiée ([KVM Forum 2024](https://kvm-forum.qemu.org/2024/Virtio-gpu_where_are_we_now_-1_1cOiDio.pdf)).
- **SPICE** : CVE-2026-105958 dans spice-server, offsets fournis par le client utilisés sans vérification de bornes → corruption du tas du processus hyperviseur ([Red Hat](https://access.redhat.com/security/cve/CVE-2026-105958)).
- **VNC** : CVE-2026-50538 dans libvncclient (décodeur Tight). Débordement de tas contrôlé en taille, contenu et offset, déclenché par **un seul FramebufferUpdate** d'un serveur malveillant, sans authentification ([Wiz](https://www.wiz.io/vulnerability-database/cve/cve-2026-50538)). C'est exactement notre scénario : l'invité joue le rôle du serveur.
- **RDP** :
  - client FreeRDP pour Windows : CVE-2026-67305, débordement de tas dans le canal presse-papiers sur une réponse serveur ([Averlon](https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-67305)) ;
  - client Microsoft : CVE-2026-47289, RCE client via la clé publique d'un serveur malveillant ([0patch](https://0patch.com/blog/micropatches-released-for-remote-desktop-client-remote-code-execution-vulnerabili)), et de nombreuses autres CVE « Remote Desktop Client RCE » en 2026 (par exemple [CVE-2026-62824](https://www.action1.com/vulnerabilities/cve-2026-62824/)).
- **WSLg** utilise RDP (Weston backend RDP → client RDP hôte, avec une variante « VAIL » à mémoire partagée), et fait passer l'audio et le presse-papiers (texte, HTML, bitmap) par RDP ([Microsoft](https://devblogs.microsoft.com/commandline/wslg-architecture)). Très pratique, mais c'est la surface RDP client complète.
- **Protocole GUI de Qubes** ([doc Qubes 4.3](https://doc.qubes-os.org/en/r4.3/developer/system/gui.html)) : c'est le meilleur modèle de conception existant.
  - En-tête fixe de 12 octets. La plupart des messages ont une taille fixe, « so the parsing code can be small ».
  - Le champ `untrusted_len` n'est jamais utilisé pour calculer une longueur.
  - Les pixels transitent par mémoire partagée (grant tables), mappée seulement depuis le domaine attendu.
  - Le presse-papiers est stocké sans être analysé, et chaque transfert est **déclenché uniquement par l'utilisateur**.
  - Le titre est préfixé par le nom de la VM et les fenêtres reçoivent des bordures colorées dessinées par dom0, contre l'usurpation.
  - Limites pour nous : spécifique à Xen et X11, et multi-fenêtres.
- **Hyper-V sockets** : AF_HYPERV côté Windows, AF_VSOCK côté invité Linux. L'enregistrement d'un GUID de service exige des **droits administrateur**. Microsoft les déclare « not suited to block-memory transfers such as backup or video » ([Microsoft Learn](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service)). C'est une **inconnue de performance critique pour Windows**.
- **virtio-vsock** : environ 10 Gbit/s invité→hôte sur Firecracker, environ 40 Gbit/s invité→hôte et 25 Gbit/s hôte→invité sous Linux 5.4+ (chiffres de 2019, [KVM Forum 2019](https://cnblogs.com/dream397/p/13865887.html)).

### B.3 Tableau comparatif

| Option | Ce que l'hôte doit analyser | Langage hôte | Exposition du pilote GPU / noyau hôte | Perf. (60 fps / 4K / vidéo) | Hôte Windows | Verdict |
|---|---|---|---|---|---|---|
| virtio-gpu 2D (QEMU) | File virtio, commandes ressources/scanout | C (QEMU) + UI QEMU (GTK/SDL/SPICE) | Faible | Correct en 1080p | Seulement QEMU+WHPX | Acceptable sous condition, mais du C dans le VMM (CVE-2026-3886) ; inutile si KDP |
| virtio-gpu 3D virgl | Flux de commandes GL + traduction de shaders | C | **Élevée** : shaders et commandes de l'invité atteignent le pilote GL hôte | Bonne | Non | **Rejeté** |
| Venus (Vulkan) | Appels Vulkan transmis | C (processus isolé) | **Élevée** (pilote Vulkan et noyau hôte) | Très bonne | Non | **Rejeté** |
| gfxstream | Flux GLES/Vulkan | C++ (volumineux) | **Élevée** | Bonne | Partiel | **Rejeté** |
| DRM native context (vDRM) | UAPI du pilote noyau GPU | Noyau hôte | **Maximale** | Excellente | Non | **Rejeté** |
| SPICE | Commandes QXL, codecs (QUIC/LZ/GLZ/JPEG/LZ4, flux vidéo GStreamer), vdagent, usbredir | C (spice-gtk, spice-server) | Moyenne (décodeurs vidéo) | Bonne | Client existant | **Rejeté** |
| VNC/RFB générique | Encodages Tight/ZRLE/Hextile + zlib/JPEG | C (libvncclient, TigerVNC) | Faible | Moyenne | Oui | **Rejeté** (CVE-2026-50538) |
| RFB restreint (Raw/CopyRect, client Rust maison) | Raw seulement | Rust | Faible | 1080p correct, 4K difficile | Oui | Repli acceptable, mais traîne l'héritage RFB sans bénéfice |
| RDP (mstsc / FreeRDP / WSLg) | Protocole énorme (canaux virtuels, codecs RemoteFX/H.264, clipboard, redirections) | C/C++ | Moyenne à élevée (décodage H.264 matériel) | Excellente | Natif | **Rejeté** (nombreuses RCE client en 2026) |
| Wayland transféré (crosvm cross-domain / virtio-wl + sommelier, waypipe) | **Le compositeur hôte** analyse le protocole Wayland de l'invité + dmabuf | C (Mutter, KWin…) dans la session utilisateur | Moyenne à élevée | Très bonne | **Non** | **Rejeté** : conçu pour des invités de confiance (ChromeOS) ; la doc crosvm ne traite pas la sécurité ([crosvm](https://crosvm.dev/book/devices/wayland.html)) |
| Protocole GUI de Qubes | En-têtes fixes, messages bornés, SHM | C | Faible (blit X11) | Bonne | Non (Xen) | **Modèle conceptuel à reprendre**, pas le code |
| **KDP : framebuffer brut/tuilé via vsock/hvsock (+ SHM optionnelle)** | ≈ 10 types de messages à taille fixe ou bornée, pixels opaques | **Rust**, processus sandboxé | **Minimale** (upload de texture 2D standard) | 1080p60 OK ; 4K60 seulement en mode SHM ou dégradé | Oui (hvsocket ; débit à mesurer) | **Recommandé** |

### B.4 Recommandation B

Il faut adopter un **protocole propriétaire minimal, KDP v1**, inspiré de Qubes, indépendant du transport :
- **Canal de contrôle et d'entrée** : flux vsock (KVM, Firecracker, Cloud Hypervisor) ou hvsocket (Hyper-V).
- **Pixels**, deux modes :
  - `INLINE` : les tuiles passent dans le flux. C'est le mode portable et la première cible.
  - `SHM` : les tuiles sont écrites dans une région de mémoire partagée (par exemple ivshmem-plain sous QEMU, ou une région dédiée selon le VMM), et le flux ne porte que des descripteurs. C'est le mode performance, à valider pour chaque VMM.
- **Côté invité** : un compositeur Wayland kiosque headless à rendu logiciel. Deux pistes : un compositeur maison en Rust (Smithay), ou cage/Weston avec un backend dédié. Il ne gère qu'**une seule surface plein cadre**, et les menus et popups sont composés dans l'invité. Aucune seconde fenêtre n'existe côté hôte.
- **Côté hôte** :
  - le processus `kaput-display-broker` (Rust, sandboxé) est le **seul** à lire le flux invité ;
  - il écrit des pixels validés dans un framebuffer privé de taille fixe, partagé avec le processus UI ;
  - l'UI ne fait qu'un blit (Wayland `wl_shm` / X11 MIT-SHM / Direct2D ou GDI) et dessine le **cadre et l'indicateur Kaput hors de la surface invitée**, comme les bordures de Qubes.
- **Pas de GPU invité, pas de codec vidéo côté hôte, pas de transfert Wayland.**

### B.5 Ébauche du protocole KDP v1

**Règles générales**
- Petit-boutiste. Toutes les longueurs sont validées par une table par type (min/max) **avant** toute allocation. Les tampons sont préalloués à la taille maximale du type. Toute l'arithmétique est vérifiée (checked).
- **Toute violation est fatale** : type inconnu, longueur hors bornes, numéro de séquence non consécutif, valeur hors domaine, message hors état, dépassement de crédit. Elle entraîne la fermeture du canal, la destruction de la VM et un compteur de diagnostic, sans écrire le contenu dans les logs.
- L'hôte ne renvoie jamais à l'invité une donnée qui provient de l'invité.
- Aucune chaîne de caractères venant de l'invité n'est affichée dans l'interface hôte. Le titre de la fenêtre est fixe, par exemple « Kaput — session isolée ».

**En-tête (12 octets, dans les deux sens)**
```
u16 type      // énuméré ; inconnu => fatal
u16 flags     // doit valoir 0 en v1
u32 len       // longueur du corps ; bornée par type
u32 seq       // = seq précédent + 1 (par direction)
```

**Invité → hôte (critique pour la sécurité)**

| Type | Corps | Taille | Validation |
|---|---|---|---|
| `HELLO` | u32 version, u32 caps | 8 | Premier message obligatoire, une seule fois ; `caps` ⊆ caps hôte |
| `SURFACE` | u32 w, u32 h, u32 format(=0 XRGB8888), u32 scale_milli | 16 | `w,h` ≥ 64 et ≤ max annoncé par l'hôte (proposition : 3840×2160) ; doit répondre à un `RESIZE` |
| `FRAME_BEGIN` | u32 frame_id, u16 n_tiles, u16 rsv=0 | 8 | `n_tiles` ≤ 1024 ; crédits disponibles |
| `TILE` | u32 x, y, w, h ; u8 enc ; u8[3] rsv=0 ; u32 data_len ; données | 24 + data | `w,h` ∈ [1,1024] ; `x+w ≤ W`, `y+h ≤ H` (checked) ; selon `enc` : `RAW` data_len = w·h·4 ; `SOLID` = 4 ; `LZ4` data_len ≤ w·h·4 + marge et décompression **exactement** w·h·4 (v1.1) ; `I420` w,h pairs et data_len = w·h·3/2 (v1.1, conversion à arithmétique fixe) |
| `TILE_SHM` | u32 x, y, w, h ; u16 slot ; u16 rsv ; u32 offset | 24 | `slot` < N ; `offset + w·h·4 ≤ slot_size` ; l'hôte **copie d'abord** dans un tampon privé, puis traite (protection double fetch) |
| `FRAME_END` | u32 frame_id | 4 | Égal au `FRAME_BEGIN` courant ; l'hôte présente une image cohérente (double buffer hôte) |
| `CURSOR` | u32 shape | 4 | Énumération fermée de curseurs système (défaut, main, texte, attente, redimensionnement…) ; pas de bitmap de curseur en v1 |
| `COPY_TEXT` | UTF-8 | ≤ 64 Kio | Accepté **seulement** si un `COPY_REQUEST` est en attente ; UTF-8 strict ; voir B.6 |
| `AUDIO_PCM` (port vsock distinct, optionnel) | u32 n_frames + s16le stéréo 48 kHz | ≤ 4 + 960·4 | `len == 4 + n·4` ; n ≤ 960 (20 ms) ; débit borné à 48 000 frames/s |
| `PONG`, `BYE` | — / u32 reason | 0 / 4 | |

**Hôte → invité**

| Type | Corps | Remarque |
|---|---|---|
| `HELLO_ACK` | u32 version, caps, max_w, max_h, u32 kbd_layout_id | La disposition est choisie par l'hôte dans une liste fermée (`fr`, `be`, `ch(fr)`, `us`, `de`…), appliquée par XKB dans l'invité. AZERTY, touches mortes et AltGr sont gérés **dans l'invité** |
| `RESIZE` | u32 w, h (pixels physiques), u32 scale_milli | HiDPI (1250 = 125 %) ; fréquence limitée (≤ 10/s) ; l'hôte étire la dernière image en attendant `SURFACE` |
| `KEY` | u16 evdev_code, u8 pressed, u8 rsv | **Codes physiques** (traduits depuis les scancodes Windows ou evdev Linux), jamais de keysyms. Les combinaisons système hôte (Ctrl+Alt+Suppr, Win+L…) ne sont pas transmises |
| `TEXT` | UTF-8 ≤ 256 o | v1.1 : texte validé par l'IME hôte (CJK, emoji) injecté via `text-input`/`virtual-keyboard` dans l'invité |
| `POINTER` | u32 x, y (coordonnées surface), u32 buttons | Absolu ; pas de capture exclusive du pointeur |
| `SCROLL` | i32 dx, dy (1/120 de cran), u8 hires | |
| `FOCUS` | u8 in | Sur perte de focus, l'invité relâche toutes les touches. Aucune frappe n'est transmise hors focus |
| `FRAME_ACK` | u32 frame_id | **Crédits** : au plus 2 images en vol ; au-delà, violation fatale |
| `PASTE_TEXT` | UTF-8 ≤ 1 Mio | Seulement après un geste explicite de l'utilisateur |
| `COPY_REQUEST` | — | Geste explicite (bouton ou raccourci Kaput) |
| `PING`, `SHUTDOWN` | — | |

**Implémentation hôte** (exigences pour l'ADR) :
- Rust sans `unsafe` dans le parseur (le mapping de la mémoire partagée est isolé dans un module audité).
- Parseurs « zero-copy interdits » sur la mémoire partagée.
- `cargo-fuzz` et propriétés (proptest) en CI, plus un corpus d'attaques : longueurs extrêmes, débordements d'entiers, séquences invalides, inondation, mémoire partagée modifiée pendant la lecture.
- Sandbox du broker :
  - **Linux** : seccomp (read, write, recvmsg, mmap, futex, exit), Landlock sans système de fichiers, aucun réseau, namespaces ;
  - **Windows** : AppContainer/LPAC, jeton restreint, Job Object (mémoire et CPU plafonnés).
  - Le descripteur vsock/hvsocket est créé par le processus parent puis transmis, parce que la création d'AF_HYPERV en AppContainer est `[inconnue]`.
- Limites CPU et mémoire et watchdog : un invité qui inonde est ralenti par les crédits, puis tué.

**Budget de bande passante** (XRGB8888, image entière) :

| Résolution | Brut, 60 fps | I420, 60 fps |
|---|---|---|
| 1080p | ≈ 498 Mo/s | ≈ 187 Mo/s |
| 1440p | ≈ 885 Mo/s | — |
| 4K | ≈ 1,99 Go/s | ≈ 746 Mo/s |

La navigation ordinaire n'envoie que des zones endommagées (faible débit). La vidéo plein écran 4K60 en mode `INLINE` dépasse probablement le budget raisonnable. Il faut alors soit le mode `SHM`, soit un plafonnement à 30 fps, soit une sous-résolution. **On n'utilise jamais de codec vidéo avec perte (H.264, VP9, AV1) côté hôte**, car un décodeur vidéo est une surface d'attaque majeure.

**Vidéo et YouTube** : le décodage est logiciel dans l'invité (ffmpeg, libvpx et dav1d intégrés à Chromium, dans le processus sandboxé). Le coût CPU invité est significatif : 1080p60 en AV1 ou VP9 demande plusieurs vCPU `[à mesurer]`. Pas de DRM matériel ; Widevine logiciel ou absent, voir la décision.

### B.6 Audio, presse-papiers, téléchargements, redimensionnement

- **Audio** :
  - par défaut, **coupé** (aucun périphérique audio dans l'invité) ;
  - option : PCM brut s16le 48 kHz stéréo à format fixe sur un port dédié, joué par l'hôte via WASAPI ou PipeWire, avec un limiteur de volume côté hôte. Le parseur est trivial. Risques résiduels : canal caché ou balises ultrasoniques (traçage entre appareils), faible risque pour l'hôte ;
  - virtio-snd est rejeté (périphérique C dans le VMM ; CVE QEMU virtio-snd antérieures `[non revérifié]`) ;
  - le **micro n'est jamais exposé** en v1.
- **Presse-papiers** : texte seul, sans HTML, image ni fichier.
  - Hôte→invité (`PASTE_TEXT`) : sur geste explicite seulement. Le risque pour l'hôte est faible. Le risque est surtout de confidentialité : l'utilisateur colle un secret dans un invité compromis.
  - Invité→hôte (`COPY_TEXT`) : **désactivé par défaut**. Si l'option est activée, le transfert n'a lieu qu'à la demande de l'hôte, avec :
    - UTF-8 strict, ≤ 64 Kio ;
    - suppression des caractères de contrôle C0/C1 (sauf `\t` et `\n`) et des contrôles bidirectionnels (U+202A–202E, U+2066–2069) ;
    - un aperçu avec confirmation, contre le « pastejacking » de commandes destinées à un terminal hôte.
  - Le presse-papiers hôte n'est jamais lu en arrière-plan.
- **Glisser-déposer** : désactivé (aucun message prévu).
- **Téléchargements** :
  - par défaut, **bloqués** (`DownloadRestrictions=3`). Les PDF s'ouvrent dans PDFium sandboxé sans téléchargement ;
  - option A : téléchargements autorisés **dans l'invité seulement** (tmpfs `noexec`, détruit à la fermeture), sans aucun transfert vers l'hôte ;
  - option B (future, ADR dédié) : export en quarantaine. Le fichier passe par un canal dédié, il est écrit dans un dossier hôte avec la Mark-of-the-Web (`Zone.Identifier`) ou un xattr d'origine, n'est jamais ouvert automatiquement, et peut être converti en « PDF sûr » (rendu en pixels dans une VM jetable, à la Qubes/Dangerzone).
- **Upload de fichiers** (hôte→invité) : absent en v1. Le sélecteur ne voit que le système de fichiers invité. C'est une **décision**.
- **Redimensionnement et HiDPI** :
  - l'hôte envoie la taille physique et l'échelle ; le compositeur invité applique une échelle fractionnaire (Chromium la gère sous Wayland) ;
  - en plein écran, il faut conserver un **indicateur hôte non recouvrable** (bandeau ou bord). Sans lui, le contenu invité peut imiter l'interface de l'hôte (fausse invite UAC ou de mot de passe). C'est une **décision**.
- **Accessibilité** : avec un transport par pixels, l'arbre d'accessibilité n'est pas transmis. Les lecteurs d'écran de l'hôte ne peuvent pas lire le contenu. C'est une limite connue à documenter.

---

## C. Risques résiduels

1. **Chaîne navigateur + noyau invité** : il faut supposer qu'elle est réalisable (des 0-days V8 existent chaque année). La frontière déterminante reste l'hyperviseur et la couche d'intégration hôte. Le navigateur n'est qu'une défense en profondeur.
2. **Bug dans le broker KDP** : la surface est minimale mais non nulle (parseur, mapping de la mémoire partagée, conversion I420/LZ4 si activées). Les atténuations (Rust, fuzzing, sandbox du broker, terminaison au premier écart) réduisent le risque sans l'éliminer.
3. **Pilote graphique hôte** : il ne reçoit que des uploads de texture XRGB opaques. Le risque est faible mais non nul (bugs de pilote sur des dimensions ou des contenus particuliers).
4. **Usurpation visuelle et ingénierie sociale** : l'invité contrôle 100 % des pixels de sa surface. Le seul rempart est le cadre et l'indicateur hôte, ainsi que l'éducation de l'utilisateur.
5. **Canaux de sortie autorisés** (presse-papiers, audio, futurs fichiers) : ce sont des canaux d'exfiltration ou d'injection volontairement ouverts dès qu'ils sont activés.
6. **Canaux auxiliaires** : timing, cache, Spectre-like entre la VM et l'hôte ; la charge CPU est observable. Ils relèvent de l'hyperviseur, mais le débit d'affichage peut servir de canal caché.
7. **Déni de service** : un invité qui monopolise le CPU ou la bande passante est borné par les crédits et quotas, mais l'expérience utilisateur se dégrade.
8. **Retard de correctifs** : entre la publication d'un correctif Chrome et l'image Kaput signée, la fenêtre d'exposition est **ouverte** sur un service jetable mais exposé à des sites malveillants par conception.
9. **Fuite de confidentialité** dans l'invité : saisie de secrets, Safe Browsing, télémétrie résiduelle.

## D. Inconnues (à lever avant les ADR)

- **Débit réel de hvsocket** pour 1080p60 brut, et existence d'un mécanisme de **mémoire partagée hôte↔invité utilisable par un tiers sous Hyper-V** (l'équivalent de VAIL de WSLg) → agents Windows et Virtualisation. Microsoft déconseille hvsocket pour la vidéo.
- Mécanisme de mémoire partagée disponible dans le VMM Linux retenu (ivshmem sous QEMU ; Firecracker et Cloud Hypervisor n'ont pas de périphérique équivalent standard, et leur vsock est relayé par un socket Unix côté hôte).
- Coût CPU invité du rendu logiciel et du décodage vidéo (nombre de vCPU nécessaire pour 1080p60).
- Comportement exact de `DefaultJavaScriptJitSetting=2` (WebAssembly ? DrumBrake ?) et de `DefaultJavaScriptOptimizerSetting` dans Chrome 157, plus l'impact mesuré sur un échantillon de sites.
- État de WebGL sans GPU (repli SwiftShader) et désactivation fiable de WebGPU.
- Disponibilité du sandbox du Network Service et du service audio sous Linux dans le build retenu.
- Statut du processus GPU de Firefox sous Linux (si Firefox reste en lice).
- Conditions de **redistribution de Google Chrome** dans une image Kaput.
- Délai réel de correctif des paquets Chromium Debian et Fedora sur les 12 derniers mois (mesure objective à faire par l'agent Supply Chain).
- Compatibilité entre le sandbox Chromium (userns) et le durcissement noyau invité retenu (userns, seccomp ou Landlock extérieurs).
- Possibilité de créer des sockets AF_HYPERV depuis un AppContainer, ou obligation de les transmettre en handle.

## E. Décisions nécessitant l'avis de l'utilisateur

1. **Binaire navigateur** : Google Chrome (licence propriétaire, le plus rapide), Chromium distro, ou Chromium compilé par Kaput (coût d'infrastructure).
2. **JIT** : désactivé par défaut (sécurité, lenteur, Wasm probablement cassé), optimiseurs seuls désactivés, ou JIT actif.
3. **GPU** : je recommande **aucune accélération GPU** (pas de virgl, Venus ni passthrough). Conséquences : WebGL et WebGPU limités ou absents, CPU plus sollicité.
4. **Résolution et fluidité** : faut-il accepter que la 4K60 vidéo soit dégradée (30 fps ou sous-résolution) plutôt que d'introduire un codec vidéo côté hôte ?
5. **Audio** : coupé par défaut, avec PCM brut en option ?
6. **Presse-papiers** : hôte→invité sur geste ? invité→hôte désactivé, ou activable en texte seul avec confirmation ?
7. **Téléchargements** : bloqués, autorisés dans l'invité uniquement, ou export en quarantaine (ADR futur) ?
8. **Upload de fichiers** vers des sites depuis l'hôte : non en v1 ?
9. **Safe Browsing** : standard ou Enhanced (envoie des URL à Google) ?
10. **DRM Widevine** (Netflix et autres) : autorisé (binaire fermé supplémentaire) ou non ?
11. **Plein écran** : autorisé avec un indicateur permanent, ou interdit ?
12. **Politique d'obsolescence** : refuser de démarrer si le navigateur a plus de 14 jours ou figure dans une liste de 0-days exploités (fail closed), ou seulement avertir ?
13. **Bloqueur de publicités** (uBlock Origin Lite) préinstallé ? Il réduit le malvertising mais ajoute une extension.

## F. Sources

Consultées le 12/11/2026 :
- Chrome Releases, 2026 : https://chromereleases.googleblog.com/2026/?hl=en
- Chrome, cycle de 2 semaines : https://developer.chrome.com/blog/chrome-two-week-release?hl=en
- Chrome 157 : https://smartscope.blog/en/blog/chrome-157-stable-released-213-security-fixes-7-2026/
- 0-days Chrome 2026 : https://securityaffairs.com/198757/security/google-fixes-the-seventh-actively-exploited-chrome-zero-day-of-2026.html ; https://esecurityplanet.com/threats/news-google-chrome-cve-2026-85046-zero-day ; https://www.helpnetsecurity.com/2026/09/09/google-chrome-cve-2026-87491-zero-day-flaw/ ; https://cybersecuritynews.com/chrome-0-day-flaw-exploited-wild/
- 0-days Chrome 2025 (8e) : https://www.cybersecurity-help.cz/blog/5124.html
- V8 sandbox : https://v8.dev/blog/sandbox ; https://www.securityweek.com/google-adds-v8-sandbox-to-chrome/amp/ ; https://popl26.sigplan.org/details/prisc-2026-papers/1/The-V8-Sandbox-From-Compiler-Correctness-to-Runtime-Containment
- Sandbox Chromium sous Linux : https://chromium.googlesource.com/chromium/src/+/404ca6f/docs/linux_sandboxing.md
- Chrome sous Wayland : https://omgubuntu.co.uk/2025/08/chrome-140-wayland-auto-detection-linux
- Cadence Firefox : https://blog.mozilla.org/sumo/2026/08/19/firefox-new-release-cadence-and-what-to-expect/
- Firefox 150.0.3 (Pwn2Own) : https://www.pcwelt.de/article/3138190/firefox-150-0-3-schnelles-update-kontert-exploit-kette-vor-pwn2own.html
- Firefox 158 : https://www.esecurityplanet.com/vulnerabilities/news-firefox-158-security-vulnerabilities-sandbox-escapes/
- Firefox 159 : https://www.pcworld.com/article/3271386/firefox-159-fixes-167-security-flaws-including-13-sandbox-escapes.html
- Firefox 152.0.6 : https://threatprotect.qualys.com/2026/07/15/mozilla-firefox-zero-day-vulnerabilities-exploited-in-attacks-cve-2026-15718-cve-2026-15719/
- Sandbox Firefox : https://wiki.mozilla.org/Security/Sandbox ; https://wiki.mozilla.org/Security/Sandbox/Specifics
- Trivalent : https://github.com/secureblue/hardened-chromium ; https://discuss.privacyguides.net/t/brave-vs-trivalent-security/25880
- ungoogled-chromium : https://discuss.privacyguides.net/t/ungoogled-chromium/15781.md
- QEMU virtio-gpu CVE-2026-3886 : https://www.wiz.io/vulnerability-database/cve/cve-2026-3886
- virglrenderer : https://www.cvedetails.com/vulnerability-list/vendor_id-16205/Virglrenderer-Project.html ; https://www.collabora.com/news-and-blog/blog/2025/01/15/the-state-of-gfx-virtualization-using-virglrenderer/ ; https://kvm-forum.qemu.org/2024/Virtio-gpu_where_are_we_now_-1_1cOiDio.pdf
- crosvm Wayland : https://crosvm.dev/book/devices/wayland.html
- SPICE CVE-2026-105958 : https://access.redhat.com/security/cve/CVE-2026-105958
- libvncclient CVE-2026-50538 : https://www.wiz.io/vulnerability-database/cve/cve-2026-50538
- FreeRDP CVE-2026-67305 : https://research.averlon.ai/vulnerability-intelligence/cve/CVE-2026-67305
- RDP client Microsoft : https://0patch.com/blog/micropatches-released-for-remote-desktop-client-remote-code-execution-vulnerabili ; https://www.action1.com/vulnerabilities/cve-2026-62824/
- WSLg : https://devblogs.microsoft.com/commandline/wslg-architecture
- Protocole GUI de Qubes : https://doc.qubes-os.org/en/r4.3/developer/system/gui.html
- Hyper-V sockets : https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
- Débit vsock : https://cnblogs.com/dream397/p/13865887.html

Références connues mais **non revérifiées** dans cette session :
- catalogue des politiques Chrome : https://chromeenterprise.google/policies/
- Edge « Super Duper Secure Mode » : https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode/
- hardened_malloc : https://github.com/GrapheneOS/hardened_malloc
- Isolation de sites Chromium : https://www.chromium.org/Home/chromium-security/site-isolation/
- Project Fission : https://wiki.mozilla.org/Project_Fission

Certaines pages consultées sont des sources secondaires, voire signalées comme « générées par IA » (Wiz, par exemple). Les identifiants de CVE et les versions doivent être recoupés avec les bulletins primaires (Chrome Releases, MFSA, GHSA, NVD) avant d'être repris dans un ADR.
