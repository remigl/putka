# 05 — Recherche réseau : politique d'accès Internet de l'invité Kaput

| Champ | Valeur |
|---|---|
| Rôle | Network Security Engineer (équipe Kaput) |
| Date | 2026-11-12 |
| Statut | RECHERCHE — aucune décision n'est figée ; à transformer en ADR `0003-network-isolation.md` après revue |
| Périmètre | Comment le navigateur (dans un Linux invité en VM) atteint Internet sans que l'invité accède au localhost, au LAN, aux interfaces ou aux services de l'hôte |
| Entrées | `docs/product-brief.md` §2, §8, §9, §17, §18, §25, §28, §32, §33 |
| Hypothèse de menace | L'invité est **entièrement compromis** (root dans l'invité, noyau invité compris). Tout octet venant de l'invité est hostile. |

> Note de méthode : les faits datés (CVE, versions, état des projets) ont été vérifiés en ligne le 2026-11-12 ; les liens sont en §13. Le quota de recherche web a été atteint en fin de travail : quelques références normatives (RFC, registres IANA) sont citées sans re-vérification du jour et sont marquées *[réf. normative]*. Les affirmations non vérifiées sont marquées *[à vérifier]*.

---

## 1. Résumé exécutif

1. **Recommandation : l'invité n'a aucune carte réseau.** Son seul canal vers l'extérieur est un socket **vsock** (Linux) / **Hyper-V socket** (Windows) vers un **proxy de sortie écrit par Kaput en Rust**, qui résout le DNS lui-même (DoH) puis applique la politique **sur l'adresse IP réellement connectée** (anti-rebinding par construction).
2. L'hôte ne parse alors **aucun paquet L2/L3 venant de l'invité** : on supprime la classe de bugs de vmswitch.sys (CVE-2021-28476, CVSS 9.9) et de libslirp (13+ CVE, dont CVE-2026-9539 corrigée en 4.9.2).
3. Les piles en espace utilisateur (libslirp, passt, gvisor-tap-vsock) **ne filtrent pas les destinations** de façon adéquate pour notre besoin (passt : pas de filtrage sortant en mai 2026 ; gvproxy : CVE-2026-107935 CVSS 9.3 exploitable depuis l'invité).
4. Politique **deny by default** : seules les unicast globales (IPv4 hors plages spéciales, IPv6 dans `2000::/3` hors sous-blocs spéciaux) sont permises ; refus dynamique des adresses de l'hôte, des préfixes **on-link** (LAN en adresses publiques, IPv6 GUA du LAN) et des routes non-défaut (split-tunnel VPN).
5. **v1 sans UDP** : pas de QUIC/HTTP3 ni WebRTC P2P en UDP ; repli TCP (HTTP/2, TURN-TCP/TLS). UDP via datagrammes encapsulés = phase 2, soumise à décision.
6. DNS : uniquement côté hôte, DoH vers un résolveur choisi par l'utilisateur (défaut proposé : Quad9), cache en mémoire par session, **fail closed** si DoH indisponible.
7. Points critiques à trancher par l'utilisateur : proxy d'entreprise / TLS-inspection, mode « DNS système », ports autorisés, UDP, portails captifs (§12).

---

## 2. Exigences réseau dérivées du brief

| ID | Exigence | Source brief |
|---|---|---|
| NET-R1 | Le navigateur atteint Internet (HTTP/1.1, HTTP/2, WebSocket au minimum) | §9 |
| NET-R2 | Aucun accès de l'invité à : loopback hôte, interfaces de l'hôte, LAN, services locaux | §8, §9 |
| NET-R3 | Pas de « host networking » ; pas d'interface inutile | §8 |
| NET-R4 | DNS isolé, pas de fuite, anti-rebinding | §9 |
| NET-R5 | IPv4 et IPv6 traités explicitement (dont IPv6 local) | §9 |
| NET-R6 | mDNS / multicast / WebRTC traités | §9 |
| NET-R7 | Fail closed, refuser par défaut, privilèges minimaux, entrées validées | §25, §10 |
| NET-R8 | Tests négatifs automatisés et mesurables | §17, §18 |
| NET-R9 | Aucune donnée réseau persistante après session (cache DNS, logs) | §7, §19 |

**Frontière de confiance réseau.** Tout ce qui est dans la VM est non fiable. Le composant de confiance est le **proxy de sortie Kaput** (processus hôte). Le noyau hôte et le transport vsock/hvsock font partie de la base de confiance (TCB) et sont une surface d'attaque résiduelle.

---

## 3. Comparaison des modèles

### 3.1 Grille synthétique

Légende : ✅ bon / ⚠️ partiel ou conditionnel / ❌ mauvais.

| Critère | M1 NIC + NAT hyperviseur | M2 Pile userspace (slirp / passt / gvproxy) | M3 Sans NIC, vsock → proxy Kaput | M4a NIC + VM réseau dédiée (type Qubes) | M4b TUN *dans* l'invité → vsock → proxy Kaput |
|---|---|---|---|---|---|
| Hôte parse des paquets invités ? | ❌ oui, en **noyau** (vmswitch.sys, bridge/netfilter) | ❌ oui, en **userspace C/Go** | ✅ non : uniquement un flux applicatif minimal | ⚠️ oui mais dans une 2e VM | ✅ non (la pile TCP/IP est dans l'invité, non fiable) |
| Accès hôte/LAN par défaut | ❌ ouvert (passerelle = hôte, NAT vers LAN) | ❌ ouvert (10.0.2.2 → loopback hôte, LAN routé) | ✅ fermé : rien n'est routable | ⚠️ dépend des règles de la VM réseau | ✅ fermé |
| Politique **après** résolution DNS | ❌ impossible au niveau NAT (ne voit que des IP ; résolution faite par l'invité) | ❌ idem (sauf patch maison) | ✅ native : le proxy résout et connecte lui-même | ⚠️ filtrage IP seulement | ⚠️ IP seulement (DNS via canal dédié possible) |
| IPv6 | ⚠️ souvent mal géré (WinNAT IPv4 seulement *[à vérifier]*) | ⚠️ variable | ✅ côté hôte, Happy Eyeballs dans le proxy | ✅ | ✅ |
| UDP / QUIC / WebRTC UDP | ✅ | ✅ | ❌ en v1 (TCP seulement) ; ⚠️ phase 2 | ✅ | ✅ (datagrammes encapsulés) |
| Performance | ✅ meilleure | ⚠️ slirp lent, passt correct | ✅ suffisante pour navigation *[à mesurer]* | ⚠️ 2 VM, RAM ×2 | ✅ *[à mesurer]* |
| Windows | ✅ Hyper-V vSwitch/WinNAT | ⚠️ slirp, gvproxy (pas passt) | ✅ hvsock (enregistrement GUID admin) | ⚠️ lourd | ✅ |
| Linux | ✅ libvirt NAT / bridge | ✅ | ✅ vsock (vhost ou userspace) | ⚠️ | ✅ |
| Privilèges | ❌ admin/root (switch, NAT, nftables) | ✅ non root | ✅ non root (Linux), admin une fois à l'installation (Windows) | ❌ | ✅ idem M3 |
| Complexité Kaput | ⚠️ firewall multi-plateforme | ⚠️ patchs de filtrage | ⚠️ écrire/fuzzer un proxy | ❌ élevée | ⚠️ M3 + pile dans l'invité |

### 3.2 M1 — NIC virtuelle + NAT de l'hyperviseur

**Windows (Hyper-V vSwitch, Default Switch, WinNAT, HNS).** Les paquets de l'invité sont traités par `vmswitch.sys` dans la partition racine (noyau hôte). Historique : CVE-2021-28476 (CVSS 9.9), un invité envoie un message RNDIS avec un OID que vmswitch ne valide pas, menant à un DoS de l'hôte et potentiellement une exécution de code sur l'hôte ([Akamai/Guardicore](https://www.akamai.com/blog/security/critical-vulnerability-in-hyper-v-allowed-attackers-to-exploit-azure)). Le flux de CVE Hyper-V invité→hôte reste soutenu en 2025–2026 (ex. CVE-2025-48807, CVE-2026-45607 : OOB read CVSS 8.4 depuis l'invité vers l'hôte ([Action1](https://www.action1.com/vulnerabilities/cve-2026-45607/)) ; un bug « netvsc » ZDI-26-416 ([ZDI](https://zerodayinitiative.com/advisories/ZDI-26-416))). Retirer la NIC retire *une* des voies VMBus exposées (le VSP réseau), pas toutes.
- Blocage hôte/LAN : la passerelle NAT *est* l'adaptateur vEthernet de l'hôte. Il faudrait des règles WFP/pare-feu Windows par adaptateur, plus un filtrage de la sortie NAT vers le LAN. Le **Hyper-V Firewall** (Windows 11 22H2+) existe mais n'est documenté que pour WSL / les conteneurs, avec des règles par `VMCreatorId` et un `LoopbackEnabled` qui autorise par défaut l'hôte↔WSL ([Microsoft Learn](https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall)). Rien ne garantit qu'il couvre une VM HCS Kaput *[à vérifier]*.
- Politique post-DNS : impossible, c'est l'invité qui résout. Rebinding : bloquer les RFC1918 au NAT ne protège ni les LAN adressés en public ni les GUA IPv6 du LAN.
- Privilèges : création de switch/NAT = administrateur.

**Linux (libvirt NAT `virbr0`, bridge, tap + nftables).** Ici c'est le noyau hôte qui reçoit les paquets (tap, bridge, conntrack, netfilter). Le filtrage (nwfilter / nftables) est expressif mais demande root ou `CAP_NET_ADMIN`, varie selon les distributions (firewalld, ufw, Docker qui réécrit les chaînes) et reste purement IP.

**Verdict M1 : écarté.** C'est la plus grande surface d'attaque hôte (noyau), la configuration demande des privilèges, et elle ouvre par défaut.

### 3.3 M2 — Pile réseau en espace utilisateur côté hôte

Ces piles terminent la TCP/IP de l'invité dans un processus hôte non privilégié et ré-émettent des sockets. La surface passe du noyau à l'espace utilisateur, ce qui est mieux, mais **le processus hôte parse toujours des trames Ethernet/IP/TCP/UDP/ICMP/DHCP/ARP/NDP hostiles**.

**libslirp (C ; QEMU user-net, rootless Podman historique, VirtualBox NAT dérivé de slirp *[à vérifier]*).**
- Historique CVE lourd et récurrent : CVE-2019-14378 (heap overflow `ip_reass`, 8.8), CVE-2019-15890 et CVE-2020-1983 (UAF `ip_reass`), CVE-2020-7039 (heap overflow `tcp_emu`), CVE-2020-8608 (overflow `tcp_subr.c`), CVE-2020-10756 (fuite mémoire ICMPv6), CVE-2020-29129/29130, CVE-2021-3592→3595 (fuites via bootp/udp/udp6/tftp) ([cvelogic](https://www.cvelogic.com/vendor/libslirp_project)). En 2026 : **CVE-2026-9539**, lecture hors limites et integer underflow dans `sosendoob` (urgent data TCP), qui fait fuiter la mémoire du processus hôte vers un invité root ; corrigée en v4.9.2 ([Debian](https://security-tracker.debian.org/tracker/CVE-2026-9539), bump [ptxdist 4.9.3→4.9.4](https://lore.ptxdist.org/ptxdist/20260904171205.3849412-1-christian.melki@t2data.com/t/)). Debian sid embarque 4.9.5.
- Accès hôte par défaut : l'invité voit l'hôte en `x.x.x.2` (10.0.2.2) ([QEMU invocation](https://www.qemu.org/docs/master/system/invocation.html)). `restrict=on` isole complètement (« the guest will be isolated, i.e. it will not be able to contact the host ») et coupe donc aussi Internet. Dans ce mode, seuls les `guestfwd` explicites passent : c'est justement l'idée de M3, mais avec une pile slirp devant.
- Pas de filtrage de destination par politique, pas de résolution post-DNS (l'invité résout, slirp proxifie le DNS vers le résolveur système, ce qui crée une **fuite DNS** par conception).

**passt / pasta (C, Linux uniquement, conçu durci).**
- Bonne hygiène (processus isolé, seccomp, sans privilège). On ne lui connaît pas d'historique de CVE comparable à slirp ; la seule CVE trouvée liée à passt (CVE-2026-84042) est en réalité une régression de **crun** avec libkrun+passt en mode rootful ([SUSE](https://www.suse.com/security/cve/CVE-2026-84042.html)).
- **Par conception, il ne filtre pas les destinations.** Les mainteneurs confirment que l'invité peut joindre les adresses secondaires de l'hôte et, avec les options par défaut, le loopback de l'hôte. Ils répondent que pasta « is not a container runtime » et que Podman doit passer `--no-map-gw` ([passt-user, 2024](https://archives.passt.top/passt-user/20240510124508.288d874d@elisabeth/t/)). En mai 2026, une demande de blocage des adresses externes de l'hôte est restée **sans patch** : le filtrage sortant n'est que « prévu », et un suivi netlink des changements d'adresse laisserait une fenêtre de course ([passt-user, mai 2026](https://archives.passt.top/passt-user/afgxhMK_fsHS5rMG@zatzit/T/)).
- Pas de Windows. Pas de politique post-DNS.

**gvisor-tap-vsock / gvproxy (Go, netstack gVisor ; Podman machine, CRC).**
- Mémoire-sûr et multiplateforme (vsock, hvsock, socket Unix). L'invité y voit cependant une passerelle et une adresse « hôte » mappée sur le loopback de l'hôte (`host.containers.internal`) *[à vérifier : adresses exactes, README non accessible]*.
- **CVE-2026-107935 (CVSS 9.3)** : traversée de chemin dans l'endpoint non authentifié `/services/forwarder/expose`, qui permet de supprimer des fichiers arbitraires sur l'hôte, exploitable depuis du code exécuté dans l'invité ; corrigée en 0.9.0 ([Red Hat](https://access.redhat.com/security/cve/CVE-2026-107935)). S'y ajoutent les avis récurrents liés à la toolchain Go ([RHSA-2024:4379](https://access.redhat.com/errata/RHSA-2024:4379)). La leçon : une API de contrôle accessible depuis l'invité est un vecteur, même dans un langage mémoire-sûr.

**smoltcp (Rust).** C'est une bibliothèque TCP/IP, pas un produit NAT : il faudrait écrire tout le NAT/proxy autour. On garderait le parsing de paquets côté hôte, en mémoire-sûre, ce qui reste moins bon que de ne rien parser du tout (M3).

**Verdict M2 : écarté comme frontière principale.** On garde l'option smoltcp côté *invité* pour M4b.

### 3.4 M3 — Aucune NIC ; vsock vers un proxy de sortie Kaput (recommandé)

```text
┌──────────── VM invitée (non fiable) ─────────────┐          ┌──────────── Hôte ─────────────────────────────┐
│ Navigateur ──SOCKS5/HTTP CONNECT──► relais local │  vsock   │ kaput-egress (Rust, non privilégié, sandboxé)  │
│ (127.0.0.1:1080, interface lo uniquement)        │ ───────► │  1. parse trame KEP v1 (hôte, port)            │
│ pas de NIC virtio-net / netvsc, pas de résolveur │  1 port  │  2. filtre nom  3. DoH  4. filtre IP + route   │
└──────────────────────────────────────────────────┘          │  5. connect() TCP vers l'IP validée → Internet │
                                                              └───────────────────────────────────────────────┘
```

- **Surface d'attaque hôte.** Côté transport, on a le device vsock (vhost-vsock noyau, ou implémentation userspace du VMM) ou hvsock sous Windows. Côté application, un seul parseur : celui du protocole Kaput. Aucun ARP/DHCP/NDP/ICMP/IP-fragments/TCP-options hostile ne parvient à l'hôte. Point de vigilance Linux : le cœur `af_vsock` du noyau a lui aussi des CVE (ex. CVE-2025-21756, UAF, 7.8, local ([Red Hat](https://access.redhat.com/security/cve/CVE-2025-21756))). Il est préférable d'utiliser un VMM qui **émule vsock en espace utilisateur** et le relie à des sockets Unix (« hybrid vsock » de Firecracker, qui contourne le code vhost du noyau hôte ([Firecracker vsock](https://github.com/roypat/firecracker/blob/main/docs/vsock.md)) ; même modèle chez Cloud Hypervisor et vhost-device-vsock). Effet de bord utile : l'invité ne peut alors joindre **que** les sockets Unix `uds_path_PORT` créées par Kaput, et non un service hôte quelconque écoutant en `AF_VSOCK` sur `VMADDR_CID_ANY`. Ce choix est à coordonner avec le Virtualization Engineer.
- **Windows.** Hyper-V sockets : l'invité Linux utilise `AF_VSOCK` (`CONFIG_HYPERV_VSOCKETS`) ; l'hôte écoute en `AF_HYPERV` sur un GUID dérivé du gabarit `xxxxxxxx-facb-11e6-bd58-64006a7986d3`. Le service doit être enregistré sous `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Virtualization\GuestCommunicationServices\`, ce qui demande des droits **administrateur** (une fois, à l'installation) ([Microsoft Learn](https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service)). Le listener doit se lier au **VMID précis** de la VM de session, pas à `HV_GUID_WILDCARD`.
- **Politique post-DNS** : native, c'est le proxy qui résout et choisit l'IP à connecter. L'invité ne voit jamais d'IP sauf s'il en fournit une littérale, auquel cas elle est filtrée de la même façon.
- **IPv4/IPv6** : le proxy fait du Happy Eyeballs v2 ([RFC 8305] *[réf. normative]*) ; l'invité n'a besoin d'aucune adresse.
- **UDP/QUIC/WebRTC** : non en v1. Chromium ne relaie pas d'UDP via SOCKS5 (« only used to proxy TCP-based URL requests ») et résout toujours côté proxy en SOCKS5 ([Chromium proxy.md](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md)). Firefox implémente CONNECT-UDP (MASQUE), mais uniquement sur une connexion HTTP/3 externe vers le proxy, donc sur QUIC ([Firefox docs](https://firefox-source-docs.mozilla.org/networking/http/connect_udp.html)). Ce n'est pas transportable directement sur un flux vsock. Voir phase 2 en §4.3.
- **Performance** : une copie userspace de plus par flux. C'est attendu suffisant pour la navigation et la vidéo en streaming (TCP), mais **à mesurer** en lab (débit, latence, 500+ flux concurrents).
- **Privilèges** : proxy en utilisateur standard ; aucun pare-feu système à modifier.

### 3.5 M4 — Autres variantes

- **M4a — VM réseau dédiée (modèle Qubes `sys-net`/`sys-firewall`).** L'isolation est forte (les pilotes et le filtrage tournent dans une VM jetable), mais il faut deux VM par session, un coût RAM et temps de démarrage élevé, et la complexité Windows est forte. Ce modèle reste une **évolution possible** si l'on veut un jour un UDP complet sans pile côté hôte. Écarté pour v1.
- **M4b — TUN dans l'invité + pile userspace *dans l'invité* (tun2proxy/smoltcp) → vsock → proxy Kaput.** La pile TCP/IP reste du côté non fiable ; l'hôte ne voit que « ouvrir flux TCP vers IP:port » et, en phase 2, « datagramme UDP vers IP:port ». Le navigateur fonctionne sans configuration proxy (mode transparent), ce qui permet UDP, QUIC et WebRTC. Coûts : le navigateur résout lui-même, il faut donc un stub DNS invité → vsock → DoH hôte, et on perd le filtrage par nom (le filtrage IP post-résolution reste exact, puisque c'est l'IP connectée qui est filtrée). C'est le **chemin naturel de la phase 2**.
- **M4c — Sortie via VPN/Tor intégré côté proxy** (WireGuard userspace, Arti). Ce serait une option de confidentialité, pas d'isolation. Hors périmètre v1 ; à proposer comme décision produit.
- **M4d — `restrict=on` + `guestfwd` (QEMU/slirp)**, qui reproduit M3 mais avec slirp en frontal. Aucun avantage sur M3, et la surface slirp est conservée.

---

## 4. Recommandation argumentée

### 4.1 Choix

**M3 en v1, avec trajectoire M4b pour l'UDP en phase 2.** Les justifications, par ordre de priorité du brief (§30) :

1. **Sécurité.** C'est la plus petite surface hôte exposée à l'invité : un protocole applicatif de quelques dizaines d'octets, écrit en Rust, fuzzé, au lieu d'une pile IP complète (M2) ou d'un switch noyau (M1). L'historique slirp (§3.3), CVE-2021-28476 et CVE-2026-107935 montrent que c'est bien là que les bugs se produisent.
2. **Fail closed par construction.** Sans NIC, l'invité n'a aucun chemin réseau, même si le proxy plante ou si une règle manque. La seule voie est le proxy, qui refuse par défaut.
3. **Politique exacte.** Le filtrage porte sur l'IP *effectivement connectée* après résolution par une partie de confiance, ce qui élimine le DNS rebinding sans heuristique.
4. **Pas de fuite DNS ni multicast possible depuis l'invité** (pas d'interface), donc mDNS, LLMNR, NetBIOS, SSDP, DHCP et NDP disparaissent du modèle.
5. **Privilèges minimaux** et comportement identique sur Windows et Linux : un seul code de politique, testé une fois.

Le compromis majeur est l'**absence d'UDP en v1**. HTTP/3 se replie sur HTTP/2 de façon transparente. La visio WebRTC passe par TURN-TCP/TLS quand le service le propose (Meet, Teams, Jitsi généralement), avec une qualité dégradée. Le P2P UDP pur ne fonctionne pas. Ce compromis est **soumis à l'utilisateur** (§12, D1).

### 4.2 Architecture du proxy `kaput-egress`

- **Langage** : Rust stable, `#![forbid(unsafe_code)]` dans la logique de politique, dépendances minimales et auditées (`cargo-vet`/`cargo-deny`). Pour le DNS, plutôt `hickory-resolver`, en suivant ses avis : RUSTSEC-2026-0118 (boucle infinie lors de la validation NSEC3 DNSSEC, versions 0.25.0-alpha.3 → 0.26.0-beta.1) ([RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0118)) et RUSTSEC-2026-0106 (empoisonnement de cache dans `hickory-recursor`, crate à **ne pas** utiliser) ([RustSec](https://rustsec.org/advisories/RUSTSEC-2026-0106)). On utilise le résolveur *stub* DoH, sans validation DNSSEC en v1.
- **Protocole invité→hôte « KEP v1 »** (Kaput Egress Protocol) : une connexion vsock par flux. Trame de requête de longueur fixe ou bornée : `version(u8)`, `type(u8: CONNECT_TCP)`, `addr_type(u8: NAME|IPV4|IPV6)`, `addr(≤253 octets ASCII LDH)`, `port(u16)`. Réponse : `code(u8)` **sans** adresse locale. Contrairement au `BND.ADDR` de SOCKS5, qui pourrait révéler l'IP LAN de l'hôte, on ne renvoie rien. Ensuite, copie d'octets bidirectionnelle. Le relais invité (SOCKS5/HTTP CONNECT → KEP) est du code non fiable et sa compromission est sans conséquence. Le parseur hôte est minimal, versionné et fuzzé (cargo-fuzz, en CI).
- **Cloisonnement du proxy (défense en profondeur)** :
  - *Linux* : utilisateur non privilégié, `seccomp` en liste blanche (familles `AF_INET`, `AF_INET6`, `AF_UNIX`/`AF_VSOCK`, `AF_NETLINK` en lecture route uniquement, si nécessaire via un processus auxiliaire), Landlock sans accès fichiers. Landlock ne filtre le réseau que **par port** (TCP ABI v4, UDP ABI v10), pas par adresse ([kernel.org](https://docs.kernel.org/userspace-api/landlock.html)) : il peut verrouiller les ports autorisés mais **pas** remplacer la politique IP. Un filtrage nftables par cgroup/UID serait une couche supplémentaire, mais exige root (décision D6).
  - *Windows* : exécuter la partie « sortie » dans un **AppContainer** avec la seule capacité `internetClient` (sans `privateNetworkClientServer`). WFP bloque alors par défaut le loopback et les plages « privées » ([Microsoft Learn](https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall)). **Limite** : la plage privée dépend de la politique et de la détection, et un exemple Microsoft montre `10.1.1.1` hors plage. C'est donc une couche secondaire, jamais la seule. Il reste à vérifier si un AppContainer peut ouvrir un listener `AF_HYPERV` ; sinon, découper en deux processus (I2).
- **Quotas** (contre un DoS sur l'hôte) : flux concurrents ≤ 512 par session, ouverture ≤ 100/s, requêtes DNS ≤ 200/s, timeout de connexion 15 s, inactivité 5 min, tampons bornés. Au dépassement, refus et compteur.
- **Journalisation** : codes de décision agrégés uniquement. **Aucun nom d'hôte ni IP de destination** par défaut, conformément au §19 (les logs ne doivent pas devenir un canal d'exfiltration ni un historique de navigation). Le mode diagnostic, activé explicitement, est éphémère.

### 4.3 Phase 2 (UDP) — options à évaluer

1. Ajouter `type=UDP_ASSOC` à KEP : des datagrammes encadrés par longueur sur un flux vsock, avec la même politique de destination par datagramme, plus des quotas débit/pps. Côté invité, une TUN + pile userspace (M4b) ou un shim.
2. Autoriser UDP **uniquement** vers 443 (QUIC) et vers les ports TURN/STUN, avec les mêmes filtres d'adresse.
3. Points de risque spécifiques : amplification/flood depuis l'hôte (réputation IP de l'utilisateur), contournement des règles d'entreprise, et WebRTC exposant l'IP publique de sortie aux pairs (c'est déjà l'IP vue par tout site web).

---

## 5. Politique réseau formelle (deny by default)

### 5.1 Pipeline de décision (ordonné, premier match gagne, défaut = REFUS)

Le pipeline s'applique à chaque requête KEP. Toute erreur de parsing, de résolution ou d'état produit un **REFUS** (fail closed).

| # | Étape | Règle | Action |
|---|---|---|---|
| P0 | État | Politique non chargée, tables d'adresses hôte non initialisées, ou horloge de rafraîchissement expirée (> 30 s) | REFUS (tous flux) |
| P1 | Trame | Version ≠ 1, type inconnu, longueur hors bornes, port 0, caractères hors `[A-Za-z0-9.-]` (après IDNA côté invité ; l'hôte n'accepte que l'ASCII LDH), label > 63, nom > 253 | REFUS |
| P2 | Littéral déguisé | Le nom est analysable comme IPv4 par *n'importe quelle* syntaxe historique (`inet_aton` : décimal `2130706433`, octal `0177.1`, hexadécimal `0x7f.1`, formes courtes `127.1`) | Le traiter comme littéral IP → P6 |
| P3 | Noms spéciaux | `localhost`, `*.localhost`, `*.local`, `*.home.arpa`, `*.internal`, `*.arpa` (dont `in-addr`/`ip6.arpa`), `*.onion`, `*.alt`, `*.test`, `*.invalid`, `*.example`, nom à **un seul label** (protège contre WPAD/suffixes de recherche), nom finissant par `.` (normaliser puis réévaluer) | REFUS |
| P4 | Port | Profil « Standard » (proposé) : TCP 80, 443 et 1024–65535 ; tous les autres ports < 1024 refusés (dont 25, 135–139, 445, 465, 587) ; liste noire explicite au-dessus de 1024 : 1900, 3389, 5353, 5355 | REFUS si hors profil (décision D4) |
| P5 | Résolution | Nom → DoH (§6) : A et AAAA ; en cas d'échec ou de réponse vide → REFUS « résolution » | — |
| P6 | Normalisation IP | `::ffff:a.b.c.d` (IPv4-mapped) → évaluer `a.b.c.d` en IPv4 ; `::a.b.c.d` (IPv4-compatible, déprécié) → REFUS ; `64:ff9b::/96` (NAT64 WKP) → extraire l'IPv4 incorporée et l'évaluer, REFUS si elle est refusée ; adresse avec zone/scope-id (`%eth0`) → REFUS | — |
| P7 | Liste noire IPv4 statique | voir §5.2 | REFUS |
| P8 | IPv6 : liste blanche de portée | Autoriser seulement `2000::/3`, puis appliquer la liste noire §5.2 (sous-blocs spéciaux dans `2000::/3`) | REFUS hors `2000::/3` |
| P9 | Adresses de l'hôte | Toute adresse configurée sur **n'importe quelle** interface de l'hôte (physique, Wi-Fi, VPN/TUN, vEthernet Hyper-V/WSL, `docker0`, bridges libvirt), y compris les GUA IPv6 et les adresses temporaires | REFUS |
| P10 | On-link | Destination appartenant à un **préfixe connecté** (route directe sans passerelle) d'une interface de l'hôte. Couvre les LAN adressés en IP publiques et les GUA IPv6 des autres appareils du LAN | REFUS |
| P11 | Route non-défaut | Lookup de route de l'OS (`RTM_GETROUTE` / `GetBestRoute2`) : interface de sortie ≠ interface de la route par défaut (split-tunnel VPN, routes d'entreprise, routes statiques internes) | REFUS par défaut (décision D5) |
| P12 | Métadonnées cloud / plateformes | `169.254.169.254`, `fd00:ec2::254`, `168.63.129.16` (Azure WireServer, IP publique *[réf.]*), `100.100.100.200` (Alibaba, dans CGNAT), `192.0.0.192` (Oracle, dans 192.0.0/24) ; noms `metadata.google.internal` (via P3) | REFUS |
| P13 | Toutes adresses résolues | Si **au moins une** adresse de la réponse DNS tombe en P6–P12, **toute** la réponse est refusée (signal fort de rebinding ou de domaine interne), avec un code distinct « destination interne » | REFUS |
| P14 | Connexion | `connect()` uniquement vers les IP validées en P6–P13, **sans re-résolution**, socket non lié à une interface spécifique (sauf D5), `IP_TTL` par défaut | AUTORISER (TCP) |
| P15 | Tout le reste | UDP, ICMP, IP brut, multicast, broadcast, ports hors profil | REFUS |

Pour P13, le choix « refuser toute la réponse » plutôt que « filtrer les mauvaises adresses » est plus strict. Il évite qu'un domaine attaquant mélange `1.2.3.4` et `10.0.0.1` pour sonder le LAN par l'observation des échecs. Il pourrait casser de rares sites mal configurés ; c'est à mesurer en lab.

### 5.2 Listes noires statiques

Elles sont dérivées des registres IANA Special-Purpose ([IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml), [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml) *[réf. normative, non re-vérifiée ce jour]*). Elles sont générées depuis un fichier de données versionné et testé, jamais tapées à la main dans le code.

| Bloc | Signification | Raison |
|---|---|---|
| `0.0.0.0/8` | « cet hôte » | `connect(0.0.0.0)` atteint le localhost sur Linux/macOS (attaque publique « 0.0.0.0 day », 2024 *[réf.]*) |
| `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` | RFC 1918 | LAN |
| `100.64.0.0/10` | CGNAT RFC 6598 | réseau opérateur, Tailscale, Alibaba metadata |
| `127.0.0.0/8` | loopback | hôte |
| `169.254.0.0/16` | link-local, métadonnées cloud | hôte / plateforme |
| `192.0.0.0/24` | IETF protocol assignments | dont 192.0.0.192 (Oracle), DS-Lite |
| `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` | documentation | jamais légitime |
| `192.88.99.0/24` | anycast relais 6to4 (déprécié RFC 7526) | transition |
| `198.18.0.0/15` | benchmarking | souvent utilisé en interne (lab, VPN) |
| `224.0.0.0/4` | multicast | mDNS 224.0.0.251, SSDP 239.255.255.250 |
| `240.0.0.0/4` (dont `255.255.255.255`) | réservé / broadcast | — |
| `::/128`, `::1/128` | non spécifié, loopback | hôte |
| `::/96`, `::ffff:0:0/96`, `::ffff:0:0:0/96` | IPv4-compatible / mapped / translated | traités en P6, sinon REFUS |
| `64:ff9b:1::/48` | NAT64 usage local (RFC 8215) | préfixe local |
| `100::/64` | discard | — |
| `2001::/23` | IETF protocol assignments (Teredo `2001::/32`, benchmark `2001:2::/48`, ORCHID…) | transition / non web |
| `2001:db8::/32`, `3fff::/20` | documentation (RFC 3849, RFC 9637) | — |
| `2002::/16` | 6to4 (encapsule IPv4, y compris privée) | transition |
| `5f00::/16` | SRv6 SID | non web |
| `fc00::/7` | ULA | LAN, dont `fd00:ec2::254` |
| `fe80::/10`, `fec0::/10` | link-local, site-local (déprécié) | LAN |
| `ff00::/8` | multicast (dont `ff02::fb` mDNS, `ff02::1:3` LLMNR) | — |

Toutes les plages IPv6 hors `2000::/3` sont refusées par P8, quelle que soit la liste.

### 5.3 NAT64 / réseaux IPv6-only

Si l'hôte est sur un réseau IPv6-only avec NAT64/DNS64, deux cas se présentent :
- avec le préfixe bien connu `64:ff9b::/96`, l'IPv4 incorporée est vérifiée (P6) ;
- avec un préfixe spécifique au réseau (NSP), découvrable via `ipv4only.arpa` (RFC 7050 *[réf.]*), le proxy doit découvrir ce préfixe et l'extraire de la même façon. Sinon, un domaine attaquant pourrait renvoyer `NSP::0a00:0001`, ce qui contournerait la liste IPv4 pour viser `10.0.0.1` via le NAT64 du réseau. Mitigation : DoH (pas de DNS64 du réseau) et IPv4 incorporée vérifiée pour tout préfixe NAT64 détecté. Sans découverte possible, les adresses du NSP doivent être refusées. C'est l'inconnue I5.

### 5.4 Invariants de configuration VM (vérifiés au démarrage, fail closed)

| ID | Invariant |
|---|---|
| VM-N1 | Zéro périphérique réseau (pas de virtio-net, netvsc/synthetic NIC, e1000, ni NIC « legacy ») ; vérifié dans la configuration VMM **et** par un agent de test dans l'invité (`/sys/class/net` = `lo` uniquement) |
| VM-N2 | Un seul port vsock/hvsock exposé (KEP) ; en Linux « hybrid vsock » userspace, seuls les sockets Unix créés par Kaput sont joignables |
| VM-N3 | Listener hvsock lié au VMID de la session, jamais `HV_GUID_WILDCARD`/`HV_GUID_ZERO` |
| VM-N4 | Aucun `guestfwd`/port-forward entrant ; aucune connexion hôte→invité initiée par un tiers |
| VM-N5 | Toute dérive de configuration → arrêt de session |

---

## 6. Stratégie DNS

| Sujet | Décision proposée |
|---|---|
| Où se fait la résolution ? | **Uniquement dans `kaput-egress`, côté hôte.** L'invité n'a pas de résolveur fonctionnel (`/etc/resolv.conf` vide, pas d'interface). Chromium résout toujours côté proxy en SOCKS5 ([proxy.md](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md)) ; Firefox exige `network.proxy.socks_remote_dns=true`. Le DoH interne du navigateur est désactivé (`DnsOverHttpsMode=off`, `network.trr.mode=5`), car toute tentative serait de toute façon une connexion proxifiée filtrée |
| Protocole amont | DoH (RFC 8484 *[réf.]*) en HTTP/2 sur TLS 1.3, bootstrap par **IP littérales intégrées** à la configuration (pas de résolveur système pour amorcer), validation de certificat par magasin de racines **embarqué et signé avec Kaput** (pas de pinning SPKI, trop fragile) |
| Résolveur par défaut | Proposé : **Quad9** (fondation suisse, pas d'ECS par défaut, blocage de domaines malveillants), alternatives listées : Cloudflare, Mullvad, DNS4EU *[à vérifier]*, URL DoH personnalisée. **Choix utilisateur** (D2) |
| Mode « DNS système » | Désactivé par défaut. S'il est activé (réseau d'entreprise, split-horizon), le proxy utilise le résolveur OS, **mais P6–P13 restent appliquées** : le rebinding reste bloqué, la confidentialité est perdue (D3) |
| DoH injoignable | **Fail closed** : page d'erreur « DNS sécurisé indisponible » dans l'invité, avec un message côté UI Kaput. Pas de repli silencieux vers le DNS système |
| Anti-rebinding | Par construction : une seule résolution par flux, l'IP vérifiée est celle connectée (P14), et toute réponse contenant une adresse interne est rejetée (P13). Le TTL n'est jamais utilisé pour revalider une connexion ouverte |
| Cache | En mémoire uniquement, par session, borné (ex. 10 000 entrées), TTL clampé [30 s, 1 h], **effacé à la destruction de session** (§7 du brief) |
| Fuites DNS | Invariants : (a) le proxy n'appelle jamais `getaddrinfo` / `DnsQuery` hors mode D3 (vérifié par revue + test d'intégration avec résolveur système empoisonné) ; (b) aucun paquet hôte vers 53/853/5353/5355/137 pendant une session (capture) ; (c) l'invité n'a pas d'interface |
| mDNS / LLMNR / NetBIOS / SSDP | Impossibles depuis l'invité (pas d'interface, multicast et broadcast refusés par P7/P8/P15) ; `*.local` refusé par P3. Le proxy n'émet jamais de requêtes multicast |
| ECH / enregistrements HTTPS | Probable perte d'ECH en mode proxy (le navigateur ne fait pas la requête HTTPS RR) — inconnue I6 ; pas un problème de sécurité pour l'hôte |
| DNSSEC | Non validé en v1 (confiance dans le résolveur DoH) ; éviter les fonctionnalités DNSSEC touchées par RUSTSEC-2026-0118 |

---

## 7. Configuration navigateur (défense en profondeur)

Ces réglages ne constituent **pas** la frontière (l'invité est supposé compromis). Ils réduisent l'exposition et les comportements imprévus. Ils sont à intégrer dans la politique gérée par le Browser Security Engineer.

| Sujet | Chromium (politiques) | Firefox (prefs / policies) |
|---|---|---|
| Proxy imposé | `ProxySettings` fixe `socks5://127.0.0.1:1080` ; ne pas utiliser de PAC/WPAD | `network.proxy.type=1`, `socks_remote_dns=true`, `network.proxy.failover_direct=false` |
| Localhost | Le contournement implicite du localhost reste dans l'invité (sans danger : c'est le loopback *invité*) ; `<-loopback>` non requis ([proxy.md](https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md)) | idem |
| QUIC | `QuicAllowed=false` en v1 (pas d'UDP) | `network.http.http3.enable=false` |
| WebRTC | `WebRtcIPHandling=disable_non_proxied_udp` (seul UDP proxifié permis, donc aucun en v1) ([Chromium](https://chromium.googlesource.com/chromium/src.git/+/lkgr-android-internal/third_party/blink/common/peerconnection/webrtc_ip_handling_policy.cc), [explication](https://github.com/aghorler/WebRTC-Leak-Prevent/blob/master/DOCUMENTATION.md)), `WebRtcLocalIpsAllowedUrls` vide | `media.peerconnection.ice.proxy_only=true`, `ice.default_address_only=true`, `ice.no_host=true` |
| Réseau local | Local Network Access (Chrome 142, prompt pour les requêtes publiques→locales/loopback) ([Chrome 142](https://developer.chrome.com/release-notes/142)) : laisser actif, refus par défaut | équivalent si disponible *[à vérifier]* |
| DoH navigateur | `DnsOverHttpsMode=off`, `BuiltInDnsClientEnabled` sans effet utile | `network.trr.mode=5` |

**Fuites WebRTC.** IP locales : l'invité n'a que `lo`, il n'y a rien à fuiter, et l'IP LAN de l'hôte n'est jamais visible dans l'invité (KEP ne renvoie aucune adresse). IP publique : sans UDP il n'y a pas de STUN. Via TURN-TCP, le pair voit l'IP publique de sortie de l'hôte, la même que celle vue par tout site visité. **Kaput n'est pas un outil d'anonymat**, et il faut l'écrire dans l'UX.

---

## 8. Cas particuliers d'environnement hôte

### 8.1 VPN sur l'hôte
- **Full-tunnel** : les sockets du proxy suivent la table de routage de l'hôte, donc le trafic passe par le VPN. Les adresses du TUN VPN sont refusées (P9) et le préfixe on-link du VPN aussi (P10).
- **Split-tunnel / VPN d'entreprise** : des réseaux internes peuvent être en IP **publiques** routées via le VPN. P11 (route ≠ défaut) les bloque. C'est la règle qui protège un intranet adressé en public ; elle doit être testée sur Windows (WireGuard, OpenVPN, clients propriétaires) et Linux (NetworkManager, policy routing `ip rule`). Limite : un VPN qui pousse une route *par défaut* et dont l'intranet est derrière cette même route reste indiscernable d'Internet (risque résiduel R4).
- Changement de VPN en cours de session : les tables P9–P11 sont rafraîchies sur notification (netlink, `NotifyIpInterfaceChange`), plus un sondage toutes les 5 s. Il y a une fenêtre de course, la même que celle notée par passt. Mitigation : P11 étant un lookup de route **au moment du connect**, la fenêtre est réduite au délai entre le lookup et le `connect()`.

### 8.2 Hôte d'entreprise avec proxy obligatoire
- Il faudrait chaîner `kaput-egress` vers le proxy amont en HTTP CONNECT. **Problème de sécurité majeur** : si Kaput envoie `CONNECT nom:443`, c'est le proxy d'entreprise qui résout, et un domaine attaquant peut pointer vers un intranet. Kaput perd alors la garantie anti-rebinding et l'invité devient un pivot SSRF vers le réseau interne.
- Options :
  - (a) Kaput résout (DoH ou DNS système), applique P6–P13, puis envoie `CONNECT <IP>:443`. C'est plus sûr, mais beaucoup de proxys refusent les IP littérales ou catégorisent par nom.
  - (b) `CONNECT nom` avec liste de domaines autorisés. Peu praticable.
  - (c) Refuser le mode entreprise en v1.
- Inspection TLS d'entreprise : le navigateur invité devrait faire confiance à la CA d'entreprise. Il faudrait injecter un certificat de l'hôte dans l'image, ce qui affaiblit la confidentialité, sans casser l'isolation hôte.
- **WPAD/PAC** : jamais d'auto-découverte (WPAD est un vecteur d'attaque connu). Un PAC n'est exécuté que s'il est configuré explicitement et, s'il est évalué côté hôte, dans un interpréteur sandboxé. Préférer une URL de proxy explicite.
- Authentification NTLM/Kerberos vers le proxy amont : elle impliquerait d'utiliser les identifiants de l'hôte au profit d'un invité non fiable, ce qui revient à une **délégation d'identité**. À refuser par défaut (D7).

### 8.3 Portails captifs
- Le portail est souvent sur une IP RFC1918 et repose sur un détournement DNS, deux choses que la politique bloque (P7, DoH). Le comportement par défaut : `kaput-egress` détecte l'échec, l'UI Kaput indique « Ce réseau exige une connexion : authentifiez-vous avec le système (Windows et GNOME/NetworkManager ont un détecteur de portail) puis réessayez ».
- Option à décider (D8) : un « mode portail » ponctuel avec consentement explicite. Il autoriserait HTTP/HTTPS uniquement vers l'URI annoncée par RFC 8910 (option DHCP 114 / RA) / API RFC 8908 *[réf.]* pendant 5 minutes, dans une session dédiée détruite ensuite. Risque : le portail est un hôte du LAN, et l'exception crée une brèche contrôlée.

### 8.4 Hôte lui-même dans le cloud (VDI, poste Azure/AWS)
Les métadonnées (P12) sont refusées, y compris `168.63.129.16`, qui n'est pas dans une plage privée. À compléter par fournisseur en lab (inconnue I7).

---

## 9. Plan de tests négatifs (à automatiser)

Le cadre : un **agent de test « malware »** tourne en root dans l'invité. Le banc expose côté hôte des services sentinelles (HTTP sur `127.0.0.1:8xxx`, `[::1]`, `0.0.0.0`, IP LAN, IP VPN, vEthernet) et un LAN de lab (routeur, appareil IPv6 GUA, serveur mDNS/SSDP, faux endpoint de métadonnées, NAT64, serveur DNS de rebinding piloté, proxy d'entreprise simulé). Chaque test **échoue si un octet atteint une sentinelle**, preuve par journal de la sentinelle et capture pcap côté hôte. Les tests tournent sur chaque cible (Windows 11 Hyper-V, Linux par backend VMM retenu) en CI et en lab nocturne.

### 9.1 Couche VM / transport
| ID | Test | Attendu |
|---|---|---|
| T-VM-01 | Énumérer les interfaces (`/sys/class/net`, `ip link`, PCI/VMBus) | `lo` uniquement ; aucune classe réseau PCI/VMBus |
| T-VM-02 | `socket(AF_PACKET)`, envoi brut, DHCP discover, RS/NS IPv6 | aucune interface ; aucun paquet observé côté hôte |
| T-VM-03 | Balayage vsock : CID 0, 1, 2, 3–N, ports 0–65535 (TCP-like stream et `SOCK_DGRAM`, `SOCK_SEQPACKET`) | seul le port KEP répond |
| T-VM-04 | Windows : connect hvsock vers tous les GUID enregistrés dans `GuestCommunicationServices` et les services connus (Docker, WSL…) | refus/aucune réponse hors KEP (inconnue I3) |
| T-VM-05 | Démarrer une VM avec NIC injectée par erreur de configuration | Kaput refuse de lancer la session (VM-N1) |

### 9.2 Destinations interdites via KEP (littéraux)
| ID | Cibles | Attendu |
|---|---|---|
| T-IP-01 | `127.0.0.1`, `127.1`, `127.255.255.254`, `2130706433`, `0177.0.0.1`, `0x7f.0.0.1`, `0x7f000001` | REFUS (P2/P7) |
| T-IP-02 | `0.0.0.0`, `0`, `0.0.0.0:<port sentinelle>` | REFUS |
| T-IP-03 | `::1`, `::`, `::ffff:127.0.0.1`, `::ffff:7f00:1`, `::127.0.0.1`, `::ffff:0:7f00:1` | REFUS |
| T-IP-04 | `64:ff9b::7f00:1`, `64:ff9b::a00:1`, `64:ff9b::c0a8:101`, `64:ff9b:1::a00:1`, NSP du lab + IPv4 privée | REFUS |
| T-IP-05 | `2002:7f00:1::1`, `2002:c0a8:101::1`, Teredo `2001:0::…` | REFUS |
| T-IP-06 | RFC1918 bornes : `10.0.0.0`, `10.255.255.255`, `172.16.0.1`, `172.31.255.255`, `192.168.0.1` ; témoins **autorisés** : `172.15.255.255`, `172.32.0.1` (IP publiques du lab) | REFUS / AUTORISER (test de borne) |
| T-IP-07 | `100.64.0.1`, `100.127.255.254`, `100.100.100.200` | REFUS |
| T-IP-08 | `169.254.169.254`, `169.254.0.1`, `fe80::1`, `fe80::1%2`, `fd00:ec2::254`, `168.63.129.16`, `192.0.0.192` | REFUS |
| T-IP-09 | `fc00::1`, `fd12:3456::1`, `fec0::1` | REFUS |
| T-IP-10 | `224.0.0.251:5353`, `239.255.255.250:1900`, `255.255.255.255`, `ff02::fb`, `ff02::1:3` | REFUS |
| T-IP-11 | Toutes les adresses de toutes les interfaces hôte (énumérées par le banc, y compris IPv6 temporaires, VPN, vEthernet, docker0, virbr0) | REFUS |
| T-IP-12 | GUA IPv6 d'un appareil du LAN de lab (préfixe on-link public) ; IPv4 publique d'un LAN de lab adressé en public | REFUS (P10) |
| T-IP-13 | Destination publique routée via un VPN split-tunnel de lab | REFUS (P11) |
| T-IP-14 | Bornes de documentation/bench/réservé : `192.0.2.1`, `198.18.0.1`, `240.0.0.1`, `2001:db8::1`, `3fff::1`, `100::1`, `5f00::1` | REFUS |

### 9.3 Noms et DNS
| ID | Test | Attendu |
|---|---|---|
| T-DNS-01 | `localhost`, `localhost.`, `LOCALHOST`, `x.localhost`, `printer.local`, `router.home.arpa`, `metadata.google.internal`, `wpad`, `intranet` (un label) | REFUS (P3) |
| T-DNS-02 | Nom public dont la réponse = `127.0.0.1` / `10.0.0.1` / `::1` / `fd00::1` / IP LAN on-link | REFUS (P13) |
| T-DNS-03 | **Rebinding** : TTL 0 alternant IP publique / `127.0.0.1`, 1 000 itérations, connexions parallèles | 0 connexion vers sentinelle |
| T-DNS-04 | Réponse mixte `A 203.0.113.x(lab public) + A 10.0.0.1` | REFUS de toute la réponse |
| T-DNS-05 | CNAME vers nom interne, chaînes CNAME longues, réponses tronquées/malformées, NXDOMAIN massif | REFUS propre, pas de crash, quotas respectés |
| T-DNS-06 | Capture hôte pendant une suite de navigation : aucun paquet vers 53/UDP-TCP, 853, 5353, 5355, 137, ni vers un résolveur autre que le DoH configuré | 0 paquet |
| T-DNS-07 | Résolveur système empoisonné (hosts/resolver de l'hôte redirigé) en mode DoH | comportement inchangé (prouve l'absence d'appel système) |
| T-DNS-08 | DoH injoignable | fail closed, aucun repli |
| T-DNS-09 | Noms Unicode : `127。0。0。1` (U+3002), points pleine chasse, homoglyphes envoyés **bruts** à KEP | REFUS (P1 : ASCII LDH seulement) |
| T-DNS-10 | Fin de session : dump mémoire/disque du processus et du profil hôte | aucune entrée de cache DNS persistée |

### 9.4 Protocole, robustesse, ressources
| ID | Test | Attendu |
|---|---|---|
| T-P-01 | Fuzzing KEP (cargo-fuzz, corpus + structure-aware) en CI, ≥ N heures par release | 0 crash, 0 panic hors gestion |
| T-P-02 | Trames : version inconnue, nom > 253, label > 63, NUL, port 0, longueur incohérente, flux fermé à mi-trame | REFUS, pas de fuite mémoire |
| T-P-03 | Réponse KEP : vérifier qu'aucune adresse locale/LAN de l'hôte n'est renvoyée (y compris dans les messages d'erreur) | aucune |
| T-P-04 | 10 000 ouvertures/s, 5 000 flux concurrents, slowloris vsock, tampons pleins | quotas appliqués ; hôte réactif ; session tuable |
| T-P-05 | Crash du proxy (kill -9) pendant la session | invité sans aucune connectivité (fail closed) ; UI informée |
| T-P-06 | UDP (v1) : toute tentative via KEP ou autre | REFUS |
| T-P-07 | Ports hors profil (25, 445, 139, 3389…) vers IP publique de lab | REFUS (selon D4) |

### 9.5 Navigateur / WebRTC / environnement
| ID | Test | Attendu |
|---|---|---|
| T-W-01 | Page de lab collectant les candidats ICE (host, srflx, relay) | aucun candidat host/srflx contenant une IP de l'hôte ou du LAN |
| T-W-02 | Page JS sondant `http://192.168.x.x`, `http://[::1]`, `http://0.0.0.0:port` (LAN scanning par timing) | aucune requête n'atteint le LAN ; timings non discriminants |
| T-W-03 | Proxy d'entreprise simulé (mode D7) : `CONNECT` vers nom interne / nom rebinding | REFUS par Kaput avant envoi amont |
| T-W-04 | Portail captif de lab | fail closed + message ; aucune exception sans consentement (D8) |
| T-W-05 | Changement d'interface / VPN up/down en cours de session | P9–P11 à jour ≤ 5 s ; aucune connexion vers la nouvelle adresse hôte |
| T-W-06 | Hôte IPv6-only + NAT64 (WKP et NSP) | Internet OK ; T-IP-04 refusé |

Une **métrique de sortie** est attendue pour chaque test : nombre d'octets reçus par les sentinelles (doit être 0), code de décision, durée. Le rapport est produit par le labo d'évasion (§18 du brief).

---

## 10. Risques résiduels

| ID | Risque | Gravité estimée | Mitigation partielle |
|---|---|---|---|
| R1 | Vulnérabilité dans le transport vsock/hvsock (noyau hôte, VMBus, VMM) exploitable depuis l'invité | Élevée (impact) / faible-moyenne (probabilité) | VMM à vsock userspace sous Linux ; correctifs OS ; surface réduite à un seul port |
| R2 | Bug logique dans `kaput-egress` (règle manquante, parseur) | Élevée | Tables générées depuis données IANA versionnées, tests de bornes, fuzzing, revue indépendante + Offensive Security |
| R3 | Bug mémoire dans une dépendance Rust (TLS, HTTP/2, DNS) déclenché par une réponse **réseau** (pas invité) | Moyenne | Dépendances minimales, `cargo-deny`, mise à jour rapide, sandbox du proxy |
| R4 | Intranets adressés en public derrière la route par défaut (VPN full-tunnel d'entreprise, réseaux universitaires) ; IP WAN du routeur domestique (accès admin par hairpin NAT) | Moyenne | P10/P11 ; option « liste noire utilisateur » ; détection de l'IP publique de sortie et refus de celle-ci *[à étudier]* |
| R5 | Course entre changement d'adresse/route et décision | Faible | Lookup de route au moment du connect ; rafraîchissement événementiel |
| R6 | Abus de l'IP de l'utilisateur (spam, scans Internet depuis l'invité compromis) | Moyenne (réputation, légal) | Ports restreints (D4), quotas, pas d'UDP en v1 |
| R7 | Exfiltration de données de l'invité vers Internet | Hors périmètre (l'invité ne contient que la session) | — |
| R8 | Fuite de confidentialité vers le résolveur DoH | Faible-moyenne | Choix utilisateur (D2), pas d'ECS |
| R9 | Mode entreprise / DNS système / portail captif réintroduisant des chemins internes | Élevée si activé | Désactivés par défaut, consentement explicite, tests dédiés |
| R10 | Couche AppContainer Windows mal configurée (plage privée incomplète) donnant une fausse confiance | Faible | Couche secondaire uniquement, jamais citée comme garantie |

Aucune de ces mesures ne rend l'architecture invulnérable. L'objectif est une surface hôte minimale, refus par défaut, avec une défense en profondeur mesurée par les tests §9.

---

## 11. Inconnues (à lever avant implémentation)

| ID | Inconnue | Comment la lever |
|---|---|---|
| I1 | Backend VMM final (QEMU/KVM, Cloud Hypervisor, Firecracker ; HCS sous Windows) et donc implémentation vsock (vhost noyau vs userspace) | Décision Virtualization Engineer ; préférence réseau : vsock userspace |
| I2 | Un processus AppContainer peut-il écouter en `AF_HYPERV` ? Sinon, découpage en 2 processus (listener / sortie) | Prototype Windows 11 |
| I3 | Isolation des services hvsock : un invité peut-il joindre des services hvsock d'autres applications (Docker Desktop, WSL) enregistrés en wildcard ? | Test T-VM-04 en lab |
| I4 | Performances réelles vsock/hvsock + proxy (débit, latence, CPU) | Bench lab |
| I5 | Découverte fiable des préfixes NAT64 réseau (NSP) côté hôte, Windows et Linux | Lab IPv6-only |
| I6 | Comportement ECH / HTTPS RR des navigateurs en mode proxy SOCKS5 | Test navigateur |
| I7 | Liste complète des endpoints de plateforme par fournisseur cloud | Recherche complémentaire |
| I8 | Qualité WebRTC réelle (Meet/Teams/Jitsi) en TURN-TCP seulement | Test utilisateur |
| I9 | Hyper-V Firewall applicable aux VM HCS non-WSL ? (utile seulement si un jour une NIC est réintroduite) | Doc + prototype |
| I10 | Taux de casse de P13 (« refus total si une IP interne ») sur le Web réel | Mesure sur top 10k sites |

---

## 12. Décisions nécessitant l'avis de l'utilisateur

| ID | Décision | Options | Recommandation |
|---|---|---|---|
| **D1** | UDP / HTTP3 / WebRTC P2P en v1 | (a) aucun UDP (b) UDP 443 + TURN via KEP phase 2 (c) UDP complet | **(a) en v1**, (b) en phase 2 après audit |
| **D2** | Résolveur DoH par défaut | Quad9 / Cloudflare / Mullvad / DNS4EU / personnalisé | Quad9 par défaut, choix visible au premier lancement |
| **D3** | Mode « DNS système » (réseaux d'entreprise, split-horizon) | interdit / option avancée | Option avancée, désactivée, avertissement de confidentialité |
| **D4** | Profil de ports TCP | (a) 80/443 seulement (b) 80/443 + 1024–65535 hors liste noire (c) tous | **(b)** ; (a) en mode « strict » |
| **D5** | Refus des routes non-défaut (P11) | toujours / désactivable | Toujours actif par défaut ; désactivation = exception explicite |
| **D6** | Couche pare-feu système Linux (nftables/cgroup) nécessitant root à l'installation | oui / non | Non par défaut (privilèges minimaux) ; option pour déploiements gérés |
| **D7** | Support proxy d'entreprise amont (+ CA d'inspection TLS, auth NTLM/Kerberos) | non en v1 / CONNECT par IP / complet | Non en v1 ; si requis, `CONNECT <IP>` uniquement, jamais d'auth implicite |
| **D8** | Exception « portail captif » | aucune / mode ponctuel avec consentement | Aucune en v1 (renvoi au système) |
| **D9** | Sortie via VPN/Tor intégré (confidentialité) | non / option | Hors v1 ; afficher clairement « Kaput n'anonymise pas » |
| **D10** | Liste noire de domaines/IP personnalisée par l'utilisateur (ex. IP WAN du routeur, intranet public) | non / oui | Oui (ajout uniquement : impossible d'élargir la liste blanche) |

---

## 13. Sources

Vérifiées le 2026-11-12 :

- Brief produit : `docs/product-brief.md`
- libslirp — liste CVE : https://www.cvelogic.com/vendor/libslirp_project
- CVE-2026-9539 (libslirp `sosendoob`) — Debian : https://security-tracker.debian.org/tracker/CVE-2026-9539
- libslirp bump 4.9.3→4.9.4 (CVE-2026-9539) — ptxdist : https://lore.ptxdist.org/ptxdist/20260904171205.3849412-1-christian.melki@t2data.com/t/
- libslirp bump 4.9.1→4.9.2 — ptxdist : https://lore.ptxdist.org/ptxdist/20260527170403.3356093-1-christian.melki@t2data.com/t/
- QEMU `-netdev user` (`restrict`, `host`, `guestfwd`) : https://www.qemu.org/docs/master/system/invocation.html
- passt — accès aux adresses secondaires de l'hôte (2024) : https://archives.passt.top/passt-user/20240510124508.288d874d@elisabeth/t/
- passt — demande `--no-map-host`, pas de filtrage sortant (mai 2026) : https://archives.passt.top/passt-user/afgxhMK_fsHS5rMG@zatzit/T/
- CVE-2026-84042 (crun + libkrun + passt) — SUSE : https://www.suse.com/security/cve/CVE-2026-84042.html
- CVE-2026-107935 (gvproxy path traversal) — Red Hat : https://access.redhat.com/security/cve/CVE-2026-107935
- RHSA-2024:4379 gvisor-tap-vsock : https://access.redhat.com/errata/RHSA-2024:4379
- CVE-2021-28476 vmswitch — Akamai/Guardicore : https://www.akamai.com/blog/security/critical-vulnerability-in-hyper-v-allowed-attackers-to-exploit-azure
- CVE-2026-45607 Hyper-V RCE — Action1 : https://www.action1.com/vulnerabilities/cve-2026-45607/
- CVE-2025-48807 Hyper-V RCE : https://stack.watch/vuln/CVE-2025-48807
- ZDI-26-416 Hyper-V netvsc : https://zerodayinitiative.com/advisories/ZDI-26-416
- Hyper-V sockets / intégration services : https://learn.microsoft.com/en-us/virtualization/hyper-v-on-windows/user-guide/make-integration-service
- Hyper-V Firewall : https://learn.microsoft.com/windows/security/operating-system-security/network-security/windows-firewall/hyper-v-firewall
- AppContainer / isolation réseau UWP : https://learn.microsoft.com/en-us/windows/security/operating-system-security/network-security/windows-firewall/troubleshooting-uwp-firewall
- Firecracker vsock (hybrid, contourne vhost) : https://github.com/roypat/firecracker/blob/main/docs/vsock.md
- CVE-2025-21756 vsock — Red Hat : https://access.redhat.com/security/cve/CVE-2025-21756
- Landlock (réseau par port, TCP ABI v4, UDP ABI v10) : https://docs.kernel.org/userspace-api/landlock.html
- Chromium — support proxy (SOCKS5, résolution côté proxy, bypass localhost) : https://chromium.googlesource.com/chromium/src/+/main/net/docs/proxy.md
- Chromium — valeurs WebRTC IP handling : https://chromium.googlesource.com/chromium/src.git/+/lkgr-android-internal/third_party/blink/common/peerconnection/webrtc_ip_handling_policy.cc
- Explication des politiques WebRTC : https://github.com/aghorler/WebRTC-Leak-Prevent/blob/master/DOCUMENTATION.md
- Chrome 142 — Local Network Access : https://developer.chrome.com/release-notes/142
- Firefox CONNECT-UDP (MASQUE) : https://firefox-source-docs.mozilla.org/networking/http/connect_udp.html
- RUSTSEC-2026-0118 (hickory-proto NSEC3) : https://rustsec.org/advisories/RUSTSEC-2026-0118
- RUSTSEC-2026-0106 (hickory-recursor cache poisoning) : https://rustsec.org/advisories/RUSTSEC-2026-0106

Références normatives *[non re-vérifiées ce jour, quota de recherche atteint]* :

- IANA IPv4 Special-Purpose Registry : https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry.xhtml
- IANA IPv6 Special-Purpose Registry : https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry.xhtml
- RFC 1918, 4193 (ULA), 4291, 6052 (NAT64), 6598 (CGNAT), 6761/8375 (noms spéciaux, home.arpa), 7050 (découverte NAT64), 7526 (dépréciation 6to4), 8215 (64:ff9b:1::/48), 8305 (Happy Eyeballs v2), 8484 (DoH), 8908/8910 (portails captifs), 9298 (CONNECT-UDP), 9484 (CONNECT-IP), 9637 (3fff::/20) : https://www.rfc-editor.org/rfc/rfc9637.html et `https://www.rfc-editor.org/rfc/rfcNNNN`
