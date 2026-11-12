# ADR 0001 — Runtime d'isolation

- **Statut** : Proposé. Passera à « Accepté » après les PoC U1–U3 (Windows) et U6 (Linux) de `PROJECT_ANALYSIS.md` §15.2.
- **Date** : 2026-11-12
- **Études** : `docs/research/01-isolation-runtime.md`, `02-windows-host.md`, `03-linux-host-and-guest.md`

## Contexte

Kaput suppose que l'invité finit compromis avec les droits root. La frontière entre l'invité et l'hôte
est donc le composant de sécurité central. Kaput doit fonctionner sous Windows 11 (éditions Home et
Pro comprises) et sous Linux, **sans privilège à l'exécution**.

## Alternatives

| Option | Avantages | Inconvénients | Verdict |
|---|---|---|---|
| Conteneurs Linux (namespaces, seccomp, Landlock) | Léger, mature | Noyau hôte partagé avec le contenu hostile ; Linux seulement | Couche secondaire |
| gVisor | Réduit fortement la surface du noyau | Linux seulement ; support graphique partiel | Rejeté |
| Windows Sandbox | Intégré à Windows | Invité Windows ; absent de Home ; défauts permissifs | Rejeté |
| WSL2 | Disponible partout | L'invité peut monter `C:` | Rejeté |
| Hyper-V / HCS | Pile Microsoft mature | Admin ou service SYSTEM ; une partie de l'émulation en noyau root | Repli documenté |
| QEMU (KVM / WHPX) | Universel | Écrit en C, surface très large, évasions récentes | Repli ultime |
| Cloud Hypervisor | Rust, Landlock | Surface plus large que Firecracker | Alternative Linux n° 2 |
| crosvm | Rust ; un processus par périphérique | WHPX non testé en amont | Repli Windows |
| **Firecracker (KVM)** | Rust, minimal, en production chez AWS, transport MMIO | Pas de Windows ; jailer exigeant root | **Retenu (Linux)** |
| **OpenVMM (WHP)** | Rust, porté par Microsoft sur WHP | Pas de releases ; interfaces « évolutives » ; base de code vaste | **Retenu (Windows), sous condition du PoC** |

## Décision

1. **Frontière principale : la virtualisation matérielle.** Kaput **refuse de démarrer** sans KVM ou
   WHP. Il n'existe aucun mode dégradé reposant sur des conteneurs.
2. **Un contrat invité unique** sur les deux plateformes :
   - boot direct du noyau, sans firmware ni initramfs ;
   - transport virtio **MMIO** ;
   - `virtio-blk` raw en **lecture seule**, sans auto-détection de format ;
   - `virtio-vsock` **émulé en espace utilisateur** dans le VMM, sans vhost noyau ni hvsocket ;
   - **aucun** autre périphérique : pas de réseau, pas de GPU, pas de son, pas de fs, pas d'USB,
     pas de TPM, pas de balloon, console série uniquement dans les builds de développement.
3. **Backend Linux** : Firecracker, épinglé à un commit et construit depuis les sources, sans les
   options PCI, MMDS, balloon ni net. Il est lancé par `kaput-jail` (voir ADR 0005) et non par le
   jailer officiel, qui exige root.
4. **Backend Windows** : OpenVMM sur WHP, compilé avec un jeu minimal de *features*. Kaput devient
   **intégrateur et veilleur sécurité** d'un commit épinglé. Repli : crosvm/WHPX si le PoC U3 échoue
   sur l'un de ces points : TCB liée, virtio-vsock en espace utilisateur, absence de VMBus/UEFI.
5. **Le VMM ne parse aucun protocole applicatif.** Réseau et affichage sont traités par des brokers
   séparés (ADR 0003 et 0005).
6. **Inventaire de l'émulation résiduelle, bloquant (revue 0001, RT-06).** Les PoC U3 et U6 doivent
   publier, pour chaque backend, la liste de tout ce qui est émulé dans le VMM ou exposé par
   l'hyperviseur : i8042, UART, LAPIC/IOAPIC, timers, ports I/O, MSR, feuilles CPUID, registres MMIO.
   L'ADR ne passe pas à « Accepté » sans cet inventaire. NEG-MSR-01, NEG-CPUID-01 et NEG-IOPORT-01
   vérifient chaque inventaire contre une liste blanche.
7. **crosvm/WHPX est évalué en parallèle d'OpenVMM** pendant les PoC Windows (RT-09), et non seulement
   en cas d'échec. Avant toute release Windows, un plan de réponse aux 0-days OpenVMM (fork + correctif
   interne) est exigé.

## Conséquences

- Deux backends à maintenir, mais une seule suite de tests d'évasion, **bloquante sur les deux**.
- Pas d'accélération GPU : rendu logiciel dans l'invité, vidéo 4K60 dégradée.
- Sans hvsocket, aucun GUID n'est enregistré dans `HKLM`, et l'invité ne peut pas atteindre les
  services hvsock d'autres logiciels (Docker, WSL).
- Le suivi des correctifs OpenVMM est à notre charge (risque R7).

## Risques

- R1 : une faille de KVM ou de l'hyperviseur court-circuite toutes les couches. Une fois root dans
  l'invité, **une seule vulnérabilité** suffit sur ce chemin (`PROJECT_ANALYSIS.md` §2.2, chemin A).
- R3 : des bogues logiques ou `unsafe` existent dans les VMM Rust (constatés en 2026 chez Firecracker
  et Cloud Hypervisor `[CVE à recouper]`).
- Si U2 (WHP dans un AppContainer) échoue, le confinement Windows s'affaiblit. Voir ADR 0005.
