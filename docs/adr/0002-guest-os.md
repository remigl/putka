# ADR 0002 — Système invité et navigateur

- **Statut** : Proposé
- **Date** : 2026-11-12
- **Études** : `docs/research/03-linux-host-and-guest.md` (partie B), `04-browser-and-display.md` (partie A)

## Contexte

L'invité exécute du contenu hostile. Son durcissement relève de la **défense en profondeur**, pas de la
frontière principale. Le critère dominant pour choisir la base est le **délai de correctif du
navigateur**. Chrome publie une version toutes les 2 semaines, avec des correctifs de sécurité
hebdomadaires.

## Alternatives

| Base | Avantages | Inconvénients | Verdict |
|---|---|---|---|
| Alpine | Très petite | musl : Chromium et Firefox non supportés en amont, sandbox seccomp corrigé en aval ; facteur bus | Rejeté |
| Ubuntu minimal / Core | — | Chromium uniquement en snap (snapd dans l'invité) | Rejeté |
| Fedora (mkosi) | Paquets rapides, glibc | Rebase tous les 13 mois ; ~6 j de retard sur un échantillon | **Plan B** |
| Fedora CoreOS, Flatcar, Bottlerocket | Immuables | Pas de navigateur ; objectif différent | Modèles d'inspiration |
| Wolfi / Chainguard | Supply chain excellente | Navigateur commercial ou incertain ; pas de noyau ni d'init | À surveiller |
| NixOS | Reproductible | Pas de garantie de rétroportage des CVE | Rejeté v1 |
| Buildroot / Yocto | Minuscule | Kaput deviendrait mainteneur du navigateur | Rejeté v1 |
| **Debian 13 via mkosi** | glibc ; équipe sécurité ; snapshot.debian.org ; Reproducible Builds | Base plus grosse ; ~4 j de retard sur un échantillon | **Retenu** |

Navigateur : Chromium est préféré à Firefox pour sa sandbox Linux à deux couches, la V8 heap sandbox
et son catalogue de politiques. Firefox reste le second choix documenté. Google Chrome est écarté :
binaire propriétaire, redistribution très probablement non autorisée, incompatible avec un projet
GPL-3.0 entièrement libre.

## Décision

- **Image** : paquets Debian 13 épinglés par un horodatage snapshot et un lockfile, assemblés par
  **mkosi** en image immuable :
  - rootfs **EROFS** en lecture seule et arbre **dm-verity** (`panic_on_corruption`) créé par
    `dm-mod.create`, **sans initramfs** ;
  - état 100 % **tmpfs** `nosuid,nodev,noexec` ; pas de swap ;
  - aucun disque inscriptible.
- **Noyau** : LTS kernel.org construit par Kaput à partir d'une liste blanche (`allnoconfig` + ajouts) :
  - `MODULES=n` et `IO_URING=n` ;
  - lockdown en mode confidentialité ;
  - options KSPP ;
  - userns, pidns et netns conservés pour la sandbox Chromium.
  La ligne de commande est **figée et signée** (ADR 0004).
- **Init** : `kaput-init`, un PID 1 statique en Rust. Il lance trois services sous des uid distincts :
  agent (1002), compositeur (1001) et navigateur (1000). Chaque service tourne sans capability, avec
  `no_new_privs` et des filtres seccomp/Landlock propres. À la sortie du navigateur ou de l'agent,
  il fait `poweroff`.
- **Retirés et vérifiés en CI** : shell, sshd, getty, dpkg/apt, interpréteurs, outils réseau, setuid,
  D-Bus. La liste blanche des ELF du rootfs est signée.
- **Navigateur** : Chromium de `trixie-security`, sandbox obligatoire. Si `Seccomp: 2` ou les
  namespaces sont absents, la session est tuée. Les points suivants viennent des décisions D2–D6 :
  - JIT **désactivé** ;
  - pas de GPU, WebGPU désactivé ;
  - environ 40 politiques de durcissement vérifiées par un test `chrome://policy` ;
  - pas de Widevine ;
  - téléchargements confinés à l'invité.
- **Âge maximal** : l'image est refusée au-delà de 14 jours ou si le navigateur figure dans une liste
  signée de versions affectées par un 0-day.

## Conséquences

- Kaput maintient un noyau (risque R5) et un pipeline de reconstruction rapide : objectif < 12 h entre
  la publication du paquet par la distribution et l'image signée.
- La latence de Debian est mesurée en continu. Au-delà de 48 h en médiane, on passe à un Chromium
  construit par Kaput (ADR futur).
- La minimisation hors du cadre Debian peut casser des chemins rares du navigateur ; elle est couverte
  par des tests.
