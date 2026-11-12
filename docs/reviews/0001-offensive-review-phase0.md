# 0001 — Revue offensive indépendante (Phase 0)

> Auteur : agent *Offensive Security Engineer*. Je n'ai pas participé à la conception.
> Date : 2026-11-12. Statut : revue de la synthèse `PROJECT_ANALYSIS.md` et des études `docs/research/01..08`.
> Méthode : revue documentaire + vérification en ligne d'un échantillon de faits (≈10). Aucun prototype
> (ni KVM ni WHP dans le conteneur). Je ne modifie aucun fichier existant.
> Posture : je ne cherche pas à confirmer que l'architecture marche, je cherche où elle casse ou ment.

---

## 1. Résumé (verdict)

L'architecture **tient comme direction** : virtualisation matérielle en frontière principale, VMM Rust
confiné sans privilège, aucun périphérique réseau invité, brokers à un seul privilège, TUF + provenance.
C'est l'état de l'art pour un navigateur jetable, et les choix sont défendables. **Mais trois affirmations
« rassurantes » ne résistent pas à l'examen** et doivent être corrigées avant l'ADR 0001 :

1. la « chaîne de 3 vulnérabilités » **ne vaut pas pour le broker réseau** : le renderer parle déjà KEP par
   conception, l'étape « LPE noyau invité » saute pour ce chemin (RT-02) ;
2. la restriction vsock « au seul uid agent » est présentée comme une défense alors qu'elle est **nulle
   contre l'hypothèse dimensionnante (invité root)** (RT-05) ;
3. le « double domaine de confiance » des mises à jour **s'effondre sur une seule personne** en variante B
   (RT-03), et le seuil root 2-sur-3 d'un mainteneur unique protège du vol, pas de l'insider ni de la
   compromission de son poste.

Aucun de ces points n'invalide le choix fondamental, mais chacun transforme une garantie annoncée en
risque résiduel qu'il faut écrire noir sur blanc. **Verdict : conserver l'architecture, réviser le
discours de sécurité et ajouter les tests négatifs ci-dessous.** Le chemin Windows (OpenVMM non publié,
WHP-en-AppContainer inconnu) reste non prouvé : il est juste de le garder au statut « Proposé ».

Les identifiants CVE porteurs vérifiés sont **tous confirmés** (§4). Rien de fabriqué détecté dans
l'échantillon ; en revanche plusieurs faits sont **sur-interprétés** par rapport à la source.

---

## 2. Constats triés par gravité

Format : ID · gravité · frontière · scénario · correction · (remise en cause d'un choix fondamental ?).

### CRITICAL

**RT-01 — La « chaîne de 3 » masque un chemin invité→hôte en 1 bug (hyperviseur).**
- Frontière : TB0 (matériel/hyperviseur).
- Scénario : un défaut de KVM/WHP/noyau hôte atteignable depuis l'invité court-circuite étapes 4 et 5 de
  §2.2. C'est un chemin **invité → hôte en une seule vulnérabilité**, pas trois. La synthèse le reconnaît
  (R1, exception §2.2) mais met en avant « au moins trois vulnérabilités indépendantes » comme propriété
  de défense en profondeur, ce qui est la formulation qu'un lecteur retiendra.
- Composant : surface KVM `ioctl` (étude 03 §R-1 la qualifie elle-même d'« incompressible »), émulation
  LAPIC/partition WHP.
- Correction : (a) requalifier partout « 3 vulnérabilités » en « 3 vulnérabilités **pour le chemin via nos
  brokers/VMM** ; 1 seule pour le chemin hyperviseur » ; (b) faire de la mesure et de l'affichage de l'état
  des mitigations CPU/hyperviseur un **prérequis fail-safe documenté**, pas un simple avertissement ;
  (c) test négatif : exécuter la suite d'évasion avec un invité root sur chaque backend et **mesurer** le
  nombre réel de bugs requis.
- Remise en cause fondamentale : **non** (c'est le risque résiduel assumé de toute VM), mais remise en
  cause du **discours**.

**RT-02 — Le broker réseau (S2/KEP) est joignable sans LPE noyau invité.**
- Frontière : TB3 (invité ↔ brokers).
- Scénario : l'étape 3 de la chaîne (§2.2) affirme qu'une LPE noyau invité est « nécessaire pour ouvrir
  vsock ou toucher les virtqueues ». C'est faux pour KEP : par conception, le navigateur pousse son trafic
  via un relais SOCKS→KEP (`kaput-agent`). Un renderer compromis (étape 1) **sans** évasion de sandbox ni
  LPE peut donc déjà adresser le parseur KEP côté hôte (c'est le flux normal de navigation). La chaîne pour
  atteindre S2 se réduit à : RCE renderer → bug du parseur KEP → évasion S2 → noyau hôte. L'étape « LPE
  invité » disparaît pour ce chemin.
- Correction : (a) réécrire §2.2 pour distinguer le chemin « périphériques virtio » (qui exige bien root
  invité) du chemin « protocoles applicatifs » (KEP, et KDP via le compositeur) qui est **nativement
  exposé au contenu web** ; (b) traiter `kaput-egress` et `kaput-display` comme recevant directement des
  données attaquant-contrôlées **sans aucune marche d'escalier préalable** — c'est déjà le niveau d'audit
  visé, mais la justification « 3 bugs » ne doit pas servir à relâcher l'effort sur ces parseurs.
- Gravité : **CRITICAL** (c'est la frontière réelle de première ligne, mal décrite).

**RT-03 — « Double domaine de confiance » illusoire pour un mainteneur unique.**
- Frontière : TB6 (chaîne de mise à jour).
- Scénario : la défense repose sur (a) provenance SLSA keyless (CI) **et** (b) signature TUF humaine
  (YubiKey). En variante B retenue (sigstore-rs trop jeune, étude 06 §4.4), **le client ne vérifie que
  TUF** ; la provenance est contrôlée par le signataire *avant* de signer. Avec un seul humain, la
  compromission de son **poste de signature** au moment de la cérémonie suffit à produire une image
  malveillante signée et acceptée par tous les clients. Le « double domaine » devient un seul domaine =
  cette personne et sa machine. Le seuil root 2-sur-3 (clés en lieux distincts, même personne) protège du
  **vol d'une clé**, pas de la compromission du poste ni de l'insider.
- Correction (contrôles compensatoires, cf. §7) : rendre la **transparence publique** vérifiable par des
  tiers (log append-only de toutes les métadonnées TUF + SBOM + provenance), avancer le **rebuilder
  indépendant reproductible** en phase 1 comme *vrai* second domaine, isoler physiquement le poste de
  signature (média live hors ligne), et publier l'identité attendue du workflow pour audit externe.
- Remise en cause fondamentale : **oui, partielle** — le modèle à deux domaines annoncé dans le threat
  model (TB6) doit être redescendu au niveau réel pour la v1 solo.

### HIGH

**RT-04 — La restriction vsock « uid agent seulement » est nulle contre l'invité root.**
- Frontière : TB1/TB3.
- Scénario : plusieurs études (01 §8.8, 05 VM-N2) présentent « seul l'uid agent est autorisé à ouvrir
  AF_VSOCK (LSM/seccomp invité) » comme mitigation. Or l'hypothèse de conception est **root dans l'invité,
  noyau invité compris** (threat model T2). Un root invité désactive tout LSM/seccomp interne et parle
  directement à tous les ports vsock. Cette « défense en profondeur » ne défend donc contre rien dans le
  modèle retenu.
- Ce qui protège *réellement* : le **vsock userspace hybride** (Firecracker/CH) qui n'expose que les
  sockets Unix `uds_path_PORT` créés par Kaput — donc le nombre et la nature des ports, validés côté hôte.
- Correction : retirer la restriction intra-invité de la colonne « mitigation » (la garder tout au plus
  comme durcissement best-effort hors modèle), et affirmer la garantie **uniquement** sur l'énumération
  des ports côté hôte + parseurs sûrs. Test négatif : `T-VM-03` doit être exécuté avec un **agent invité
  root hostile** qui tente tous les CID/ports, pas seulement un balayage non privilégié.

**RT-05 — IP WAN du routeur (hairpin NAT) et relais publics vers le LAN non couverts.**
- Frontière : TB5 (politique réseau P0–P15).
- Scénario : P9–P13 refusent les IP des interfaces de l'hôte, les préfixes on-link et les routes
  non-défaut. Ils **ne couvrent pas** l'**IP publique WAN du routeur domestique** : un domaine attaquant
  la résout, et via le hairpin NAT le `connect()` atteint l'interface d'admin du routeur (`:80/:443`) — une
  destination publique, on-route-défaut, hors interfaces hôte. Même logique pour tout **service public qui
  relaie vers un réseau interne** (proxys ouverts, prévisualiseurs d'URL, SSRF-as-a-service) : la cible
  TCP vue par Kaput est publique et légitime. L'étude 05 le classe en R4 avec, comme mitigation,
  « détection de l'IP publique de sortie et refus de celle-ci *[à étudier]* » — donc **non spécifié**.
- Correction : spécifier et implémenter la détection de l'**IP publique de sortie** (par le canal DoH/HTTPS
  de confiance, pas par STUN UDP) et la refuser par défaut (P-nouveau) ; activer par défaut la liste noire
  utilisateur (D10) amorcée avec l'IP WAN détectée ; documenter explicitement que les relais applicatifs
  tiers restent hors de portée de la politique (c'est une limite, pas un bug). Tests : étendre `T-IP-*`
  avec une sentinelle « routeur » en IP publique atteignable par hairpin.

**RT-06 — « Deux périphériques / le VMM ne relaie que des octets » sous-estime la surface résiduelle.**
- Frontière : TB1.
- Scénario : l'étude 01 §4.1 liste, même pour Firecracker, `i8042` partiel (reset), série (dev), MMDS,
  l'APIC/LAPIC et le transport MMIO lui-même. La synthèse parle de « 2 périphériques virtio » et d'un VMM
  « simple relais d'octets ». Un attaquant audite **tout** ce qui est émulé en user-mode, y compris
  i8042, l'horloge/timers, les registres MMIO résiduels, et les MSR/CPUID/ports I/O traités par le VMM ou
  passés à l'hyperviseur. CPUID/MSR, kvmclock/TSC et l'entropie (RDRAND/RDSEED/jitter, voire virtio-rng)
  ne sont **pas énumérés** comme surface dans le contrat invité.
- Correction : ajouter au contrat invité (§2.3) une **énumération exhaustive de l'émulation réellement
  liée** par backend (i8042, série, APIC, timers, MSR/CPUID exposés, RNG), avec pour chacun : activé/désactivé
  en release, qui l'émule (hyperviseur vs VMM user-mode), fuzzé ou non. C'est précisément l'objet du PoC U3
  (`cargo tree`/`tokei`) — le rendre bloquant. Tests : `probe_ioport`, `probe_pci`, lecture MSR/CPUID
  depuis l'invité comparées à une liste blanche (déjà en germe dans l'étude 07, à compléter MSR/CPUID).

**RT-07 — Résidus mémoire : kdump hôte et hibernation forcée non traités.**
- Frontière : TB8 / R5 / R7.
- Scénario : la RAM invitée (pages web, saisies) peut atteindre le disque hôte via pagefile/swap
  (atténué par `MemorySwapMax=0`, `VirtualLock` borné), mais **zswap/zram**, **kdump** (un crash du noyau
  hôte vide la RAM, invité compris, dans `/var/crash`) et une **hibernation déclenchée hors application**
  (batterie critique, `systemctl hibernate` par un tiers) échappent aux mitigations « détruire la session
  avant la veille » (qui ne capte que la veille notifiée) et à `MemorySwapMax=0` (qui ne couvre pas kdump).
- Correction : documenter kdump et l'hibernation non-notifiée comme **résidus non éliminables sans
  configuration hôte** ; recommander fermement le chiffrement intégral du disque (déjà dit) **et** préciser
  qu'il est la seule mitigation réelle de ces deux canaux ; étudier `init_on_free=1` côté invité (déjà en
  cmdline) comme réduction partielle. Test : `NEG-FOR-*` doit inclure un scénario **panique noyau hôte +
  kdump** et un **hibernate externe**, pas seulement `close` et `kill -9`.

**RT-08 — Incohérence threat model : T5 (malware local même-UID) adversaire *dans* le périmètre mais concédé par TB8.**
- Frontière : TB8.
- Scénario : le threat model §3 liste T5 (« logiciel local non privilégié sur l'hôte … lire l'état de
  session Kaput, injecter dans le processus Kaput, TOCTOU ») comme adversaire couvert, et O-? vise à
  résister au TOCTOU. Mais TB8 **accepte et documente hors périmètre** la lecture de la RAM du VMM par un
  malware de même UID (`PR_SET_DUMPABLE=0` n'empêche qu'un sous-ensemble). Il y a donc une tension : T5 est
  à la fois « adversaire traité » et « hors modèle » selon la capacité. Un même-UID peut lire la RAM
  invitée, le `session.lock`, les métadonnées TUF locales, le cache d'images.
- Correction : clarifier dans le threat model **quelles capacités de T5 sont dans le périmètre** (TOCTOU
  image, remplacement du cache → couverts par hash-sur-tampon + dm-verity + Authenticode) et **lesquelles
  sont hors périmètre** (lecture de la RAM du même UID → acceptée, car équivaut à un hôte partiellement
  compromis, proche de H1). En l'état la formulation laisse croire à une protection plus forte qu'elle
  n'est. Remise en cause : **non**, mais cohérence interne à corriger.

**RT-09 — Dépendance du TCB Windows à un VMM non publié (OpenVMM).**
- Frontière : TB1 (Windows) / R7.
- Scénario : OpenVMM n'a **pas de releases**, des « interfaces évolutives » et un processus d'avis de
  sécurité **inconnu** (vérifié : dépôt GitHub, section Releases vide au moment des études). Kaput épingle
  un commit et devient seul veilleur. Un 0-day OpenVMM n'a ni canal d'avis ni correctif amont garanti.
  Toute la frontière Windows (U1–U3) est non prouvée : WHP en utilisateur standard, WHP depuis
  AppContainer/LPAC, build minimal sans VMBus/UEFI/chipset.
- Correction : (a) garder l'ADR 0001 « Proposé » jusqu'aux PoC — déjà fait ; (b) **budgéter crosvm/WHPX
  comme repli réel** et le tester en parallèle, pas seulement « si le PoC échoue » ; (c) exiger un plan de
  réponse 0-day OpenVMM (fork + patch interne) documenté avant toute release Windows.

### MEDIUM

**RT-10 — KDP mode SHM : double fetch et mapping de mémoire invitée (unsafe).**
- Frontière : TB3 (S3/KDP).
- Scénario : `TILE_SHM` mappe une région écrite par l'invité, qui peut la modifier **pendant** la lecture
  (double fetch / TOCTOU mémoire). L'étude 04 impose « copie d'abord dans un tampon privé » et
  « zero-copy interdit » — bonne réponse. Mais c'est de l'`unsafe` dans `kaput-sys`, et le mode SHM n'existe
  pas en standard sous Firecracker/Cloud Hypervisor (pas de périphérique mémoire partagée), donc il ne sert
  qu'à Windows/QEMU et augmente la divergence entre backends (R8).
- Correction : marquer SHM **optionnel, hors chemin par défaut**, soumis à audit `kaput-sys` double revue ;
  rendre INLINE la seule cible v1 obligatoire. Test de fuzzing dédié : région SHM mutée par un thread
  concurrent pendant le parsing (déjà listé étude 04 §B.5, le rendre `required`).

**RT-11 — TOCTOU image sous %LOCALAPPDATA% (mise à jour sans élévation).**
- Frontière : TB6/T7.
- Scénario : l'image invitée est mise à jour sans UAC dans `%LOCALAPPDATA%` (donc modifiable par tout
  processus même-UID). Entre vérification et mmap, un même-UID la remplace.
- Mitigations présentes (bonnes) : SHA-256 recalculé **sur le tampon passé à l'hyperviseur** ou une copie
  privée, ouverture `FILE_SHARE_READ` sans write, dm-verity `panic-on-corruption`. Résiduel : dépend de la
  discipline « copier puis hacher puis mapper la même copie ». 
- Correction : en faire un **invariant testé** (`NEG-TOCTOU-*` : remplacer le fichier juste après la
  vérification et exiger soit l'échec, soit l'usage de la copie vérifiée), pas une simple intention.

**RT-12 — Plein écran réel (D14) réintroduit le spoofing d'UI.**
- Frontière : TB7.
- Scénario : par défaut, pas de vrai plein écran et cadre hôte hors zone invitée — robuste. Mais D14 laisse
  l'option « vrai plein écran » ; une page peut alors peindre un faux cadre Kaput / faux UAC / faux
  verrouillage Windows. « Kaput ne demande jamais de mot de passe » aide mais l'ingénierie sociale reste.
- Correction : si l'option est offerte, imposer un **liseré d'état non contrefaisable** redessiné par
  l'hôte à fréquence fixe et une **mire d'authenticité** déclenchée par la touche hôte (que l'invité ne
  reçoit pas) ; sinon, ne jamais autoriser le vrai plein écran en v1 (recommandation).

**RT-13 — NAT64 NSP : contournement de la liste IPv4 possible (I5 non levé).**
- Frontière : TB5 (P6).
- Scénario : sur réseau IPv6-only avec préfixe NAT64 **spécifique au réseau** (NSP, pas le WKP
  `64:ff9b::/96`), un domaine attaquant renvoie `NSP::0a00:0001` ; sans découverte du NSP, l'IPv4 interne
  incorporée n'est pas extraite ni filtrée. L'étude 05 le sait (I5) mais la découverte fiable du NSP
  (Windows et Linux) n'est pas spécifiée.
- Correction : à défaut de découverte fiable du NSP, **refuser toute adresse hors `2000::/3` ET hors plages
  globales connues qui n'est pas prouvée non-NAT64**, c'est-à-dire traiter tout préfixe NAT64 non vérifié
  comme interne (fail closed). Test `T-W-06` à durcir sur NSP.

**RT-14 — `cmdline` signée : liste blanche d'ajouts = surface.**
- Frontière : TB6 (boot).
- Scénario : la ligne de commande est construite « exclusivement depuis le champ signé », avec « ajouts
  autorisés : liste blanche de paramètres non sensibles (ex. identifiant de session) ». Toute donnée
  variable concaténée dans la cmdline est un vecteur (injection de paramètre si le parsing de la liste
  blanche est faible, ou si l'identifiant de session n'est pas strictement typé/borné).
- Correction : l'identifiant de session doit être un **entier/opaque de longueur fixe validé**, jamais une
  chaîne libre ; test négatif : tenter d'injecter `init=`, `lockdown=`, espaces, via l'identifiant de
  session → doit être rejeté/encodé.

**RT-15 — SignPath Foundation : le modèle solo frotte contre les exigences.**
- Frontière : TB6 (signature hôte Windows, décision utilisateur actée).
- Scénario (vérifié sur signpath.org/terms) : SignPath Foundation exige une **structure d'équipe** (authors
  / reviewers / approvers), la **MFA** pour tous, et « chaque demande de signature doit être approuvée par
  un membre de l'équipe de confiance pour toute l'équipe ». Un projet **à une seule personne** satisfait
  mal « reviewer ≠ committer » et « approver distinct ». De plus, l'éditeur affiché est **SignPath
  Foundation**, pas Kaput (réputation SmartScreen mutualisée). Enfin, SignPath Foundation **ne signe pas**
  les outils offensifs (« white hat tools … cannot be signed ») : Kaput est un navigateur jetable, pas un
  scanner, donc *a priori* éligible, mais à **faire confirmer** vu la nature « sécurité » du projet.
- Correction : clarifier avec SignPath l'éligibilité d'un projet solo et la classification du produit
  **avant** de dépendre de ce canal ; prévoir un repli (certificat OV particulier, ~150–300 USD/an) ;
  documenter que l'identité éditeur sera « SignPath Foundation ».

### LOW

**RT-16 — Landlock ABI 6 ne « scope » que les sockets Unix *abstraits*, pas *pathname*.**
- Vérifié (doc noyau) : ABI 6 = `LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET` + `_SIGNAL` ; les sockets Unix
  *pathname* ne sont couverts que par `LANDLOCK_ACCESS_FS_RESOLVE_UNIX` (ABI 9). Dans Kaput, les sockets
  pathname hôte (Wayland, PipeWire, Pulse) sont de toute façon hors d'atteinte via **netns vide +
  pivot_root tmpfs sans FS**. Donc couvert — mais ne pas présenter Landlock ABI 6 comme suffisant seul ;
  c'est le **netns vide** qui porte la garantie sur les sockets abstraits, et l'**absence de FS** sur les
  pathname. À dire explicitement (les études 03 §89 le disent déjà, à harmoniser avec 08 §149 qui attribue
  à Landlock ABI 6 le blocage « des sockets abstraites et signaux »).

**RT-17 — Journal/logs comme canal : bien conçu, un angle à tester.**
- Les logs typés sans `String` libre (étude 08) ferment l'exfiltration par le log. Reste `session.lock`,
  le cache d'images et les métadonnées TUF locales, lisibles/inscriptibles par le même UID (cf. RT-08).
  Non un canal *depuis l'invité* (l'invité n'y écrit pas), mais un canal *local même-UID*. Cohérent avec
  TB8 accepté. Test `NEG-FOR-*` : vérifier qu'après session, `session.lock` est supprimé et ne contient
  jamais d'URL/contenu (déjà spécifié ; garder `required`).

**RT-18 — Divergence « initramfs ».**
- Incohérence rédactionnelle (voir §5).

---

## 3. Attaque du modèle à mainteneur unique & contrôles compensatoires

**Le problème, sans détour.** Avec une seule personne réelle :
- root TUF « 2-sur-3 » = la même personne détient les 3 clés → c'est **1-sur-1 contre sa compromission** ;
  le seuil ne protège que contre la **perte/vol d'une** clé et la panne matérielle. À documenter ainsi.
- Le « double domaine CI + humain » (TB6) se réduit à **un domaine** en variante B (RT-03) : la machine de
  signature de cette personne.
- Pas de séparation des tâches possible (author = reviewer = approver = releaser).

**Contrôles compensatoires proposés (par ordre d'effet réel) :**

1. **Rebuild reproductible indépendant = le vrai second domaine.** Avancer le rebuilder de la « phase 2 »
   à la **phase 1** : publier les instructions de build hermétique et inviter des tiers (même bénévoles) à
   reconstruire et à **attester publiquement l'égalité du `verity_roothash`**. Pour un projet GPL-3.0
   open source, c'est le substitut crédible à une seconde personne de confiance. Debian trixie est à
   96,9 % reproductible et le paquet chromium l'est (vérifié étude 06) : la cible est réaliste.
2. **Transparence publique vérifiable par les utilisateurs.** Publier **toutes** les métadonnées TUF, SBOM
   (CycloneDX + SPDX) et attestations de provenance dans un log append-only public (GitHub immutable
   releases + Rekor v2). Effet : un tiers détecte une release inattendue que le mainteneur seul ne
   « reviewerait » pas. C'est ce qui remplace l'« approver » manquant.
3. **Poste de signature isolé et éphémère.** Cérémonie sur média live hors ligne (type Tails), jamais sur
   le poste de dev ; vérifier provenance + diff SBOM/lockfile sur ce poste **avant** de signer (variante B)
   et **journaliser la cérémonie de façon signée** (pièges CalyxOS/Oxide cités étude 06 : sessions PKCS#11,
   journal HSM non signé — à éviter explicitement).
4. **Révocation rapide gardée.** Conserver `guest-image` expiration 14 j + `policy.minimum_version` /
   `security_epoch` comme révocation 0-day indépendante de l'expiration. C'est la meilleure limite de dégât
   si une clé d'astreinte fuit.
5. **Déléguer par chemin.** Garder des clés **distinctes** guest-image / host-app / trust-config (motifs de
   chemins terminants) pour qu'une fuite ne signe pas tout le TCB (déjà prévu — maintenir).
6. **Hygiène build (leçon arrayref, vérifiée).** `cargo vendor` + `--locked --offline`, **liste blanche de
   `build.rs`/proc-macros avec objectif zéro dans `kaput-vmm` et les brokers**, actions GitHub épinglées
   par SHA, aucun `pull_request_target`. L'incident arrayref (20–22/08/2026, `proc-macro1` typosquat de
   `proc-macro2`, charge via `build.rs`) est confirmé : c'est exactement ce vecteur.
7. **Procédure de vérification hors-bande pour l'utilisateur.** Publier l'empreinte root et l'identité du
   workflow attendu par un canal indépendant (site, README signé) afin qu'un utilisateur averti puisse
   recouper. Annoncer d'avance une politique « jamais de mise à jour hors TUF ».

**Ce qui ne compense PAS** : acheter plus de YubiKeys pour une seule personne (théâtre, l'étude 06 §7 le
dit déjà) ; multiplier les seuils sans second humain ; se fier au badge « Immutable » d'une action (leçon
Trivy, confirmée).

---

## 4. Vérification des faits (échantillon ≈ 10)

| Fait cité | Où | Résultat | Note |
|---|---|---|---|
| **CVE-2026-5747** OOB write transport **virtio PCI** Firecracker, 1.13.0–1.14.3 + 1.15.0, corrigé 1.14.4/1.15.1, **MMIO par défaut non affecté** | 01, PA §2.3 | **Confirmé** | Bulletin AWS 2026-015 : « The legacy MMIO transport is the default and is not affected ». PCI = opt-in `--enable-pci`. Le choix MMIO de Kaput est donc justifié. |
| **CVE-2026-1386** jailer Firecracker, écrasement de fichier hôte via symlink, corrigé 1.13.2/1.14.1 (23/01/2026) | 03 §2 | **Confirmé** | Bulletin AWS 2026-003, Red Hat, NVD. Justifie le remplacement du jailer par `kaput-jail` sans root. |
| **CVE-2026-27211** Cloud Hypervisor : invité réécrit l'en-tête disque en QCOW2 → exfiltration de fichier hôte ; raw+RO non affecté ; corrigé v50.1 | 01 §4.4 | **Confirmé** | Multiples bases (SentinelOne, Wiz, Tenable, cvelogic). Justifie « raw imposé, pas d'auto-détection, RO ». |
| **CVE-2026-107935** gvproxy path traversal `/services/forwarder/expose`, CVSS 9.3, depuis l'invité, corrigé 0.9.0 | 05 §3.3 | **Confirmé** | Red Hat, Debian, SUSE. Argument solide contre les piles userspace M2. |
| **CVE-2026-85046** Chrome V8 type confusion, 6ᵉ 0-day exploité 2026 (sept.) | 04, 06 | **Confirmé** | eSecurityPlanet, BleepingComputer, Help Net (04/09/2026). |
| **CVE-2026-87491** Chrome V8 OOB write, 7ᵉ 0-day exploité 2026, corrigé 153.0.8010.36 (sept.) | 04 | **Confirmé** | The Hacker News, BleepingComputer, Help Net (09/09/2026). Appuie « JIT off par défaut » et l'âge max image. |
| **CVE-2026-105958** spice-server, offsets client sans borne → corruption tas | 04 | **Confirmé** (existe) | Red Hat/SUSE/Debian référencent l'ID. Détail exact de la fonction non revérifié ligne à ligne, mais l'ID et la classe (spice-server, heap) tiennent. Justifie le rejet de SPICE. |
| **Incident `arrayref` août 2026** (`build.rs` malveillant, `proc-macro1` typosquat) | 06, 08 | **Confirmé** | Semgrep, Wiz, SafeDep : `arrayref`/`append-only-vec` compromis ~20–22/08/2026 via dépendance `proc-macro1`, malware au build. Chevauchement DPRK signalé (Wiz/CSA). |
| **Azure Artifact Signing** : particulier UE **non éligible** | 02, 06, PA §7 | **Confirmé** | DevClass : éligible = « organisations ou individus US/CA, ou organisations UE/UK ». Un particulier belge n'est pas éligible → SignPath/OV requis. |
| **SignPath Foundation** gratuit pour OSS | 02, décision utilisateur | **Confirmé, avec réserves** | signpath.org/terms : OSI-approved, structure author/reviewer/approver + MFA, éditeur = « SignPath Foundation », **pas d'outils offensifs**. Frottement pour un projet solo (RT-15). |
| **Landlock ABI 6** = scoping sockets abstraits + signaux | 03, 08 | **Confirmé, précision** | Doc noyau : ABI 6 ne couvre que les sockets **abstraits** ; pathname → ABI 9 (`RESOLVE_UNIX`). Ne pas sur-attribuer à Landlock ce que porte le netns vide (RT-16). |

**Bilan vérification** : 11/11 confirmés (dont 2 avec nuance). **Aucun identifiant fabriqué détecté** dans
l'échantillon. Les numéros « inhabituels » (105958, 107935, 87491, 85046) sont réels. La faiblesse n'est
pas l'invention de CVE mais la **sur-interprétation** (ex. « 2 périphériques », « 3 bugs », « uid agent »).
Les points restés `[à recouper]` dans les études (CVE QEMU virtio-gpu/blk, CVE tough 04/2026, RUSTSEC
hickory, Hyper-V 2026) n'ont pas été revérifiés ici faute de budget ; ils ne changent pas le verdict mais
doivent l'être avant tout ADR, comme le demande U12.

---

## 5. Incohérences internes relevées

1. **Chaîne « 3 vulnérabilités »** (PA §2.2 / étude 01 §5.2) vs exposition directe de KEP au renderer
   (étude 05 : le navigateur pousse SOCKS→KEP). → RT-02.
2. **initramfs** : étude 01 §4.5 décrit le boot direct « bzImage/Image **+ initramfs** », alors que la
   synthèse (§0.5) et l'étude 03 (§17, §B.6) imposent **« dm-verity sans initramfs »**. À trancher et
   harmoniser (impact sur la surface de boot et le hash signé).
3. **vsock « uid agent »** (01 §8.8, 05 VM-N2) présenté comme mitigation vs hypothèse **invité root**
   (threat model T2). → RT-04.
4. **T5 adversaire couvert** (threat model §3) vs **TB8 même-UID hors périmètre** (PA §4.1). → RT-08.
5. **Landlock ABI 6** crédité du blocage des sockets abstraits dans 08 §149, alors que c'est le **netns**
   qui le porte réellement et que Landlock ABI 6 ne couvre pas les sockets pathname. → RT-16.
6. **« Le VMM ne fait que relayer des octets »** (PA §0.3) vs liste d'émulation résiduelle i8042/série/APIC
   (01 §4.1). → RT-06.
7. **Réseau** : la synthèse fige « M3, aucune NIC », mais l'étude 02 (Windows) évoque encore « virtio-net
   ou vsock » et un `kaput-netd` qui parse « trames ou flux » (08 §151). Cohérent sur le fond mais le
   vocabulaire « trames L2 » traîne et doit être purgé pour éviter de réintroduire un parseur de paquets.

---

## 6. Tests négatifs à ajouter (au-delà du catalogue existant)

Les suites `NEG-*`, `T-IP-*`, `T-DNS-*`, `T-VM-*` sont déjà solides. À **ajouter** :

- **NEG-CHAIN-01** : mesurer, avec un **renderer compromis mais sandbox intacte**, si le parseur KEP est
  atteint sans LPE invité (doit confirmer RT-02 et prouver que S2 résiste directement).
- **NEG-VSOCK-ROOT-01** : agent invité **root hostile** balayant tous CID/ports vsock et tentant d'ouvrir
  des ports KDP/contrôle depuis des uid non-agent **après avoir désactivé le LSM invité** → seuls les ports
  Kaput répondent ; aucune fuite (valide RT-04).
- **NEG-NET-WAN-01** : domaine attaquant résolvant vers l'**IP WAN publique du routeur** (hairpin) et vers
  l'IP publique de sortie de l'hôte → REFUS (valide RT-05).
- **NEG-MSR-01 / NEG-CPUID-01 / NEG-IOPORT-01** : lecture MSR/CPUID/ports I/O depuis l'invité comparée à
  une liste blanche ; tout registre hors liste = échec (complète RT-06).
- **NEG-FOR-KDUMP-01** : panique du **noyau hôte** forçant un kdump, puis scan de `/var/crash` pour des
  canaris de session ; **NEG-FOR-HIBER-01** : hibernation déclenchée **hors** application (valide RT-07).
- **NEG-TOCTOU-IMG-01** : remplacement de l'image en cache **juste après** la vérification de hash →
  soit échec, soit usage prouvé de la copie vérifiée (valide RT-11).
- **NEG-CMDLINE-01** : tentative d'injection (`init=`, `lockdown=`, espaces) via l'identifiant de session
  ou tout champ variable de la cmdline → rejet (valide RT-14).
- **NEG-SHM-RACE-01** : mutation concurrente de la région `TILE_SHM` pendant le parsing KDP → aucune
  lecture incohérente, aucun crash (valide RT-10 ; rendre `required`).
- **NEG-UI-FULLSCREEN-01** (si D14 « vrai plein écran » retenu) : page peignant un faux cadre/UAC →
  le liseré d'état hôte et la mire d'authenticité restent non contrefaisables (valide RT-12).
- **NEG-REBUILD-01** : un rebuild indépendant produit le **même `verity_roothash`** ; divergence = blocage
  (contrôle compensatoire §3.1, à rendre bloquant dès que la reproductibilité est prouvée).

---

## 7. Questions ouvertes (à trancher avant ADR 0001/0004/0005)

1. **RT-02/RT-04** : accepte-t-on de réécrire le modèle de chaîne et de retirer les mitigations intra-invité
   du tableau des garanties ? (impact : honnêteté du threat model, priorité d'audit des brokers).
2. **RT-05** : la détection+refus de l'IP publique de sortie est-elle faisable de façon fiable sans STUN
   UDP (interdit en v1) ? Sinon, documenter le hairpin/routeur comme risque résiduel assumé.
3. **RT-03/§3** : avance-t-on le rebuilder reproductible indépendant en phase 1 comme condition de release,
   vu le mainteneur unique ?
4. **RT-07** : kdump et hibernation non-notifiée sont-ils acceptés comme résidus « chiffrement disque
   obligatoire en pratique » ? Faut-il refuser de démarrer si BitLocker/LUKS est absent (durcissement) ?
5. **RT-09** : budget et calendrier d'un repli crosvm/WHPX testé **en parallèle** d'OpenVMM, pas après.
6. **RT-15** : confirmation écrite de SignPath (projet solo + classification « non outil offensif ») avant
   d'en dépendre ; repli OV prévu.
7. **U12** (rappel) : recouper **tous** les CVE encore `[à recouper]` des études (QEMU virtio-gpu/blk, tough
   04/2026, RUSTSEC hickory, Hyper-V 2026, CVE-2026-9539 libslirp) avant citation en ADR.
8. **Incohérence initramfs** (§5.2) : trancher « avec/sans initramfs » et refléter dans le champ `boot`
   signé et le calcul de hash.

---

_Fin de la revue 0001. Les constats CRITICAL (RT-01, RT-02, RT-03) et HIGH (RT-04 à RT-09) conditionnent
la bascule de l'ADR 0001 de « Proposé » à « Accepté ». Les corrections proposées ne changent pas le choix
d'architecture ; elles corrigent le **discours de sécurité** et ajoutent des tests qui échouent
aujourd'hui faute d'exister._
