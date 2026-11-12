# Kaput — Threat Model

> Statut : **phase 0, revu par l'agent offensif** (`docs/reviews/0001`). Les sections 1 à 5 sont
> indépendantes de l'architecture. Les sections 6 et 7 renvoient à `PROJECT_ANALYSIS.md`.
> Aucune architecture logicielle n'est présentée ici comme invulnérable : ce document décrit des
> propriétés de sécurité **visées**, les **hypothèses** sur lesquelles elles reposent et le **risque résiduel**.

## 1. Objet et périmètre

Kaput permet à un utilisateur Windows ou Linux de naviguer sur des sites potentiellement malveillants
dans un environnement isolé et jetable. Le périmètre couvre :

- l'application hôte Kaput (lanceur, UI, orchestrateur, composants d'intégration) ;
- le runtime d'isolation (hyperviseur et moniteur de machine virtuelle) ;
- l'image invitée (noyau, userspace minimal, navigateur) ;
- les canaux hôte ↔ invité (affichage, entrées, réseau, contrôle, et tout canal optionnel) ;
- la chaîne de build, de signature et de mise à jour.

Hors périmètre (documenté comme hypothèse, voir §4) : un hôte déjà compromis, un attaquant ayant un
accès physique à la machine en cours de session, les attaques sur le matériel (microcode, DMA) au-delà
des mitigations fournies par l'OS hôte et l'hyperviseur.

## 2. Actifs à protéger

| ID | Actif | Propriété visée |
|----|-------|-----------------|
| A1 | Fichiers de l'utilisateur sur l'hôte (`$HOME`, `C:\Users`, partages montés) | Confidentialité, intégrité |
| A2 | Processus, mémoire et identifiants de l'hôte (jetons, cookies d'autres navigateurs, trousseaux) | Confidentialité, intégrité |
| A3 | Réseau local de l'hôte (LAN, services localhost, métadonnées cloud, VPN d'entreprise) | Inaccessibilité depuis l'invité |
| A4 | Intégrité du système hôte (aucune persistance, aucune élévation de privilèges) | Intégrité |
| A5 | Intégrité de l'image invitée et du binaire Kaput (chaîne de mise à jour) | Intégrité, authenticité, fraîcheur |
| A6 | Données de la session de navigation (historique, cookies, téléchargements, saisies) | Non-persistance après fermeture ; confidentialité vis-à-vis de l'hôte si possible |
| A7 | Vie privée de l'utilisateur (IP locales, empreinte matérielle de l'hôte, résolution DNS) | Minimisation des fuites |
| A8 | Disponibilité de l'hôte (pas de déni de service durable causé par une session) | Disponibilité |

## 3. Adversaires

| ID | Adversaire | Capacités supposées |
|----|-----------|---------------------|
| T1 | Site web malveillant | Contrôle total du contenu HTML/JS/WASM/médias/polices/PDF servi ; peut chaîner des 0-days navigateur |
| T2 | Code exécuté dans l'invité (après exploit navigateur, + évasion sandbox navigateur, + LPE noyau invité) | **Hypothèse de conception : root dans l'invité.** Contrôle total du noyau invité, des pilotes, de tout ce qui parle aux périphériques virtuels |
| T3 | Attaquant réseau (Wi-Fi public, FAI, MITM) | Observe et modifie le trafic ; tente DNS spoofing, downgrade |
| T4 | Attaquant de la chaîne d'approvisionnement | Compromission du serveur de mise à jour, d'un miroir, d'une dépendance, d'un paquet de distribution, d'un runner CI, ou d'une clé de signature non-root |
| T5 | Logiciel local non privilégié sur l'hôte, de **même UID** que l'utilisateur | **Dans le périmètre** : remplacer l'image ou les métadonnées en cache, exploiter un TOCTOU entre vérification et boot. **Hors périmètre** : lire la RAM du VMM, injecter du code dans un processus Kaput, lire `session.lock`. Ces capacités équivalent à un hôte déjà partiellement compromis (H1) |
| T6 | Contenu web cherchant à tromper l'utilisateur | Plein écran, fausses boîtes de dialogue imitant l'OS hôte ou Kaput, ingénierie sociale pour faire sortir un fichier |

Le cas dimensionnant est **T2** : Kaput est conçu en supposant que l'invité finira compromis. La
frontière de sécurité principale n'est donc pas le navigateur mais **l'interface entre l'invité et l'hôte**.

## 4. Hypothèses

- H1. L'OS hôte est à jour et non compromis au lancement de Kaput.
- H2. L'hyperviseur matériel (KVM, Hyper-V/WHP) et le CPU fournissent l'isolation mémoire annoncée ;
  les correctifs d'exécution spéculative de l'hôte sont actifs. Risque résiduel : vulnérabilités
  matérielles (classes Spectre/MDS/Retbleed…) et de l'hyperviseur non corrigées.
- H3. La clé racine de mise à jour est conservée hors ligne et n'est pas compromise.
- H4. L'utilisateur ne désactive pas volontairement les protections (ex. activer un transfert de fichiers
  et ouvrir un exécutable téléchargé sur l'hôte) ; quand il le fait, Kaput rend la sortie de la frontière explicite.
- H5. Le temps de l'hôte est approximativement correct (nécessaire à la détection de métadonnées périmées).

## 5. Objectifs de sécurité (indépendants de l'implémentation)

- O1. Un invité compromis (T2) ne peut ni lire ni écrire A1, ni atteindre A2.
- O2. Un invité compromis ne peut joindre aucune adresse de A3 ; seul Internet public est accessible,
  et seulement via un chemin dont la politique est appliquée **hors de l'invité**.
- O3. La surface exposée par l'hôte à l'invité est minimale, énumérée, et chaque interface est écrite dans
  un langage mémoire-sûr ou confinée dans un processus sans privilèges.
- O4. Une évasion de la VM vers le processus moniteur ne donne pas directement les droits de l'utilisateur :
  le moniteur est confiné (utilisateur dédié/AppContainer, seccomp/Landlock, pas d'accès FS ni réseau).
- O5. Aucune donnée de session ne persiste après fermeture, y compris après un crash de Kaput ;
  les résidus inévitables sur l'hôte sont documentés et minimisés.
- O6. Kaput ne démarre jamais une image ou un binaire dont l'authenticité, l'intégrité et la fraîcheur
  n'ont pas été vérifiées (fail closed), et résiste aux attaques rollback, freeze, mix-and-match.
- O7. L'UI de Kaput reste distinguable du contenu web (anti-spoofing).
- O8. Les logs ne contiennent ni URL, ni contenu, ni identifiants de navigation par défaut.

## 6. Frontières de confiance, menaces par frontière, mitigations, risque résiduel

Le tableau de référence des frontières TB0–TB8 se trouve dans `PROJECT_ANALYSIS.md` §4.1. Les chemins
d'attaque, avec le nombre minimal de vulnérabilités par chemin, sont au §2.2.

Points dimensionnants, après la revue offensive 0001 :

- **Chemin A (hyperviseur)** : une fois root dans l'invité, **une seule** vulnérabilité de KVM, de
  l'hyperviseur Microsoft ou du noyau hôte suffit. C'est le risque résiduel R1 de toute architecture
  à machine virtuelle.
- **Chemin C (KEP/KDP)** : les parseurs des brokers sont **exposés au contenu web**, sans marche invitée
  garantie. Ils sont traités comme des parseurs de première ligne.
- **Contrôles internes à l'invité** (LSM, seccomp, restriction vsock par uid) : ce sont des
  durcissements best effort, **jamais des garanties**, puisque l'invité est supposé root.
- **Chaîne de mise à jour en v1 (mainteneur unique)** : un seul domaine de confiance humain. Les
  contrôles compensatoires sont dans `PROJECT_ANALYSIS.md` §10 et l'ADR 0004.

## 7. Risques résiduels

Le registre des risques résiduels R1–R16 est maintenu dans `PROJECT_ANALYSIS.md` §15.1. Les tests qui
mesurent chaque frontière sont catalogués dans `docs/research/07-testing-ci.md` §3, `05-network.md` §9 et
`docs/reviews/0001-offensive-review-phase0.md` §6.
