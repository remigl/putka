# ADR 0005 — Intégration hôte : processus, confinement et canaux

- **Statut** : Proposé. Le confinement Windows dépend du PoC U2 : WHP doit fonctionner dans un AppContainer.
- **Date** : 2026-11-12
- **Études** : `docs/research/02`, `03` (partie A), `04` (partie B), `08`

## Contexte

L'hôte est une frontière de sécurité (brief §8). Tout code hôte qui touche des données de l'invité fait
partie de la TCB et doit être supposé attaquable.

## Décision

### Processus

Les processus sont séparés, chacun avec un seul privilège :

| Processus | Privilège unique | Linux | Windows |
|---|---|---|---|
| `kaput` (UI + superviseur) | fenêtre ; possède le Job Object ou le cgroup | utilisateur, Landlock | utilisateur standard, mitigations |
| `kaput-vmm` | `/dev/kvm` ou WHP | `kaput-jail` : userns/mount/pid/**net vide**/ipc ; capabilities = ∅ ; seccomp (liste blanche, KILL) ; Landlock ABI ≥ 6 ; `MemorySwapMax=0` ; `PR_SET_DUMPABLE=0` | **LPAC sans capability** + Job + CIG/ACG/CFG/CET + `disallow_win32k` |
| `kaput-egress` | TCP sortant | idem, sans `/dev/kvm` | AppContainer `internetClient` |
| `kaput-display` | aucun (mémoire partagée uniquement) | idem, sans réseau | AppContainer sans capability |
| `kaput-update` | réseau + cache d'images | Landlock + seccomp | AppContainer `internetClient` |

### Canaux

- L'IPC passe uniquement par des **handles et fds hérités**, avec une liste explicite
  (`PROC_THREAD_ATTRIBUTE_HANDLE_LIST`, `close_range`). **Aucun endpoint nommé** : pas de named pipe
  nommé, pas de socket dans `/tmp`, pas de port TCP local.
- Le codec binaire est écrit à la main : `[u16 version][u16 type][u32 len]`, énumérations fermées,
  bornes vérifiées, fuzzé. Pas de JSON, protobuf, D-Bus, COM ni `serde_derive` aux frontières.
- **KDP v1** (affichage et entrées, `docs/research/04` §B.5) :
  - analysé **uniquement** par `kaput-display` ;
  - pixels validés écrits dans une mémoire partagée de taille fixe imposée par l'hôte ;
  - l'UI ne fait que copier ces pixels et dessiner le cadre ;
  - toute violation détruit la session.
- L'invité **ne peut rien demander** à l'hôte : ni ouvrir une URL, ni afficher une notification, ni
  écrire un fichier, ni changer le titre.
- **KDP v1 = mode `INLINE` uniquement.** Le mode mémoire partagée écrite par l'invité est reporté
  (double fetch, `unsafe`, RT-10).
- **Garantie sur vsock** : seuls les ports créés par Kaput existent côté hôte (« hybrid vsock » en
  espace utilisateur). Les restrictions internes à l'invité (uid agent, LSM) sont un durcissement best
  effort, sans effet contre un root invité (RT-04, NEG-VSOCK-ROOT-01).
- `kaput-egress` et `kaput-display` sont des **parseurs de première ligne**, exposés au contenu web sans
  marche invitée garantie (RT-02). Ils sont soumis aux mêmes exigences que le VMM.

### Fonctions désactivées par défaut

- presse-papiers (dans les deux sens) ;
- glisser-déposer ;
- audio ;
- dossiers partagés ;
- périphériques ;
- transfert de fichiers vers l'hôte.

Options v1 (décision D6) : collage de texte hôte → invité sur geste explicite ; sortie audio PCM à
format fixe. **Jamais de transfert invité → hôte en v1.**

### Anti-spoofing

- Cadre dessiné par l'hôte, hors de la zone invitée.
- **Aucun vrai plein écran en v1** (RT-12).
- Touche hôte jamais transmise à l'invité.
- Titre de fenêtre fixe.

### Cycle de vie

- Machine à états pure (`docs/research/08` §5).
- **Dès `PREPARING`, tout chemin mène à `DESTROYING`.**
- Mort de la session garantie par le noyau : Job `KILL_ON_JOB_CLOSE` sous Windows ; `cgroup.kill` et
  `PDEATHSIG` depuis un thread dédié sous Linux.
- Détection des sessions orphelines grâce à `session.lock`.

## Conséquences

- Plus de processus et de code IPC à auditer. En contrepartie, une évasion du VMM n'obtient ni fichiers,
  ni réseau, ni fenêtre.
- **Si U2 échoue** (WHP refuse l'AppContainer), le repli est un jeton restreint + intégrité Low + Job.
  C'est plus faible ; ce sera documenté et soumis à l'utilisateur. Un service SYSTEM ne sera **pas**
  ajouté sans son accord.
- Accessibilité : les lecteurs d'écran ne voient pas le contenu invité. Cette limite sera documentée.
