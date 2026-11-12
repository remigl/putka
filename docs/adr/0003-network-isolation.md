# ADR 0003 — Isolation réseau

- **Statut** : Proposé
- **Date** : 2026-11-12
- **Étude** : `docs/research/05-network.md`

## Contexte

Le navigateur doit atteindre Internet. L'invité, supposé compromis, ne doit atteindre ni le loopback
de l'hôte, ni le LAN, ni les interfaces de l'hôte, ni les services locaux, ni les métadonnées cloud.
Il ne doit pas non plus pouvoir contourner ces règles par DNS rebinding.

## Alternatives

| Modèle | Avantages | Inconvénients | Verdict |
|---|---|---|---|
| M1 : NIC virtuelle + NAT de l'hyperviseur (vSwitch, WinNAT, bridge) | Performances, UDP natif | Le noyau hôte parse les paquets de l'invité ; admin requis ; politique de destination difficile | Rejeté |
| M2 : NIC + pile IP en espace utilisateur (slirp, passt, gvproxy) | Sans root | Historique de CVE ; filtrage de destination absent ou partiel | Rejeté |
| **M3 : aucune NIC ; vsock vers un proxy Kaput** | Surface minimale ; fail closed par construction ; politique appliquée sur l'IP effectivement connectée | TCP seul en v1 | **Retenu** |
| M4 : TUN dans l'invité + pile utilisateur encapsulée | Permettrait l'UDP | Plus de code | Trajectoire phase 2 |

## Décision

- **Zéro périphérique réseau dans l'invité.** C'est un invariant VM-N1, vérifié dans la configuration
  du VMM **et** par l'agent de test.
- **KEP v1** (Kaput Egress Protocol) sur un port vsock unique :
  - une connexion par flux ;
  - requête bornée `CONNECT_TCP(nom ASCII LDH | IPv4 | IPv6, port)` ;
  - réponse = **code seul, sans aucune adresse**.
- **`kaput-egress`** (Rust, confiné, voir ADR 0005) applique le pipeline **P0–P15**. Le premier match
  gagne et le défaut est le REFUS. Le pipeline couvre :
  - littéraux IPv4 historiques et noms spéciaux ;
  - profil de ports ;
  - résolution DoH ;
  - normalisation IPv4-mapped et NAT64 ;
  - listes noires **générées** depuis les registres IANA versionnés ;
  - IPv6 limitée à `2000::/3` ;
  - adresses de l'hôte, préfixes on-link et routes non-défaut ;
  - métadonnées cloud ;
  - **refus de toute la réponse DNS si une seule adresse est interne** ;
  - `connect()` sur l'IP validée, sans nouvelle résolution ;
  - **P16 (revue 0001, RT-05)** : refus de l'**IP publique de sortie** de l'hôte. C'est souvent l'IP WAN
    du routeur, accessible par hairpin NAT. Elle est détectée sans UDP via le canal DoH et amorce la liste
    noire utilisateur, active par défaut ;
  - **NAT64 (RT-13)** : tout préfixe NAT64 non vérifié est traité comme interne.
- **`kaput-egress` est un parseur de première ligne** (RT-02). Le contenu web influence ses entrées sans
  qu'aucune marche invitée préalable soit garantie. Il est donc audité, fuzzé et confiné au niveau d'un
  VMM.
- **DNS** :
  - résolu uniquement par `kaput-egress`, en DoH, amorcé par des IP littérales ;
  - racines TLS embarquées et signées ;
  - jamais par le résolveur de l'OS ;
  - cache en RAM, effacé à la destruction de la session ;
  - DoH injoignable = fail closed.
- **TCP seul en v1.** QUIC est désactivé ; WebRTC est limité à `disable_non_proxied_udp`.
- **Hors v1** : proxy d'entreprise amont, exception pour les portails captifs, mode « DNS système ».
- **Logs** : compteurs par catégorie de refus uniquement, jamais de destination.

## Conséquences

- Visio dégradée (TURN-TCP) et services P2P UDP inutilisables en v1.
- Inutilisable derrière un proxy d'entreprise obligatoire en v1.
- Environ 45 tests négatifs (`docs/research/05` §9) forment une suite **bloquante**. Chacun échoue si
  un seul octet atteint une sentinelle.

## Risques résiduels

- Un intranet en IP publiques derrière la route par défaut (R10) reste indistinguable d'Internet.
- Les services publics qui relaient vers un réseau interne (proxys ouverts, prévisualiseurs d'URL) sont
  hors de portée d'une politique fondée sur la destination TCP. C'est une limite documentée.
- Un bug logique dans le moteur de politique (R4) : atténué par des tests de bornes, le fuzzing et une
  revue indépendante.
- Une faille du transport vsock dans le VMM (TB1).
