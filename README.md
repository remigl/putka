# Kaput

**Naviguer en sécurité.** Kaput est un navigateur jetable pour Windows et Linux. Chaque session
s'exécute dans une machine virtuelle Linux minimale, sans accès aux fichiers, aux processus ni au
réseau local de l'hôte. Tout est détruit à la fermeture.

> **État : phase 0 (conception).** Aucun binaire utilisable n'existe encore. Ce dépôt contient pour
> l'instant l'analyse d'architecture, le threat model et les décisions d'architecture. N'utilisez pas
> Kaput pour vous protéger tant qu'une release n'est pas publiée et auditée.

## Principe

```text
HÔTE ── Kaput (UI, superviseur, brokers confinés)
          │  virtualisation matérielle (KVM / Windows Hypervisor Platform)
          └── VM Linux minimale, immuable, vérifiée ── Chromium (sandbox active)
```

- **Frontière principale** : la virtualisation matérielle. Les sandboxes logicielles sont des couches
  supplémentaires.
- **Pas de carte réseau dans la VM** : un proxy Kaput côté hôte résout le DNS (DoH) et refuse par
  défaut le LAN, le localhost et les adresses de l'hôte.
- **Pas de partage** de fichiers, de presse-papiers ni de périphériques par défaut.
- **Aucune persistance** : disque en lecture seule vérifié par dm-verity, état en RAM uniquement.
- **Mises à jour signées** (TUF), vérifiées avant chaque démarrage.

Kaput n'est **pas** un outil d'anonymat et ne protège pas un hôte déjà compromis. Aucune isolation
n'est infaillible : voir le [threat model](docs/threat-model.md) et ses risques résiduels.

## Documentation

- [`PROJECT_ANALYSIS.md`](PROJECT_ANALYSIS.md) : analyse de phase 0 (architecture, menaces, risques, décisions)
- [`docs/threat-model.md`](docs/threat-model.md) : threat model
- [`docs/adr/`](docs/adr/) : Architecture Decision Records
- [`docs/research/`](docs/research/) : études détaillées de phase 0
- [`docs/reviews/`](docs/reviews/) : revues offensives indépendantes
- [`docs/product-brief.md`](docs/product-brief.md) : cahier des charges d'origine

## Licence

[GPL-3.0](LICENSE)
