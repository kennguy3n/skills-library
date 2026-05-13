---
id: infrastructure-security
language: fr
version: "1.0.0"
title: "Sécurité de l'infrastructure"
description: "Durcir l'infrastructure : buckets S3 publics, security groups ouverts, IAM permissif, secrets en clair"
category: hardening
severity: critical
applies_to:
  - "lors de l'écriture ou de la revue d'IaC (Terraform, CloudFormation, Pulumi)"
  - "lors du déploiement de nouveaux services"
  - "lors de la revue de politiques IAM"
languages: ["*"]
token_budget:
  minimal: 900
  compact: 1400
  full: 2200
rules_path: "rules/"
related_skills: ["iac-security", "iam-best-practices"]
last_updated: "2026-05-13"
sources:
  - "CIS Benchmarks (AWS, GCP, Azure)"
  - "NIST SP 800-53 Rév. 5"
  - "MITRE ATT&CK Cloud Matrix"
---

# Sécurité de l'infrastructure

## Règles (pour agents IA)

### TOUJOURS
- Conserver les buckets de stockage privés par défaut (block public
  ACLs, block public policy, ignore public ACLs, restrict public
  buckets).
- Restreindre les security groups et NSG aux ports et CIDR strictement
  nécessaires. Pas de `0.0.0.0/0` sauf sur des ports publics conçus
  pour l'être.
- Chiffrer les données au repos (SSE-KMS) et en transit (TLS 1.2+).
- Activer la journalisation et la supervision (CloudTrail, VPC Flow
  Logs, GuardDuty, Cloud Audit Logs).

### JAMAIS
- Utiliser le compte racine pour les tâches opérationnelles.
- Attacher des politiques IAM `Action: "*"` / `Resource: "*"`.
- Stocker des secrets dans des variables d'environnement persistantes
  ou dans le code.
- Exposer SSH/RDP à Internet sans bastion ni ZTNA.

### FAUX POSITIFS CONNUS
- Buckets délibérément publics destinés à un site statique
  (`*-public-site`) avec policy minimale.

## Contexte

Les erreurs de configuration sont la principale cause de fuites massives
dans le cloud. Les contrôles préventifs (IaC + validation) sont bien
moins coûteux que la réponse a posteriori.

## Références

- CIS Benchmarks AWS / GCP / Azure
- NIST SP 800-53 Rév. 5
- MITRE ATT&CK Cloud Matrix
