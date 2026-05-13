---
id: infrastructure-security
language: de
version: "1.0.0"
title: "Infrastruktursicherheit"
description: "Infrastruktur härten: öffentliche S3-Buckets, offene Security Groups, zu großzügige IAM-Policies, Klartext-Geheimnisse"
category: hardening
severity: critical
applies_to:
  - "beim Schreiben oder Review von IaC (Terraform, CloudFormation, Pulumi)"
  - "beim Deployment neuer Dienste"
  - "beim Review von IAM-Policies"
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
  - "NIST SP 800-53 Rev. 5"
  - "MITRE ATT&CK Cloud Matrix"
---

# Infrastruktursicherheit

## Regeln (für KI-Agenten)

### IMMER
- Object-Storage-Buckets standardmäßig privat halten (Block Public
  ACLs, Block Public Policy, Ignore Public ACLs, Restrict Public
  Buckets).
- Security Groups und NSGs auf strikt notwendige Ports und CIDRs
  beschränken. Kein `0.0.0.0/0` außer auf Ports, die bewusst öffentlich
  sind.
- Daten im Ruhezustand (SSE-KMS) und während der Übertragung
  (TLS 1.2+) verschlüsseln.
- Audit-Logging und Monitoring aktivieren (CloudTrail, VPC Flow Logs,
  GuardDuty, Cloud Audit Logs).

### NIEMALS
- Den Root-Account/Root-User für operative Aufgaben verwenden.
- IAM-Policies mit `Action: "*"` und `Resource: "*"` zuweisen.
- Geheimnisse in dauerhaft persistenten Umgebungsvariablen oder im Code
  speichern.
- SSH/RDP ohne Bastion oder ZTNA gegen das Internet öffnen.

### BEKANNTE FALSCH-POSITIVE
- Buckets, die bewusst als öffentliche Static Sites konzipiert sind
  (`*-public-site`) und nur eine minimale Policy haben.

## Kontext

Fehlkonfigurationen sind die häufigste Ursache für massive Cloud-Daten-
lecks. Präventive Kontrollen (IaC mit Validierung) sind erheblich
günstiger als die nachträgliche Aufarbeitung.

## Referenzen

- CIS Benchmarks AWS Foundations / GCP / Azure
- NIST SP 800-53 Rev. 5
- MITRE ATT&CK Cloud Matrix
