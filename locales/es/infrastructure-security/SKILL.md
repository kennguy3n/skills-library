---
id: infrastructure-security
language: es
version: "1.0.0"
title: "Seguridad de infraestructura"
description: "Endurecer la infraestructura: buckets S3 públicos, security groups abiertos, IAM permisivo, secretos en código"
category: hardening
severity: critical
applies_to:
  - "al escribir o revisar IaC (Terraform, CloudFormation, Pulumi)"
  - "al desplegar nuevos servicios"
  - "al revisar políticas IAM"
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

# Seguridad de infraestructura

## Reglas (para agentes de IA)

### SIEMPRE
- Mantener todos los buckets de almacenamiento de objetos privados por
  defecto (block public ACLs, block public policy, ignore public ACLs,
  restrict public buckets).
- Restringir security groups y NSGs a los puertos y CIDRs estrictamente
  necesarios. Nada de `0.0.0.0/0` salvo en puertos públicos diseñados
  para serlo.
- Cifrar datos en reposo (SSE-KMS, encryption-at-rest) y en tránsito
  (TLS 1.2+).
- Habilitar registro y monitoreo (CloudTrail, VPC Flow Logs, GuardDuty,
  Cloud Audit Logs).

### NUNCA
- Usar el rol/usuario raíz para tareas operativas.
- Adjuntar políticas IAM con `Action: "*"` y `Resource: "*"`.
- Almacenar secretos en variables de entorno persistentes o en el código.
- Permitir acceso SSH/RDP abierto a internet sin un bastión o ZTNA.

### FALSOS POSITIVOS CONOCIDOS
- Buckets diseñados explícitamente como sitios estáticos públicos
  (`*-public-site`) con política mínima.

## Contexto

Una mala configuración de infraestructura es la causa más común de
filtraciones masivas en la nube. Los controles preventivos (IaC con
validación) son mucho más baratos que la respuesta posterior.

## Referencias

- CIS Benchmarks AWS Foundations / GCP / Azure
- NIST SP 800-53 Rev. 5
- MITRE ATT&CK Cloud Matrix
