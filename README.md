# I. Local Security Assessment Tool

Outil complet d'audit de sécurité local pour les systèmes Windows, conçu pour identifier les protocoles obsolètes et les configurations non sécurisées selon les recommandations CIS et les bonnes pratiques Microsoft.

## 1. Fonctionnalités

- **Audit complet des protocoles obsolètes** (SMBv1, TLS faibles, etc.)
- **Vérification de la sécurité PowerShell**
- **Analyse des configurations réseau** (LLMNR, NetBIOS, RDP)
- **Détection des services risqués** (Telnet, FTP, SNMP)
- **Rapport HTML détaillé** avec recommandations
- **Support multilingue** (Français/Anglais)
- **Exécution locale** sans accès réseau requis

## 2. Prérequis
- Windows PowerShell 5.1 ou supérieur
- Accès administrateur sur la machine auditée
- ExecutionPolicy permettant l'exécution de scripts

# II. Utilisation
## 1. Structure des Dossiers
```
C:\SecurityScanner
└───Reports
```

## 2. Exécution de base
- Exécution interactive (demande le choix de la langue)
```
.\LocalSecScan.ps1
```

- Exécution avec langue spécifique
```
.\LocalSecScan.ps1 -Language French
.\LocalSecScan.ps1 -Language English
```

## 3. Options de scan avancées
- Scan complet avec rapport automatique
```
.\LocalSecScan.ps1 -ScanScope Comprehensive -OpenReport
```
- Inclure l'analyse des services réseau
```
.\LocalSecScan.ps1 -ScanNetworkServices
```
- Changer le dossier de sortie
```
.\LocalSecScan.ps1 -OutputPath "D:\SecurityReports\"
```
- Scan complet en français avec services réseau et ouverture automatique
```
.\LocalSecScan.ps1 -Language French -ScanScope Comprehensive -ScanNetworkServices -OpenReport
```

## 4. Codes de sortie
```
0	-> Succès - Aucun problème critique  ->    Surveillance normale
1	-> Problèmes critiques détectés      ->    Action immédiate requise
2	-> Erreur d'exécution                ->    Vérifier les logs
```

# III. Sécurité
## 1. Permissions requises
- [x] Exécution de scripts PowerShell
- [x] Accès administrateur local
- [x] Lecture du registre Windows
- [x] Accès aux services Windows

## 2. Impact système
- [x] Aucune modification : L'outil est en lecture seule
- [x] Aucun redémarrage requis
- [x] Aucune donnée personnelle collectée

# IV. Dépannage
## 1. Problèmes courants
- Erreur d'exécution de script : *modifier la politique d'exécution*
```
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser
```

- Accès refusé : *exécuter en tant qu'administrateur*
```
Start-Process PowerShell -Verb RunAs -ArgumentList "-File LocalSecScan.ps1"
```

- Rapport non généré :
    - Vérifier les permissions d'écriture dans ```OutputPath```
    - Consulter le fichier de log pour les erreurs détaillées

## 2. Journalisation
Les logs détaillés sont sauvegardés dans :
```
C:\SecurityScanner\Reports\LocalSecurityScan-YYYYMMDD-HHMMSS.log
```

# V. Support et améliorations
- [x] Vos retours sont précieux ! Envoyez vos commentaires et suggestions d'amélioration par courriel à : [semspprt=#@#=proton.me]
- [x] Points à signaler ? :
  - [ ] Faux positifs/négatifs dans la détection
  - [ ] Problèmes d'exécution ou d'intégration spécifiques
  - [ ] Suggestions de nouveaux protocoles à analyser
  - [ ] Améliorations de l'interface
  - [ ] Autres

# VI. Journal des modifications
```
v1.1 : Support multilingue (Français/Anglais)
v1.0 : Audit complet des protocoles obsolètes et Rapport HTML détaillé
v0.1 : Analyse des configurations réseaux et systèmes
```

- [x] Dernière mise à jour : Octobre 2025
- [x] Compatibilité : WINDOWS

