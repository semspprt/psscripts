<#
.SYNOPSIS
    Comprehensive Local Security Assessment for Windows Servers
.DESCRIPTION
    Performs deep local security assessment to identify weak protocols and insecure configurations
    No remote access required - runs directly on the target server
.NOTES
    Author: EMMANUEL S. M. / Cybersecurity Specialist
    For any improvement or comment : semspprt=#@#=proton.me
    Version: 1.2 (2025-10-15) - Added multilingual support
#>

param(
    [Parameter(HelpMessage = "Output path for reports")]
    [string]$OutputPath = "C:\SecurityScanner\Reports\",
    
    [Parameter(HelpMessage = "Open report after generation")]
    [switch]$OpenReport,
    
    [Parameter(HelpMessage = "Assessment scope")]
    [ValidateSet("Quick", "Comprehensive")]
    [string]$ScanScope = "Comprehensive",
    
    [Parameter(HelpMessage = "Include network services scan")]
    [switch]$ScanNetworkServices,
    
    [Parameter(HelpMessage = "Language for output")]
    [ValidateSet("English", "French")]
    [string]$Language = "English"
)

# Multilingual text resources
$TextResources = @{
    English = @{
        # Logging messages
        "StartingAssessment" = "Starting Comprehensive Local Security Assessment"
        "ScanScope" = "Scan Scope"
        "Computer" = "Computer"
        "CollectingSystemInfo" = "Collecting system information..."
        "SystemInfoCollected" = "System information collected successfully"
        "FailedSystemInfo" = "Failed to collect system information"
        "PerformingSecurityAssessments" = "Performing comprehensive security assessments..."
        "AssessmentCompleted" = "Assessment completed!"
        "CriticalFindings" = "Critical findings: {0}"
        "WarningFindings" = "Warning findings: {0}"
        "TotalChecks" = "Total checks performed: {0}"
        "ReportLocation" = "Report location: {0}"
        "LogFileLocation" = "Log file: {0}"
        "ImmediateActionRequired" = "IMPORTANT: {0} critical findings require immediate attention!"
        "ReviewRecommended" = "Review recommended: {0} warnings should be addressed."
        "NoCriticalIssues" = "No critical security issues detected. System appears secure."
        "FatalError" = "Fatal error: {0}"
        "OpeningReport" = "Opening report in default browser..."
        "OpenReportFailed" = "Could not open report automatically: {0}"
        "GeneratingReport" = "Generating comprehensive HTML report..."
        "ReportGenerated" = "Report generated: {0}"
        
        # SMB Messages
        "CheckingSMB" = "Checking SMB configurations..."
        "SMBv1Critical" = "SMBv1 is ENABLED - Critical Risk!"
        "SMBv1Disabled" = "SMBv1 is disabled"
        "SMBv1Unknown" = "Could not determine SMBv1 status"
        "SMBSigningWarning" = "SMB Signing not required"
        "SMBSigningSuccess" = "SMB Signing is enforced"
        "SMBSigningUnknown" = "Could not check SMB signing"
        
        # PowerShell Messages
        "CheckingPowerShell" = "Checking PowerShell security..."
        "PSv2Critical" = "PowerShell v2 is ENABLED - Critical Risk!"
        "PSv2Disabled" = "PowerShell v2 is disabled"
        "PSv2Unknown" = "Could not determine PowerShell v2 status"
        "PSPolicyCritical" = "PowerShell Execution Policy is {0}"
        "PSPolicySuccess" = "PowerShell Execution Policy is {0}"
        "PSPolicyUnknown" = "Could not check PowerShell Execution Policy"
        "PSTranscriptWarning" = "PowerShell transcription not enabled"
        "PSTranscriptSuccess" = "PowerShell transcription is enabled"
        
        # Name Resolution
        "CheckingNameResolution" = "Checking name resolution protocols..."
        "LLMNRWarning" = "LLMNR is likely ENABLED"
        "LLMNRSuccess" = "LLMNR is disabled via policy"
        "LLMNRUnknown" = "Could not determine LLMNR status"
        "NetBIOSWarning" = "NetBIOS enabled on {0} adapter(s)"
        "NetBIOSSuccess" = "NetBIOS is disabled on all adapters"
        "NetBIOSUnknown" = "Could not check NetBIOS settings"
        
        # TLS/SSL
        "CheckingTLS" = "Checking TLS/SSL configurations..."
        "TLSEnabledCritical" = "{0} is ENABLED"
        "TLSDisabledSuccess" = "{0} is disabled"
        "TLSUnknown" = "Could not check {0} status"
        "WeakCiphersWarning" = "Weak cipher suites enabled: {0}"
        "NoWeakCiphersSuccess" = "No weak cipher suites detected"
        "CiphersUnknown" = "Could not check cipher suites"
        
        # NTLM
        "CheckingNTLM" = "Checking NTLM configurations..."
        "NTLMSuccess" = "NTLM restrictions are configured"
        "NTLMWarning" = "NTLM restrictions not configured"
        "NTLMUnknown" = "Could not determine NTLM restriction settings"
        "LMWarning" = "LM Compatibility Level allows weak authentication"
        "LMSuccess" = "LM Compatibility Level is secure"
        "LMUnknown" = "Could not check LM Compatibility Level"
        
        # Services
        "CheckingServices" = "Checking Windows services and features..."
        "TelnetCritical" = "Telnet Client is INSTALLED"
        "TelnetSuccess" = "Telnet Client is not installed"
        "TelnetUnknown" = "Could not check Telnet Client"
        "FTPCritical" = "FTP Server is ENABLED"
        "SNMPWarning" = "SNMP Service is running"
        "WebClientWarning" = "WebClient service is running"
        
        # WinRM
        "CheckingWinRM" = "Checking WinRM configuration..."
        "WinRMCritical" = "WinRM HTTP listeners active"
        "WinRMSuccess" = "WinRM configured for HTTPS only"
        "WinRMStopped" = "WinRM service is not running"
        "WinRMUnknown" = "Could not check WinRM configuration"
        
        # RDP
        "CheckingRDP" = "Checking RDP configuration..."
        "RDPEnabled" = "RDP is enabled"
        "RDPWeak" = "RDP security settings are weak"
        "RDPSecure" = "RDP is enabled with NLA"
        "RDPDisabled" = "RDP is disabled"
        "RDPUnknown" = "Could not check RDP configuration"
        
        # Network Services
        "CheckingNetworkServices" = "Scanning network services..."
        "RiskyServicesWarning" = "Potentially risky network services detected"
        "NoRiskyServices" = "No obviously risky network services detected"
        "NetworkScanFailed" = "Could not scan network services"
        
        # Finding Titles
        "SMBv1Title" = "SMBv1 Protocol"
        "SMBSigningTitle" = "SMB Signing Enforcement"
        "PSv2Title" = "PowerShell Version 2.0"
        "PSPolicyTitle" = "PowerShell Execution Policy"
        "PSTranscriptTitle" = "PowerShell Transcription"
        "LLMNRTitle" = "LLMNR (Link-Local Multicast Name Resolution)"
        "NetBIOSTitle" = "NetBIOS over TCP/IP"
        "TLSTitle" = "{0} Protocol"
        "WeakCiphersTitle" = "Weak Cipher Suites"
        "NTLMTitle" = "NTLM Audit/Restrictions"
        "LMTitle" = "LAN Manager Authentication Level"
        "TelnetTitle" = "Telnet Client"
        "FTPTitle" = "FTP Server"
        "SNMPTitle" = "SNMP Service"
        "WebClientTitle" = "WebClient Service (WebDAV)"
        "WinRMTitle" = "WinRM {0}"
        "RDPTitle" = "Remote Desktop Protocol (RDP)"
        "NetworkServicesTitle" = "Network Services"
        
        # Finding Details
        "SMBv1EnabledDetails" = "SMBv1 is installed and enabled. Vulnerable to EternalBlue (MS17-010), SMB Relay, and other attacks."
        "SMBv1DisabledDetails" = "SMBv1 is properly disabled."
        "SMBSigningWeakDetails" = "SMB signing is not required. This could allow SMB relay attacks."
        "SMBSigningSecureDetails" = "SMB signing is properly configured."
        "PSv2EnabledDetails" = "PowerShell v2 lacks modern security features, script block logging, and AMSI integration."
        "PSv2DisabledDetails" = "PowerShell v2 is properly disabled."
        "PSPolicyWeakDetails" = "PowerShell scripts can run without restrictions."
        "PSPolicySecureDetails" = "PowerShell execution policy is appropriately configured."
        "PSTranscriptWeakDetails" = "PowerShell command transcription is not enabled for security monitoring."
        "LLMNRWeakDetails" = "LLMNR can be abused for NTLM relay attacks and spoofing."
        "LLMNRSecureDetails" = "LLMNR is properly disabled via registry policy."
        "NetBIOSWeakDetails" = "NetBIOS enabled on adapters: {0}. Vulnerable to name resolution poisoning."
        "NetBIOSSecureDetails" = "NetBIOS over TCP/IP is disabled on all network adapters."
        "TLSWeakDetails" = "{0} has known vulnerabilities and should be disabled."
        "TLSSecureDetails" = "{0} is properly disabled."
        "WeakCiphersDetails" = "Weak cipher suites detected: {0}. These are cryptographically weak."
        "NTLMWeakDetails" = "NTLM relay attacks are possible without restrictions."
        "NTLMSecureDetails" = "NTLM traffic is being audited and restricted."
        "LMWeakDetails" = "LM and NTLMv1 authentication may be allowed."
        "LMSecureDetails" = "Only NTLMv2 and Kerberos authentication are allowed."
        "TelnetWeakDetails" = "Telnet transmits all credentials and data in cleartext."
        "TelnetSecureDetails" = "Telnet client is not present on the system."
        "FTPWeakDetails" = "FTP transmits credentials and data in cleartext."
        "SNMPWeakDetails" = "SNMP may use weak community strings and transmit data in cleartext."
        "WebClientWeakDetails" = "WebClient service can be abused for authentication coercion attacks."
        "WinRMWeakDetails" = "WinRM is configured with HTTP listeners. Credentials and data are transmitted in cleartext."
        "WinRMSecureDetails" = "WinRM is properly configured without cleartext HTTP listeners."
        "WinRMStoppedDetails" = "WinRM service is not active."
        "RDPWeakDetails" = "RDP is enabled but may not require Network Level Authentication (NLA)."
        "RDPSecureDetails" = "RDP is properly configured with Network Level Authentication."
        "RDPDisabledDetails" = "RDP connections are disabled."
        "NetworkServicesWeakDetails" = "The following services are listening: {0}"
        
        # Recommendations
        "DisableSMBv1" = "Immediately disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        "MaintainSMBv1" = "Maintain current configuration."
        "EnableSMBSigning" = "Enable SMB signing via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always)"
        "DisablePSv2" = "Disable PowerShell v2: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart"
        "SetPSPolicy" = "Set Execution Policy to RemoteSigned: Set-ExecutionPolicy RemoteSigned"
        "EnablePSTranscript" = "Enable PowerShell transcription via GPO for security auditing."
        "DisableLLMNR" = "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution"
        "DisableNetBIOS" = "Disable NetBIOS on all network adapters in network adapter properties."
        "DisableTLS" = "Disable {0} via Group Policy: Computer Configuration > Administrative Templates > Network > SSL Configuration Settings"
        "DisableWeakCiphers" = "Disable weak cipher suites via Group Policy and prioritize AES-GCM suites."
        "ConfigureNTLM" = "Configure NTLM restrictions via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options"
        "MigrateToKerberos" = "Consider migrating to Kerberos authentication where possible."
        "SetLMLevel" = "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)"
        "UninstallTelnet" = "Uninstall immediately: Remove-WindowsCapability -Online -Name TelnetClient~~~~0.0.1.0"
        "DisableFTP" = "Disable FTP server if not required: Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer"
        "SecureSNMP" = "Disable SNMP if not required, or secure with strong community strings and ACLs."
        "DisableWebClient" = "Disable WebClient service if WebDAV is not required: Set-Service WebClient -StartupType Disabled"
        "SecureWinRM" = "Remove HTTP listeners and configure WinRM for HTTPS only: winrm delete winrm/config/listener?Address=*+Transport=HTTP"
        "EnableNLA" = "Enable NLA: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
        "ReviewServices" = "Review and disable unnecessary services. Ensure cleartext protocols are replaced with encrypted alternatives."
    }
    French = @{
        # Logging messages
        "StartingAssessment" = "Démarrage de l'audit de sécurité local complet"
        "ScanScope" = "Portée du scan"
        "Computer" = "Ordinateur"
        "CollectingSystemInfo" = "Collecte des informations système..."
        "SystemInfoCollected" = "Informations système collectées avec succès"
        "FailedSystemInfo" = "Échec de la collecte des informations système"
        "PerformingSecurityAssessments" = "Exécution des vérifications de sécurité complètes..."
        "AssessmentCompleted" = "Audit terminé !"
        "CriticalFindings" = "Findings critiques : {0}"
        "WarningFindings" = "Avertissements : {0}"
        "TotalChecks" = "Total des vérifications effectuées : {0}"
        "ReportLocation" = "Emplacement du rapport : {0}"
        "LogFileLocation" = "Fichier de log : {0}"
        "ImmediateActionRequired" = "IMPORTANT : {0} problèmes critiques nécessitent une attention immédiate !"
        "ReviewRecommended" = "Recommandation de revue : {0} avertissements doivent être traités."
        "NoCriticalIssues" = "Aucun problème de sécurité critique détecté. Le système semble sécurisé."
        "FatalError" = "Erreur fatale : {0}"
        "OpeningReport" = "Ouverture du rapport dans le navigateur par défaut..."
        "OpenReportFailed" = "Impossible d'ouvrir le rapport automatiquement : {0}"
        "GeneratingReport" = "Génération du rapport HTML complet..."
        "ReportGenerated" = "Rapport généré : {0}"
        
        # SMB Messages
        "CheckingSMB" = "Vérification des configurations SMB..."
        "SMBv1Critical" = "SMBv1 est ACTIVÉ - Risque Critique !"
        "SMBv1Disabled" = "SMBv1 est désactivé"
        "SMBv1Unknown" = "Impossible de déterminer le statut SMBv1"
        "SMBSigningWarning" = "Signature SMB non requise"
        "SMBSigningSuccess" = "Signature SMB activée"
        "SMBSigningUnknown" = "Impossible de vérifier la signature SMB"
        
        # PowerShell Messages
        "CheckingPowerShell" = "Vérification de la sécurité PowerShell..."
        "PSv2Critical" = "PowerShell v2 est ACTIVÉ - Risque Critique !"
        "PSv2Disabled" = "PowerShell v2 est désactivé"
        "PSv2Unknown" = "Impossible de déterminer le statut PowerShell v2"
        "PSPolicyCritical" = "La politique d'exécution PowerShell est {0}"
        "PSPolicySuccess" = "La politique d'exécution PowerShell est {0}"
        "PSPolicyUnknown" = "Impossible de vérifier la politique d'exécution PowerShell"
        "PSTranscriptWarning" = "Transcription PowerShell non activée"
        "PSTranscriptSuccess" = "Transcription PowerShell activée"
        
        # Name Resolution
        "CheckingNameResolution" = "Vérification des protocoles de résolution de noms..."
        "LLMNRWarning" = "LLMNR est probablement ACTIVÉ"
        "LLMNRSuccess" = "LLMNR est désactivé par politique"
        "LLMNRUnknown" = "Impossible de déterminer le statut LLMNR"
        "NetBIOSWarning" = "NetBIOS activé sur {0} adaptateur(s)"
        "NetBIOSSuccess" = "NetBIOS est désactivé sur tous les adaptateurs"
        "NetBIOSUnknown" = "Impossible de vérifier les paramètres NetBIOS"
        
        # TLS/SSL
        "CheckingTLS" = "Vérification des configurations TLS/SSL..."
        "TLSEnabledCritical" = "{0} est ACTIVÉ"
        "TLSDisabledSuccess" = "{0} est désactivé"
        "TLSUnknown" = "Impossible de vérifier le statut {0}"
        "WeakCiphersWarning" = "Suites de chiffrement faibles activées : {0}"
        "NoWeakCiphersSuccess" = "Aucune suite de chiffrement faible détectée"
        "CiphersUnknown" = "Impossible de vérifier les suites de chiffrement"
        
        # NTLM
        "CheckingNTLM" = "Vérification des configurations NTLM..."
        "NTLMSuccess" = "Les restrictions NTLM sont configurées"
        "NTLMWarning" = "Restrictions NTLM non configurées"
        "NTLMUnknown" = "Impossible de déterminer les paramètres de restriction NTLM"
        "LMWarning" = "Le niveau de compatibilité LM autorise une authentification faible"
        "LMSuccess" = "Le niveau de compatibilité LM est sécurisé"
        "LMUnknown" = "Impossible de vérifier le niveau de compatibilité LM"
        
        # Services
        "CheckingServices" = "Vérification des services et fonctionnalités Windows..."
        "TelnetCritical" = "Le client Telnet est INSTALLÉ"
        "TelnetSuccess" = "Le client Telnet n'est pas installé"
        "TelnetUnknown" = "Impossible de vérifier le client Telnet"
        "FTPCritical" = "Le serveur FTP est ACTIVÉ"
        "SNMPWarning" = "Le service SNMP est en cours d'exécution"
        "WebClientWarning" = "Le service WebClient est en cours d'exécution"
        
        # WinRM
        "CheckingWinRM" = "Vérification de la configuration WinRM..."
        "WinRMCritical" = "Écouteurs HTTP WinRM actifs"
        "WinRMSuccess" = "WinRM configuré pour HTTPS uniquement"
        "WinRMStopped" = "Le service WinRM n'est pas en cours d'exécution"
        "WinRMUnknown" = "Impossible de vérifier la configuration WinRM"
        
        # RDP
        "CheckingRDP" = "Vérification de la configuration RDP..."
        "RDPEnabled" = "RDP est activé"
        "RDPWeak" = "Les paramètres de sécurité RDP sont faibles"
        "RDPSecure" = "RDP est activé avec NLA"
        "RDPDisabled" = "RDP est désactivé"
        "RDPUnknown" = "Impossible de vérifier la configuration RDP"
        
        # Network Services
        "CheckingNetworkServices" = "Scan des services réseau..."
        "RiskyServicesWarning" = "Services réseau potentiellement risqués détectés"
        "NoRiskyServices" = "Aucun service réseau visiblement risqué détecté"
        "NetworkScanFailed" = "Impossible de scanner les services réseau"
        
        # Finding Titles
        "SMBv1Title" = "Protocole SMBv1"
        "SMBSigningTitle" = "Application de la signature SMB"
        "PSv2Title" = "PowerShell Version 2.0"
        "PSPolicyTitle" = "Politique d'exécution PowerShell"
        "PSTranscriptTitle" = "Transcription PowerShell"
        "LLMNRTitle" = "LLMNR (Link-Local Multicast Name Resolution)"
        "NetBIOSTitle" = "NetBIOS over TCP/IP"
        "TLSTitle" = "Protocole {0}"
        "WeakCiphersTitle" = "Suites de chiffrement faibles"
        "NTLMTitle" = "Audit/Restrictions NTLM"
        "LMTitle" = "Niveau d'authentification LAN Manager"
        "TelnetTitle" = "Client Telnet"
        "FTPTitle" = "Serveur FTP"
        "SNMPTitle" = "Service SNMP"
        "WebClientTitle" = "Service WebClient (WebDAV)"
        "WinRMTitle" = "WinRM {0}"
        "RDPTitle" = "Protocole Bureau à distance (RDP)"
        "NetworkServicesTitle" = "Services réseau"
        
        # Finding Details
        "SMBv1EnabledDetails" = "SMBv1 est installé et activé. Vulnérable à EternalBlue (MS17-010), SMB Relay et autres attaques."
        "SMBv1DisabledDetails" = "SMBv1 est correctement désactivé."
        "SMBSigningWeakDetails" = "La signature SMB n'est pas requise. Cela pourrait permettre des attaques SMB Relay."
        "SMBSigningSecureDetails" = "La signature SMB est correctement configurée."
        "PSv2EnabledDetails" = "PowerShell v2 manque des fonctionnalités de sécurité modernes, la journalisation des blocs de script et l'intégration AMSI."
        "PSv2DisabledDetails" = "PowerShell v2 est correctement désactivé."
        "PSPolicyWeakDetails" = "Les scripts PowerShell peuvent s'exécuter sans restrictions."
        "PSPolicySecureDetails" = "La politique d'exécution PowerShell est correctement configurée."
        "PSTranscriptWeakDetails" = "La transcription des commandes PowerShell n'est pas activée pour la surveillance de sécurité."
        "LLMNRWeakDetails" = "LLMNR peut être exploité pour des attaques de relais NTLM et d'usurpation."
        "LLMNRSecureDetails" = "LLMNR est correctement désactivé via la politique de registre."
        "NetBIOSWeakDetails" = "NetBIOS activé sur les adaptateurs : {0}. Vulnérable à l'empoisonnement de la résolution de noms."
        "NetBIOSSecureDetails" = "NetBIOS over TCP/IP est désactivé sur tous les adaptateurs réseau."
        "TLSWeakDetails" = "{0} a des vulnérabilités connues et devrait être désactivé."
        "TLSSecureDetails" = "{0} est correctement désactivé."
        "WeakCiphersDetails" = "Suites de chiffrement faibles détectées : {0}. Ces suites sont cryptographiquement faibles."
        "NTLMWeakDetails" = "Les attaques par relais NTLM sont possibles sans restrictions."
        "NTLMSecureDetails" = "Le trafic NTLM est audité et restreint."
        "LMWeakDetails" = "L'authentification LM et NTLMv1 peut être autorisée."
        "LMSecureDetails" = "Seules l'authentification NTLMv2 et Kerberos sont autorisées."
        "TelnetWeakDetails" = "Telnet transmet toutes les informations d'identification et données en clair."
        "TelnetSecureDetails" = "Le client Telnet n'est pas présent sur le système."
        "FTPWeakDetails" = "FTP transmet les informations d'identification et données en clair."
        "SNMPWeakDetails" = "SNMP peut utiliser des chaînes de communauté faibles et transmettre des données en clair."
        "WebClientWeakDetails" = "Le service WebClient peut être exploité pour des attaques de coercition d'authentification."
        "WinRMWeakDetails" = "WinRM est configuré avec des écouteurs HTTP. Les informations d'identification et données sont transmises en clair."
        "WinRMSecureDetails" = "WinRM est correctement configuré sans écouteurs HTTP en clair."
        "WinRMStoppedDetails" = "Le service WinRM n'est pas actif."
        "RDPWeakDetails" = "RDP est activé mais peut ne pas nécessiter l'authentification au niveau réseau (NLA)."
        "RDPSecureDetails" = "RDP est correctement configuré avec l'authentification au niveau réseau (NLA)."
        "RDPDisabledDetails" = "Les connexions RDP sont désactivées."
        "NetworkServicesWeakDetails" = "Les services suivants sont en écoute : {0}"
        
        # Recommendations
        "DisableSMBv1" = "Désactivez immédiatement SMBv1 : Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
        "MaintainSMBv1" = "Maintenez la configuration actuelle."
        "EnableSMBSigning" = "Activez la signature SMB via GPO : Configuration ordinateur > Stratégies > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Options de sécurité > Serveur de réseau Microsoft : Signer numériquement les communications (toujours)"
        "DisablePSv2" = "Désactivez PowerShell v2 : Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart"
        "SetPSPolicy" = "Définissez la politique d'exécution sur RemoteSigned : Set-ExecutionPolicy RemoteSigned"
        "EnablePSTranscript" = "Activez la transcription PowerShell via GPO pour l'audit de sécurité."
        "DisableLLMNR" = "Désactivez LLMNR via GPO : Configuration ordinateur > Modèles d'administration > Réseau > Client DNS > Désactiver la résolution de noms multicast"
        "DisableNetBIOS" = "Désactivez NetBIOS sur tous les adaptateurs réseau dans les propriétés de l'adaptateur réseau."
        "DisableTLS" = "Désactivez {0} via Stratégie de groupe : Configuration ordinateur > Modèles d'administration > Réseau > Paramètres SSL"
        "DisableWeakCiphers" = "Désactivez les suites de chiffrement faibles via Stratégie de groupe et priorisez les suites AES-GCM."
        "ConfigureNTLM" = "Configurez les restrictions NTLM via Stratégie de groupe : Configuration ordinateur > Paramètres Windows > Paramètres de sécurité > Stratégies locales > Options de sécurité"
        "MigrateToKerberos" = "Envisagez de migrer vers l'authentification Kerberos si possible."
        "SetLMLevel" = "Définissez LmCompatibilityLevel à 5 (Envoyer uniquement la réponse NTLMv2, refuser LM & NTLM)"
        "UninstallTelnet" = "Désinstallez immédiatement : Remove-WindowsCapability -Online -Name TelnetClient~~~~0.0.1.0"
        "DisableFTP" = "Désactivez le serveur FTP si non requis : Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer"
        "SecureSNMP" = "Désactivez SNMP si non requis, ou sécurisez avec des chaînes de communauté fortes et des ACL."
        "DisableWebClient" = "Désactivez le service WebClient si WebDAV n'est pas requis : Set-Service WebClient -StartupType Disabled"
        "SecureWinRM" = "Supprimez les écouteurs HTTP et configurez WinRM pour HTTPS uniquement : winrm delete winrm/config/listener?Address=*+Transport=HTTP"
        "EnableNLA" = "Activez NLA : Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
        "ReviewServices" = "Revoyez et désactivez les services non nécessaires. Assurez-vous que les protocoles en clair sont remplacés par des alternatives chiffrées."
    }
}

# Enhanced logging function with multilingual support
function Write-SecurityLog {
    param(
        [string]$MessageKey,
        [string]$Type = "INFO",
        [string]$Color = "White",
        [array]$FormatArgs = @()
    )
    
    # Get message in selected language
    $LocalizedMessage = $TextResources[$Language][$MessageKey]
    if (-not $LocalizedMessage) {
        $LocalizedMessage = $MessageKey # Fallback to key if translation missing
    }
    
    # Format message if arguments provided
    if ($FormatArgs.Count -gt 0) {
        $LocalizedMessage = $LocalizedMessage -f $FormatArgs
    }
    
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Type] $LocalizedMessage"
    
    switch ($Type) {
        "SUCCESS" { $Color = "Green" }
        "WARNING" { $Color = "Yellow" }
        "ERROR" { $Color = "Red" }
        "CRITICAL" { $Color = "Red" }
        "INFO" { $Color = "Cyan" }
        "DETAIL" { $Color = "Gray" }
    }
    
    Write-Host $LogMessage -ForegroundColor $Color
    if ($Global:LogFile) {
        $LogMessage | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
    }
}

# Get comprehensive system information
function Get-SystemInformation {
    Write-SecurityLog "CollectingSystemInfo" "INFO"
    
    $Info = @{}
    
    try {
        # OS Information
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $Info.ComputerName = $env:COMPUTERNAME
        $Info.OSName = $OS.Caption
        $Info.OSVersion = $OS.Version
        $Info.BuildNumber = $OS.BuildNumber
        $Info.InstallDate = $OS.InstallDate
        $Info.LastBootTime = $OS.LastBootUpTime
        $Info.Timezone = (Get-TimeZone).DisplayName
        
        # Computer System
        $CS = Get-CimInstance -ClassName Win32_ComputerSystem
        $Info.Model = $CS.Model
        $Info.Manufacturer = $CS.Manufacturer
        $Info.TotalMemory = "{0:N2} GB" -f ($CS.TotalPhysicalMemory / 1GB)
        $Info.Processors = $CS.NumberOfProcessors
        $Info.Domain = $CS.Domain
        $Info.DomainRole = $CS.DomainRole
        
        # Network Information
        $Networks = Get-NetIPAddress | Where-Object { $_.AddressFamily -eq 'IPv4' -and $_.IPAddress -ne '127.0.0.1' }
        $Info.IPAddresses = ($Networks.IPAddress) -join ", "
        
        # DNS Information
        $DNS = Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses.Count -gt 0 }
        $Info.DNSServers = ($DNS.ServerAddresses) -join ", "
        
        # Hotfix Information
        $Hotfixes = Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object -First 5
        $Info.LastUpdates = ($Hotfixes.InstalledOn | ForEach-Object { $_.ToString("yyyy-MM-dd") }) -join ", "
        
        Write-SecurityLog "SystemInfoCollected" "SUCCESS"
        
    } catch {
        Write-SecurityLog "FailedSystemInfo" "ERROR" -FormatArgs @($_.Exception.Message)
    }
    
    return $Info
}

# Check SMB configurations
function Test-SMBConfig {
    Write-SecurityLog "CheckingSMB" "INFO"
    
    $Findings = @()
    
    # Check SMBv1
    try {
        $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($SMBv1.State -eq "Enabled") {
            Write-SecurityLog "SMBv1Critical" "CRITICAL"
            $Findings += @{
                Title = "SMBv1Title"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "SMBv1EnabledDetails"
                Recommendation = "DisableSMBv1"
                CVE = "MS17-010, CVE-2017-0143-CVE-2017-0148"
                Reference = "https://support.microsoft.com/en-us/help/2696547"
            }
        } else {
            Write-SecurityLog "SMBv1Disabled" "SUCCESS"
            $Findings += @{
                Title = "SMBv1Title"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "SMBv1DisabledDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "SMBv1Unknown" "WARNING"
    }
    
    # Check SMB Signing
    try {
        $SMBSigning = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "requiresecuritysignature" -ErrorAction SilentlyContinue
        if ($SMBSigning.requiresecuritysignature -ne 1) {
            Write-SecurityLog "SMBSigningWarning" "WARNING"
            $Findings += @{
                Title = "SMBSigningTitle"
                Status = "Not Enforced"
                RiskLevel = "Warning"
                Details = "SMBSigningWeakDetails"
                Recommendation = "EnableSMBSigning"
            }
        } else {
            Write-SecurityLog "SMBSigningSuccess" "SUCCESS"
            $Findings += @{
                Title = "SMBSigningTitle"
                Status = "Enforced"
                RiskLevel = "OK"
                Details = "SMBSigningSecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "SMBSigningUnknown" "WARNING"
    }
    
    return $Findings
}

# Check PowerShell security
function Test-PowerShellSecurity {
    Write-SecurityLog "CheckingPowerShell" "INFO"
    
    $Findings = @()
    
    # Check PowerShell v2
    try {
        $PSv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction Stop
        if ($PSv2.State -eq "Enabled") {
            Write-SecurityLog "PSv2Critical" "CRITICAL"
            $Findings += @{
                Title = "PSv2Title"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "PSv2EnabledDetails"
                Recommendation = "DisablePSv2"
                Reference = "CIS Benchmark 18.9.84.1"
            }
        } else {
            Write-SecurityLog "PSv2Disabled" "SUCCESS"
            $Findings += @{
                Title = "PSv2Title"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "PSv2DisabledDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "PSv2Unknown" "WARNING"
    }
    
    # Check PowerShell Execution Policy
    try {
        $ExecutionPolicy = Get-ExecutionPolicy
        if ($ExecutionPolicy -eq "Unrestricted") {
            Write-SecurityLog "PSPolicyCritical" "CRITICAL" -FormatArgs @($ExecutionPolicy)
            $Findings += @{
                Title = "PSPolicyTitle"
                Status = "Unrestricted"
                RiskLevel = "Critical"
                Details = "PSPolicyWeakDetails"
                Recommendation = "SetPSPolicy"
            }
        } elseif ($ExecutionPolicy -eq "Bypass") {
            Write-SecurityLog "PSPolicyCritical" "CRITICAL" -FormatArgs @($ExecutionPolicy)
            $Findings += @{
                Title = "PSPolicyTitle"
                Status = "Bypass"
                RiskLevel = "Critical"
                Details = "PSPolicyWeakDetails"
                Recommendation = "SetPSPolicy"
            }
        } else {
            Write-SecurityLog "PSPolicySuccess" "SUCCESS" -FormatArgs @($ExecutionPolicy)
            $Findings += @{
                Title = "PSPolicyTitle"
                Status = $ExecutionPolicy
                RiskLevel = "OK"
                Details = "PSPolicySecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "PSPolicyUnknown" "WARNING"
    }
    
    # Check PowerShell Transcription/Logging
    try {
        $Transcript = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        if ($Transcript.EnableTranscripting -ne 1) {
            Write-SecurityLog "PSTranscriptWarning" "WARNING"
            $Findings += @{
                Title = "PSTranscriptTitle"
                Status = "Disabled"
                RiskLevel = "Warning"
                Details = "PSTranscriptWeakDetails"
                Recommendation = "EnablePSTranscript"
            }
        } else {
            Write-SecurityLog "PSTranscriptSuccess" "SUCCESS"
        }
    } catch {
        # Transcription not configured is common
    }
    
    return $Findings
}

# Check name resolution protocols
function Test-NameResolution {
    Write-SecurityLog "CheckingNameResolution" "INFO"
    
    $Findings = @()
    
    # Check LLMNR
    try {
        $LLMNR = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($null -eq $LLMNR -or $LLMNR.EnableMulticast -ne 0) {
            Write-SecurityLog "LLMNRWarning" "WARNING"
            $Findings += @{
                Title = "LLMNRTitle"
                Status = "Likely Enabled"
                RiskLevel = "Warning"
                Details = "LLMNRWeakDetails"
                Recommendation = "DisableLLMNR"
                Reference = "CIS Benchmark 18.4.4"
            }
        } else {
            Write-SecurityLog "LLMNRSuccess" "SUCCESS"
            $Findings += @{
                Title = "LLMNRTitle"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "LLMNRSecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "LLMNRUnknown" "WARNING"
    }
    
    # Check NetBIOS
    try {
        $Adapters = Get-NetAdapter | Where-Object Status -eq 'Up'
        $EnabledAdapters = @()
        
        foreach ($Adapter in $Adapters) {
            $NetbiosSetting = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\NetBT\Parameters\Interfaces\Tcpip_$($Adapter.InterfaceGuid)" -Name "NetbiosOptions" -ErrorAction SilentlyContinue
            if ($NetbiosSetting.NetbiosOptions -ne 2) {
                $EnabledAdapters += $Adapter.Name
            }
        }
        
        if ($EnabledAdapters.Count -gt 0) {
            Write-SecurityLog "NetBIOSWarning" "WARNING" -FormatArgs @($EnabledAdapters.Count)
            $Findings += @{
                Title = "NetBIOSTitle"
                Status = "Enabled"
                RiskLevel = "Warning"
                Details = "NetBIOSWeakDetails"
                Recommendation = "DisableNetBIOS"
                Reference = "CIS Benchmark 18.4.7"
            }
        } else {
            Write-SecurityLog "NetBIOSSuccess" "SUCCESS"
            $Findings += @{
                Title = "NetBIOSTitle"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "NetBIOSSecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "NetBIOSUnknown" "WARNING"
    }
    
    return $Findings
}

# Check TLS/SSL configurations
function Test-TLSConfig {
    Write-SecurityLog "CheckingTLS" "INFO"
    
    $Findings = @()
    
    # Check weak TLS versions
    $TLSVersions = @(
        @{ Version = "SSL 2.0"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0" }
        @{ Version = "SSL 3.0"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0" }
        @{ Version = "TLS 1.0"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0" }
        @{ Version = "TLS 1.1"; Path = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1" }
    )
    
    foreach ($TLS in $TLSVersions) {
        try {
            $ServerEnabled = Get-ItemProperty "$($TLS.Path)\Server" -Name "Enabled" -ErrorAction SilentlyContinue
            $ClientEnabled = Get-ItemProperty "$($TLS.Path)\Client" -Name "Enabled" -ErrorAction SilentlyContinue
            
            $IsEnabled = ($ServerEnabled.Enabled -ne 0) -or ($ClientEnabled.Enabled -ne 0)
            
            if ($IsEnabled) {
                Write-SecurityLog "TLSEnabledCritical" "CRITICAL" -FormatArgs @($TLS.Version)
                $RiskLevel = if ($TLS.Version -like "SSL*" -or $TLS.Version -eq "TLS 1.0") { "Critical" } else { "Warning" }
                
                $Findings += @{
                    Title = "TLSTitle"
                    Status = "Enabled"
                    RiskLevel = $RiskLevel
                    Details = "TLSWeakDetails"
                    Recommendation = "DisableTLS"
                    CVE = if ($TLS.Version -eq "SSL 3.0") { "POODLE" } elseif ($TLS.Version -eq "TLS 1.0") { "BEAST" } else { "Various" }
                    FormatArgs = @($TLS.Version)
                }
            } else {
                Write-SecurityLog "TLSDisabledSuccess" "SUCCESS" -FormatArgs @($TLS.Version)
                $Findings += @{
                    Title = "TLSTitle"
                    Status = "Disabled"
                    RiskLevel = "OK"
                    Details = "TLSSecureDetails"
                    Recommendation = "MaintainSMBv1"
                    FormatArgs = @($TLS.Version)
                }
            }
        } catch {
            Write-SecurityLog "TLSUnknown" "WARNING" -FormatArgs @($TLS.Version)
        }
    }
    
    # Check weak cipher suites
    try {
        $WeakCiphers = @(
            "RC4", "DES", "3DES", "NULL", "MD5", "ANON", "ADH", "EXPORT"
        )
        
        $EnabledCiphers = @()
        $CipherKeys = Get-ChildItem "HKLM:\SYSTEM\CurrentControlSet\Control\Cryptography\Configuration\Local\SSL\00010002" -ErrorAction SilentlyContinue
        
        foreach ($Cipher in $WeakCiphers) {
            $MatchingCiphers = $CipherKeys | Where-Object { $_.GetValue("Functions") -like "*$Cipher*" }
            if ($MatchingCiphers) {
                $EnabledCiphers += $Cipher
            }
        }
        
        if ($EnabledCiphers.Count -gt 0) {
            Write-SecurityLog "WeakCiphersWarning" "WARNING" -FormatArgs @(($EnabledCiphers -join ', '))
            $Findings += @{
                Title = "WeakCiphersTitle"
                Status = "Enabled"
                RiskLevel = "Warning"
                Details = "WeakCiphersDetails"
                Recommendation = "DisableWeakCiphers"
                FormatArgs = @(($EnabledCiphers -join ', '))
            }
        } else {
            Write-SecurityLog "NoWeakCiphersSuccess" "SUCCESS"
        }
    } catch {
        Write-SecurityLog "CiphersUnknown" "WARNING"
    }
    
    return $Findings
}

# Check NTLM configurations
function Test-NTLMConfig {
    Write-SecurityLog "CheckingNTLM" "INFO"
    
    $Findings = @()
    
    # Check NTLM restrictions
    try {
        $NTLMRestrictions = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        
        if ($NTLMRestrictions.RestrictSendingNTLMTraffic -eq 2) {
            Write-SecurityLog "NTLMSuccess" "SUCCESS"
            $Findings += @{
                Title = "NTLMTitle"
                Status = "Restricted"
                RiskLevel = "OK"
                Details = "NTLMSecureDetails"
                Recommendation = "MigrateToKerberos"
            }
        } else {
            Write-SecurityLog "NTLMWarning" "WARNING"
            $Findings += @{
                Title = "NTLMTitle"
                Status = "Unrestricted"
                RiskLevel = "Warning"
                Details = "NTLMWeakDetails"
                Recommendation = "ConfigureNTLM"
                Reference = "CIS Benchmark 2.3.1.1-2.3.1.6"
            }
        }
    } catch {
        Write-SecurityLog "NTLMUnknown" "WARNING"
    }
    
    # Check LM Compatibility Level
    try {
        $LMLevel = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        
        if ($LMLevel.LmCompatibilityLevel -lt 5) {
            Write-SecurityLog "LMWarning" "WARNING"
            $Findings += @{
                Title = "LMTitle"
                Status = "Weak"
                RiskLevel = "Warning"
                Details = "LMWeakDetails"
                Recommendation = "SetLMLevel"
            }
        } else {
            Write-SecurityLog "LMSuccess" "SUCCESS"
            $Findings += @{
                Title = "LMTitle"
                Status = "Secure"
                RiskLevel = "OK"
                Details = "LMSecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "LMUnknown" "WARNING"
    }
    
    return $Findings
}

# Check Windows services and features
function Test-WindowsServices {
    Write-SecurityLog "CheckingServices" "INFO"
    
    $Findings = @()
    
    # Check Telnet Client
    try {
        $Telnet = Get-WindowsCapability -Online -Name "TelnetClient*" -ErrorAction SilentlyContinue
        if ($Telnet.State -eq "Installed") {
            Write-SecurityLog "TelnetCritical" "CRITICAL"
            $Findings += @{
                Title = "TelnetTitle"
                Status = "Installed"
                RiskLevel = "Critical"
                Details = "TelnetWeakDetails"
                Recommendation = "UninstallTelnet"
            }
        } else {
            Write-SecurityLog "TelnetSuccess" "SUCCESS"
            $Findings += @{
                Title = "TelnetTitle"
                Status = "Not Installed"
                RiskLevel = "OK"
                Details = "TelnetSecureDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "TelnetUnknown" "WARNING"
    }
    
    # Check FTP Server
    try {
        $FTP = Get-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -ErrorAction SilentlyContinue
        if ($FTP.State -eq "Enabled") {
            Write-SecurityLog "FTPCritical" "CRITICAL"
            $Findings += @{
                Title = "FTPTitle"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "FTPWeakDetails"
                Recommendation = "DisableFTP"
            }
        } else {
            Write-SecurityLog "TelnetSuccess" "SUCCESS"
        }
    } catch {
        # FTP not installed is normal
    }
    
    # Check SNMP Service
    try {
        $SNMP = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if ($SNMP.Status -eq "Running") {
            Write-SecurityLog "SNMPWarning" "WARNING"
            $Findings += @{
                Title = "SNMPTitle"
                Status = "Running"
                RiskLevel = "Warning"
                Details = "SNMPWeakDetails"
                Recommendation = "SecureSNMP"
            }
        }
    } catch {
        # SNMP not installed is normal
    }
    
    # Check WebClient Service (WebDAV)
    try {
        $WebClient = Get-Service -Name "WebClient" -ErrorAction SilentlyContinue
        if ($WebClient.Status -eq "Running") {
            Write-SecurityLog "WebClientWarning" "WARNING"
            $Findings += @{
                Title = "WebClientTitle"
                Status = "Running"
                RiskLevel = "Warning"
                Details = "WebClientWeakDetails"
                Recommendation = "DisableWebClient"
            }
        }
    } catch {
        # WebClient not available is normal
    }
    
    return $Findings
}

# Check WinRM configuration
function Test-WinRMConfig {
    Write-SecurityLog "CheckingWinRM" "INFO"
    
    $Findings = @()
    
    try {
        $WinRMService = Get-Service -Name "WinRM" -ErrorAction SilentlyContinue
        
        if ($WinRMService.Status -eq "Running") {
            # Check WinRM listeners
            $Listeners = Get-ChildItem WSMan:\Localhost\Listener -ErrorAction SilentlyContinue
            
            $HTTPListeners = @()
            foreach ($Listener in $Listeners) {
                $Transport = (Get-ChildItem "WSMan:\Localhost\Listener\$($Listener.Name)\" | Where-Object Name -eq "Transport").Value
                if ($Transport -eq "HTTP") {
                    $HTTPListeners += $Listener.Name
                }
            }
            
            if ($HTTPListeners.Count -gt 0) {
                Write-SecurityLog "WinRMCritical" "CRITICAL"
                $Findings += @{
                    Title = "WinRMTitle"
                    Status = "Active"
                    RiskLevel = "Critical"
                    Details = "WinRMWeakDetails"
                    Recommendation = "SecureWinRM"
                    FormatArgs = @("HTTP Listeners")
                }
            } else {
                Write-SecurityLog "WinRMSuccess" "SUCCESS"
                $Findings += @{
                    Title = "WinRMTitle"
                    Status = "Secure"
                    RiskLevel = "OK"
                    Details = "WinRMSecureDetails"
                    Recommendation = "MaintainSMBv1"
                    FormatArgs = @("Configuration")
                }
            }
        } else {
            Write-SecurityLog "WinRMStopped" "SUCCESS"
            $Findings += @{
                Title = "WinRMTitle"
                Status = "Stopped"
                RiskLevel = "OK"
                Details = "WinRMStoppedDetails"
                Recommendation = "MaintainSMBv1"
                FormatArgs = @("Service")
            }
        }
    } catch {
        Write-SecurityLog "WinRMUnknown" "WARNING"
    }
    
    return $Findings
}

# Check RDP configuration
function Test-RDPConfig {
    Write-SecurityLog "CheckingRDP" "INFO"
    
    $Findings = @()
    
    try {
        $RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        
        if ($RDP.fDenyTSConnections -eq 0) {
            Write-SecurityLog "RDPEnabled" "WARNING"
            
            # Check RDP Security Layer
            $SecurityLayer = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            $UserAuthentication = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            
            if ($SecurityLayer.SecurityLayer -ne 2 -or $UserAuthentication.UserAuthentication -ne 1) {
                Write-SecurityLog "RDPWeak" "WARNING"
                $Findings += @{
                    Title = "RDPTitle"
                    Status = "Enabled with weak security"
                    RiskLevel = "Warning"
                    Details = "RDPWeakDetails"
                    Recommendation = "EnableNLA"
                }
            } else {
                Write-SecurityLog "RDPSecure" "SUCCESS"
                $Findings += @{
                    Title = "RDPTitle"
                    Status = "Enabled with NLA"
                    RiskLevel = "OK"
                    Details = "RDPSecureDetails"
                    Recommendation = "MaintainSMBv1"
                }
            }
        } else {
            Write-SecurityLog "RDPDisabled" "SUCCESS"
            $Findings += @{
                Title = "RDPTitle"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "RDPDisabledDetails"
                Recommendation = "MaintainSMBv1"
            }
        }
    } catch {
        Write-SecurityLog "RDPUnknown" "WARNING"
    }
    
    return $Findings
}

# Check network services (if requested)
function Test-NetworkServices {
    Write-SecurityLog "CheckingNetworkServices" "INFO"
    
    $Findings = @()
    
    try {
        $TCPListeners = Get-NetTCPConnection | Where-Object { $_.State -eq "Listen" } | Select-Object LocalPort, OwningProcess | Sort-Object LocalPort -Unique
        
        $SuspiciousPorts = @{
            21 = "FTP (Cleartext)"
            23 = "Telnet (Cleartext)" 
            25 = "SMTP (Potentially unencrypted)"
            53 = "DNS"
            80 = "HTTP (Cleartext)"
            110 = "POP3 (Cleartext)"
            135 = "RPC Endpoint Mapper"
            139 = "NetBIOS Session Service"
            143 = "IMAP (Cleartext)"
            445 = "SMB"
            1433 = "SQL Server"
            3389 = "RDP"
        }
        
        $OpenPorts = @()
        foreach ($Port in $TCPListeners) {
            if ($SuspiciousPorts.ContainsKey($Port.LocalPort)) {
                $OpenPorts += "$($Port.LocalPort) - $($SuspiciousPorts[$Port.LocalPort])"
            }
        }
        
        if ($OpenPorts.Count -gt 0) {
            Write-SecurityLog "RiskyServicesWarning" "WARNING"
            $Findings += @{
                Title = "NetworkServicesTitle"
                Status = "Risky Services Detected"
                RiskLevel = "Warning"
                Details = "NetworkServicesWeakDetails"
                Recommendation = "ReviewServices"
                FormatArgs = @(($OpenPorts -join '; '))
            }
        } else {
            Write-SecurityLog "NoRiskyServices" "SUCCESS"
        }
    } catch {
        Write-SecurityLog "NetworkScanFailed" "WARNING"
    }
    
    return $Findings
}

# Generate HTML Report with multilingual support
function New-SecurityReport {
    param(
        [hashtable]$ServerInfo,
        [array]$Findings,
        [string]$OutputPath,
        [string]$Language
    )
    
    Write-SecurityLog "GeneratingReport" "INFO"
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ReportFile = Join-Path $OutputPath "$($ServerInfo.ComputerName)-Security-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    
    # Count findings by risk level
    $CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $WarningCount = ($Findings | Where-Object { $_.RiskLevel -eq "Warning" }).Count
    $OKCount = ($Findings | Where-Object { $_.RiskLevel -eq "OK" }).Count
    
    # Localized strings for report
    $ReportText = @{
        English = @{
            Title = "Local Security Assessment Report"
            Server = "Server"
            Generated = "Generated"
            ScanInfo = "Scan Information"
            Scope = "Scope"
            NetworkServices = "Network Services"
            AssessmentType = "Assessment Type"
            SystemInfo = "System Information"
            ComputerName = "Computer Name"
            OperatingSystem = "Operating System"
            OSVersion = "OS Version"
            Domain = "Domain"
            DomainRole = "Domain Role"
            Manufacturer = "Manufacturer"
            Model = "Model"
            Memory = "Memory"
            Processors = "Processors"
            IPAddresses = "IP Addresses"
            DNSServers = "DNS Servers"
            Timezone = "Timezone"
            LastBoot = "Last Boot"
            RecentUpdates = "Recent Updates"
            CriticalFindings = "Critical Findings"
            Warnings = "Warnings"
            SecureConfigurations = "Secure Configurations"
            SecurityFindings = "Security Findings"
            Status = "Status"
            Details = "Details"
            CVEReferences = "CVE References"
            Reference = "Reference"
            Recommendation = "Recommendation"
            AssessmentSummary = "Assessment Summary"
            OverallSecurity = "Overall Security Posture"
            TotalChecks = "Total Security Checks"
            RecommendationPriority = "Recommendation Priority"
            NextSteps = "Next Steps"
            ImmediateAction = "IMMEDIATE ACTION"
            AddressCritical = "Address all critical findings first"
            ReviewWarnings = "Review and plan remediation for warning findings"
            ImplementChanges = "Implement changes in a controlled manner"
            TestConfigurations = "Test configurations in non-production environment first"
            CISGuidance = "Refer to CIS Benchmarks for Windows Server for comprehensive guidance"
            ScheduleAssessments = "Schedule regular security assessments"
            AdditionalControls = "Consider implementing additional security controls based on risk assessment"
            ReportFooter = "Generated by Local Security Assessment Tool v4.0"
            ReportNote = "This report provides security recommendations based on industry best practices. Always test changes in a non-production environment."
            Excellent = "Excellent - No issues detected"
            Good = "Good - Review warnings"
            Poor = "Poor - Immediate action required"
            Unknown = "Unknown"
            AddressCriticalAction = "Address critical findings immediately"
            ReviewWarningsAction = "Review and address warnings"
            MaintainConfig = "Maintain current security configuration"
        }
        French = @{
            Title = "Rapport d'Audit de Sécurité Local"
            Server = "Serveur"
            Generated = "Généré le"
            ScanInfo = "Informations du Scan"
            Scope = "Portée"
            NetworkServices = "Services Réseau"
            AssessmentType = "Type d'Audit"
            SystemInfo = "Informations Système"
            ComputerName = "Nom de l'Ordinateur"
            OperatingSystem = "Système d'Exploitation"
            OSVersion = "Version du SE"
            Domain = "Domaine"
            DomainRole = "Rôle de Domaine"
            Manufacturer = "Fabricant"
            Model = "Modèle"
            Memory = "Mémoire"
            Processors = "Processeurs"
            IPAddresses = "Adresses IP"
            DNSServers = "Serveurs DNS"
            Timezone = "Fuseau Horaire"
            LastBoot = "Dernier Démarrage"
            RecentUpdates = "Mises à Jour Récentes"
            CriticalFindings = "Problèmes Critiques"
            Warnings = "Avertissements"
            SecureConfigurations = "Configurations Sécurisées"
            SecurityFindings = "Résultats de Sécurité"
            Status = "Statut"
            Details = "Détails"
            CVEReferences = "Références CVE"
            Reference = "Référence"
            Recommendation = "Recommandation"
            AssessmentSummary = "Résumé de l'Audit"
            OverallSecurity = "Posture de Sécurité Globale"
            TotalChecks = "Total des Vérifications de Sécurité"
            RecommendationPriority = "Priorité des Recommandations"
            NextSteps = "Prochaines Étapes"
            ImmediateAction = "ACTION IMMÉDIATE"
            AddressCritical = "Traitez tous les problèmes critiques en premier"
            ReviewWarnings = "Revoyez et planifiez la correction des avertissements"
            ImplementChanges = "Implémentez les changements de manière contrôlée"
            TestConfigurations = "Testez les configurations d'abord en environnement de pré-production"
            CISGuidance = "Consultez les CIS Benchmarks pour Windows Server pour des directives complètes"
            ScheduleAssessments = "Planifiez des audits de sécurité réguliers"
            AdditionalControls = "Envisagez de mettre en œuvre des contrôles de sécurité supplémentaires basés sur l'évaluation des risques"
            ReportFooter = "Généré par l'Outil d'Audit de Sécurité Local v4.0"
            ReportNote = "Ce rapport fournit des recommandations de sécurité basées sur les meilleures pratiques de l'industrie. Testez toujours les changements dans un environnement de pré-production."
            Excellent = "Excellent - Aucun problème détecté"
            Good = "Bon - Revoyez les avertissements"
            Poor = "Mauvais - Action immédiate requise"
            Unknown = "Inconnu"
            AddressCriticalAction = "Traitez les problèmes critiques immédiatement"
            ReviewWarningsAction = "Revoyez et traitez les avertissements"
            MaintainConfig = "Maintenez la configuration de sécurité actuelle"
        }
    }
    
    $Text = $ReportText[$Language]

    # HTML report generation
    $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>$($Text.Title) - $($ServerInfo.ComputerName)</title>
    <style>
        body { 
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; 
            margin: 0; 
            padding: 20px; 
            background-color: #f5f5f5;
            color: #333;
        }
        .container { 
            max-width: 1400px; 
            margin: 0 auto; 
            background: white; 
            border-radius: 8px; 
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        .header { 
            background: linear-gradient(135deg, #004578, #0078d4); 
            color: white; 
            padding: 30px; 
            text-align: center;
        }
        .server-info { 
            background: #e3f2fd; 
            padding: 20px; 
            margin: 20px;
            border-radius: 6px;
            border-left: 4px solid #0078d4;
        }
        .summary-cards {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 15px;
            margin: 20px;
        }
        .summary-card {
            padding: 20px;
            border-radius: 6px;
            text-align: center;
            color: white;
            font-weight: bold;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .critical { background: linear-gradient(135deg, #d13438, #a4262c); }
        .warning { background: linear-gradient(135deg, #ffaa44, #d18302); }
        .ok { background: linear-gradient(135deg, #107c10, #0e5f0e); }
        .finding {
            margin: 15px 20px;
            padding: 15px;
            border-radius: 6px;
            border-left: 5px solid;
            box-shadow: 0 1px 3px rgba(0,0,0,0.1);
        }
        .finding-critical { border-left-color: #d13438; background: #fef7f7; }
        .finding-warning { border-left-color: #ffaa44; background: #fff8f0; }
        .finding-ok { border-left-color: #107c10; background: #f8fff8; }
        .risk-badge {
            display: inline-block;
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 12px;
            font-weight: bold;
            margin-left: 10px;
        }
        .badge-critical { background: #d13438; color: white; }
        .badge-warning { background: #ffaa44; color: black; }
        .badge-ok { background: #107c10; color: white; }
        table { width: 100%; border-collapse: collapse; margin: 10px 0; }
        th, td { padding: 8px 12px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #f2f2f2; font-weight: bold; }
        .recommendation { 
            background: #fffacd; 
            padding: 10px; 
            margin-top: 10px;
            border-radius: 4px;
            border-left: 3px solid #ffd700;
        }
        .cve-alert {
            background: #ffebee;
            padding: 8px;
            margin: 5px 0;
            border-radius: 4px;
            border-left: 3px solid #f44336;
        }
        .timestamp { color: #666; font-style: italic; }
        .scan-info {
            background: #f8fdff;
            padding: 15px;
            margin: 10px 20px;
            border-radius: 6px;
            border-left: 4px solid #2196f3;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ $($Text.Title)</h1>
            <h2>$($Text.Server): $($ServerInfo.ComputerName)</h2>
            <div class="timestamp">$($Text.Generated): $Timestamp</div>
        </div>
        
        <div class="scan-info">
            <h3>$($Text.ScanInfo)</h3>
            <p><strong>$($Text.Scope):</strong> $ScanScope Scan | <strong>$($Text.NetworkServices):</strong> $(if($ScanNetworkServices){'$($Language)'}else{'Not Scanned'})</p>
            <p><strong>$($Text.AssessmentType):</strong> Local Comprehensive Security Audit</p>
        </div>
        
        <div class="server-info">
            <h3>$($Text.SystemInfo)</h3>
            <table>
                <tr><th>$($Text.ComputerName):</th><td>$($ServerInfo.ComputerName)</td></tr>
                <tr><th>$($Text.OperatingSystem):</th><td>$($ServerInfo.OSName)</td></tr>
                <tr><th>$($Text.OSVersion):</th><td>$($ServerInfo.OSVersion) (Build $($ServerInfo.BuildNumber))</td></tr>
                <tr><th>$($Text.Domain):</th><td>$($ServerInfo.Domain)</td></tr>
                <tr><th>$($Text.DomainRole):</th><td>$(switch($ServerInfo.DomainRole){0{'Standalone Workstation'}1{'Member Workstation'}2{'Standalone Server'}3{'Member Server'}4{'Backup Domain Controller'}5{'Primary Domain Controller'}})</td></tr>
                <tr><th>$($Text.Manufacturer):</th><td>$($ServerInfo.Manufacturer)</td></tr>
                <tr><th>$($Text.Model):</th><td>$($ServerInfo.Model)</td></tr>
                <tr><th>$($Text.Memory):</th><td>$($ServerInfo.TotalMemory)</td></tr>
                <tr><th>$($Text.Processors):</th><td>$($ServerInfo.Processors)</td></tr>
                <tr><th>$($Text.IPAddresses):</th><td>$($ServerInfo.IPAddresses)</td></tr>
                <tr><th>$($Text.DNSServers):</th><td>$($ServerInfo.DNSServers)</td></tr>
                <tr><th>$($Text.Timezone):</th><td>$($ServerInfo.Timezone)</td></tr>
                <tr><th>$($Text.LastBoot):</th><td>$($ServerInfo.LastBootTime)</td></tr>
                <tr><th>$($Text.RecentUpdates):</th><td>$($ServerInfo.LastUpdates)</td></tr>
            </table>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card critical">
                <div style="font-size: 24px;">$CriticalCount</div>
                <div>$($Text.CriticalFindings)</div>
            </div>
            <div class="summary-card warning">
                <div style="font-size: 24px;">$WarningCount</div>
                <div>$($Text.Warnings)</div>
            </div>
            <div class="summary-card ok">
                <div style="font-size: 24px;">$OKCount</div>
                <div>$($Text.SecureConfigurations)</div>
            </div>
        </div>
        
        <div style="margin: 20px;">
            <h3>$($Text.SecurityFindings)</h3>
"@

    # Add findings to report, sorted by risk level
    foreach ($Finding in $Findings | Sort-Object { 
        @{ "Critical" = 0; "Warning" = 1; "OK" = 2 }[$_.RiskLevel] 
    }) {
        # Get localized finding details
        $Title = if ($Finding.FormatArgs) { 
            $TextResources[$Language][$Finding.Title] -f $Finding.FormatArgs
        } else {
            $TextResources[$Language][$Finding.Title]
        }
        
        $Details = if ($Finding.FormatArgs) { 
            $TextResources[$Language][$Finding.Details] -f $Finding.FormatArgs
        } else {
            $TextResources[$Language][$Finding.Details]
        }
        
        $Recommendation = $TextResources[$Language][$Finding.Recommendation]
        
        $FindingClass = "finding-$($Finding.RiskLevel.ToLower())"
        $BadgeClass = "badge-$($Finding.RiskLevel.ToLower())"
        
        $HTML += @"
            <div class="finding $FindingClass">
                <h4>$Title <span class="risk-badge $BadgeClass">$($Finding.RiskLevel)</span></h4>
                <p><strong>$($Text.Status):</strong> $($Finding.Status)</p>
                <p><strong>$($Text.Details):</strong> $Details</p>
                $(if ($Finding.CVE) { "<div class='cve-alert'><strong>🔓 $($Text.CVEReferences):</strong> $($Finding.CVE)</div>" } )
                $(if ($Finding.Reference) { "<p><strong>$($Text.Reference):</strong> $($Finding.Reference)</p>" } )
                <div class="recommendation">
                    <strong>🔧 $($Text.Recommendation):</strong> $Recommendation
                </div>
            </div>
"@
    }

    # Determine overall security posture
    $OverallPosture = if ($CriticalCount -eq 0 -and $WarningCount -eq 0) { $Text.Excellent }
        elseif ($CriticalCount -eq 0 -and $WarningCount -gt 0) { $Text.Good }
        elseif ($CriticalCount -gt 0) { $Text.Poor }
        else { $Text.Unknown }
    
    $PriorityRecommendation = if ($CriticalCount -gt 0) { $Text.AddressCriticalAction }
        elseif ($WarningCount -gt 0) { $Text.ReviewWarningsAction }
        else { $Text.MaintainConfig }

    $HTML += @"
        </div>
        
        <div style="margin: 20px; padding: 15px; background: #f8fdff; border-radius: 6px;">
            <h3>$($Text.AssessmentSummary)</h3>
            <p><strong>$($Text.OverallSecurity):</strong> $OverallPosture</p>
            <p><strong>$($Text.TotalChecks):</strong> $($Findings.Count)</p>
            <p><strong>$($Text.CriticalFindings):</strong> $CriticalCount - <strong>$($Text.Warnings):</strong> $WarningCount - <strong>$($Text.SecureConfigurations):</strong> $OKCount</p>
            <p><strong>$($Text.RecommendationPriority):</strong> $PriorityRecommendation</p>
        </div>

        <div style="margin: 20px; padding: 15px; background: #f3e5f5; border-radius: 6px;">
            <h3>🔧 $($Text.NextSteps)</h3>
            <ul>
                $(if ($CriticalCount -gt 0) { "<li><strong>$($Text.ImmediateAction):</strong> $($Text.AddressCritical)</li>" } )
                $(if ($WarningCount -gt 0) { "<li>$($Text.ReviewWarnings)</li>" } )
                <li>$($Text.ImplementChanges)</li>
                <li>$($Text.TestConfigurations)</li>
                <li>$($Text.CISGuidance)</li>
                <li>$($Text.ScheduleAssessments)</li>
                <li>$($Text.AdditionalControls)</li>
            </ul>
        </div>

        <div style="text-align: center; padding: 20px; background: #f5f5f5; color: #666; font-size: 12px;">
            <p>$($Text.ReportFooter) | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>$($Text.ReportNote)</p>
        </div>
    </div>
</body>
</html>
"@

    # Write the HTML content to file
    $HTML | Out-File -FilePath $ReportFile -Encoding UTF8

    Write-SecurityLog "ReportGenerated" "SUCCESS" -FormatArgs @($ReportFile)
    
    return $ReportFile
}

# Main execution function
function Start-LocalSecurityAssessment {
    param(
        [string]$OutputPath,
        [switch]$OpenReport,
        [string]$ScanScope,
        [switch]$ScanNetworkServices,
        [string]$Language
    )
    
    # Initialize logging
    $Global:LogFile = Join-Path $OutputPath "LocalSecurityScan-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    
    Write-SecurityLog "StartingAssessment" "INFO"
    Write-SecurityLog "ScanScope" "INFO" -FormatArgs @($ScanScope)
    Write-SecurityLog "Computer" "INFO" -FormatArgs @($env:COMPUTERNAME)
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Collect system information
    Write-SecurityLog "CollectingSystemInfo" "INFO"
    $ServerInfo = Get-SystemInformation
    
    # Perform security assessments
    $AllFindings = @()
    
    Write-SecurityLog "PerformingSecurityAssessments" "INFO"
    
    # Core security checks (always performed)
    $AllFindings += Test-SMBConfig
    $AllFindings += Test-PowerShellSecurity
    $AllFindings += Test-NameResolution
    $AllFindings += Test-TLSConfig
    $AllFindings += Test-NTLMConfig
    $AllFindings += Test-WindowsServices
    $AllFindings += Test-WinRMConfig
    $AllFindings += Test-RDPConfig
    
    # Optional network services scan
    if ($ScanNetworkServices) {
        $AllFindings += Test-NetworkServices
    }
    
    # Flatten the findings array
    $FlatFindings = @()
    foreach ($FindingCategory in $AllFindings) {
        if ($FindingCategory -is [array]) {
            $FlatFindings += $FindingCategory
        } elseif ($FindingCategory -is [hashtable]) {
            $FlatFindings += $FindingCategory
        }
    }
    
    # Generate report
    $ReportPath = New-SecurityReport -ServerInfo $ServerInfo -Findings $FlatFindings -OutputPath $OutputPath -Language $Language
    
    # Open report if requested
    if ($OpenReport -and $ReportPath) {
        try {
            Start-Process $ReportPath
            Write-SecurityLog "OpeningReport" "INFO"
        } catch {
            Write-SecurityLog "OpenReportFailed" "WARNING" -FormatArgs @($_.Exception.Message)
        }
    }
    
    # Summary
    $CriticalCount = ($FlatFindings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $WarningCount = ($FlatFindings | Where-Object { $_.RiskLevel -eq "Warning" }).Count
    
    Write-SecurityLog "AssessmentCompleted" "SUCCESS"
    Write-SecurityLog "CriticalFindings" $(if ($CriticalCount -gt 0) { "CRITICAL" } else { "SUCCESS" }) -FormatArgs @($CriticalCount)
    Write-SecurityLog "WarningFindings" $(if ($WarningCount -gt 0) { "WARNING" } else { "SUCCESS" }) -FormatArgs @($WarningCount)
    Write-SecurityLog "TotalChecks" "INFO" -FormatArgs @($FlatFindings.Count)
    Write-SecurityLog "ReportLocation" "INFO" -FormatArgs @($ReportPath)
    Write-SecurityLog "LogFileLocation" "INFO" -FormatArgs @($Global:LogFile)
    
    return @{
        CriticalCount = $CriticalCount
        WarningCount = $WarningCount
        ReportPath = $ReportPath
        LogFile = $Global:LogFile
    }
}

# Language selection prompt if not specified
if (-not $PSBoundParameters.ContainsKey('Language')) {
    $choice = ""
    while ($choice -notin '1','2') {
        Write-Host "`nPlease select language / Veuillez choisir la langue:" -ForegroundColor Yellow
        Write-Host "1. English" -ForegroundColor Cyan
        Write-Host "2. Français" -ForegroundColor Cyan
        $choice = Read-Host "`nEnter choice / Entrez votre choix (1-2)"
    }
    $Language = if ($choice -eq '1') { "English" } else { "French" }
    Write-Host "`nSelected language / Langue sélectionnée: $Language" -ForegroundColor Green
}

# Script execution
try {
    # Start assessment
    $Result = Start-LocalSecurityAssessment -OutputPath $OutputPath -OpenReport:$OpenReport -ScanScope $ScanScope -ScanNetworkServices:$ScanNetworkServices -Language $Language
    
    if ($Result.CriticalCount -gt 0) {
        Write-SecurityLog "ImmediateActionRequired" "CRITICAL" -FormatArgs @($Result.CriticalCount)
        exit 1
    } elseif ($Result.WarningCount -gt 0) {
        Write-SecurityLog "ReviewRecommended" "WARNING" -FormatArgs @($Result.WarningCount)
        exit 0
    } else {
        Write-SecurityLog "NoCriticalIssues" "SUCCESS"
        exit 0
    }
    
} catch {
    Write-SecurityLog "FatalError" "ERROR" -FormatArgs @($_.Exception.Message)
    exit 1
}