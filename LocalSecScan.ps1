<#
.SYNOPSIS
    Comprehensive Local Security Assessment for Windows Servers
.DESCRIPTION
    Performs deep local security assessment to identify weak protocols and insecure configurations
    No remote access required - runs directly on the target server
.NOTES
    Author: EMMANUEL S. M. / Cybersecurity Specialist
    For any improvement or comment : semspprt=#@#=proton.me
    Version: 1.1 (2025-10-15) - Local Comprehensive Assessment
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
    [switch]$ScanNetworkServices
)

# Enhanced logging function
function Write-SecurityLog {
    param(
        [string]$Message, 
        [string]$Type = "INFO",
        [string]$Color = "White"
    )
    
    $Timestamp = Get-Date -Format "HH:mm:ss"
    $LogMessage = "[$Timestamp] [$Type] $Message"
    
    switch ($Type) {
        "SUCCESS" { $Color = "Green" }
        "WARNING" { $Color = "Yellow" }
        "ERROR" { $Color = "Red" }
        "CRITICAL" { $Color = "Red" }
        "INFO" { $Color = "Cyan" }
        "DETAIL" { $Color = "Gray" }
    }
    
    Write-Host $LogMessage -ForegroundColor $Color
    $LogMessage | Out-File -FilePath $Global:LogFile -Append -Encoding UTF8
}

# Get comprehensive system information
function Get-SystemInformation {
    Write-SecurityLog "Collecting system information..." "INFO"
    
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
        
        Write-SecurityLog "System information collected successfully" "SUCCESS"
        
    } catch {
        Write-SecurityLog "Failed to collect system information: $($_.Exception.Message)" "ERROR"
    }
    
    return $Info
}

# Check SMB configurations
function Test-SMBConfig {
    Write-SecurityLog "Checking SMB configurations..." "INFO"
    
    $Findings = @()
    
    # Check SMBv1
    try {
        $SMBv1 = Get-WindowsOptionalFeature -Online -FeatureName "SMB1Protocol" -ErrorAction Stop
        if ($SMBv1.State -eq "Enabled") {
            Write-SecurityLog "SMBv1 is ENABLED - Critical Risk!" "CRITICAL"
            $Findings += @{
                Title = "SMBv1 Protocol"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "SMBv1 is installed and enabled. Vulnerable to EternalBlue (MS17-010), SMB Relay, and other attacks."
                Recommendation = "Immediately disable SMBv1: Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart"
                CVE = "MS17-010, CVE-2017-0143-CVE-2017-0148"
                Reference = "https://support.microsoft.com/en-us/help/2696547"
            }
        } else {
            Write-SecurityLog "SMBv1 is disabled" "SUCCESS"
            $Findings += @{
                Title = "SMBv1 Protocol"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "SMBv1 is properly disabled."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "Could not determine SMBv1 status" "WARNING"
    }
    
    # Check SMB Signing
    try {
        $SMBSigning = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Services\LanManServer\Parameters" -Name "requiresecuritysignature" -ErrorAction SilentlyContinue
        if ($SMBSigning.requiresecuritysignature -ne 1) {
            Write-SecurityLog "SMB Signing not required" "WARNING"
            $Findings += @{
                Title = "SMB Signing Enforcement"
                Status = "Not Enforced"
                RiskLevel = "Warning"
                Details = "SMB signing is not required. This could allow SMB relay attacks."
                Recommendation = "Enable SMB signing via GPO: Computer Configuration > Policies > Windows Settings > Security Settings > Local Policies > Security Options > Microsoft network server: Digitally sign communications (always)"
            }
        } else {
            Write-SecurityLog "  SMB Signing is enforced" "SUCCESS"
            $Findings += @{
                Title = "SMB Signing Enforcement"
                Status = "Enforced"
                RiskLevel = "OK"
                Details = "SMB signing is properly configured."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "  Could not check SMB signing" "WARNING"
    }
    
    return $Findings
}

# Check PowerShell security
function Test-PowerShellSecurity {
    Write-SecurityLog "Checking PowerShell security..." "INFO"
    
    $Findings = @()
    
    # Check PowerShell v2
    try {
        $PSv2 = Get-WindowsOptionalFeature -Online -FeatureName "MicrosoftWindowsPowerShellV2" -ErrorAction Stop
        if ($PSv2.State -eq "Enabled") {
            Write-SecurityLog "PowerShell v2 is ENABLED - Critical Risk!" "CRITICAL"
            $Findings += @{
                Title = "PowerShell Version 2.0"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "PowerShell v2 lacks modern security features, script block logging, and AMSI integration."
                Recommendation = "Disable PowerShell v2: Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2 -NoRestart"
                Reference = "CIS Benchmark 18.9.84.1"
            }
        } else {
            Write-SecurityLog "  PowerShell v2 is disabled" "SUCCESS"
            $Findings += @{
                Title = "PowerShell Version 2.0"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "PowerShell v2 is properly disabled."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "Could not determine PowerShell v2 status" "WARNING"
    }
    
    # Check PowerShell Execution Policy
    try {
        $ExecutionPolicy = Get-ExecutionPolicy
        if ($ExecutionPolicy -eq "Unrestricted") {
            Write-SecurityLog "PowerShell Execution Policy is Unrestricted" "CRITICAL"
            $Findings += @{
                Title = "PowerShell Execution Policy"
                Status = "Unrestricted"
                RiskLevel = "Critical"
                Details = "PowerShell scripts can run without restrictions."
                Recommendation = "Set Execution Policy to RemoteSigned: Set-ExecutionPolicy RemoteSigned"
            }
        } elseif ($ExecutionPolicy -eq "Bypass") {
            Write-SecurityLog "PowerShell Execution Policy is Bypass" "CRITICAL"
            $Findings += @{
                Title = "PowerShell Execution Policy"
                Status = "Bypass"
                RiskLevel = "Critical"
                Details = "All PowerShell restrictions are bypassed."
                Recommendation = "Set Execution Policy to RemoteSigned: Set-ExecutionPolicy RemoteSigned"
            }
        } else {
            Write-SecurityLog "PowerShell Execution Policy is $ExecutionPolicy" "SUCCESS"
            $Findings += @{
                Title = "PowerShell Execution Policy"
                Status = $ExecutionPolicy
                RiskLevel = "OK"
                Details = "PowerShell execution policy is appropriately configured."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "  Could not check PowerShell Execution Policy" "WARNING"
    }
    
    # Check PowerShell Transcription/Logging
    try {
        $Transcript = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\Transcription" -Name "EnableTranscripting" -ErrorAction SilentlyContinue
        if ($Transcript.EnableTranscripting -ne 1) {
            Write-SecurityLog "PowerShell transcription not enabled" "WARNING"
            $Findings += @{
                Title = "PowerShell Transcription"
                Status = "Disabled"
                RiskLevel = "Warning"
                Details = "PowerShell command transcription is not enabled for security monitoring."
                Recommendation = "Enable PowerShell transcription via GPO for security auditing."
            }
        } else {
            Write-SecurityLog "  PowerShell transcription is enabled" "SUCCESS"
        }
    } catch {
        # Transcription not configured is common
    }
    
    return $Findings
}

# Check name resolution protocols
function Test-NameResolution {
    Write-SecurityLog "Checking name resolution protocols..." "INFO"
    
    $Findings = @()
    
    # Check LLMNR
    try {
        $LLMNR = Get-ItemProperty "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -ErrorAction SilentlyContinue
        if ($null -eq $LLMNR -or $LLMNR.EnableMulticast -ne 0) {
            Write-SecurityLog "LLMNR is likely ENABLED" "WARNING"
            $Findings += @{
                Title = "LLMNR (Link-Local Multicast Name Resolution)"
                Status = "Likely Enabled"
                RiskLevel = "Warning"
                Details = "LLMNR can be abused for NTLM relay attacks and spoofing."
                Recommendation = "Disable LLMNR via GPO: Computer Configuration > Administrative Templates > Network > DNS Client > Turn off multicast name resolution"
                Reference = "CIS Benchmark 18.4.4"
            }
        } else {
            Write-SecurityLog "LLMNR is disabled via policy" "SUCCESS"
            $Findings += @{
                Title = "LLMNR (Link-Local Multicast Name Resolution)"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "LLMNR is properly disabled via registry policy."
                Recommendation = "Maintain current policy."
            }
        }
    } catch {
        Write-SecurityLog "Could not determine LLMNR status" "WARNING"
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
            Write-SecurityLog "NetBIOS enabled on $($EnabledAdapters.Count) adapter(s)" "WARNING"
            $Findings += @{
                Title = "NetBIOS over TCP/IP"
                Status = "Enabled"
                RiskLevel = "Warning"
                Details = "NetBIOS enabled on adapters: $($EnabledAdapters -join ', '). Vulnerable to name resolution poisoning."
                Recommendation = "Disable NetBIOS on all network adapters in network adapter properties."
                Reference = "CIS Benchmark 18.4.7"
            }
        } else {
            Write-SecurityLog "NetBIOS is disabled on all adapters" "SUCCESS"
            $Findings += @{
                Title = "NetBIOS over TCP/IP"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "NetBIOS over TCP/IP is disabled on all network adapters."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "Could not check NetBIOS settings" "WARNING"
    }
    
    return $Findings
}

# Check TLS/SSL configurations
function Test-TLSConfig {
    Write-SecurityLog "Checking TLS/SSL configurations..." "INFO"
    
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
                Write-SecurityLog "$($TLS.Version) is ENABLED" "CRITICAL"
                $RiskLevel = if ($TLS.Version -like "SSL*" -or $TLS.Version -eq "TLS 1.0") { "Critical" } else { "Warning" }
                
                $Findings += @{
                    Title = "$($TLS.Version) Protocol"
                    Status = "Enabled"
                    RiskLevel = $RiskLevel
                    Details = "$($TLS.Version) has known vulnerabilities and should be disabled."
                    Recommendation = "Disable $($TLS.Version) via Group Policy: Computer Configuration > Administrative Templates > Network > SSL Configuration Settings"
                    CVE = if ($TLS.Version -eq "SSL 3.0") { "POODLE" } elseif ($TLS.Version -eq "TLS 1.0") { "BEAST" } else { "Various" }
                }
            } else {
                Write-SecurityLog "$($TLS.Version) is disabled" "SUCCESS"
                $Findings += @{
                    Title = "$($TLS.Version) Protocol"
                    Status = "Disabled"
                    RiskLevel = "OK"
                    Details = "$($TLS.Version) is properly disabled."
                    Recommendation = "Maintain current configuration."
                }
            }
        } catch {
            Write-SecurityLog "Could not check $($TLS.Version) status" "WARNING"
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
            Write-SecurityLog "Weak cipher suites enabled: $($EnabledCiphers -join ', ')" "WARNING"
            $Findings += @{
                Title = "Weak Cipher Suites"
                Status = "Enabled"
                RiskLevel = "Warning"
                Details = "Weak cipher suites detected: $($EnabledCiphers -join ', '). These are cryptographically weak."
                Recommendation = "Disable weak cipher suites via Group Policy and prioritize AES-GCM suites."
            }
        } else {
            Write-SecurityLog "No weak cipher suites detected" "SUCCESS"
        }
    } catch {
        Write-SecurityLog "Could not check cipher suites" "WARNING"
    }
    
    return $Findings
}

# Check NTLM configurations
function Test-NTLMConfig {
    Write-SecurityLog "Checking NTLM configurations..." "INFO"
    
    $Findings = @()
    
    # Check NTLM restrictions
    try {
        $NTLMRestrictions = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" -Name "RestrictSendingNTLMTraffic" -ErrorAction SilentlyContinue
        
        if ($NTLMRestrictions.RestrictSendingNTLMTraffic -eq 2) {
            Write-SecurityLog "NTLM restrictions are configured" "SUCCESS"
            $Findings += @{
                Title = "NTLM Audit/Restrictions"
                Status = "Restricted"
                RiskLevel = "OK"
                Details = "NTLM traffic is being audited and restricted."
                Recommendation = "Consider migrating to Kerberos authentication where possible."
            }
        } else {
            Write-SecurityLog "NTLM restrictions not configured" "WARNING"
            $Findings += @{
                Title = "NTLM Audit/Restrictions"
                Status = "Unrestricted"
                RiskLevel = "Warning"
                Details = "NTLM relay attacks are possible without restrictions."
                Recommendation = "Configure NTLM restrictions via Group Policy: Computer Configuration > Windows Settings > Security Settings > Local Policies > Security Options"
                Reference = "CIS Benchmark 2.3.1.1-2.3.1.6"
            }
        }
    } catch {
        Write-SecurityLog "Could not determine NTLM restriction settings" "WARNING"
    }
    
    # Check LM Compatibility Level
    try {
        $LMLevel = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name "LmCompatibilityLevel" -ErrorAction SilentlyContinue
        
        if ($LMLevel.LmCompatibilityLevel -lt 5) {
            Write-SecurityLog "LM Compatibility Level allows weak authentication" "WARNING"
            $Findings += @{
                Title = "LAN Manager Authentication Level"
                Status = "Weak"
                RiskLevel = "Warning"
                Details = "LM and NTLMv1 authentication may be allowed."
                Recommendation = "Set LmCompatibilityLevel to 5 (Send NTLMv2 response only, refuse LM & NTLM)"
            }
        } else {
            Write-SecurityLog "LM Compatibility Level is secure" "SUCCESS"
            $Findings += @{
                Title = "LAN Manager Authentication Level"
                Status = "Secure"
                RiskLevel = "OK"
                Details = "Only NTLMv2 and Kerberos authentication are allowed."
                Recommendation = "Maintain current configuration."
            }
        }
    } catch {
        Write-SecurityLog "Could not check LM Compatibility Level" "WARNING"
    }
    
    return $Findings
}

# Check Windows services and features
function Test-WindowsServices {
    Write-SecurityLog "Checking Windows services and features..." "INFO"
    
    $Findings = @()
    
    # Check Telnet Client
    try {
        $Telnet = Get-WindowsCapability -Online -Name "TelnetClient*" -ErrorAction SilentlyContinue
        if ($Telnet.State -eq "Installed") {
            Write-SecurityLog "Telnet Client is INSTALLED" "CRITICAL"
            $Findings += @{
                Title = "Telnet Client"
                Status = "Installed"
                RiskLevel = "Critical"
                Details = "Telnet transmits all credentials and data in cleartext."
                Recommendation = "Uninstall immediately: Remove-WindowsCapability -Online -Name TelnetClient~~~~0.0.1.0"
            }
        } else {
            Write-SecurityLog "Telnet Client is not installed" "SUCCESS"
            $Findings += @{
                Title = "Telnet Client"
                Status = "Not Installed"
                RiskLevel = "OK"
                Details = "Telnet client is not present on the system."
                Recommendation = "Maintain current state."
            }
        }
    } catch {
        Write-SecurityLog "Could not check Telnet Client" "WARNING"
    }
    
    # Check FTP Server
    try {
        $FTP = Get-WindowsOptionalFeature -Online -FeatureName "IIS-FTPServer" -ErrorAction SilentlyContinue
        if ($FTP.State -eq "Enabled") {
            Write-SecurityLog "FTP Server is ENABLED" "CRITICAL"
            $Findings += @{
                Title = "FTP Server"
                Status = "Enabled"
                RiskLevel = "Critical"
                Details = "FTP transmits credentials and data in cleartext."
                Recommendation = "Disable FTP server if not required: Disable-WindowsOptionalFeature -Online -FeatureName IIS-FTPServer"
            }
        } else {
            Write-SecurityLog "FTP Server is disabled" "SUCCESS"
        }
    } catch {
        # FTP not installed is normal
    }
    
    # Check SNMP Service
    try {
        $SNMP = Get-Service -Name "SNMP" -ErrorAction SilentlyContinue
        if ($SNMP.Status -eq "Running") {
            Write-SecurityLog "  SNMP Service is running" "WARNING"
            $Findings += @{
                Title = "SNMP Service"
                Status = "Running"
                RiskLevel = "Warning"
                Details = "SNMP may use weak community strings and transmit data in cleartext."
                Recommendation = "Disable SNMP if not required, or secure with strong community strings and ACLs."
            }
        }
    } catch {
        # SNMP not installed is normal
    }
    
    # Check WebClient Service (WebDAV)
    try {
        $WebClient = Get-Service -Name "WebClient" -ErrorAction SilentlyContinue
        if ($WebClient.Status -eq "Running") {
            Write-SecurityLog "WebClient service is running" "WARNING"
            $Findings += @{
                Title = "WebClient Service (WebDAV)"
                Status = "Running"
                RiskLevel = "Warning"
                Details = "WebClient service can be abused for authentication coercion attacks."
                Recommendation = "Disable WebClient service if WebDAV is not required: Set-Service WebClient -StartupType Disabled"
            }
        }
    } catch {
        # WebClient not available is normal
    }
    
    return $Findings
}

# Check WinRM configuration
function Test-WinRMConfig {
    Write-SecurityLog "Checking WinRM configuration..." "INFO"
    
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
                Write-SecurityLog "WinRM HTTP listeners active" "CRITICAL"
                $Findings += @{
                    Title = "WinRM HTTP Listeners"
                    Status = "Active"
                    RiskLevel = "Critical"
                    Details = "WinRM is configured with HTTP listeners. Credentials and data are transmitted in cleartext."
                    Recommendation = "Remove HTTP listeners and configure WinRM for HTTPS only: winrm delete winrm/config/listener?Address=*+Transport=HTTP"
                }
            } else {
                Write-SecurityLog "WinRM configured for HTTPS only" "SUCCESS"
                $Findings += @{
                    Title = "WinRM Configuration"
                    Status = "Secure"
                    RiskLevel = "OK"
                    Details = "WinRM is properly configured without cleartext HTTP listeners."
                    Recommendation = "Maintain current configuration."
                }
            }
        } else {
            Write-SecurityLog "WinRM service is not running" "SUCCESS"
            $Findings += @{
                Title = "WinRM Service"
                Status = "Stopped"
                RiskLevel = "OK"
                Details = "WinRM service is not active."
                Recommendation = "Maintain current state unless remote management is required."
            }
        }
    } catch {
        Write-SecurityLog "Could not check WinRM configuration" "WARNING"
    }
    
    return $Findings
}

# Check RDP configuration
function Test-RDPConfig {
    Write-SecurityLog "Checking RDP configuration..." "INFO"
    
    $Findings = @()
    
    try {
        $RDP = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server" -Name "fDenyTSConnections" -ErrorAction SilentlyContinue
        
        if ($RDP.fDenyTSConnections -eq 0) {
            Write-SecurityLog "RDP is enabled" "WARNING"
            
            # Check RDP Security Layer
            $SecurityLayer = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "SecurityLayer" -ErrorAction SilentlyContinue
            $UserAuthentication = Get-ItemProperty "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp" -Name "UserAuthentication" -ErrorAction SilentlyContinue
            
            if ($SecurityLayer.SecurityLayer -ne 2 -or $UserAuthentication.UserAuthentication -ne 1) {
                Write-SecurityLog "RDP security settings are weak" "WARNING"
                $Findings += @{
                    Title = "Remote Desktop Protocol (RDP)"
                    Status = "Enabled with weak security"
                    RiskLevel = "Warning"
                    Details = "RDP is enabled but may not require Network Level Authentication (NLA)."
                    Recommendation = "Enable NLA: Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' -Name 'UserAuthentication' -Value 1"
                }
            } else {
                Write-SecurityLog "RDP is enabled with NLA" "SUCCESS"
                $Findings += @{
                    Title = "Remote Desktop Protocol (RDP)"
                    Status = "Enabled with NLA"
                    RiskLevel = "OK"
                    Details = "RDP is properly configured with Network Level Authentication."
                    Recommendation = "Maintain current configuration."
                }
            }
        } else {
            Write-SecurityLog "RDP is disabled" "SUCCESS"
            $Findings += @{
                Title = "Remote Desktop Protocol (RDP)"
                Status = "Disabled"
                RiskLevel = "OK"
                Details = "RDP connections are disabled."
                Recommendation = "Maintain current state unless remote access is required."
            }
        }
    } catch {
        Write-SecurityLog "Could not check RDP configuration" "WARNING"
    }
    
    return $Findings
}

# Check network services (if requested)
function Test-NetworkServices {
    Write-SecurityLog "Scanning network services..." "INFO"
    
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
            Write-SecurityLog "Potentially risky network services detected" "WARNING"
            $Findings += @{
                Title = "Network Services"
                Status = "Risky Services Detected"
                RiskLevel = "Warning"
                Details = "The following services are listening: $($OpenPorts -join '; ')"
                Recommendation = "Review and disable unnecessary services. Ensure cleartext protocols are replaced with encrypted alternatives."
            }
        } else {
            Write-SecurityLog "No obviously risky network services detected" "SUCCESS"
        }
    } catch {
        Write-SecurityLog "Could not scan network services" "WARNING"
    }
    
    return $Findings
}

# Generate HTML Report (same as previous version, but updated for local use)
function New-SecurityReport {
    param(
        [hashtable]$ServerInfo,
        [array]$Findings,
        [string]$OutputPath
    )
    
    Write-SecurityLog "Generating comprehensive HTML report..." "INFO"
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $ReportFile = Join-Path $OutputPath "$($ServerInfo.ComputerName)-Security-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').html"
    
    # Count findings by risk level
    $CriticalCount = ($Findings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $WarningCount = ($Findings | Where-Object { $_.RiskLevel -eq "Warning" }).Count
    $OKCount = ($Findings | Where-Object { $_.RiskLevel -eq "OK" }).Count
    
    # HTML report generation code 


        $HTML = @"
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Local Security Assessment Report - $($ServerInfo.ComputerName)</title>
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
            <h1>🛡️ Local Security Assessment Report</h1>
            <h2>Server: $($ServerInfo.ComputerName)</h2>
            <div class="timestamp">Generated: $Timestamp</div>
        </div>
        
        <div class="scan-info">
            <h3>Scan Information</h3>
            <p><strong>Scope:</strong> $ScanScope Scan | <strong>Network Services:</strong> $(if($ScanNetworkServices){'Scanned'}else{'Not Scanned'})</p>
            <p><strong>Assessment Type:</strong> Local Comprehensive Security Audit</p>
        </div>
        
        <div class="server-info">
            <h3>System Information</h3>
            <table>
                <tr><th>Computer Name:</th><td>$($ServerInfo.ComputerName)</td></tr>
                <tr><th>Operating System:</th><td>$($ServerInfo.OSName)</td></tr>
                <tr><th>OS Version:</th><td>$($ServerInfo.OSVersion) (Build $($ServerInfo.BuildNumber))</td></tr>
                <tr><th>Domain:</th><td>$($ServerInfo.Domain)</td></tr>
                <tr><th>Domain Role:</th><td>$(switch($ServerInfo.DomainRole){0{'Standalone Workstation'}1{'Member Workstation'}2{'Standalone Server'}3{'Member Server'}4{'Backup Domain Controller'}5{'Primary Domain Controller'}})</td></tr>
                <tr><th>Manufacturer:</th><td>$($ServerInfo.Manufacturer)</td></tr>
                <tr><th>Model:</th><td>$($ServerInfo.Model)</td></tr>
                <tr><th>Memory:</th><td>$($ServerInfo.TotalMemory)</td></tr>
                <tr><th>Processors:</th><td>$($ServerInfo.Processors)</td></tr>
                <tr><th>IP Addresses:</th><td>$($ServerInfo.IPAddresses)</td></tr>
                <tr><th>DNS Servers:</th><td>$($ServerInfo.DNSServers)</td></tr>
                <tr><th>Timezone:</th><td>$($ServerInfo.Timezone)</td></tr>
                <tr><th>Last Boot:</th><td>$($ServerInfo.LastBootTime)</td></tr>
                <tr><th>Recent Updates:</th><td>$($ServerInfo.LastUpdates)</td></tr>
            </table>
        </div>
        
        <div class="summary-cards">
            <div class="summary-card critical">
                <div style="font-size: 24px;">$CriticalCount</div>
                <div>Critical Findings</div>
            </div>
            <div class="summary-card warning">
                <div style="font-size: 24px;">$WarningCount</div>
                <div>Warnings</div>
            </div>
            <div class="summary-card ok">
                <div style="font-size: 24px;">$OKCount</div>
                <div>Secure Configurations</div>
            </div>
        </div>
        
        <div style="margin: 20px;">
            <h3>Security Findings</h3>
"@

    # Add findings to report, sorted by risk level
    foreach ($Finding in $FlatFindings | Sort-Object { 
        @{ "Critical" = 0; "Warning" = 1; "OK" = 2 }[$_.RiskLevel] 
    }) {
        $FindingClass = "finding-$($Finding.RiskLevel.ToLower())"
        $BadgeClass = "badge-$($Finding.RiskLevel.ToLower())"
        
        $HTML += @"
            <div class="finding $FindingClass">
                <h4>$($Finding.Title) <span class="risk-badge $BadgeClass">$($Finding.RiskLevel)</span></h4>
                <p><strong>Status:</strong> $($Finding.Status)</p>
                <p><strong>Details:</strong> $($Finding.Details)</p>
                $(if ($Finding.CVE) { "<div class='cve-alert'><strong>🔓 CVE References:</strong> $($Finding.CVE)</div>" } )
                $(if ($Finding.Reference) { "<p><strong>Reference:</strong> $($Finding.Reference)</p>" } )
                <div class="recommendation">
                    <strong>🔧 Recommendation:</strong> $($Finding.Recommendation)
                </div>
            </div>
"@
    }

    $HTML += @"
        </div>
        
        <div style="margin: 20px; padding: 15px; background: #f8fdff; border-radius: 6px;">
            <h3>Assessment Summary</h3>
            <p><strong>Overall Security Posture:</strong> 
                $(if ($CriticalCount -eq 0 -and $WarningCount -eq 0) {'Excellent - No issues detected'} 
                elseif ($CriticalCount -eq 0 -and $WarningCount -gt 0) {'Good - Review warnings'} 
                elseif ($CriticalCount -gt 0) {'Poor - Immediate action required'} 
                else {'Unknown'})
            </p>
            <p><strong>Total Security Checks:</strong> $($FlatFindings.Count)</p>
            <p><strong>Critical Findings:</strong> $CriticalCount - <strong>Warnings:</strong> $WarningCount - <strong>Secure:</strong> $OKCount</p>
            <p><strong>Recommendation Priority:</strong> 
                $(if ($CriticalCount -gt 0) {'Address critical findings immediately'} 
                elseif ($WarningCount -gt 0) {'Review and address warnings'} 
                else {'Maintain current security configuration'})
            </p>
        </div>

        <div style="margin: 20px; padding: 15px; background: #f3e5f5; border-radius: 6px;">
            <h3>🔧 Next Steps</h3>
            <ul>
                $(if ($CriticalCount -gt 0) { '<li><strong>IMMEDIATE ACTION:</strong> Address all critical findings first</li>' } )
                $(if ($WarningCount -gt 0) { '<li>Review and plan remediation for warning findings</li>' } )
                <li>Implement changes in a controlled manner</li>
                <li>Test configurations in non-production environment first</li>
                <li>Refer to CIS Benchmarks for Windows Server for comprehensive guidance</li>
                <li>Schedule regular security assessments</li>
                <li>Consider implementing additional security controls based on risk assessment</li>
            </ul>
        </div>

        <div style="text-align: center; padding: 20px; background: #f5f5f5; color: #666; font-size: 12px;">
            <p>Generated by Local Security Assessment Tool v4.0 | $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')</p>
            <p>This report provides security recommendations based on industry best practices. Always test changes in a non-production environment.</p>
        </div>
    </div>
</body>
</html>
"@

    # Write the HTML content to file
    $HTML | Out-File -FilePath $ReportFile -Encoding UTF8

    Write-SecurityLog "Report generated: $ReportFile" "SUCCESS"

    
    return $ReportFile
}

# Main execution function
function Start-LocalSecurityAssessment {
    param(
        [string]$OutputPath,
        [switch]$OpenReport,
        [string]$ScanScope,
        [switch]$ScanNetworkServices
    )
    
    # Initialize logging
    $Global:LogFile = Join-Path $OutputPath "LocalSecurityScan-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
    
    Write-SecurityLog "Starting Comprehensive Local Security Assessment" "INFO"
    Write-SecurityLog "==============================================" "INFO"
    Write-SecurityLog "Scan Scope: $ScanScope" "INFO"
    Write-SecurityLog "Computer: $env:COMPUTERNAME" "INFO"
    
    # Create output directory
    if (!(Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Collect system information
    $ServerInfo = Get-SystemInformation
    
    # Perform security assessments
    $AllFindings = @()
    
    Write-SecurityLog "Performing comprehensive security assessments..." "INFO"
    
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
    $ReportPath = New-SecurityReport -ServerInfo $ServerInfo -Findings $FlatFindings -OutputPath $OutputPath
    
    # Open report if requested
    if ($OpenReport -and $ReportPath) {
        try {
            Start-Process $ReportPath
            Write-SecurityLog "Opening report in default browser..." "INFO"
        } catch {
            Write-SecurityLog "Could not open report automatically: $($_.Exception.Message)" "WARNING"
        }
    }
    
    # Summary
    $CriticalCount = ($FlatFindings | Where-Object { $_.RiskLevel -eq "Critical" }).Count
    $WarningCount = ($FlatFindings | Where-Object { $_.RiskLevel -eq "Warning" }).Count
    
    Write-SecurityLog "Assessment completed!" "SUCCESS"
    Write-SecurityLog "Critical findings: $CriticalCount" $(if ($CriticalCount -gt 0) { "CRITICAL" } else { "SUCCESS" })
    Write-SecurityLog "Warning findings: $WarningCount" $(if ($WarningCount -gt 0) { "WARNING" } else { "SUCCESS" })
    Write-SecurityLog "Total checks performed: $($FlatFindings.Count)" "INFO"
    Write-SecurityLog "Report location: $ReportPath" "INFO"
    Write-SecurityLog "Log file: $Global:LogFile" "INFO"
    
    return @{
        CriticalCount = $CriticalCount
        WarningCount = $WarningCount
        ReportPath = $ReportPath
        LogFile = $Global:LogFile
    }
}

# Script execution
try {
    # Start assessment
    $Result = Start-LocalSecurityAssessment -OutputPath $OutputPath -OpenReport:$OpenReport -ScanScope $ScanScope -ScanNetworkServices:$ScanNetworkServices
    
    if ($Result.CriticalCount -gt 0) {
        Write-SecurityLog "IMPORTANT: $($Result.CriticalCount) critical findings require immediate attention!" "CRITICAL"
        exit 1
    } elseif ($Result.WarningCount -gt 0) {
        Write-SecurityLog "Review recommended: $($Result.WarningCount) warnings should be addressed." "WARNING"
        exit 0
    } else {
        Write-SecurityLog "No critical security issues detected. System appears secure." "SUCCESS"
        exit 0
    }
    
} catch {
    Write-SecurityLog "Fatal error: $($_.Exception.Message)" "ERROR"
    exit 1
}