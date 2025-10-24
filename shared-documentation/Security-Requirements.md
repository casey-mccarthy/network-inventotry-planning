# Security Requirements for Inventory Agent Deployment

## Document Information
- **Version**: 1.0.0
- **Last Updated**: 2024-10-24
- **Audience**: Security Team, IT Operations, System Administrators

---

## Executive Summary

This document outlines the security controls, requirements, and configurations necessary for deploying the Inventory Agent in a restrictive enterprise environment. The agent has been designed to operate within strict security boundaries while maintaining functionality.

**Critical Success Factors:**
- All PowerShell scripts MUST be digitally signed
- Application control policies (AppLocker/WDAC) MUST be configured
- Antivirus/EDR exclusions MUST be coordinated with security team
- Network firewall rules MUST be documented and approved

---

## Table of Contents

1. [Code Signing Requirements](#1-code-signing-requirements)
2. [Application Control Policies](#2-application-control-policies)
3. [PowerShell Security](#3-powershell-security)
4. [WMI/CIM Permissions](#4-wmicim-permissions)
5. [Event Log Access](#5-event-log-access)
6. [Network Security](#6-network-security)
7. [Certificate Management](#7-certificate-management)
8. [Antivirus/EDR Configuration](#8-antiviredr-configuration)
9. [File System Permissions](#9-file-system-permissions)
10. [Scheduled Task Security](#10-scheduled-task-security)
11. [Compliance and Audit](#11-compliance-and-audit)

---

## 1. Code Signing Requirements

### 1.1 Overview
All PowerShell scripts and compiled executables MUST be digitally signed with the organization's code signing certificate to prevent tampering and satisfy application control policies.

### 1.2 Certificate Requirements

**Certificate Type**: Code Signing Certificate
**Key Requirements**:
- Key Algorithm: RSA
- Minimum Key Size: 2048 bits (4096 bits recommended)
- Hash Algorithm: SHA256 or higher
- Enhanced Key Usage (EKU): Code Signing (1.3.6.1.5.5.7.3.3)
- Certificate Authority: Enterprise CA or trusted public CA

**Certificate Subject**:
```
CN=YourCompany Code Signing Certificate
O=YourCompany
L=YourCity
S=YourState
C=US
```

### 1.3 Signing Procedure

**For PowerShell Scripts**:
```powershell
# Sign a single script
$Cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath ".\Collect-Inventory.ps1" -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"

# Sign all scripts in directory
Get-ChildItem -Path "C:\InventoryAgent\Source" -Filter "*.ps1" -Recurse | ForEach-Object {
    Set-AuthenticodeSignature -FilePath $_.FullName -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"
}
```

**For Compiled Executables (.exe, .dll)**:
```cmd
signtool sign /sha1 CERT_THUMBPRINT /t http://timestamp.digicert.com /fd SHA256 /v "InventoryAgent.exe"
```

### 1.4 Verification

```powershell
# Verify script signature
Get-AuthenticodeSignature -FilePath ".\Collect-Inventory.ps1"

# Expected output:
# Status: Valid
# SignerCertificate: CN=YourCompany Code Signing Certificate
```

### 1.5 Deployment Checklist

- [ ] Code signing certificate obtained and installed
- [ ] Certificate deployed to build/deployment servers
- [ ] All PowerShell scripts signed
- [ ] All executables and DLLs signed
- [ ] Signatures verified before deployment
- [ ] Certificate renewal process documented (recommend 1 year before expiration)

---

## 2. Application Control Policies

### 2.1 AppLocker Configuration

AppLocker is the standard application control mechanism for Windows 7-11 Enterprise editions.

#### 2.1.1 Required Rules

**Script Rules** (for PowerShell solution):

1. **Publisher Rule** (Preferred - Most Secure):
   - Rule Type: Publisher
   - Publisher: O=YourCompany, L=YourCity, S=YourState, C=US
   - Product: *
   - File: *.ps1
   - Version: Any
   - Action: Allow
   - Applied to: Everyone

2. **Path Rule** (Fallback - Less Secure):
   - Rule Type: Path
   - Path: `C:\ProgramData\InventoryAgent\*.ps1`
   - Action: Allow
   - Applied to: Everyone
   - **Warning**: Path rules can be bypassed if users can write to the path

**Executable Rules** (for compiled .NET solution):

1. **Publisher Rule**:
   - Publisher: O=YourCompany, L=YourCity, S=YourState, C=US
   - Product: Inventory Agent
   - File: InventoryAgent.exe
   - Version: 1.0.0.0 and above
   - Action: Allow

#### 2.1.2 Deployment via GPO

**Group Policy Path**:
```
Computer Configuration > Policies > Windows Settings > Security Settings > Application Control Policies > AppLocker
```

**Steps**:
1. Import `AppLocker-Rules.xml` (provided in security-templates/)
2. Configure rule enforcement:
   - Executable rules: Enforced
   - Script rules: Enforced
   - Windows Installer rules: Enforced
   - DLL rules: Not configured (unless required)
3. Set AppLocker service to start automatically:
   ```
   Computer Configuration > Preferences > Control Panel Settings > Services
   Service: Application Identity (AppIDSvc)
   Startup: Automatic
   ```

#### 2.1.3 Testing Procedure

1. **Enable Audit Mode First**:
   ```powershell
   Set-AppLockerPolicy -XMLPolicy "AppLocker-Rules.xml" -Merge
   # Rules start in "Audit Only" mode
   ```

2. **Monitor Events**:
   - Event Viewer → Applications and Services Logs → Microsoft → Windows → AppLocker
   - Event ID 8002: File would have been blocked (in Audit mode)
   - Event ID 8004: File was allowed

3. **Analyze for 2-4 Weeks**:
   ```powershell
   # Get blocked events
   Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" |
       Where-Object {$_.Id -eq 8002} |
       Format-Table TimeCreated, Message -AutoSize
   ```

4. **Switch to Enforced Mode** (after validation):
   ```powershell
   # Update XML enforcement mode from "AuditOnly" to "Enabled"
   Set-AppLockerPolicy -XMLPolicy "AppLocker-Rules-Enforced.xml" -Merge
   ```

### 2.2 Windows Defender Application Control (WDAC)

WDAC is the modern, more secure application control for Windows 10 1903+ and Windows 11.

#### 2.2.1 Policy Creation

Use the provided `Create-WDACPolicy.ps1` script:

```powershell
.\Create-WDACPolicy.ps1 -PolicyName "Inventory Agent" `
    -EnforceMode Audit `
    -IncludeSignedScripts `
    -IncludeCompiledAgent `
    -CodeSigningCertThumbprint "YOUR_CERT_THUMBPRINT"
```

#### 2.2.2 Policy Deployment

1. **Convert to Binary**:
   ```powershell
   ConvertFrom-CIPolicy -XmlFilePath "InventoryAgent-WDAC-Policy.xml" -BinaryFilePath "InventoryAgent.cip"
   ```

2. **Deploy via Group Policy**:
   - Copy .cip file to: `\\domain\SYSVOL\domain\Policies\{GPO-GUID}\Machine\Microsoft\Windows\CodeIntegrity\`
   - GPO Setting: `Computer Configuration > Administrative Templates > System > Device Guard > Deploy Code Integrity Policy`
   - Value: Path to .cip file

3. **Verify Deployment**:
   ```powershell
   Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CIPolicyInfo
   ```

#### 2.2.3 Monitoring

**Event Viewer Logs**:
- Location: `Applications and Services > Microsoft > Windows > CodeIntegrity > Operational`
- Event ID 3076: File would be blocked (Audit mode) - **Action Required**
- Event ID 3077: File allowed
- Event ID 3089: Policy loaded successfully

**PowerShell Monitoring**:
```powershell
# Get recent Code Integrity events
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 100 |
    Where-Object {$_.Id -in @(3076,3077,3089)} |
    Format-Table TimeCreated, Id, Message -Wrap
```

### 2.3 Enforcement Recommendations

| Environment | AppLocker | WDAC | Recommendation |
|-------------|-----------|------|----------------|
| **Standard Corporate** | Recommended | Optional | AppLocker with Publisher rules |
| **High Security** | Recommended | Recommended | Both (WDAC for stronger protection) |
| **Legacy (Windows 7)** | Recommended | Not Available | AppLocker only |
| **Windows 11** | Optional | Recommended | WDAC with Hardware-based Security |

---

## 3. PowerShell Security

### 3.1 Execution Policy

**Recommended Setting**: `RemoteSigned` or `AllSigned`

**Configuration via GPO**:
```
Computer Configuration > Policies > Administrative Templates > Windows Components > Windows PowerShell
Setting: "Turn on Script Execution"
Value: "Allow only signed scripts" (RemoteSigned)
```

**Verification**:
```powershell
Get-ExecutionPolicy -List
```

**Do NOT use `Bypass` or `Unrestricted` in production** except for specific installation scenarios with signed scripts.

### 3.2 Constrained Language Mode

**Impact**: The inventory agent is fully compatible with Constrained Language Mode.

**What's Disabled in Constrained Mode**:
- .NET type acceleration (`[System.Text.Encoding]::UTF8`)
- Add-Type cmdlet
- COM object creation
- Certain .NET method calls

**Agent Adaptations**:
- Compression disabled automatically in Constrained Mode
- Uses built-in cmdlets instead of .NET classes
- Hash calculation uses `Get-FileHash` instead of .NET crypto classes

**Check Current Mode**:
```powershell
$ExecutionContext.SessionState.LanguageMode
```

**Enable Constrained Mode (if required)**:
```powershell
# Via AppLocker - when AppLocker is enabled, unsigned scripts run in Constrained mode
# Or via environment variable:
$env:__PSLockdownPolicy = 4
```

### 3.3 PowerShell Logging

**Recommended Logging Settings** (via GPO):

1. **Script Block Logging**:
   ```
   Computer Configuration > Administrative Templates > Windows Components > Windows PowerShell
   "Turn on PowerShell Script Block Logging" = Enabled
   ```
   - Logs all script content and commands
   - Critical for audit and forensics
   - **Warning**: Can generate large logs (plan for log retention)

2. **Module Logging**:
   ```
   "Turn on Module Logging" = Enabled
   Module Names: * (or specific modules)
   ```

3. **Transcription** (optional):
   ```
   "Turn on PowerShell Transcription" = Enabled
   Transcript output directory: \\server\logs\PowerShell\
   Include invocation headers: Enabled
   ```

**Log Locations**:
- Event Viewer: `Applications and Services > Microsoft > Windows > PowerShell > Operational`
- Event IDs:
  - 4103: Module logging
  - 4104: Script block logging (execution)
  - 4105: Script block logging (start)
  - 4106: Script block logging (stop)

**Log Retention**:
- Minimum: 90 days
- Recommended: 1 year
- High-security: 3-7 years

### 3.4 JEA (Just Enough Administration)

If JEA is configured in your environment, ensure the following PowerShell cmdlets are available:

**Required Cmdlets**:
- `Get-CimInstance`
- `Get-ItemProperty`
- `Get-Content`
- `Out-File`
- `Invoke-WebRequest`
- `ConvertTo-Json` / `ConvertFrom-Json`
- `Get-FileHash`
- `Get-Date`
- `Get-Service`

**JEA Session Configuration** (if applicable):
```powershell
# Example JEA role capability for Inventory Agent
@{
    ModulesToImport = 'Microsoft.PowerShell.Management', 'CimCmdlets'
    VisibleCmdlets = @(
        'Get-CimInstance',
        'Get-ItemProperty',
        'Get-Content',
        'Out-File',
        'Invoke-WebRequest',
        'ConvertTo-Json',
        'ConvertFrom-Json',
        'Get-FileHash'
    )
    VisibleFunctions = @()
    VisibleProviders = 'FileSystem', 'Registry'
}
```

---

## 4. WMI/CIM Permissions

### 4.1 Overview

The inventory agent queries multiple WMI/CIM classes to collect hardware information. The agent runs as `NT AUTHORITY\SYSTEM` via scheduled tasks, which has full WMI access.

### 4.2 Required WMI Classes

| WMI Class | Purpose | Required Permission |
|-----------|---------|---------------------|
| `Win32_BIOS` | Serial number, BIOS version | Read |
| `Win32_ComputerSystem` | Computer name, manufacturer, model | Read |
| `Win32_OperatingSystem` | OS version, boot time | Read |
| `Win32_Processor` | CPU information | Read |
| `Win32_DiskDrive` | Disk serial numbers | Read |
| `Win32_DiskDriveToDiskPartition` | Partition mapping | Read |
| `Win32_LogicalDiskToPartition` | Drive letter mapping | Read |
| `Win32_NetworkAdapterConfiguration` | IP addresses, MAC addresses | Read |
| `Win32_NetworkAdapter` | Network adapter details | Read |

### 4.3 Permission Verification

**Test WMI Access**:
```powershell
# Test each WMI class
$WMIClasses = @(
    "Win32_BIOS",
    "Win32_ComputerSystem",
    "Win32_OperatingSystem",
    "Win32_Processor",
    "Win32_DiskDrive",
    "Win32_NetworkAdapterConfiguration"
)

foreach ($Class in $WMIClasses) {
    try {
        $Result = Get-CimInstance -ClassName $Class -ErrorAction Stop | Select-Object -First 1
        Write-Host "✓ $Class - Access OK" -ForegroundColor Green
    }
    catch {
        Write-Host "✗ $Class - Access DENIED: $_" -ForegroundColor Red
    }
}
```

### 4.4 Troubleshooting WMI Access

**Check WMI Service**:
```powershell
Get-Service -Name "Winmgmt" | Select-Object Name, Status, StartType
# Should be: Status = Running, StartType = Automatic
```

**Verify WMI Repository**:
```cmd
winmgmt /verifyrepository
# Should return: WMI repository is consistent
```

**Repair WMI (if needed)**:
```cmd
# Stop WMI service
net stop winmgmt /y

# Repair repository
winmgmt /salvagerepository

# Restart WMI
net start winmgmt
```

### 4.5 Non-SYSTEM Account Access

If running the agent as a service account (not SYSTEM), grant WMI permissions:

```powershell
# Grant WMI permissions to service account
$account = "DOMAIN\ServiceAccount"
$namespace = "root/cimv2"

$SDDL = (Get-WmiObject -Namespace $namespace -Class __SystemSecurity).GetSecurityDescriptor().Descriptor.SDDL
# Modify SDDL to include service account with READ permissions
# (Complex operation - recommend using SYSTEM account instead)
```

**Recommendation**: Run agent as `NT AUTHORITY\SYSTEM` to avoid WMI permission complexity.

---

## 5. Event Log Access

### 5.1 Application Event Log

**Purpose**: Agent writes operational logs to Application event log.

**Event Source**: `InventoryAgent`

**Pre-Creation Required**: Event sources must be created with admin rights.

**Pre-Create Event Source**:
```powershell
# Run once during deployment (requires admin)
New-EventLog -LogName Application -Source "InventoryAgent"
```

**Verification**:
```powershell
[System.Diagnostics.EventLog]::SourceExists("InventoryAgent")
# Should return: True
```

**GPO Deployment**:
```
Computer Configuration > Preferences > Windows Settings > Registry
Action: Create
Hive: HKEY_LOCAL_MACHINE
Key Path: SYSTEM\CurrentControlSet\Services\EventLog\Application\InventoryAgent
Value name: EventMessageFile
Value type: REG_EXPAND_SZ
Value data: C:\Windows\Microsoft.NET\Framework64\v4.0.30319\EventLogMessages.dll
```

### 5.2 Security Event Log (Logon Detection)

**Purpose**: Monitor for user logon events (Event ID 4624) to trigger inventory collection.

**Permission Required**: Read access to Security log (only SYSTEM and Administrators by default).

**Agent Configuration**: Agent runs as SYSTEM via scheduled task, has access automatically.

**Event IDs Monitored**:
- 4624: An account was successfully logged on
  - LogonType 2: Interactive (console)
  - LogonType 10: RemoteInteractive (RDP)

**Note**: Non-admin users cannot read Security log. This is expected and secure.

### 5.3 Log Retention

Configure Event Log size and retention via GPO:

```
Computer Configuration > Administrative Templates > Windows Components > Event Log Service > Application
Maximum Log Size (KB): 102400 (100 MB minimum, 512 MB recommended)
```

**Recommended Settings**:
- Application Log: 100-500 MB
- PowerShell Operational Log: 100-500 MB (if Script Block Logging enabled)
- Security Log: 1-4 GB (high-volume)

---

## 6. Network Security

### 6.1 Firewall Rules

**Required Outbound Rules**:

| Protocol | Port | Destination | Purpose |
|----------|------|-------------|---------|
| HTTPS | 443 | inventory.company.com | API endpoint |
| DNS | 53 | Internal DNS servers | Name resolution |
| HTTP | 80 | timestamp.digicert.com (optional) | Code signing timestamp |

**Windows Firewall GPO Configuration**:
```
Computer Configuration > Policies > Windows Settings > Security Settings > Windows Defender Firewall with Advanced Security > Outbound Rules
```

**Rule Details**:
- Rule Name: Inventory Agent - HTTPS Outbound
- Profile: Domain, Private, Public
- Direction: Outbound
- Protocol: TCP
- Local Port: Any
- Remote Port: 443
- Remote Address: inventory.company.com (or specific IP)
- Program: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe (PowerShell solution)
- Program: C:\Program Files\InventoryAgent\InventoryAgent.exe (Compiled solution)
- Action: Allow

**PowerShell Command**:
```powershell
New-NetFirewallRule -DisplayName "Inventory Agent - HTTPS Outbound" `
    -Direction Outbound `
    -Protocol TCP `
    -RemotePort 443 `
    -Program "C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" `
    -Action Allow `
    -Profile Domain,Private `
    -Description "Allow Inventory Agent to communicate with collection server"
```

### 6.2 Proxy Configuration

**Proxy Support**: Agent includes proxy authentication support.

**Configuration Methods**:

1. **System Proxy** (Automatic):
   - Agent uses system proxy settings automatically
   - `netsh winhttp show proxy`

2. **Manual Configuration** (Config.json):
   ```json
   {
       "UseProxy": true,
       "ProxyServer": "http://proxy.company.com:8080",
       "ProxyUseDefaultCredentials": true
   }
   ```

3. **Authenticated Proxy**:
   - Agent uses default credentials (SYSTEM account)
   - For user-based proxy auth, consider using network-based auth (NTLM/Kerberos)

**Proxy Bypass**:
```powershell
# Add inventory server to proxy bypass list
netsh winhttp set proxy proxy-server="proxy.company.com:8080" bypass-list="inventory.company.com;*.internal.company.com"
```

### 6.3 TLS/SSL Requirements

**Minimum TLS Version**: TLS 1.2
**Cipher Suites**: Modern, secure ciphers only

**Agent Enforcement**:
```powershell
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
```

**Server Requirements**:
- Valid SSL certificate (not self-signed in production)
- Certificate issued by trusted CA
- Hostname matches certificate CN/SAN
- No SSL/TLS vulnerabilities (check with `nmap --script ssl-enum-ciphers`)

**Certificate Pinning** (optional, high-security):
```powershell
# Add to agent configuration
$Config.ValidateServerCertificate = $true
$Config.TrustedServerThumbprint = "ABC123..." # SHA256 thumbprint
```

### 6.4 Network Segmentation

**Recommendations**:
- Inventory server should be in management VLAN
- Clients communicate outbound-only to server
- Server does not initiate connections to clients
- Network-based IDS/IPS monitoring recommended

**IP Allowlist** (if required):
```
Source: Any (workstation VLANs)
Destination: 10.50.100.10 (inventory server)
Port: 443/TCP
Protocol: HTTPS
```

---

## 7. Certificate Management

### 7.1 Client Authentication Certificates

**Purpose**: Optional - for mutual TLS (mTLS) authentication.

**Certificate Requirements**:
- Enhanced Key Usage: Client Authentication (1.3.6.1.5.5.7.3.2)
- Issued by trusted enterprise CA
- Deployed to: `LocalMachine\My` certificate store
- Private key marked as exportable: No (security best practice)

**Deployment via GPO**:
```
Computer Configuration > Policies > Windows Settings > Security Settings > Public Key Policies > Automatic Certificate Request
```

**Agent Configuration**:
```json
{
    "CertificateThumbprint": "1234567890ABCDEF..."
}
```

**Verification**:
```powershell
Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq "1234567890ABCDEF" }
```

### 7.2 Code Signing Certificate Lifecycle

**Certificate Expiration Management**:
1. Set up alerts for expiration (recommend 90 days before)
2. Renew certificate with same key pair (if possible)
3. Re-sign all scripts and executables
4. Update AppLocker/WDAC policies with new certificate
5. Test in pre-production environment
6. Deploy updated policies

**Certificate Revocation**:
- If code signing cert is compromised, immediately revoke
- Issue new certificate
- Re-sign all code
- Update all policies
- Investigate affected systems

### 7.3 Server SSL Certificate

**Requirements**:
- Issued by trusted CA (internal or public)
- Matches server hostname (inventory.company.com)
- Wildcard or SAN for multiple names
- Auto-renewal recommended (Let's Encrypt, ACME protocol)

**Client-Side Validation**:
- Agent validates server certificate by default
- CRL/OCSP checking enabled
- Certificate chain validation

---

## 8. Antivirus/EDR Configuration

### 8.1 Overview

Antivirus and EDR solutions may flag the inventory agent as suspicious due to:
- PowerShell script execution
- WMI queries
- Network communication
- System information enumeration

### 8.2 Windows Defender Exclusions

**Recommended Exclusions**:

1. **Path Exclusions**:
   ```powershell
   Add-MpPreference -ExclusionPath "C:\ProgramData\InventoryAgent"
   Add-MpPreference -ExclusionPath "C:\ProgramData\InventoryAgent\*.ps1"
   Add-MpPreference -ExclusionPath "C:\Program Files\InventoryAgent"  # For compiled version
   ```

2. **Process Exclusions**:
   ```powershell
   Add-MpPreference -ExclusionProcess "powershell.exe" # Only if necessary, not recommended globally
   ```

**GPO Deployment**:
```
Computer Configuration > Administrative Templates > Windows Components > Microsoft Defender Antivirus > Exclusions
```

**Verification**:
```powershell
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

**⚠️ Security Warning**: Exclusions should be as specific as possible. Do NOT exclude `powershell.exe` globally.

### 8.3 Third-Party AV/EDR Exclusions

**Common EDR Solutions**:

| Product | Exclusion Type | Configuration |
|---------|----------------|---------------|
| **CrowdStrike Falcon** | Path Exclusion | Policies > Exclusions > Add Path: `C:\ProgramData\InventoryAgent\**` |
| **SentinelOne** | Path Exclusion | Exclusions > Paths > Add: `C:\ProgramData\InventoryAgent\` |
| **Carbon Black** | Process/Script | Policies > Add Approval: SHA256 hash of signed scripts |
| **Cylance** | Safe File | File > Add to Safe List: SHA256 hash |
| **Microsoft Defender for Endpoint** | Indicator | Settings > Indicators > Add File Hash Allow |
| **Symantec Endpoint Protection** | Application Control | Policies > Application Control > Add Exception |
| **Trend Micro Apex One** | Approved Program | Agents > Approved Program List |

**Best Practice**: Use file hash or certificate-based exclusions instead of path exclusions.

### 8.4 EDR Behavioral Detection

**Potential Alerts**:
- **Alert**: Suspicious PowerShell script execution
  - **Mitigation**: Whitelist signed scripts by hash or certificate
- **Alert**: WMI enumeration detected
  - **Mitigation**: Whitelist specific scheduled task or process
- **Alert**: Outbound HTTPS to unknown domain
  - **Mitigation**: Add inventory server to trusted domains
- **Alert**: Mass data collection activity
  - **Mitigation**: Whitelist inventory agent process/script hash

**Coordination Required**:
1. Submit inventory agent for EDR vendor analysis
2. Request behavioral policy tuning
3. Document legitimate use case
4. Establish baseline normal behavior
5. Create exception/allowlist rules

### 8.5 Testing Procedure

1. **Deploy in Test Environment**:
   - Install agent on test system with AV/EDR enabled
   - Monitor for alerts and blocks
   - Document all triggered detections

2. **Request AV/EDR Exclusions**:
   - Submit exclusion request with business justification
   - Include script hashes, certificate thumbprint, file paths
   - Reference this security requirements document

3. **Validate Exclusions**:
   - Run agent manually to confirm no blocks
   - Check AV/EDR logs for any remaining alerts
   - Perform full inventory collection test

4. **Production Rollout**:
   - Deploy exclusions via GPO or AV management console
   - Pilot with small group (50-100 systems)
   - Monitor for 1-2 weeks before full deployment

---

## 9. File System Permissions

### 9.1 Installation Directory

**Path**: `C:\ProgramData\InventoryAgent\`

**Required Permissions**:
- `NT AUTHORITY\SYSTEM`: Full Control
- `BUILTIN\Administrators`: Full Control
- `BUILTIN\Users`: Read & Execute, List Folder Contents, Read

**PowerShell Configuration**:
```powershell
$Path = "C:\ProgramData\InventoryAgent"
$Acl = Get-Acl $Path

# Remove inherited permissions
$Acl.SetAccessRuleProtection($true, $false)

# Add SYSTEM - Full Control
$SystemRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "NT AUTHORITY\SYSTEM", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$Acl.AddAccessRule($SystemRule)

# Add Administrators - Full Control
$AdminRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$Acl.AddAccessRule($AdminRule)

# Add Users - Read Only
$UsersRule = New-Object System.Security.AccessControl.FileSystemAccessRule(
    "BUILTIN\Users", "ReadAndExecute", "ContainerInherit,ObjectInherit", "None", "Allow"
)
$Acl.AddAccessRule($UsersRule)

Set-Acl -Path $Path -AclObject $Acl
```

### 9.2 Log Directory

**Path**: `C:\ProgramData\InventoryAgent\Logs\`

**Permissions**:
- `NT AUTHORITY\SYSTEM`: Modify (Write logs)
- `BUILTIN\Administrators`: Full Control
- `BUILTIN\Users`: Read (for troubleshooting)

### 9.3 Queue Directory

**Path**: `C:\ProgramData\InventoryAgent\Queue\`

**Purpose**: Temporary storage for offline inventory data

**Permissions**:
- `NT AUTHORITY\SYSTEM`: Modify
- `BUILTIN\Administrators`: Full Control
- Others: No access

**Security Considerations**:
- Contains potentially sensitive inventory data
- Should be excluded from user access
- Consider encryption at rest (BitLocker/EFS)

### 9.4 Compiled Agent (Optional)

**Path**: `C:\Program Files\InventoryAgent\`

**Permissions**:
- `NT AUTHORITY\SYSTEM`: Read & Execute
- `BUILTIN\Administrators`: Full Control
- `BUILTIN\Users`: Read & Execute

**Service Executable**:
- File: `InventoryAgent.exe`
- Digital signature required
- Permissions: Read & Execute only (prevent modification)

---

## 10. Scheduled Task Security

### 10.1 Task Configuration

**Required Tasks**:

1. **Daily Collection Task**:
   - Name: `InventoryAgent-DailyCollection`
   - Trigger: Daily at 02:00
   - Action: Execute PowerShell script
   - User: `NT AUTHORITY\SYSTEM`
   - Run whether user is logged on or not
   - Run with highest privileges

2. **Logon Collection Task**:
   - Name: `InventoryAgent-LogonCollection`
   - Trigger: At logon (any user)
   - Action: Execute PowerShell script
   - User: `NT AUTHORITY\SYSTEM`
   - Run with highest privileges

3. **Queue Processing Task**:
   - Name: `InventoryAgent-ProcessQueue`
   - Trigger: Every 4 hours
   - Action: Execute PowerShell script
   - User: `NT AUTHORITY\SYSTEM`
   - Run with highest privileges

### 10.2 Task Security Settings

```xml
<Principal>
    <UserId>S-1-5-18</UserId> <!-- SYSTEM -->
    <RunLevel>HighestAvailable</RunLevel>
</Principal>
<Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <RunOnlyIfNetworkAvailable>true</RunOnlyIfNetworkAvailable>
    <ExecutionTimeLimit>PT30M</ExecutionTimeLimit> <!-- 30 minute timeout -->
    <Priority>7</Priority>
    <RestartOnFailure>
        <Interval>PT1M</Interval>
        <Count>3</Count>
    </RestartOnFailure>
</Settings>
```

### 10.3 PowerShell Execution Arguments

**Secure Execution**:
```powershell
-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"
```

**Argument Explanation**:
- `-NoProfile`: Don't load user profile (faster, more secure)
- `-NonInteractive`: No user prompts
- `-WindowStyle Hidden`: Don't show PowerShell window
- `-ExecutionPolicy Bypass`: Allow signed scripts (combined with script signature validation)
- `-File`: Specify script path

**⚠️ Security Note**: `-ExecutionPolicy Bypass` is acceptable when:
1. Scripts are digitally signed
2. AppLocker/WDAC is enforcing application control
3. Running as SYSTEM with no user interaction

### 10.4 Task Monitoring

**Event IDs**:
- Event ID 100: Task started
- Event ID 102: Task completed
- Event ID 103: Task action started
- Event ID 111: Task terminated
- Event ID 201: Task action completed with error

**PowerShell Monitoring**:
```powershell
# Get task status
Get-ScheduledTask -TaskName "InventoryAgent-*" | Get-ScheduledTaskInfo

# Get task history
Get-WinEvent -LogName "Microsoft-Windows-TaskScheduler/Operational" |
    Where-Object {$_.Message -like "*InventoryAgent*"} |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-Table -AutoSize
```

---

## 11. Compliance and Audit

### 11.1 Data Collection Scope

**Information Collected**:
- ✅ Computer name
- ✅ Hardware serial numbers (system, disks)
- ✅ Manufacturer and model information
- ✅ CPU, memory, disk specifications
- ✅ Network adapter MAC addresses and IP addresses
- ✅ Operating system version
- ✅ Last logged-in user name
- ✅ System boot time

**Information NOT Collected**:
- ❌ Passwords or credentials
- ❌ Personal files or documents
- ❌ Browser history or cookies
- ❌ Email content
- ❌ Encryption keys
- ❌ Biometric data
- ❌ Financial information

### 11.2 GDPR Compliance

**Personal Data Considerations**:
- **Username**: Considered personal data under GDPR
- **IP Address**: Considered personal data under GDPR
- **MAC Address**: Considered personal data under GDPR

**Compliance Measures**:
1. **Legal Basis**: Legitimate interest (IT asset management)
2. **Data Minimization**: Only collect necessary data
3. **Purpose Limitation**: Use only for inventory management
4. **Retention Period**: Maximum 2 years active, 5 years archived (configurable)
5. **Right to Erasure**: Implement data deletion upon employee departure
6. **Data Protection Impact Assessment (DPIA)**: Recommended for high-volume deployments

**Privacy Notice**:
- Inform employees about inventory data collection
- Explain purpose and legal basis
- Provide contact for data protection officer

### 11.3 Audit Logging

**Server-Side Audit Log Requirements**:
- All API requests logged with timestamp
- Source IP address recorded
- User context (if applicable)
- Data payload checksum
- Success/failure status
- Retention: Minimum 1 year

**Client-Side Audit Log**:
- Collection events logged to Application Event Log
- Event Source: `InventoryAgent`
- Event IDs:
  - 1000: Collection started (Info)
  - 1001: Collection completed (Info)
  - 1002: Collection failed (Error)
  - 1003: Security event (FailureAudit) - signature validation, access denials

**Sample Audit Log Entry**:
```json
{
    "timestamp": "2024-10-24T14:32:15Z",
    "source": "DESKTOP-ABC123",
    "source_ip": "10.50.10.55",
    "event": "inventory_submitted",
    "user": "SYSTEM",
    "status": "success",
    "data_hash": "sha256:abc123...",
    "agent_version": "2.1.0"
}
```

### 11.4 Security Audit Checklist

**Monthly Audit**:
- [ ] Review failed collection attempts
- [ ] Verify code signing certificates valid and not expiring
- [ ] Check for unauthorized changes to agent scripts
- [ ] Review network firewall logs for blocked connections
- [ ] Analyze AV/EDR alerts related to inventory agent
- [ ] Verify scheduled tasks are running on all systems
- [ ] Check agent version distribution (ensure updates deployed)

**Quarterly Audit**:
- [ ] Review AppLocker/WDAC event logs for violations
- [ ] Validate permissions on installation directories
- [ ] Test disaster recovery and agent reinstallation
- [ ] Review data retention and archival process
- [ ] Update security documentation
- [ ] Conduct penetration testing (if applicable)

**Annual Audit**:
- [ ] Full security assessment by independent team
- [ ] Review compliance with GDPR/data protection regulations
- [ ] Update DPIA (Data Protection Impact Assessment)
- [ ] Renew code signing certificates
- [ ] Review and update incident response procedures
- [ ] Validate business continuity plan

### 11.5 Incident Response

**Security Incidents**:

1. **Compromised Code Signing Certificate**:
   - Immediately revoke certificate
   - Notify security team and management
   - Audit all systems for unauthorized signed code
   - Re-sign all legitimate code with new certificate
   - Update all AppLocker/WDAC policies

2. **Unauthorized Agent Modification**:
   - Isolate affected systems
   - Compare with known-good file hashes
   - Investigate source of modification
   - Re-deploy agent from trusted source
   - Review access logs and permissions

3. **Data Breach (Inventory Data Exposed)**:
   - Activate incident response plan
   - Notify data protection officer
   - Assess scope of exposure
   - Notify affected individuals (if PII exposed)
   - Implement additional security controls

4. **Malicious Use of Agent**:
   - Disable scheduled tasks immediately
   - Quarantine agent files
   - Investigate command history and logs
   - Determine attack vector
   - Implement preventive controls

**Contact Information**:
```
Security Team: security@company.com
IT Operations: itops@company.com
Data Protection Officer: dpo@company.com
Incident Response Hotline: +1-555-SECURITY
```

---

## 12. Deployment Security Checklist

### 12.1 Pre-Deployment

**Phase 1: Certificate and Signing**
- [ ] Code signing certificate obtained from trusted CA
- [ ] Certificate installed on build server
- [ ] All PowerShell scripts digitally signed
- [ ] All executables (if compiled version) digitally signed
- [ ] Signatures verified (Status: Valid)
- [ ] Timestamp server configured for long-term validation

**Phase 2: Application Control**
- [ ] AppLocker/WDAC policy created
- [ ] Policy tested in audit mode (minimum 2 weeks)
- [ ] No false positives detected
- [ ] Event logs reviewed and analyzed
- [ ] Policy approved by security team
- [ ] Deployment plan documented

**Phase 3: Network and Infrastructure**
- [ ] Firewall rules created and tested
- [ ] Proxy configuration validated
- [ ] Server SSL certificate valid and trusted
- [ ] DNS resolution working
- [ ] Network connectivity verified
- [ ] Bandwidth impact assessed

**Phase 4: Security Software**
- [ ] AV/EDR exclusion requests submitted
- [ ] Exclusions approved by security team
- [ ] Exclusions deployed to pilot group
- [ ] No false positives after exclusions
- [ ] Behavioral detection tuned (if needed)

**Phase 5: Permissions and Access**
- [ ] Event Log source pre-created
- [ ] File system permissions configured
- [ ] WMI access validated
- [ ] Scheduled task permissions verified
- [ ] Certificate store access confirmed

### 12.2 Deployment

**Pilot Deployment (50-100 systems)**:
- [ ] Agent deployed to pilot group
- [ ] Monitoring enabled for all security logs
- [ ] No security alerts triggered
- [ ] Collections successful
- [ ] Performance impact acceptable
- [ ] User feedback collected (if applicable)
- [ ] Run for 2-4 weeks minimum

**Production Deployment**:
- [ ] Deployment plan approved
- [ ] Rollback plan documented
- [ ] Deployment scheduled during change window
- [ ] Phased rollout (by OU or AD group)
- [ ] Real-time monitoring during deployment
- [ ] Help desk notified and trained
- [ ] Communication sent to end users (if applicable)

### 12.3 Post-Deployment

**Week 1**:
- [ ] Daily monitoring of security event logs
- [ ] Review failed collections
- [ ] Check AV/EDR alerts
- [ ] Validate network traffic patterns
- [ ] Review help desk tickets
- [ ] Assess performance impact

**Week 2-4**:
- [ ] Weekly security log reviews
- [ ] Validate data accuracy in inventory database
- [ ] Review offline queue statistics
- [ ] Check for certificate expiration warnings
- [ ] Update documentation with lessons learned

**Ongoing**:
- [ ] Monthly security audits
- [ ] Quarterly review of security controls
- [ ] Annual penetration testing
- [ ] Continuous monitoring of security alerts
- [ ] Regular updates and patching

---

## 13. Security Contact and Escalation

### 13.1 Security Team Contacts

**Primary Contacts**:
```
Security Operations Center (SOC): soc@company.com
Information Security Team: infosec@company.com
IT Operations Team: itops@company.com
```

**Escalation Path**:
1. Level 1: IT Help Desk / System Administrator
2. Level 2: Security Operations / IT Operations Manager
3. Level 3: CISO / Director of IT
4. Level 4: Executive Management

### 13.2 Reporting Security Issues

**Report Immediately**:
- Unauthorized access or tampering
- Code signing certificate compromise
- Data breach or exposure
- Malicious use of agent
- Security control bypass

**Reporting Channels**:
- Email: security-incident@company.com
- Phone: +1-555-SECURITY (24/7 hotline)
- Internal Ticket System: Priority = Critical

### 13.3 Security Review Schedule

**Weekly** (Security Operations):
- Review security event logs
- Check AV/EDR alerts
- Validate agent deployment status

**Monthly** (Security Team):
- Audit security controls
- Review access logs
- Check certificate expiration
- Validate compliance

**Quarterly** (CISO / Security Leadership):
- Security control effectiveness review
- Risk assessment update
- Compliance validation
- Policy review and updates

**Annually** (Executive / Board):
- Comprehensive security audit
- Penetration testing
- Risk posture review
- Strategic security planning

---

## Appendix A: Security Tools and Scripts

See the `deployment-tools/` folder for:
- `Test-DeploymentReadiness.ps1` - Pre-deployment security validation
- `Test-SecurityCompliance.ps1` - Post-deployment compliance check

See the `security-templates/` folder for:
- `AppLocker-Rules.xml` - AppLocker policy template
- `Create-WDACPolicy.ps1` - WDAC policy generator
- `Security-Baseline-GPO.xml` - Group Policy baseline

---

## Appendix B: Glossary

**Terms and Acronyms**:
- **AppLocker**: Windows Application Control technology (Windows 7+)
- **WDAC**: Windows Defender Application Control (Windows 10+)
- **CIM**: Common Information Model (WMI successor)
- **WMI**: Windows Management Instrumentation
- **EDR**: Endpoint Detection and Response
- **GPO**: Group Policy Object
- **JEA**: Just Enough Administration
- **SIEM**: Security Information and Event Management
- **TLS**: Transport Layer Security
- **mTLS**: Mutual TLS (two-way certificate authentication)
- **GDPR**: General Data Protection Regulation
- **DPIA**: Data Protection Impact Assessment

---

## Document Control

**Version History**:
| Version | Date | Author | Changes |
|---------|------|--------|---------|
| 1.0.0 | 2024-10-24 | IT Security | Initial release |

**Review Schedule**: Quarterly
**Next Review Due**: 2025-01-24
**Document Owner**: Chief Information Security Officer (CISO)
**Approval**: [Pending Security Team Review]

---

**END OF DOCUMENT**
