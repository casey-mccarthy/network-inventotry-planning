# Deployment Guide - Windows Inventory Agent
## Security-Hardened Edition for Restrictive Environments

**Version**: 2.1.0
**Last Updated**: 2024-10-24
**Target Audience**: IT Operations, Security Teams, System Administrators

---

## 📋 Executive Summary

This guide provides step-by-step instructions for deploying the Windows inventory agent in security-conscious environments with strict application control, execution policies, and monitoring requirements.

**Deployment Time Estimates**:
- **Planning & Preparation**: 1-2 weeks
- **Security Configuration**: 1-2 weeks
- **Pilot Deployment**: 2-4 weeks
- **Production Rollout**: 2-4 weeks
- **Total**: 6-12 weeks (depending on organizational processes)

**Prerequisites**:
- ✅ Code signing certificate obtained
- ✅ Security team approval
- ✅ Server infrastructure deployed
- ✅ Pilot group identified

---

## 🎯 Solution Selection Decision Tree

```
Start: How many endpoints?
│
├── < 5,000 endpoints
│   └── Use Option 2 (PowerShell) ✅ RECOMMENDED
│       - Easier deployment
│       - Simpler maintenance
│       - No compilation required
│       - Native Windows tools
│
└── > 5,000 endpoints
    ├── Need real-time event processing?
    │   ├── YES → Option 1 (.NET Service)
    │   │   - Real-time logon detection
    │   │   - Always-on service
    │   │   - Better performance
    │   │
    │   └── NO → Option 2 (PowerShell)
    │       - Scheduled tasks sufficient
    │       - Easier to customize
    │
    └── Have C# development resources?
        ├── YES → Option 1 (.NET Service)
        │   - Can customize and maintain
        │   - Can build in-house
        │
        └── NO → Option 2 (PowerShell) ✅ RECOMMENDED
            - No development needed
            - Easy to modify scripts
```

**Recommendation for Most Organizations**: **Option 2 (PowerShell Native Solution)**

---

## 🚀 Quick Start - Option 2 (PowerShell)

### Phase 1: Pre-Deployment (Week 1)

#### Day 1-2: Obtain Code Signing Certificate

```powershell
# Check if you have a code signing certificate
Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert

# If not, request from your internal CA or purchase from public CA
# Required EKU: Code Signing (1.3.6.1.5.5.7.3.3)
```

**Procurement**:
- **Internal CA**: Submit certificate request via MMC or certreq
- **Public CA**: DigiCert, GlobalSign, Sectigo (annual cost: $200-500)

#### Day 3: Run Deployment Readiness Checker

```powershell
# Download and run the readiness checker
cd deployment-tools/
.\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com" -Detailed -ExportReport

# Review the report
Get-Content .\DeploymentReadinessReport.json
```

**Expected Issues**:
- ⚠️ AppLocker/WDAC not configured → Will configure in Phase 2
- ⚠️ Event source doesn't exist → Will create during installation
- ⚠️ No antivirus exclusions → Will request from security team

#### Day 4-5: Review Security Requirements with Security Team

**Meeting Agenda**:
1. Present the Security Requirements document
2. Discuss required exclusions (AV/EDR)
3. Review AppLocker/WDAC policies
4. Agree on monitoring and audit procedures
5. Set deployment timeline

**Documents to Share**:
- `shared-documentation/Security-Requirements.md`
- `security-templates/AppLocker-Rules.xml`
- Results from deployment readiness checker

### Phase 2: Security Configuration (Week 2)

#### Step 1: Sign All Scripts

```powershell
# Navigate to PowerShell solution
cd option2-powershell-native/

# Get your code signing certificate
$Cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

if (-not $Cert) {
    Write-Error "No code signing certificate found!"
    exit 1
}

# Sign all scripts
$Scripts = Get-ChildItem -Filter "*.ps1"
foreach ($Script in $Scripts) {
    $Result = Set-AuthenticodeSignature -FilePath $Script.FullName -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"
    Write-Host "$($Script.Name): $($Result.Status)" -ForegroundColor $(if($Result.Status -eq 'Valid'){'Green'}else{'Red'})
}

# Verify signatures
foreach ($Script in $Scripts) {
    $Sig = Get-AuthenticodeSignature -FilePath $Script.FullName
    if ($Sig.Status -ne 'Valid') {
        Write-Error "$($Script.Name) signature is invalid!"
    }
}

Write-Host "`nAll scripts signed successfully!" -ForegroundColor Green
```

#### Step 2: Create AppLocker Policy

**Option A: Use Provided Template** (Recommended)
```powershell
# Import the AppLocker policy template
cd ../security-templates/
Set-AppLockerPolicy -XMLPolicy ".\AppLocker-Rules.xml" -Merge

# Verify import
Get-AppLockerPolicy -Effective -Xml | Out-File "Current-AppLocker-Policy.xml"
```

**Option B: Create Custom Policy**
```powershell
# Create publisher rule for your signed scripts
$Publisher = $Cert.Subject  # e.g., "CN=YourCompany Code Signing, O=YourCompany..."

New-AppLockerPolicy -RuleType Publisher `
    -Path "C:\ProgramData\InventoryAgent\*.ps1" `
    -Publisher $Publisher `
    -User Everyone `
    -Action Allow `
    -RuleName "Inventory Agent - Signed Scripts" |
    Set-AppLockerPolicy -Merge
```

**Set to Audit Mode First**:
```xml
<!-- In AppLocker policy XML, set: -->
<RuleCollection Type="Script" EnforcementMode="AuditOnly">
```

**Monitor for 2 weeks** before switching to `Enforced`.

#### Step 3: Create WDAC Policy (Windows 10 1903+ / Windows 11)

```powershell
cd ../security-templates/

# Run the WDAC policy generator
.\Create-WDACPolicy.ps1 `
    -PolicyName "Inventory Agent Policy" `
    -EnforceMode Audit `
    -IncludeSignedScripts `
    -CodeSigningCertThumbprint $Cert.Thumbprint

# Convert to binary
ConvertFrom-CIPolicy -XmlFilePath ".\InventoryAgent-WDAC-Policy.xml" -BinaryFilePath ".\InventoryAgent.cip"
```

**Deploy via GPO**:
1. Copy `InventoryAgent.cip` to SYSVOL
2. GPO: `Computer Config > Admin Templates > System > Device Guard > Deploy Code Integrity Policy`
3. Value: Path to .cip file

#### Step 4: Request AV/EDR Exclusions

**Email Template to Security Team**:

```
Subject: AV/EDR Exclusion Request - Windows Inventory Agent

Security Team,

I am requesting the following antivirus/EDR exclusions for the Windows Inventory Agent deployment:

PURPOSE:
The inventory agent collects hardware information (serial numbers, IP addresses, etc.) for asset management.

EXCLUSIONS REQUESTED:

1. Path Exclusion:
   - C:\ProgramData\InventoryAgent\
   - Reason: Contains signed PowerShell scripts and operational logs

2. Process Exclusion (if path exclusion insufficient):
   - File Hash (SHA256): [Run Get-FileHash on Collect-Inventory.ps1]
   - Reason: Signed script for inventory collection

SECURITY JUSTIFICATION:
- All scripts digitally signed with organizational code signing certificate
- AppLocker publisher rule enforces only signed scripts can run
- No user interaction or elevation required
- Logs all activities to Event Log (Event Source: InventoryAgent)
- Code review completed and approved

BUSINESS JUSTIFICATION:
- Required for accurate asset tracking and compliance
- Supports hardware lifecycle management
- Enables rapid asset location for incident response

RISK MITIGATION:
- Scripts are read-only for standard users
- Only SYSTEM account can execute via scheduled tasks
- Network communication restricted to inventory server (HTTPS only)
- Certificate-based authentication
- Comprehensive audit logging

TESTING:
- Successfully tested in isolated environment
- No false positives or security concerns identified
- Pilot deployment planned for [OU/Group Name]

Please approve and implement these exclusions for the pilot group by [Date].

Attached:
- Security-Requirements.md (comprehensive security documentation)
- AppLocker-Rules.xml (application control policy)
- File hashes for all scripts

Thank you,
[Your Name]
IT Operations Team
```

**Include**:
- SHA256 hashes of all scripts
- Copy of code signing certificate (public key)
- Security Requirements document

#### Step 5: Configure Network Firewall

**Firewall Rule Request**:

```
Rule Name: Inventory Agent - HTTPS Outbound
Direction: Outbound
Protocol: TCP
Source: Any (workstation VLANs)
Destination: inventory.company.com (or IP: 10.50.100.10)
Port: 443 (HTTPS)
Application: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Action: Allow
Profiles: Domain, Private
Description: Allow inventory agent to transmit data to collection server
```

**Test Connectivity**:
```powershell
# DNS resolution
Resolve-DnsName -Name inventory.company.com

# TCP connectivity
Test-NetConnection -ComputerName inventory.company.com -Port 443

# HTTPS request
Invoke-WebRequest -Uri "https://inventory.company.com/api/v1/health" -UseBasicParsing
```

### Phase 3: Pilot Deployment (Week 3-6)

#### Step 1: Prepare Pilot Systems

**Select Pilot Group**:
- Size: 50-100 systems
- Criteria:
  - Diverse hardware (different manufacturers)
  - Mix of user profiles (roaming, VPN users)
  - IT staff machines (for direct feedback)
  - Geographically distributed (if applicable)

**Create Pilot OU**:
```powershell
# Create test OU in Active Directory
New-ADOrganizationalUnit -Name "InventoryAgent-Pilot" -Path "OU=Computers,DC=company,DC=com"

# Move pilot computers
$PilotComputers = @("DESKTOP-001", "LAPTOP-025", "WORKSTATION-042")
foreach ($Computer in $PilotComputers) {
    Get-ADComputer -Identity $Computer | Move-ADObject -TargetPath "OU=InventoryAgent-Pilot,OU=Computers,DC=company,DC=com"
}
```

#### Step 2: Deploy Scripts via GPO

**Create Deployment GPO**:

```powershell
# Import GroupPolicy module
Import-Module GroupPolicy

# Create new GPO
$GPOName = "Deploy-InventoryAgent-Pilot"
$GPO = New-GPO -Name $GPOName -Comment "Deploys PowerShell inventory agent to pilot group"

# Link to pilot OU
$TargetOU = "OU=InventoryAgent-Pilot,OU=Computers,DC=company,DC=com"
New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes

Write-Host "GPO created and linked to $TargetOU" -ForegroundColor Green
```

**Configure GPO - File Deployment**:

1. **Copy scripts to SYSVOL**:
```powershell
$GPOPath = "\\company.com\SYSVOL\company.com\Policies\{$($GPO.Id)}\Machine\Scripts"
New-Item -Path $GPOPath -ItemType Directory -Force

# Copy signed scripts
Copy-Item -Path ".\option2-powershell-native\Collect-Inventory.ps1" -Destination "$GPOPath\" -Force
Copy-Item -Path ".\option2-powershell-native\Install-InventoryTasks.ps1" -Destination "$GPOPath\" -Force

Write-Host "Scripts copied to SYSVOL" -ForegroundColor Green
```

2. **Create startup script** that deploys to local system:

Create `Deploy-InventoryAgent.ps1` in SYSVOL:

```powershell
# Startup script: Deploy-InventoryAgent.ps1
$ErrorActionPreference = "SilentlyContinue"

# Define paths
$TargetPath = "C:\ProgramData\InventoryAgent"
$GPOPath = "\\company.com\SYSVOL\company.com\Policies\{GPO-GUID}\Machine\Scripts"

# Create directory
if (!(Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}

# Copy scripts
Copy-Item -Path "$GPOPath\*.ps1" -Destination $TargetPath -Force

# Create Event Log source
if (![System.Diagnostics.EventLog]::SourceExists("InventoryAgent")) {
    New-EventLog -LogName Application -Source "InventoryAgent"
}

# Create configuration
$Config = @{
    ServerEndpoint = "https://inventory.company.com/api/v1"
    EnableDebounce = $true
    DebounceMinutes = 60
    MaxRetryAttempts = 3
    RetryDelaySeconds = 30
    QueueMaxSize = 1000
    EnableCompression = $false
    UseProxy = $false
    ProxyUseDefaultCredentials = $true
}
$Config | ConvertTo-Json | Out-File "$TargetPath\Config.json" -Force

# Install scheduled tasks
& "$TargetPath\Install-InventoryTasks.ps1" -Force

# Log deployment
$LogFile = "$TargetPath\deployment.log"
"Deployed by GPO on $(Get-Date) to $env:COMPUTERNAME" | Out-File $LogFile -Append
```

3. **Configure GPO to run startup script**:

```powershell
# Set startup script in GPO
$GPOPath = "\\company.com\SYSVOL\company.com\Policies\{$($GPO.Id)}\Machine\Scripts\Startup"
New-Item -Path $GPOPath -ItemType Directory -Force

# Copy deployment script
Copy-Item -Path ".\Deploy-InventoryAgent.ps1" -Destination $GPOPath -Force

# GPO setting: Computer Configuration > Policies > Windows Settings > Scripts > Startup
# Add: Deploy-InventoryAgent.ps1
```

**Configure Registry Settings** (alternative to config file):

```powershell
# Set registry values via GPO
Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\SOFTWARE\YourCompany\InventoryAgent" `
    -ValueName "ServerEndpoint" `
    -Type String `
    -Value "https://inventory.company.com/api/v1"

Set-GPRegistryValue -Name $GPOName `
    -Key "HKLM\SOFTWARE\YourCompany\InventoryAgent" `
    -ValueName "DebounceMinutes" `
    -Type DWord `
    -Value 60
```

#### Step 3: Force GPO Update on Pilot Systems

**Option A: Remote GPO Update**
```powershell
$PilotComputers = Get-ADComputer -SearchBase "OU=InventoryAgent-Pilot,OU=Computers,DC=company,DC=com" -Filter *

foreach ($Computer in $PilotComputers) {
    Invoke-Command -ComputerName $Computer.Name -ScriptBlock {
        gpupdate /force
    } -ErrorAction Continue
}
```

**Option B: Wait for Next Group Policy Refresh** (90-120 minutes)

**Option C: Manual on Each System**:
```powershell
gpupdate /force
shutdown /r /t 60 /c "Restarting for Inventory Agent deployment"
```

#### Step 4: Monitor Pilot Deployment

**Day 1-3: Intensive Monitoring**

```powershell
# Create monitoring script
$PilotComputers = Get-ADComputer -SearchBase "OU=InventoryAgent-Pilot,OU=Computers,DC=company,DC=com" -Filter *

$Results = foreach ($Computer in $PilotComputers) {
    $Status = Invoke-Command -ComputerName $Computer.Name -ScriptBlock {
        # Check if agent installed
        $AgentPath = "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"
        $AgentInstalled = Test-Path $AgentPath

        # Check scheduled tasks
        $Tasks = Get-ScheduledTask -TaskName "InventoryAgent-*" -ErrorAction SilentlyContinue
        $TasksCreated = $Tasks.Count -eq 3

        # Check recent collection
        $LogPath = "C:\ProgramData\InventoryAgent\Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log"
        $LogExists = Test-Path $LogPath

        # Check queue
        $QueuePath = "C:\ProgramData\InventoryAgent\Queue"
        $QueueItems = (Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue).Count

        [PSCustomObject]@{
            ComputerName = $env:COMPUTERNAME
            AgentInstalled = $AgentInstalled
            TasksCreated = $TasksCreated
            LogExists = $LogExists
            QueueItems = $QueueItems
        }
    } -ErrorAction SilentlyContinue

    if ($Status) { $Status } else {
        [PSCustomObject]@{
            ComputerName = $Computer.Name
            AgentInstalled = "UNREACHABLE"
            TasksCreated = $false
            LogExists = $false
            QueueItems = 0
        }
    }
}

# Display results
$Results | Format-Table -AutoSize

# Summary
$TotalComputers = $Results.Count
$SuccessfulDeployments = ($Results | Where-Object {$_.AgentInstalled -eq $true -and $_.TasksCreated -eq $true}).Count
$SuccessRate = [math]::Round(($SuccessfulDeployments / $TotalComputers) * 100, 2)

Write-Host "`nDeployment Summary:" -ForegroundColor Cyan
Write-Host "  Total Systems: $TotalComputers"
Write-Host "  Successful: $SuccessfulDeployments"
Write-Host "  Success Rate: $SuccessRate%"

if ($SuccessRate -lt 95) {
    Write-Host "`nWARNING: Success rate below 95% - investigate failures" -ForegroundColor Yellow
}
```

**Check for Security Alerts**:

```powershell
# AppLocker violations
Get-WinEvent -LogName "Microsoft-Windows-AppLocker/EXE and DLL" -MaxEvents 100 |
    Where-Object {$_.Message -like "*InventoryAgent*"} |
    Format-Table TimeCreated, Id, Message

# WDAC violations
Get-WinEvent -LogName "Microsoft-Windows-CodeIntegrity/Operational" -MaxEvents 100 |
    Where-Object {$_.Id -eq 3076 -and $_.Message -like "*Inventory*"} |
    Format-Table TimeCreated, Message

# Windows Defender blocks
Get-MpThreatDetection | Where-Object {$_.Resources -like "*InventoryAgent*"}
```

**Week 2-4: Ongoing Monitoring**

Weekly checks:
- [ ] Collection success rate >95%
- [ ] No security violations
- [ ] Server receiving data correctly
- [ ] No performance complaints from users
- [ ] Event logs clean (no errors)
- [ ] Queue not growing (network issues)

#### Step 5: Validate Data Quality

**On Server Side**:
```sql
-- Check recent collections
SELECT
    computer_name,
    last_login,
    collection_timestamp,
    agent_version
FROM inventory
WHERE collection_timestamp > NOW() - INTERVAL '24 hours'
ORDER BY collection_timestamp DESC;

-- Pilot system coverage
SELECT
    COUNT(DISTINCT computer_name) as systems_reporting
FROM inventory
WHERE computer_name IN (SELECT name FROM pilot_systems);
```

**Expected Results**:
- All pilot systems reporting within 24 hours
- Data complete (serial numbers, IPs, etc.)
- No corrupted or malformed data

### Phase 4: Production Rollout (Week 7-10)

#### Go/No-Go Decision Criteria

**Criteria for Production Rollout**:
- ✅ Pilot success rate >95%
- ✅ No critical security violations
- ✅ No performance issues reported
- ✅ Data quality validated
- ✅ All AV/EDR exclusions approved and deployed
- ✅ Security team approval obtained
- ✅ Runbook and support procedures documented
- ✅ Rollback plan tested

**If ANY criterion is not met**: Extend pilot, investigate, remediate.

#### Production Deployment Strategy

**Option A: Phased by OU** (Recommended)

```
Week 7: OU=IT Department (500 systems)
Week 8: OU=Finance,OU=HR (1000 systems)
Week 9: OU=Sales,OU=Marketing (2000 systems)
Week 10: Remaining OUs (remaining systems)
```

**Option B: Phased by Geography**

```
Week 7: Headquarters (1000 systems)
Week 8: Regional Office 1 (800 systems)
Week 9: Regional Office 2 (600 systems)
Week 10: Remote sites (remaining)
```

**Implementation**:

```powershell
# Week 7: Link GPO to IT Department OU
New-GPLink -Name "Deploy-InventoryAgent-Production" -Target "OU=IT,OU=Departments,DC=company,DC=com" -LinkEnabled Yes

# Monitor for 3-5 days, validate success

# Week 8: Link to next OUs
New-GPLink -Name "Deploy-InventoryAgent-Production" -Target "OU=Finance,OU=Departments,DC=company,DC=com" -LinkEnabled Yes
New-GPLink -Name "Deploy-InventoryAgent-Production" -Target "OU=HR,OU=Departments,DC=company,DC=com" -LinkEnabled Yes

# Continue weekly until complete
```

**Daily Monitoring During Rollout**:

```powershell
# Deployment progress tracking
$AllComputers = Get-ADComputer -Filter {OperatingSystem -like "*Windows 11*"} | Measure-Object
$DeployedComputers = # Query inventory server for systems reporting

$Coverage = [math]::Round(($DeployedComputers / $AllComputers.Count) * 100, 2)

Write-Host "Deployment Coverage: $Coverage%" -ForegroundColor Cyan
Write-Host "  Total Windows 11 Systems: $($AllComputers.Count)"
Write-Host "  Systems Reporting: $DeployedComputers"
Write-Host "  Remaining: $($AllComputers.Count - $DeployedComputers)"
```

#### Communication Plan

**Week Before Rollout**:
- Email to IT staff: Deployment schedule, support procedures
- Email to end users (optional): Brief notification about inventory agent
- Update help desk ticketing system with FAQ

**During Rollout**:
- Daily status emails to stakeholders
- Weekly metrics reports
- Immediate escalation for critical issues

**Post-Rollout**:
- Success summary report
- Lessons learned documentation
- Handoff to operations team

### Phase 5: Post-Deployment (Ongoing)

#### Week 1 Post-Rollout

**Tasks**:
- [ ] Verify 100% coverage achieved
- [ ] Validate data quality across all systems
- [ ] Review all event logs for anomalies
- [ ] Check for any late-appearing security alerts
- [ ] Gather feedback from help desk
- [ ] Document any issues and resolutions

#### Monthly Maintenance

**Security Audits**:
```powershell
# Check code signing certificate expiration
$Scripts = Get-ChildItem -Path "C:\ProgramData\InventoryAgent" -Filter "*.ps1" -Recurse
foreach ($Script in $Scripts) {
    $Sig = Get-AuthenticodeSignature -FilePath $Script.FullName
    if ($Sig.Status -ne 'Valid') {
        Write-Warning "$($Script.Name): Signature invalid - $($Sig.Status)"
    }
    $Cert = $Sig.SignerCertificate
    if ($Cert -and $Cert.NotAfter -lt (Get-Date).AddMonths(3)) {
        Write-Warning "$($Script.Name): Certificate expires soon - $($Cert.NotAfter)"
    }
}
```

**Agent Version Distribution**:
```powershell
# Query inventory database for agent versions
SELECT agent_version, COUNT(*) as count
FROM inventory
GROUP BY agent_version
ORDER BY count DESC;
```

**Collection Health**:
```powershell
# Systems not reporting in 48 hours
SELECT computer_name, last_updated
FROM inventory
WHERE last_updated < NOW() - INTERVAL '48 hours'
ORDER BY last_updated;
```

#### Quarterly Reviews

**Tasks**:
- [ ] Review security controls effectiveness
- [ ] Update documentation
- [ ] Check certificate renewal schedules
- [ ] Validate compliance with data protection policies
- [ ] Performance optimization review
- [ ] Disaster recovery test

---

## 🚨 Rollback Procedures

### Emergency Rollback (Critical Issue)

**Scenario**: Critical security vulnerability or widespread system impact

**Immediate Actions**:

```powershell
# Disable GPO immediately
Set-GPLink -Name "Deploy-InventoryAgent-Production" -Target "OU=Computers,DC=company,DC=com" -LinkEnabled No

# Stop agent on all systems
$AllComputers = Get-ADComputer -Filter * -SearchBase "OU=Computers,DC=company,DC=com"
Invoke-Command -ComputerName $AllComputers.Name -ScriptBlock {
    # Disable scheduled tasks
    Get-ScheduledTask -TaskName "InventoryAgent-*" | Disable-ScheduledTask

    # Optionally remove
    # Get-ScheduledTask -TaskName "InventoryAgent-*" | Unregister-ScheduledTask -Confirm:$false
} -ErrorAction Continue
```

**Communication**:
1. Immediate notification to security team
2. Email to IT staff: Rollback in progress
3. Status updates every 2 hours until resolved
4. Post-mortem within 24 hours

### Partial Rollback (Specific OU)

```powershell
# Unlink GPO from specific OU
Remove-GPLink -Name "Deploy-InventoryAgent-Production" -Target "OU=Finance,OU=Departments,DC=company,DC=com"

# Force GPO refresh
$FinanceComputers = Get-ADComputer -SearchBase "OU=Finance,OU=Departments,DC=company,DC=com" -Filter *
Invoke-Command -ComputerName $FinanceComputers.Name -ScriptBlock {
    gpupdate /force
}
```

### Complete Uninstall

```powershell
# Removal script
Invoke-Command -ComputerName $Computers -ScriptBlock {
    # Stop and remove scheduled tasks
    Get-ScheduledTask -TaskName "InventoryAgent-*" | Unregister-ScheduledTask -Confirm:$false

    # Remove files
    Remove-Item -Path "C:\ProgramData\InventoryAgent" -Recurse -Force -ErrorAction SilentlyContinue

    # Remove Event Log source
    Remove-EventLog -Source "InventoryAgent" -ErrorAction SilentlyContinue

    # Remove registry keys
    Remove-Item -Path "HKLM:\SOFTWARE\YourCompany\InventoryAgent" -Recurse -Force -ErrorAction SilentlyContinue
}
```

---

## 📞 Support and Escalation

### Support Tiers

**Tier 1: Help Desk**
- Initial triage
- Basic troubleshooting (restart tasks, check logs)
- Escalate to Tier 2 if unresolved in 30 minutes

**Tier 2: IT Operations**
- Advanced troubleshooting
- GPO and configuration issues
- Network connectivity problems
- Escalate to Tier 3 for security issues

**Tier 3: Security Team**
- Application control violations
- Security incidents
- Certificate issues
- Policy modifications

**Tier 4: Executive Escalation**
- Critical widespread impact
- Security breaches
- Compliance violations

### Common Issues - Quick Reference

| Issue | Symptoms | Quick Fix |
|-------|----------|-----------|
| Script won't run | Execution policy error | Verify script signature valid |
| AppLocker block | Event ID 8002 | Check AppLocker policy includes signed script |
| WMI access denied | Collection fails, error in log | Verify task runs as SYSTEM |
| Network timeout | Queue growing, connection errors | Check firewall, proxy, server availability |
| Certificate expired | Signature invalid | Re-sign scripts with renewed certificate |
| High queue count | Many JSON files in Queue\ | Investigate network/server issues |

---

## 📊 Success Metrics Dashboard

Track these metrics weekly:

```
┌────────────────────────────────────────────────┐
│ INVENTORY AGENT - DEPLOYMENT DASHBOARD        │
├────────────────────────────────────────────────┤
│ Coverage:          [████████████████] 98.5%   │
│ Collection Rate:   [█████████████████] 97.2%  │
│ Security Events:   0 critical, 2 warnings     │
│ Network Errors:    0.5% timeout rate          │
│ Queue Health:      Avg 3 items, Max 45        │
│ Performance:       <1% CPU, <75MB RAM         │
└────────────────────────────────────────────────┘
```

**Green Status**: All metrics within target
**Yellow Status**: 1-2 metrics below target, investigate
**Red Status**: Critical metric failure, immediate action

---

## 🎓 Training Materials

### For IT Staff

**Topics**:
1. How the inventory agent works
2. Scheduled task architecture
3. Troubleshooting common issues
4. Reading event logs
5. Security considerations
6. Escalation procedures

**Duration**: 1 hour

### For Help Desk

**Topics**:
1. What is the inventory agent?
2. Expected behavior (what users might notice)
3. Common user questions
4. Basic troubleshooting
5. When to escalate

**Duration**: 30 minutes

### For End Users (Optional)

**Email Template**:

```
Subject: New IT Asset Management Tool

Dear [User],

Our IT team is deploying a new automated inventory management system to better track and manage company hardware assets.

WHAT IT DOES:
- Automatically collects computer hardware information (serial numbers, specifications)
- Helps IT quickly locate and support your device
- Improves asset tracking for security and compliance

WHAT YOU'LL NOTICE:
- Nothing! The process runs in the background
- No performance impact
- No user interaction required
- Completely automatic

SECURITY:
- Only collects hardware information (no personal files or data)
- Digitally signed and approved by IT Security
- Data transmitted securely via encrypted connection

QUESTIONS:
Contact IT Help Desk at: helpdesk@company.com

Thank you,
IT Operations Team
```

---

## 📝 Final Checklist

Before marking deployment as complete:

### Technical
- [ ] 100% of target systems have agent installed
- [ ] Collection success rate >95%
- [ ] All scripts properly signed and signatures valid
- [ ] AppLocker/WDAC policies enforced (not just audit)
- [ ] AV/EDR exclusions deployed
- [ ] Event Log source created on all systems
- [ ] Network firewall rules configured
- [ ] Server infrastructure stable and monitored

### Security
- [ ] Security audit completed
- [ ] No critical security violations
- [ ] Compliance validation passed
- [ ] Audit logging configured and tested
- [ ] Incident response procedures documented
- [ ] Certificate renewal schedule established

### Operational
- [ ] Help desk trained and FAQ published
- [ ] Runbook documented
- [ ] Monitoring configured
- [ ] Backup and disaster recovery tested
- [ ] Support procedures documented
- [ ] Escalation paths defined

### Documentation
- [ ] Final deployment report completed
- [ ] Lessons learned documented
- [ ] Configuration management updated
- [ ] User communications sent
- [ ] Handoff to operations team completed

---

## 🎉 Deployment Complete!

Congratulations on successfully deploying the Windows Inventory Agent!

**Next Steps**:
1. Monitor daily for first week
2. Weekly monitoring thereafter
3. Monthly security audits
4. Quarterly reviews
5. Annual penetration testing

**Continuous Improvement**:
- Gather feedback from users and IT staff
- Optimize based on operational experience
- Update security controls as needed
- Plan for future enhancements

---

**Document Version**: 1.0.0
**Last Updated**: 2024-10-24
**Owner**: IT Operations
**Approvers**: IT Management, Security Team

---

**END OF DEPLOYMENT GUIDE**
