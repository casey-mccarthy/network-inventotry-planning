# Quick Start Guide - Windows Inventory Agent

## ⚡ 5-Minute Test Deployment (Non-Production)

### Prerequisites
- Windows 11 test machine
- Administrator access
- PowerShell 5.1+
- Internet connectivity

### Steps

```powershell
# 1. Clone/download repository
cd C:\Temp
# Extract files to C:\Temp\network-inventory-planning\

# 2. Navigate to PowerShell solution
cd network-inventory-planning\option2-powershell-native\

# 3. Copy scripts to installation directory
New-Item -ItemType Directory -Path "C:\ProgramData\InventoryAgent" -Force
Copy-Item -Path "*.ps1" -Destination "C:\ProgramData\InventoryAgent\" -Force

# 4. Create Event Log source
New-EventLog -LogName Application -Source "InventoryAgent"

# 5. Create configuration
$Config = @{
    ServerEndpoint = "https://inventory.company.com/api/v1"
    EnableDebounce = $true
    DebounceMinutes = 60
    MaxRetryAttempts = 3
    RetryDelaySeconds = 30
    QueueMaxSize = 1000
    EnableCompression = $false
}
$Config | ConvertTo-Json | Out-File "C:\ProgramData\InventoryAgent\Config.json"

# 6. Test manual collection
cd C:\ProgramData\InventoryAgent
.\Collect-Inventory.ps1 -TriggerType Manual

# 7. Check results
Get-Content "C:\ProgramData\InventoryAgent\Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log" -Tail 20

# 8. Install scheduled tasks (optional)
.\Install-InventoryTasks.ps1
```

**Expected Output**: Log file showing successful collection and (if server running) transmission.

---

## 🚀 Production Deployment Checklist

### Pre-Deployment
- [ ] Read [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
- [ ] Review [Security-Requirements.md](shared-documentation/Security-Requirements.md)
- [ ] Run [Test-DeploymentReadiness.ps1](deployment-tools/Test-DeploymentReadiness.ps1)
- [ ] Obtain code signing certificate
- [ ] Get security team approval

### Security Configuration
- [ ] Sign all scripts with code signing certificate
- [ ] Create AppLocker/WDAC policy from [templates](security-templates/)
- [ ] Request and deploy AV/EDR exclusions
- [ ] Configure network firewall rules
- [ ] Pre-create Event Log source

### Pilot Deployment
- [ ] Select 50-100 pilot systems
- [ ] Create pilot OU in Active Directory
- [ ] Deploy via GPO to pilot group
- [ ] Monitor for 2-4 weeks
- [ ] Validate success rate >95%
- [ ] Get go/no-go approval

### Production Rollout
- [ ] Phased deployment by OU or geography
- [ ] Monitor daily during rollout
- [ ] Validate data quality
- [ ] Complete final documentation
- [ ] Handoff to operations team

---

## 📁 Key Files

| File | Purpose | Audience |
|------|---------|----------|
| [README.md](README.md) | Project overview and navigation | Everyone |
| [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) | Step-by-step deployment instructions | IT Ops |
| [Security-Requirements.md](shared-documentation/Security-Requirements.md) | Comprehensive security documentation | Security Team |
| [Test-DeploymentReadiness.ps1](deployment-tools/Test-DeploymentReadiness.ps1) | Pre-deployment validation script | IT Ops |
| [AppLocker-Rules.xml](security-templates/AppLocker-Rules.xml) | Application control policy template | Security Team |

---

## 🔧 Common Commands

### Check Deployment Status
```powershell
# Verify scripts installed
Test-Path "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"

# Check scheduled tasks
Get-ScheduledTask -TaskName "InventoryAgent-*" | Format-Table TaskName, State

# View recent logs
Get-Content "C:\ProgramData\InventoryAgent\Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log" -Tail 50

# Check Event Log
Get-WinEvent -LogName Application -ProviderName "InventoryAgent" -MaxEvents 20 | Format-Table TimeCreated, LevelDisplayName, Message
```

### Troubleshooting
```powershell
# Run deployment readiness check
cd deployment-tools\
.\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com" -Detailed

# Manually trigger collection
cd C:\ProgramData\InventoryAgent
.\Collect-Inventory.ps1 -TriggerType Manual -Verbose

# Check offline queue
Get-ChildItem "C:\ProgramData\InventoryAgent\Queue" -Filter "*.json"

# Verify script signature
Get-AuthenticodeSignature -FilePath "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"
```

### Security Validation
```powershell
# Check AppLocker policy
Get-AppLockerPolicy -Effective | Test-AppLockerPolicy -Path "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1" -User Everyone

# Check WDAC policy
Get-CimInstance -Namespace root\Microsoft\Windows\CI -ClassName PS_CIPolicyInfo

# Check Defender exclusions
Get-MpPreference | Select-Object -ExpandProperty ExclusionPath
```

---

## 🆘 Quick Troubleshooting

| Problem | Solution |
|---------|----------|
| "Script cannot be loaded" | Sign script: `Set-AuthenticodeSignature -FilePath script.ps1 -Certificate $Cert` |
| "Constrained Language Mode" | ✅ Expected - agent is compatible, no action needed |
| "WMI Access Denied" | Ensure task runs as SYSTEM: `sc.exe qc "InventoryAgent"` |
| "Connection timeout" | Check firewall, proxy, server: `Test-NetConnection inventory.company.com -Port 443` |
| "Queue growing" | Network issue - check server logs and connectivity |

---

## 📞 Getting Help

1. **Check Documentation**:
   - [README.md](README.md) - Overview
   - [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md) - Detailed deployment steps
   - [Security-Requirements.md](shared-documentation/Security-Requirements.md) - Security details
   - Solution-specific READMEs in option1 and option2 folders

2. **Run Diagnostics**:
   ```powershell
   .\deployment-tools\Test-DeploymentReadiness.ps1 -Detailed
   ```

3. **Contact Support**:
   - IT Operations: itops@company.com
   - Security Team: security@company.com
   - Emergency: +1-555-ITOPS

---

## 📊 Success Criteria

**Pilot Success** (before production):
- ✅ 95%+ of pilot systems reporting
- ✅ No critical security violations
- ✅ Collection success rate >95%
- ✅ Data quality validated
- ✅ No performance complaints

**Production Success** (post-rollout):
- ✅ 100% coverage of target systems
- ✅ <1% error rate
- ✅ Data freshness <24 hours
- ✅ Security compliance maintained
- ✅ Minimal support tickets

---

## 🎯 Next Steps

1. **First Time**: Read [README.md](README.md) for project overview
2. **Planning**: Review [DEPLOYMENT_GUIDE.md](DEPLOYMENT_GUIDE.md)
3. **Security**: Study [Security-Requirements.md](shared-documentation/Security-Requirements.md)
4. **Testing**: Run on test machine using instructions above
5. **Deployment**: Follow phased rollout in deployment guide

---

**Quick Reference Version**: 1.0.0
**Last Updated**: 2024-10-24

For complete documentation, see [README.md](README.md)
