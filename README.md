# Windows Active Directory Inventory Management System

## 📋 Project Overview

This repository contains comprehensive planning, documentation, and implementation artifacts for deploying an automated hardware inventory management system across a Windows Active Directory environment.

**Last Updated**: 2024-10-24
**Status**: Ready for Deployment
**Version**: 2.1.0

---

## 🎯 Purpose

Automate the collection, storage, and reporting of hardware inventory information from Windows 11 workstations including:
- System serial numbers and hardware specifications
- Disk serial numbers and storage information
- Network adapter MAC addresses and IP configurations
- User login history and system assignments
- Operating system versions and update status

---

## 📁 Repository Structure

```
network-inventory-planning/
├── README.md                           ← You are here
├── option1-dotnet-compiled/            ← Compiled .NET Windows Service solution
│   ├── README.md
│   └── [.NET source code and artifacts]
├── option2-powershell-native/          ← PowerShell native solution (RECOMMENDED)
│   ├── README.md
│   ├── Collect-Inventory.ps1          ← Security-hardened collection script
│   └── Install-InventoryTasks.ps1     ← Scheduled task installation
├── security-templates/                 ← Security policies and templates
│   ├── AppLocker-Rules.xml            ← AppLocker policy template
│   └── Create-WDACPolicy.ps1          ← WDAC policy generator
├── deployment-tools/                   ← Deployment validation and testing
│   └── Test-DeploymentReadiness.ps1   ← Pre-deployment security checker
├── shared-documentation/               ← Cross-solution documentation
│   └── Security-Requirements.md        ← Comprehensive security guide
├── inventory_system_prd.md            ← Product Requirements Document
├── inventory_system_architecture.md   ← Technical Architecture Document
├── option1_compiled_client.md         ← Option 1 detailed design
└── option2_powershell_solution.md     ← Option 2 detailed design
```

---

## 🚀 Quick Start

### Choose Your Solution

| Solution | Best For | Deployment Complexity | Maintenance | Security |
|----------|----------|----------------------|-------------|----------|
| **Option 2: PowerShell** | Most environments | ⭐⭐ Easy | ⭐⭐⭐ Simple | ⭐⭐⭐ High |
| **Option 1: .NET Compiled** | Enterprise scale (10k+ endpoints) | ⭐⭐⭐ Complex | ⭐⭐ Moderate | ⭐⭐⭐ High |

**Recommendation**: Start with **Option 2 (PowerShell)** for easier deployment and maintenance.

### Option 2: PowerShell Native (Recommended)

**Why Choose This**:
- ✅ No compilation required
- ✅ Easy to modify and customize
- ✅ Works in Constrained Language Mode
- ✅ Compatible with AppLocker/WDAC
- ✅ Simple GPO-based deployment
- ✅ Native Windows tools only

**Get Started**:
```bash
cd option2-powershell-native/
# Read the README for detailed instructions
```

**5-Minute Deployment** (for testing):
1. Sign the scripts with your code signing certificate
2. Copy to `C:\ProgramData\InventoryAgent\`
3. Run `Install-InventoryTasks.ps1` as Administrator
4. Verify with `Test-InventoryAgent.ps1`

### Option 1: Compiled .NET Service

**Why Choose This**:
- ✅ Better performance at scale
- ✅ Runs as Windows Service
- ✅ Real-time event monitoring
- ✅ More difficult to tamper with

**Get Started**:
```bash
cd option1-dotnet-compiled/
# Read the README for build and deployment instructions
```

---

## 🔐 Security Considerations

### ⚠️ CRITICAL: Read This Before Deployment

**For Restrictive Security Environments**, you MUST address these requirements:

1. **Code Signing** (REQUIRED):
   - All scripts and executables must be digitally signed
   - See: `shared-documentation/Security-Requirements.md` Section 1

2. **Application Control** (AppLocker/WDAC):
   - Configure policies to allow inventory agent
   - Templates: `security-templates/AppLocker-Rules.xml`
   - Generator: `security-templates/Create-WDACPolicy.ps1`

3. **PowerShell Security**:
   - Execution Policy: RemoteSigned or AllSigned
   - Constrained Language Mode: Fully supported
   - See: Security Requirements Section 3

4. **Antivirus/EDR Exclusions**:
   - Coordinate with security team for required exclusions
   - See: Security Requirements Section 8

5. **Network Security**:
   - Firewall rules for outbound HTTPS
   - Proxy authentication support included
   - See: Security Requirements Section 6

### 🛡️ Security Checklist

Before deployment, complete the **Pre-Deployment Security Checklist**:

```powershell
# Run the deployment readiness checker
cd deployment-tools/
.\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com" -Detailed
```

This script checks for:
- ✅ PowerShell version and execution policy
- ✅ Constrained Language Mode compatibility
- ✅ AppLocker/WDAC policies
- ✅ WMI/CIM access permissions
- ✅ Event Log access
- ✅ Network connectivity and proxy configuration
- ✅ Certificate store access
- ✅ Antivirus/EDR status
- ✅ File system permissions
- ✅ Scheduled task capability

---

## 📚 Documentation

### Core Documentation

| Document | Description | Audience |
|----------|-------------|----------|
| [Product Requirements (PRD)](inventory_system_prd.md) | Business requirements and success criteria | All stakeholders |
| [Technical Architecture](inventory_system_architecture.md) | System design and infrastructure | Technical teams |
| [Security Requirements](shared-documentation/Security-Requirements.md) | Comprehensive security guide | Security team, IT Ops |

### Solution-Specific Documentation

| Document | Description |
|----------|-------------|
| [Option 1: .NET Compiled](option1_compiled_client.md) | Detailed design for compiled solution |
| [Option 2: PowerShell Native](option2_powershell_solution.md) | Detailed design for PowerShell solution |
| [Option 2 README](option2-powershell-native/README.md) | Quick start guide for PowerShell solution |

### Security and Compliance

| Document | Purpose |
|----------|---------|
| [Security Requirements](shared-documentation/Security-Requirements.md) | Complete security controls documentation |
| [AppLocker Policy](security-templates/AppLocker-Rules.xml) | Application control policy template |
| [WDAC Policy Generator](security-templates/Create-WDACPolicy.ps1) | Windows Defender Application Control setup |

---

## 🎓 Implementation Guide

### Phase 1: Planning and Preparation (Week 1-2)

**Tasks**:
1. Review all documentation
2. Choose implementation option (PowerShell or .NET)
3. Obtain code signing certificate
4. Review security requirements with security team
5. Identify pilot group (50-100 systems)
6. Set up server infrastructure

**Deliverables**:
- [ ] Implementation decision documented
- [ ] Code signing certificate obtained
- [ ] Security requirements approved
- [ ] Pilot group identified
- [ ] Server deployed and tested

### Phase 2: Security Configuration (Week 2-3)

**Tasks**:
1. Create and sign all scripts/executables
2. Create AppLocker/WDAC policies
3. Test in isolated environment
4. Request AV/EDR exclusions
5. Configure network firewall rules
6. Set up monitoring and logging

**Deliverables**:
- [ ] All code digitally signed
- [ ] AppLocker/WDAC policies created and tested
- [ ] AV/EDR exclusions approved
- [ ] Firewall rules documented
- [ ] Monitoring configured

### Phase 3: Pilot Deployment (Week 3-6)

**Tasks**:
1. Run deployment readiness checker on pilot systems
2. Deploy to pilot group via GPO
3. Monitor for issues (security alerts, collection failures)
4. Gather feedback
5. Tune configurations based on results
6. Document lessons learned

**Deliverables**:
- [ ] Pilot deployment successful
- [ ] No critical security alerts
- [ ] Collection success rate >95%
- [ ] Issues documented and resolved
- [ ] Go/no-go decision for production

### Phase 4: Production Rollout (Week 6-10)

**Tasks**:
1. Update deployment based on pilot learnings
2. Create phased rollout plan (by OU or geography)
3. Deploy to production in waves
4. Monitor continuously
5. Provide user support
6. Complete final documentation

**Deliverables**:
- [ ] 100% of target systems have agent deployed
- [ ] Collection success rate >95%
- [ ] Security monitoring active
- [ ] Help desk trained
- [ ] Final documentation complete

---

## 🔧 Deployment Tools

### Test-DeploymentReadiness.ps1

Pre-deployment validation script that checks for common security blockers.

**Usage**:
```powershell
.\deployment-tools\Test-DeploymentReadiness.ps1 -ServerEndpoint "https://inventory.company.com" -Detailed -ExportReport
```

**Checks Performed**:
- PowerShell environment (version, execution policy, language mode)
- Application control (AppLocker, WDAC)
- WMI/CIM access
- Event Log permissions
- Network connectivity (DNS, TCP, HTTPS, proxy)
- Certificate store access
- Security software (AV/EDR)
- File system permissions
- Scheduled task capability

**Output**:
- Console summary with color-coded results
- Detailed remediation guidance
- JSON report (optional)
- Exit code: 0 (ready) or 1 (issues found)

---

## 🐛 Troubleshooting

### Common Issues and Solutions

#### Issue: "Script cannot be loaded because running scripts is disabled"

**Cause**: Execution policy restriction

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Option 1: Change policy (requires admin)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# Option 2: Sign the script (RECOMMENDED)
$Cert = Get-ChildItem Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1
Set-AuthenticodeSignature -FilePath ".\Collect-Inventory.ps1" -Certificate $Cert
```

#### Issue: AppLocker blocking script execution

**Cause**: No AppLocker rule allowing the script

**Solution**:
```powershell
# Import provided AppLocker policy
Set-AppLockerPolicy -XMLPolicy ".\security-templates\AppLocker-Rules.xml" -Merge

# Or create custom rule
New-AppLockerPolicy -RuleType Publisher -Path "C:\ProgramData\InventoryAgent\*.ps1" -User Everyone -Action Allow
```

#### Issue: "Constrained Language Mode" warning

**Status**: ✅ Expected and supported

The PowerShell agent is fully compatible with Constrained Language Mode. Compression is automatically disabled.

#### Issue: WMI Access Denied

**Cause**: Agent not running as SYSTEM

**Solution**:
Verify scheduled task runs as `NT AUTHORITY\SYSTEM`:
```powershell
Get-ScheduledTask -TaskName "InventoryAgent-*" | ForEach-Object {
    $Info = Get-ScheduledTaskInfo -TaskName $_.TaskName
    [PSCustomObject]@{
        TaskName = $_.TaskName
        User = $_.Principal.UserId
        RunLevel = $_.Principal.RunLevel
    }
}
```

#### Issue: Connection timeouts or network errors

**Causes**:
- Firewall blocking outbound HTTPS
- Proxy authentication required
- Server not reachable

**Solutions**:
```powershell
# Test connectivity
Test-NetConnection -ComputerName inventory.company.com -Port 443

# Check proxy settings
netsh winhttp show proxy

# Configure proxy in agent config
$Config = Get-Content "C:\ProgramData\InventoryAgent\Config.json" | ConvertFrom-Json
$Config.UseProxy = $true
$Config.ProxyServer = "http://proxy.company.com:8080"
$Config | ConvertTo-Json | Out-File "C:\ProgramData\InventoryAgent\Config.json"
```

---

## 📊 Monitoring and Maintenance

### Daily Monitoring

**Check**:
- Collection success rate
- Network errors
- Security alerts from AV/EDR

**Script**:
```powershell
# Get today's collection statistics
Get-WinEvent -LogName Application -ProviderName "InventoryAgent" |
    Where-Object {$_.TimeCreated -gt (Get-Date).AddDays(-1)} |
    Group-Object Id |
    Select-Object Count, @{Name="EventType";Expression={
        switch($_.Name) {
            1000 {"Started"}
            1001 {"Completed"}
            1002 {"Failed"}
            1003 {"Security"}
        }
    }}
```

### Weekly Monitoring

**Check**:
- Code signing certificate expiration
- AppLocker/WDAC policy violations
- Offline queue buildup

### Monthly Maintenance

**Tasks**:
- Review security audit logs
- Check agent version distribution
- Validate data accuracy
- Update documentation

---

## 📈 Success Metrics

Track these KPIs to measure deployment success:

| Metric | Target | Measurement |
|--------|--------|-------------|
| **Inventory Coverage** | >95% of AD-joined Windows 11 systems | Systems reporting / Total systems |
| **Collection Success Rate** | >95% | Successful collections / Total attempts |
| **Data Freshness** | <24 hours | Time since last collection |
| **Network Reliability** | <1% timeout rate | Failed transmissions / Total attempts |
| **Security Compliance** | 0 critical violations | AppLocker/WDAC blocks, AV alerts |
| **Performance Impact** | <1% CPU, <100MB RAM | Resource monitoring |

---

## 🤝 Contributing

This is an internal project. For questions, issues, or improvements:

**Contact**:
- IT Operations: itops@company.com
- Security Team: security@company.com
- Project Owner: [Your Name]

**Process**:
1. Document the issue or enhancement request
2. Review with security team (if security-related)
3. Test changes in isolated environment
4. Update documentation
5. Deploy to pilot group before production

---

## 📝 Version History

| Version | Date | Changes | Author |
|---------|------|---------|--------|
| 2.1.0 | 2024-10-24 | Security hardening for restrictive environments | IT Security |
| 2.0.0 | 2024-10-20 | Initial PowerShell native solution | IT Operations |
| 1.0.0 | 2024-10-15 | Project planning and architecture | IT Operations |

---

## 📄 License

**Internal Use Only** - YourCompany IT Department

This inventory system and all associated documentation are proprietary to YourCompany and intended for internal use only. Do not distribute outside the organization.

---

## 🔗 Related Resources

### Internal Links

- **IT Operations Wiki**: [Link to internal wiki]
- **Security Policies**: [Link to security policy portal]
- **Change Management**: [Link to change request system]
- **Service Desk**: [Link to ticketing system]

### External Resources

- [Microsoft PowerShell Documentation](https://docs.microsoft.com/powershell/)
- [AppLocker Overview](https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/applocker/applocker-overview)
- [Windows Defender Application Control](https://docs.microsoft.com/windows/security/threat-protection/windows-defender-application-control/windows-defender-application-control)
- [PowerShell Security Best Practices](https://docs.microsoft.com/powershell/scripting/learn/security-features)

---

## 🆘 Support

### Getting Help

1. **Documentation**: Check the relevant README and documentation first
2. **Troubleshooting**: Run `Test-DeploymentReadiness.ps1` for diagnostics
3. **Security Questions**: Review `Security-Requirements.md`
4. **Technical Issues**: Contact IT Operations
5. **Security Concerns**: Contact Security Team immediately

### Emergency Contacts

**Critical Security Issues**:
- Email: security-incident@company.com
- Phone: +1-555-SECURITY (24/7)

**Production Outage**:
- Email: itops-oncall@company.com
- Phone: +1-555-ITOPS (24/7)

---

**Last Updated**: 2024-10-24
**Document Owner**: IT Operations
**Review Schedule**: Quarterly

---

## 🎯 Next Steps

**Ready to Deploy?**

1. ✅ **Read the documentation** - Start with the PRD and Security Requirements
2. ✅ **Choose your solution** - Option 2 (PowerShell) recommended for most
3. ✅ **Run readiness checker** - Validate your environment
4. ✅ **Review security requirements** - Coordinate with security team
5. ✅ **Deploy to pilot group** - Test with 50-100 systems first
6. ✅ **Monitor and validate** - 2-4 weeks before production rollout
7. ✅ **Go to production** - Phased deployment via GPO

**Questions?** Contact IT Operations: itops@company.com

---

**END OF README**
