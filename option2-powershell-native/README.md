# Option 2: PowerShell Native Solution

## Overview

This solution provides a lightweight, PowerShell-based inventory agent that requires no compilation and can be easily deployed via Group Policy. It's designed to work in restrictive security environments with full support for:

- ✅ Constrained Language Mode
- ✅ AppLocker / WDAC policies
- ✅ Code signing requirements
- ✅ Antivirus / EDR coexistence
- ✅ Enterprise proxy configurations
- ✅ Offline queue management

## 🔐 Security Enhancements (v2.1.0)

This version includes critical security improvements for restrictive environments:

### ✅ Fixed Critical Issues:
1. **Removed .NET compression** - Now compatible with Constrained Language Mode
2. **Added TLS 1.2 enforcement** - Meets modern security standards
3. **Enhanced proxy support** - Includes authentication
4. **Improved error handling** - Graceful degradation when permissions limited
5. **Script signature validation** - Verifies own integrity on execution
6. **Security audit logging** - Separate event channel for security events

### ✅ New Features:
- Environment detection (Language Mode, Execution Policy, Elevation)
- Comprehensive logging to both file and Event Log
- Automatic adaptation to Constrained Language Mode
- Certificate-based server authentication
- Configurable proxy with default credential support

## 📁 Files Included

| File | Purpose |
|------|---------|
| `Collect-Inventory.ps1` | Main inventory collection script (Security Hardened v2.1.0) |
| `Install-InventoryTasks.ps1` | Creates scheduled tasks for automated collection |
| `README.md` | This file |

## 🚀 Quick Start

### Prerequisites

1. **PowerShell 5.1 or higher** (built into Windows 10/11)
2. **Administrator privileges** (for installation only)
3. **Code signing certificate** (for production deployment)
4. **Network connectivity** to inventory server

### Installation Steps

#### Step 1: Sign the Scripts (REQUIRED for production)

```powershell
# Get your code signing certificate
$Cert = Get-ChildItem -Path Cert:\CurrentUser\My -CodeSigningCert | Select-Object -First 1

# Sign all scripts
Set-AuthenticodeSignature -FilePath ".\Collect-Inventory.ps1" -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"
Set-AuthenticodeSignature -FilePath ".\Install-InventoryTasks.ps1" -Certificate $Cert -TimestampServer "http://timestamp.digicert.com"

# Verify signatures
Get-AuthenticodeSignature -FilePath ".\Collect-Inventory.ps1"
Get-AuthenticodeSignature -FilePath ".\Install-InventoryTasks.ps1"
```

#### Step 2: Deploy Scripts

```powershell
# Create installation directory
New-Item -ItemType Directory -Path "C:\ProgramData\InventoryAgent" -Force

# Copy scripts
Copy-Item -Path ".\Collect-Inventory.ps1" -Destination "C:\ProgramData\InventoryAgent\" -Force
Copy-Item -Path ".\Install-InventoryTasks.ps1" -Destination "C:\ProgramData\InventoryAgent\" -Force
```

#### Step 3: Configure Settings

Edit the configuration (or deploy via Group Policy Registry settings):

```json
{
    "ServerEndpoint": "https://inventory.company.com/api/v1",
    "ApiKey": "",
    "CertificateThumbprint": "",
    "EnableDebounce": true,
    "DebounceMinutes": 60,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 30,
    "QueueMaxSize": 1000,
    "EnableCompression": false,
    "UseProxy": false,
    "ProxyServer": "",
    "ProxyUseDefaultCredentials": true,
    "ConnectionTimeoutSeconds": 30,
    "ValidateServerCertificate": true
}
```

Save as: `C:\ProgramData\InventoryAgent\Config.json`

#### Step 4: Create Event Log Source

```powershell
# Must be run as Administrator
New-EventLog -LogName Application -Source "InventoryAgent"
```

#### Step 5: Install Scheduled Tasks

```powershell
# Run as Administrator
cd C:\ProgramData\InventoryAgent
.\Install-InventoryTasks.ps1 -ValidateSignature
```

This creates three scheduled tasks:
- **InventoryAgent-DailyCollection**: Runs daily at 2:00 AM
- **InventoryAgent-LogonCollection**: Runs when any user logs on
- **InventoryAgent-ProcessQueue**: Runs every 4 hours to process offline queue

#### Step 6: Test Manual Collection

```powershell
# Run a test collection
.\Collect-Inventory.ps1 -TriggerType Manual -Username $env:USERNAME
```

Check logs:
```powershell
# View log file
Get-Content "C:\ProgramData\InventoryAgent\Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log" -Tail 20

# View Event Log
Get-WinEvent -LogName Application -ProviderName "InventoryAgent" -MaxEvents 10 | Format-List
```

## 📋 Configuration Options

### Server Settings

| Setting | Description | Default | Required |
|---------|-------------|---------|----------|
| `ServerEndpoint` | Inventory server API URL | `https://inventory.company.com/api/v1` | ✅ Yes |
| `ApiKey` | Bearer token for API authentication | (empty) | Optional |
| `CertificateThumbprint` | Client certificate for mTLS | (empty) | Optional |

### Collection Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `EnableDebounce` | Prevent duplicate collections within time window | `true` |
| `DebounceMinutes` | Minutes between collections for same user | `60` |
| `MaxRetryAttempts` | Number of retries for failed transmissions | `3` |
| `RetryDelaySeconds` | Base delay between retries (exponential backoff) | `30` |
| `QueueMaxSize` | Maximum offline queue items | `1000` |

### Network Settings

| Setting | Description | Default |
|---------|-------------|---------|
| `EnableCompression` | GZIP compression (disabled for CLM compatibility) | `false` |
| `UseProxy` | Enable proxy configuration | `false` |
| `ProxyServer` | Proxy server URL | (empty) |
| `ProxyUseDefaultCredentials` | Use SYSTEM account for proxy auth | `true` |
| `ConnectionTimeoutSeconds` | HTTP request timeout | `30` |
| `ValidateServerCertificate` | Enforce SSL certificate validation | `true` |

## 🔧 Troubleshooting

### Issue: Script won't run - "Execution policy does not allow"

**Solution**:
```powershell
# Check current policy
Get-ExecutionPolicy

# Set to RemoteSigned (requires admin)
Set-ExecutionPolicy RemoteSigned -Scope LocalMachine

# OR sign the script with your code signing certificate (recommended)
```

### Issue: Script runs but shows "Constrained Language Mode" warning

**Status**: ✅ This is expected and supported

The agent automatically disables compression and adapts to Constrained Language Mode. No action required.

### Issue: WMI Access Denied errors

**Solution**:
The agent must run as `NT AUTHORITY\SYSTEM` via scheduled task. Verify:

```powershell
Get-ScheduledTask -TaskName "InventoryAgent-*" | Select-Object TaskName, TaskPath, @{Name="User";Expression={(Get-ScheduledTaskInfo $_).Principal.UserId}}
```

Should show: `NT AUTHORITY\SYSTEM`

### Issue: Connection timeout or proxy errors

**Solution 1**: Check proxy configuration
```powershell
netsh winhttp show proxy
```

**Solution 2**: Configure proxy in Config.json
```json
{
    "UseProxy": true,
    "ProxyServer": "http://proxy.company.com:8080",
    "ProxyUseDefaultCredentials": true
}
```

**Solution 3**: Add to proxy bypass list
```powershell
netsh winhttp set proxy proxy-server="proxy:8080" bypass-list="inventory.company.com"
```

### Issue: Inventory data not appearing on server

**Check**:
1. Queue directory for pending items:
   ```powershell
   Get-ChildItem "C:\ProgramData\InventoryAgent\Queue" -Filter "*.json"
   ```

2. Network connectivity:
   ```powershell
   Test-NetConnection -ComputerName inventory.company.com -Port 443
   ```

3. Firewall rules (outbound HTTPS allowed)

4. Server logs for received data

### Issue: AppLocker/WDAC blocking script execution

**Solution**: See `../security-templates/AppLocker-Rules.xml` for required policies

Import policy:
```powershell
Set-AppLockerPolicy -XMLPolicy "..\security-templates\AppLocker-Rules.xml" -Merge
```

## 📊 Monitoring and Maintenance

### View Scheduled Task Status

```powershell
Get-ScheduledTask -TaskName "InventoryAgent-*" | Get-ScheduledTaskInfo | Format-Table TaskName, LastRunTime, NextRunTime, LastTaskResult
```

### View Collection Logs

```powershell
# Today's file log
Get-Content "C:\ProgramData\InventoryAgent\Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log"

# Event log (last 50 events)
Get-WinEvent -LogName Application -ProviderName "InventoryAgent" -MaxEvents 50 | Format-Table TimeCreated, Id, LevelDisplayName, Message
```

### Check Offline Queue

```powershell
$QueuePath = "C:\ProgramData\InventoryAgent\Queue"
$QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json"

Write-Host "Queued Items: $($QueueFiles.Count)"

if ($QueueFiles.Count -gt 0) {
    Write-Host "Oldest: $($QueueFiles | Sort-Object CreationTime | Select-Object -First 1 | Select-Object Name, CreationTime)"
    Write-Host "Newest: $($QueueFiles | Sort-Object CreationTime -Descending | Select-Object -First 1 | Select-Object Name, CreationTime)"
}
```

### Manual Queue Processing

```powershell
# Process offline queue immediately
. "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"
Process-OfflineQueue
```

### Update Configuration Remotely (via GPO Registry)

```powershell
# Set registry values via GPO
$RegPath = "HKLM:\SOFTWARE\YourCompany\InventoryAgent"
New-Item -Path $RegPath -Force
Set-ItemProperty -Path $RegPath -Name "ServerEndpoint" -Value "https://new-server.company.com/api/v1"
Set-ItemProperty -Path $RegPath -Name "DebounceMinutes" -Value 120
```

Agent automatically reads registry values on next run.

## 🔐 Security Best Practices

### ✅ DO:

1. **Sign all scripts** with organizational code signing certificate
2. **Deploy via GPO** for centralized management
3. **Use AppLocker or WDAC** to enforce execution policies
4. **Monitor Event Logs** for security events (Event ID 1003)
5. **Implement TLS 1.2+** on server endpoint
6. **Use certificate-based authentication** (mTLS) for high-security environments
7. **Review logs monthly** for anomalies
8. **Test in pilot group** before production deployment
9. **Document exclusions** required for AV/EDR
10. **Maintain offline backups** of signed scripts

### ❌ DON'T:

1. **Don't use unsigned scripts** in production
2. **Don't run with Unrestricted execution policy** globally
3. **Don't disable SSL certificate validation** (except for testing)
4. **Don't store API keys** in plaintext config files (use certificate auth instead)
5. **Don't disable antivirus** - request proper exclusions instead
6. **Don't skip testing** in restricted environments
7. **Don't ignore Constrained Language Mode** warnings
8. **Don't deploy without reviewing** Security Requirements document
9. **Don't collect more data** than necessary (privacy/GDPR)
10. **Don't forget to renew** code signing certificates annually

## 📚 Additional Resources

- **Security Requirements**: `../shared-documentation/Security-Requirements.md`
- **AppLocker Policy Template**: `../security-templates/AppLocker-Rules.xml`
- **WDAC Policy Generator**: `../security-templates/Create-WDACPolicy.ps1`
- **Deployment Readiness Checker**: `../deployment-tools/Test-DeploymentReadiness.ps1`

## 🆘 Support

**Documentation**: See `../shared-documentation/` folder
**Security Questions**: Review Security-Requirements.md first
**Deployment Issues**: Run Test-DeploymentReadiness.ps1 for diagnostics

## 📝 Version History

| Version | Date | Changes |
|---------|------|---------|
| 2.1.0 | 2024-10-24 | Security hardening for restrictive environments |
| 2.0.0 | 2024-10-20 | Initial PowerShell native solution |

## 📄 License

Internal use only - YourCompany IT Department
