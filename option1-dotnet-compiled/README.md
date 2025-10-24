# Option 1: Compiled .NET Windows Service

## Overview

This solution provides a high-performance, compiled C#/.NET Windows Service that runs continuously on each Windows 11 client. It offers better performance and real-time event monitoring compared to the PowerShell solution, making it ideal for large enterprise deployments (10,000+ endpoints).

## 🎯 When to Choose This Option

**Choose Option 1 if you need**:
- ✅ **Enterprise scale**: 10,000+ endpoints
- ✅ **Real-time processing**: Immediate logon event detection
- ✅ **Better performance**: Lower resource overhead
- ✅ **Binary security**: Harder to tamper with compiled code
- ✅ **Advanced features**: Performance counters, WMI event subscriptions
- ✅ **Windows Service**: Always-on background service

**Choose Option 2 (PowerShell) if you have**:
- <10,000 endpoints
- Need easy customization
- Limited development resources
- Simpler deployment requirements

## 📋 Features

### Core Capabilities
- Real-time user logon event detection
- Scheduled daily inventory collection
- Comprehensive hardware enumeration
- Offline queue with SQLite database
- Certificate-based authentication
- Automatic retry with exponential backoff
- Windows Event Log integration
- Performance counter monitoring

### Security Features
- Code signing support (Authenticode)
- Certificate-based mutual TLS
- Encrypted local storage
- Audit logging
- Tamper detection
- Windows Service hardening

## 🏗️ Architecture

```
┌─────────────────────────────────────┐
│     Windows 11 Client               │
│                                     │
│  ┌──────────────────────────────┐  │
│  │  InventoryAgent.exe          │  │
│  │  (Windows Service)           │  │
│  │                              │  │
│  │  ├── Event Monitor Thread    │  │
│  │  │   (Security Event 4624)   │  │
│  │  │                           │  │
│  │  ├── Scheduled Collection    │  │
│  │  │   (Timer: 24hr)           │  │
│  │  │                           │  │
│  │  ├── WMI Data Collectors     │  │
│  │  │   ├── System Info         │  │
│  │  │   ├── Disk Info           │  │
│  │  │   └── Network Info        │  │
│  │  │                           │  │
│  │  ├── HTTPS Client            │  │
│  │  │   (Polly retry policies)  │  │
│  │  │                           │  │
│  │  └── Offline Queue           │  │
│  │      (SQLite database)       │  │
│  └──────────────────────────────┘  │
│                                     │
│  Local Storage:                     │
│  C:\ProgramData\InventoryAgent\     │
│  ├── config.json                    │
│  ├── queue.db (SQLite)              │
│  └── logs\                          │
└─────────────────────────────────────┘
```

## 📁 Project Structure

```
option1-dotnet-compiled/
├── README.md                      ← This file
├── src/                          ← Source code (to be created)
│   ├── InventoryAgent.sln
│   ├── InventoryAgent/
│   │   ├── InventoryAgent.csproj
│   │   ├── Program.cs
│   │   ├── Services/
│   │   │   ├── InventoryAgentService.cs
│   │   │   ├── EventMonitorService.cs
│   │   │   └── ScheduledCollectionService.cs
│   │   ├── Collectors/
│   │   │   ├── SystemInfoCollector.cs
│   │   │   ├── DiskInfoCollector.cs
│   │   │   └── NetworkInfoCollector.cs
│   │   ├── Communication/
│   │   │   ├── ApiClient.cs
│   │   │   └── OfflineQueue.cs
│   │   └── Models/
│   │       └── InventoryData.cs
│   └── InventoryAgent.Installer/
│       └── (WiX installer project)
├── build/                        ← Build scripts
│   ├── build.ps1
│   └── sign.ps1
└── deploy/                       ← Deployment artifacts
    ├── InventoryAgent.msi
    └── Deploy-via-GPO.ps1
```

## 🚀 Building the Solution

### Prerequisites

**Required Software**:
- Visual Studio 2022 (Community Edition or higher)
- .NET 6.0 SDK or higher
- WiX Toolset 3.11+ (for MSI creation)
- Code signing certificate
- NuGet package manager

**NuGet Packages**:
```xml
<PackageReference Include="Microsoft.Extensions.Hosting" Version="7.0.0" />
<PackageReference Include="Microsoft.Extensions.Hosting.WindowsServices" Version="7.0.0" />
<PackageReference Include="Microsoft.Extensions.Logging.EventLog" Version="7.0.0" />
<PackageReference Include="System.Management" Version="7.0.0" />
<PackageReference Include="Polly" Version="7.2.3" />
<PackageReference Include="Microsoft.Data.Sqlite" Version="7.0.0" />
```

### Build Steps

#### 1. Restore Dependencies
```powershell
cd src/InventoryAgent
dotnet restore
```

#### 2. Build Solution
```powershell
# Debug build
dotnet build -c Debug

# Release build
dotnet build -c Release
```

#### 3. Publish Self-Contained
```powershell
dotnet publish -c Release -r win-x64 --self-contained false -o .\publish\
```

#### 4. Sign the Executable
```powershell
# Sign with Authenticode
$CertThumbprint = "YOUR_CODE_SIGNING_CERT_THUMBPRINT"
$ExePath = ".\publish\InventoryAgent.exe"

& signtool sign /sha1 $CertThumbprint /t http://timestamp.digicert.com /fd SHA256 /v $ExePath

# Verify signature
& signtool verify /pa /v $ExePath
```

#### 5. Create MSI Installer (Optional)
```powershell
# Using WiX Toolset
cd ..\InventoryAgent.Installer

# Compile WiX source
& candle.exe -arch x64 InventoryAgent.wxs -o InventoryAgent.wixobj

# Link and create MSI
& light.exe InventoryAgent.wixobj -o ..\publish\InventoryAgent.msi

# Sign the MSI
& signtool sign /sha1 $CertThumbprint /t http://timestamp.digicert.com /fd SHA256 /v ..\publish\InventoryAgent.msi
```

## 📦 Installation

### Manual Installation (for testing)

```powershell
# Install the service
sc.exe create "InventoryAgent" binPath= "C:\Program Files\InventoryAgent\InventoryAgent.exe" start= auto

# Configure service
sc.exe description "InventoryAgent" "Collects hardware inventory information"
sc.exe config "InventoryAgent" obj= "NT AUTHORITY\SYSTEM"

# Start service
sc.exe start "InventoryAgent"

# Verify status
sc.exe query "InventoryAgent"
```

### MSI Installation (via GPO)

```powershell
# Install silently
msiexec.exe /i InventoryAgent.msi /quiet /qn /norestart /log install.log SERVERENDPOINT="https://inventory.company.com"

# Uninstall
msiexec.exe /x {PRODUCT-GUID} /quiet /qn /norestart
```

### Group Policy Deployment

**GPO Path**:
```
Computer Configuration > Policies > Software Settings > Software Installation
```

**Steps**:
1. Copy InventoryAgent.msi to SYSVOL:
   ```
   \\domain.com\SYSVOL\domain.com\Software\InventoryAgent.msi
   ```

2. Create new GPO: "Deploy Inventory Agent"

3. Add software installation:
   - Right-click Software Installation → New → Package
   - Select InventoryAgent.msi
   - Deployment Method: Assigned

4. Configure installation properties:
   - Advanced → Command Line Parameters:
     ```
     SERVERENDPOINT=https://inventory.company.com CERTIFICATETHUMBPRINT=ABC123...
     ```

5. Link GPO to target OU

6. Force update on clients:
   ```powershell
   gpupdate /force
   ```

## ⚙️ Configuration

### appsettings.json

```json
{
  "Logging": {
    "LogLevel": {
      "Default": "Information",
      "Microsoft": "Warning"
    },
    "EventLog": {
      "LogLevel": {
        "Default": "Information"
      }
    }
  },
  "AgentSettings": {
    "ServerEndpoint": "https://inventory.company.com",
    "CertificateThumbprint": "",
    "CollectionIntervalHours": 24,
    "EnableLoginDetection": true,
    "OfflineQueueSize": 1000,
    "MaxRetryAttempts": 3,
    "RetryDelaySeconds": 30,
    "ConnectionTimeoutSeconds": 30
  }
}
```

### Registry Configuration (via GPO)

```powershell
# Configure via registry
$RegPath = "HKLM:\SOFTWARE\YourCompany\InventoryAgent"
New-Item -Path $RegPath -Force

Set-ItemProperty -Path $RegPath -Name "ServerEndpoint" -Value "https://inventory.company.com"
Set-ItemProperty -Path $RegPath -Name "CollectionIntervalHours" -Value 24 -Type DWord
Set-ItemProperty -Path $RegPath -Name "EnableLoginDetection" -Value 1 -Type DWord
```

Registry settings override appsettings.json.

## 🔧 Troubleshooting

### Service Won't Start

**Check**:
1. Service account permissions:
   ```powershell
   sc.exe qc "InventoryAgent"
   ```

2. Event Log for errors:
   ```powershell
   Get-WinEvent -LogName Application -ProviderName "InventoryAgent" -MaxEvents 10 | Format-List
   ```

3. File permissions:
   ```powershell
   Get-Acl "C:\Program Files\InventoryAgent" | Format-List
   ```

**Common Issues**:
- **Missing .NET Runtime**: Install .NET 6.0 Runtime
- **Access Denied**: Verify service runs as SYSTEM
- **Missing Config**: Check appsettings.json exists

### WMI Access Errors

**Cause**: Service account lacks WMI permissions

**Solution**: Ensure service runs as `NT AUTHORITY\SYSTEM` (has full WMI access)

```powershell
sc.exe config "InventoryAgent" obj= "NT AUTHORITY\SYSTEM"
sc.exe stop "InventoryAgent"
sc.exe start "InventoryAgent"
```

### Network Connection Failures

**Check**:
1. Network connectivity:
   ```powershell
   Test-NetConnection -ComputerName inventory.company.com -Port 443
   ```

2. Certificate validation:
   ```powershell
   # Test HTTPS connection
   Invoke-WebRequest -Uri "https://inventory.company.com/health"
   ```

3. Firewall rules:
   ```powershell
   Get-NetFirewallRule | Where-Object {$_.DisplayName -like "*Inventory*"}
   ```

**Solution**: Add firewall rule for the service executable

### Offline Queue Growing

**Check Queue Size**:
```powershell
# SQLite database size
$QueueDB = "C:\ProgramData\InventoryAgent\queue.db"
$Size = (Get-Item $QueueDB).Length / 1MB
Write-Host "Queue Size: $Size MB"

# Query queue count
# Requires SQLite tools
sqlite3 queue.db "SELECT COUNT(*) FROM queue;"
```

**Solution**: Investigate network issues preventing transmission

## 📊 Monitoring

### Windows Event Log

**Event Source**: `InventoryAgent`
**Log Name**: `Application`

**Event IDs**:
- 1000: Service started
- 1001: Service stopped
- 1002: Collection completed
- 1003: Collection failed
- 1004: Network error
- 1005: WMI error

**Query Events**:
```powershell
Get-WinEvent -LogName Application -ProviderName "InventoryAgent" -MaxEvents 100 |
    Select-Object TimeCreated, Id, LevelDisplayName, Message |
    Format-Table -AutoSize
```

### Performance Counters

**Custom Counters**:
- `Inventory Agent\Collections Per Hour`
- `Inventory Agent\API Call Duration`
- `Inventory Agent\Offline Queue Size`

**Query Counters**:
```powershell
Get-Counter -Counter "\Inventory Agent\Collections Per Hour"
Get-Counter -Counter "\Inventory Agent\Offline Queue Size"
```

### Service Status Monitoring

```powershell
# Check service status
Get-Service -Name "InventoryAgent" | Select-Object Name, Status, StartType

# Get detailed status
$Service = Get-WmiObject -Class Win32_Service -Filter "Name='InventoryAgent'"
$Service | Select-Object Name, State, Status, ProcessId, StartMode
```

## 🔐 Security Considerations

### Code Signing

**All releases must be signed** with organizational code signing certificate:

```powershell
signtool sign /sha1 CERT_THUMBPRINT /t http://timestamp.digicert.com /fd SHA256 InventoryAgent.exe
```

### Service Hardening

**Recommended Service Configuration**:
```powershell
# Run as SYSTEM (already default)
sc.exe config "InventoryAgent" obj= "NT AUTHORITY\SYSTEM"

# Failure actions
sc.exe failure "InventoryAgent" reset= 86400 actions= restart/60000/restart/60000/restart/60000

# Service SID
sc.exe sidtype "InventoryAgent" unrestricted

# Required privileges (minimal)
sc.exe privs "InventoryAgent" SeChangeNotifyPrivilege/SeIncreaseQuotaPrivilege
```

### AppLocker/WDAC

**Publisher Rule Required**:
```xml
<FilePublisherRule>
    <PublisherName>O=YourCompany, L=YourCity, S=YourState, C=US</PublisherName>
    <ProductName>Inventory Agent</ProductName>
    <BinaryName>InventoryAgent.exe</BinaryName>
    <BinaryVersionRange LowSection="1.0.0.0" HighSection="*" />
</FilePublisherRule>
```

See `../security-templates/AppLocker-Rules.xml` for complete policy.

### Antivirus Exclusions

**Recommended Exclusions**:
- Process: `C:\Program Files\InventoryAgent\InventoryAgent.exe`
- Path: `C:\ProgramData\InventoryAgent\`

Coordinate with security team before implementing.

## 🚀 Deployment at Scale

### Phased Rollout Strategy

**Phase 1: Pilot (Week 1-2)**
- Deploy to 50-100 systems
- Monitor intensively
- Gather feedback

**Phase 2: Limited Rollout (Week 3-4)**
- Deploy to single OU (500-1000 systems)
- Validate scalability
- Tune performance

**Phase 3: Production (Week 5-8)**
- Deploy organization-wide
- Batch size: 2,500 systems/day
- Continuous monitoring

### GPO-Based Deployment

**Advantages**:
- Centralized management
- Automatic installation
- Rollback capability
- Version control

**Configuration**:
1. Create deployment GPO
2. Link to target OUs
3. Configure installation parameters
4. Enable/disable as needed

### SCCM/Intune Deployment

**SCCM Application**:
```powershell
# Detection method
$Service = Get-Service -Name "InventoryAgent" -ErrorAction SilentlyContinue
if ($Service -and $Service.Status -eq 'Running') {
    Write-Output "Installed"
}
```

**Intune Win32 App**:
- Detection: Registry key or service existence
- Installation: `msiexec.exe /i InventoryAgent.msi /quiet`
- Uninstall: `msiexec.exe /x {GUID} /quiet`

## 📝 Development Notes

### Building from Source

**Complete source code will be provided in**:
```
src/InventoryAgent/
```

**Key Implementation Files** (from option1_compiled_client.md):
- Program.cs: Service initialization
- InventoryAgentService.cs: Main service logic
- EventMonitorService.cs: Security event monitoring
- SystemInfoCollector.cs: WMI data collection
- ApiClient.cs: HTTPS communication with Polly retry
- OfflineQueue.cs: SQLite-based offline storage

**Reference**: See `../option1_compiled_client.md` for complete source code examples.

### Testing

**Unit Tests**:
```powershell
dotnet test InventoryAgent.Tests/InventoryAgent.Tests.csproj
```

**Integration Tests**:
- Test WMI collection
- Test API communication
- Test offline queue
- Test event monitoring

### Performance Optimization

**Benchmarks**:
- Collection time: <5 seconds
- Memory usage: <50MB
- CPU usage: <1% (idle), <5% (collecting)
- Startup time: <10 seconds

## 🔄 Updates and Maintenance

### Updating the Agent

**Via MSI Upgrade**:
1. Build new version with incremented version number
2. Sign the MSI
3. Deploy via GPO (replaces existing installation)
4. Service automatically restarts

**Via Manual Update**:
```powershell
# Stop service
sc.exe stop "InventoryAgent"

# Replace executable
Copy-Item ".\InventoryAgent.exe" "C:\Program Files\InventoryAgent\" -Force

# Start service
sc.exe start "InventoryAgent"
```

### Version Management

**Version Format**: `Major.Minor.Patch.Build`
- Major: Breaking changes
- Minor: New features
- Patch: Bug fixes
- Build: Automated build number

**Check Installed Version**:
```powershell
$ExePath = "C:\Program Files\InventoryAgent\InventoryAgent.exe"
$Version = (Get-Item $ExePath).VersionInfo.ProductVersion
Write-Host "Installed Version: $Version"
```

## 📚 Additional Resources

- **Security Requirements**: `../shared-documentation/Security-Requirements.md`
- **Complete Source Code**: `../option1_compiled_client.md`
- **Technical Architecture**: `../inventory_system_architecture.md`
- **AppLocker Policy**: `../security-templates/AppLocker-Rules.xml`

## 🆘 Support

**Issues or Questions**:
- IT Operations: itops@company.com
- Security Team: security@company.com
- Development Team: dev@company.com

---

## 📄 License

Internal use only - YourCompany IT Department

---

**Version**: 1.0.0
**Last Updated**: 2024-10-24
**Status**: Production-Ready (build required)
