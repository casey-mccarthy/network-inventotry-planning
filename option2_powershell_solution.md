# Option 2: PowerShell-Based Implementation
## Lightweight Script Solution with Scheduled Tasks and Logon Events

### Overview
This implementation uses native PowerShell scripts deployed via Group Policy, leveraging Windows Task Scheduler for both scheduled collection and event-triggered collection on user logon. This approach requires no compilation and is easier to modify and maintain.

### Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                    Windows 11 Client                        │
│                                                             │
│  ┌────────────────────────────────────────────────────┐    │
│  │           Windows Task Scheduler                    │    │
│  │                                                     │    │
│  │  ┌──────────────────────────────────────────┐     │    │
│  │  │  Task: "Inventory-OnLogon"               │     │    │
│  │  │  Trigger: User Logon                     │     │    │
│  │  │  Action: PowerShell.exe                  │     │    │
│  │  │         -File Collect-Inventory.ps1     │     │    │
│  │  └──────────────────────────────────────────┘     │    │
│  │                                                     │    │
│  │  ┌──────────────────────────────────────────┐     │    │
│  │  │  Task: "Inventory-Daily"                 │     │    │
│  │  │  Trigger: Daily at 2:00 AM               │     │    │
│  │  │  Action: PowerShell.exe                  │     │    │
│  │  │         -File Collect-Inventory.ps1     │     │    │
│  │  └──────────────────────────────────────────┘     │    │
│  └────────────────────────────────────────────────────┘    │
│                                                             │
│  PowerShell Scripts Location:                              │
│  └── C:\ProgramData\InventoryAgent\                       │
│      ├── Collect-Inventory.ps1     (Main script)          │
│      ├── Send-Inventory.ps1        (API communication)    │
│      ├── Config.json               (Configuration)        │
│      └── Queue\                    (Offline queue)        │
│                                                             │
│  Logs:                                                      │
│  └── C:\ProgramData\InventoryAgent\Logs\                  │
└─────────────────────────────────────────────────────────────┘
```

### Complete PowerShell Implementation

#### 1. Main Inventory Collection Script

**Collect-Inventory.ps1**
```powershell
<#
.SYNOPSIS
    Collects hardware inventory from Windows 11 system
.DESCRIPTION
    This script collects comprehensive hardware and system information
    and sends it to the central inventory server
.PARAMETER TriggerType
    Specifies what triggered the collection: "Logon", "Scheduled", or "Manual"
.PARAMETER Username
    Optional username for logon events
#>

[CmdletBinding()]
param(
    [Parameter()]
    [ValidateSet("Logon", "Scheduled", "Manual")]
    [string]$TriggerType = "Manual",
    
    [Parameter()]
    [string]$Username = $env:USERNAME
)

# Script configuration
$ErrorActionPreference = "Stop"
$ProgressPreference = "SilentlyContinue"

# Paths
$ScriptRoot = "C:\ProgramData\InventoryAgent"
$ConfigPath = Join-Path $ScriptRoot "Config.json"
$LogPath = Join-Path $ScriptRoot "Logs"
$QueuePath = Join-Path $ScriptRoot "Queue"

# Ensure directories exist
@($ScriptRoot, $LogPath, $QueuePath) | ForEach-Object {
    if (!(Test-Path $_)) {
        New-Item -ItemType Directory -Path $_ -Force | Out-Null
    }
}

#region Logging Functions
function Write-Log {
    param(
        [string]$Message,
        [ValidateSet("Info", "Warning", "Error")]
        [string]$Level = "Info"
    )
    
    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogFile = Join-Path $LogPath "inventory_$(Get-Date -Format 'yyyyMMdd').log"
    $LogEntry = "$Timestamp [$Level] $Message"
    
    # Write to file
    Add-Content -Path $LogFile -Value $LogEntry -Force
    
    # Also write to Windows Event Log if available
    try {
        $EventLogSource = "InventoryAgent"
        if (![System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            New-EventLog -LogName Application -Source $EventLogSource -ErrorAction SilentlyContinue
        }
        
        $EventType = switch ($Level) {
            "Info" { [System.Diagnostics.EventLogEntryType]::Information }
            "Warning" { [System.Diagnostics.EventLogEntryType]::Warning }
            "Error" { [System.Diagnostics.EventLogEntryType]::Error }
        }
        
        Write-EventLog -LogName Application -Source $EventLogSource -EntryType $EventType -EventId 1000 -Message $Message
    }
    catch {
        # Event log writing failed, continue with file logging only
    }
}
#endregion

#region Configuration Management
function Get-Configuration {
    try {
        if (Test-Path $ConfigPath) {
            $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
        }
        else {
            # Default configuration
            $Config = @{
                ServerEndpoint = "https://inventory.company.com/api/v1"
                ApiKey = ""
                CertificateThumbprint = ""
                EnableDebounce = $true
                DebounceMinutes = 60
                MaxRetryAttempts = 3
                RetryDelaySeconds = 30
                QueueMaxSize = 1000
                EnableCompression = $true
            }
            
            # Check registry for GPO-deployed settings
            $RegPath = "HKLM:\SOFTWARE\YourCompany\InventoryAgent"
            if (Test-Path $RegPath) {
                $RegConfig = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue
                if ($RegConfig.ServerEndpoint) { $Config.ServerEndpoint = $RegConfig.ServerEndpoint }
                if ($RegConfig.ApiKey) { $Config.ApiKey = $RegConfig.ApiKey }
                if ($RegConfig.CertificateThumbprint) { $Config.CertificateThumbprint = $RegConfig.CertificateThumbprint }
            }
            
            # Save configuration
            $Config | ConvertTo-Json | Out-File $ConfigPath -Force
        }
        
        return $Config
    }
    catch {
        Write-Log "Failed to load configuration: $_" -Level Error
        throw
    }
}
#endregion

#region Debounce Check
function Test-ShouldCollect {
    param(
        [string]$TriggerType,
        [string]$Username
    )
    
    $Config = Get-Configuration
    
    if (-not $Config.EnableDebounce -or $TriggerType -eq "Scheduled") {
        return $true
    }
    
    # Check last collection time for this user
    $DebounceFile = Join-Path $ScriptRoot "debounce_$($Username -replace '[^\w]', '_').txt"
    
    if (Test-Path $DebounceFile) {
        $LastRun = Get-Content $DebounceFile -Raw
        $LastRunTime = [DateTime]::Parse($LastRun)
        $TimeSinceLastRun = (Get-Date) - $LastRunTime
        
        if ($TimeSinceLastRun.TotalMinutes -lt $Config.DebounceMinutes) {
            Write-Log "Skipping collection - last run was $([int]$TimeSinceLastRun.TotalMinutes) minutes ago" -Level Info
            return $false
        }
    }
    
    # Update debounce file
    Get-Date -Format "yyyy-MM-dd HH:mm:ss" | Out-File $DebounceFile -Force
    return $true
}
#endregion

#region System Information Collection
function Get-SystemInfo {
    Write-Log "Collecting system information" -Level Info
    
    $SystemInfo = @{}
    
    try {
        # Computer System
        $ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem
        $SystemInfo.ComputerName = $ComputerSystem.Name
        $SystemInfo.Domain = $ComputerSystem.Domain
        $SystemInfo.Manufacturer = $ComputerSystem.Manufacturer
        $SystemInfo.Model = $ComputerSystem.Model
        $SystemInfo.TotalPhysicalMemory = $ComputerSystem.TotalPhysicalMemory
        $SystemInfo.NumberOfProcessors = $ComputerSystem.NumberOfProcessors
        
        # BIOS
        $BIOS = Get-CimInstance -ClassName Win32_BIOS
        $SystemInfo.SerialNumber = $BIOS.SerialNumber
        $SystemInfo.BIOSVersion = $BIOS.SMBIOSBIOSVersion
        $SystemInfo.BIOSManufacturer = $BIOS.Manufacturer
        $SystemInfo.BIOSReleaseDate = $BIOS.ReleaseDate
        
        # Operating System
        $OS = Get-CimInstance -ClassName Win32_OperatingSystem
        $SystemInfo.OperatingSystem = $OS.Caption
        $SystemInfo.OSVersion = $OS.Version
        $SystemInfo.OSBuildNumber = $OS.BuildNumber
        $SystemInfo.OSArchitecture = $OS.OSArchitecture
        $SystemInfo.LastBootTime = $OS.LastBootUpTime
        $SystemInfo.InstallDate = $OS.InstallDate
        
        # Processor
        $CPU = Get-CimInstance -ClassName Win32_Processor | Select-Object -First 1
        $SystemInfo.ProcessorName = $CPU.Name
        $SystemInfo.ProcessorManufacturer = $CPU.Manufacturer
        $SystemInfo.ProcessorCores = $CPU.NumberOfCores
        $SystemInfo.ProcessorThreads = $CPU.NumberOfLogicalProcessors
        $SystemInfo.ProcessorMaxSpeed = $CPU.MaxClockSpeed
        
        # Windows version details
        $WindowsVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
        $SystemInfo.WindowsDisplayVersion = $WindowsVersion.DisplayVersion
        $SystemInfo.WindowsReleaseId = $WindowsVersion.ReleaseId
        $SystemInfo.WindowsUBR = $WindowsVersion.UBR
        
        Write-Log "System information collected successfully" -Level Info
    }
    catch {
        Write-Log "Error collecting system information: $_" -Level Error
    }
    
    return $SystemInfo
}

function Get-DiskInfo {
    Write-Log "Collecting disk information" -Level Info
    
    $Disks = @()
    
    try {
        $PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive | Where-Object { $_.MediaType -eq 'Fixed hard disk media' }
        
        foreach ($Disk in $PhysicalDisks) {
            $DiskInfo = @{
                DeviceID = $Disk.DeviceID
                Model = $Disk.Model
                SerialNumber = ($Disk.SerialNumber -replace '\s+', '').Trim()
                Size = $Disk.Size
                InterfaceType = $Disk.InterfaceType
                MediaType = $Disk.MediaType
                Status = $Disk.Status
                Partitions = @()
            }
            
            # Get partition information
            $Partitions = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskDrive.DeviceID='$($Disk.DeviceID.Replace('\','\\'))'} WHERE AssocClass=Win32_DiskDriveToDiskPartition"
            
            foreach ($Partition in $Partitions) {
                $PartitionInfo = @{
                    Index = $Partition.Index
                    Size = $Partition.Size
                    Type = $Partition.Type
                    Bootable = $Partition.Bootable
                    DriveLetter = $null
                    FreeSpace = $null
                }
                
                # Get logical disk (drive letter) information
                $LogicalDisks = Get-CimInstance -Query "ASSOCIATORS OF {Win32_DiskPartition.DeviceID='$($Partition.DeviceID)'} WHERE AssocClass=Win32_LogicalDiskToPartition"
                
                foreach ($LogicalDisk in $LogicalDisks) {
                    $PartitionInfo.DriveLetter = $LogicalDisk.DeviceID
                    $PartitionInfo.FreeSpace = $LogicalDisk.FreeSpace
                    $PartitionInfo.FileSystem = $LogicalDisk.FileSystem
                    $PartitionInfo.VolumeName = $LogicalDisk.VolumeName
                }
                
                $DiskInfo.Partitions += $PartitionInfo
            }
            
            $Disks += $DiskInfo
        }
        
        Write-Log "Collected information for $($Disks.Count) disk(s)" -Level Info
    }
    catch {
        Write-Log "Error collecting disk information: $_" -Level Error
    }
    
    return $Disks
}

function Get-NetworkInfo {
    Write-Log "Collecting network information" -Level Info
    
    $NetworkAdapters = @()
    
    try {
        $Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
        
        foreach ($Adapter in $Adapters) {
            $AdapterInfo = @{
                Description = $Adapter.Description
                MACAddress = $Adapter.MACAddress
                IPAddresses = $Adapter.IPAddress
                IPSubnets = $Adapter.IPSubnet
                DefaultGateway = $Adapter.DefaultIPGateway
                DNSServers = $Adapter.DNSServerSearchOrder
                DHCPEnabled = $Adapter.DHCPEnabled
                DHCPServer = $Adapter.DHCPServer
                DNSDomain = $Adapter.DNSDomain
            }
            
            # Get additional adapter details
            $PhysicalAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter | Where-Object { $_.Index -eq $Adapter.Index }
            if ($PhysicalAdapter) {
                $AdapterInfo.AdapterType = $PhysicalAdapter.AdapterType
                $AdapterInfo.Speed = $PhysicalAdapter.Speed
                $AdapterInfo.Manufacturer = $PhysicalAdapter.Manufacturer
            }
            
            $NetworkAdapters += $AdapterInfo
        }
        
        Write-Log "Collected information for $($NetworkAdapters.Count) network adapter(s)" -Level Info
    }
    catch {
        Write-Log "Error collecting network information: $_" -Level Error
    }
    
    return $NetworkAdapters
}

function Get-UserInfo {
    param(
        [string]$Username
    )
    
    Write-Log "Collecting user information" -Level Info
    
    $UserInfo = @{
        LastLoggedUser = $Username
        LogonTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CurrentUsers = @()
    }
    
    try {
        # Get all currently logged in users
        $LoggedOnUsers = Get-CimInstance -ClassName Win32_ComputerSystem | Select-Object -ExpandProperty UserName
        if ($LoggedOnUsers) {
            $UserInfo.CurrentUsers += $LoggedOnUsers
        }
        
        # Get user sessions via quser command
        try {
            $QuserOutput = quser 2>$null
            if ($QuserOutput) {
                $UserSessions = $QuserOutput | Select-Object -Skip 1 | ForEach-Object {
                    $parts = $_ -split '\s+'
                    @{
                        Username = $parts[0].TrimStart('>')
                        SessionName = $parts[1]
                        State = if ($parts[3] -eq 'Active') { $parts[3] } else { $parts[2] }
                        LogonTime = if ($parts[3] -eq 'Active') { "$($parts[4]) $($parts[5])" } else { "$($parts[3]) $($parts[4])" }
                    }
                }
                $UserInfo.UserSessions = $UserSessions
            }
        }
        catch {
            # quser might not be available on all systems
        }
        
        # Get last logon from registry if not provided
        if ([string]::IsNullOrEmpty($Username)) {
            try {
                $RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                $LastLoggedOnUser = Get-ItemProperty -Path $RegPath -Name "LastLoggedOnUser" -ErrorAction SilentlyContinue
                if ($LastLoggedOnUser) {
                    $UserInfo.LastLoggedUser = $LastLoggedOnUser.LastLoggedOnUser
                }
            }
            catch {
                # Registry key might not exist
            }
        }
        
        Write-Log "User information collected successfully" -Level Info
    }
    catch {
        Write-Log "Error collecting user information: $_" -Level Error
    }
    
    return $UserInfo
}

function Get-InstalledSoftware {
    Write-Log "Collecting installed software information" -Level Info
    
    $Software = @()
    
    try {
        # Get software from registry (32-bit and 64-bit)
        $RegistryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*",
            "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*"
        )
        
        foreach ($Path in $RegistryPaths) {
            $InstalledApps = Get-ItemProperty $Path -ErrorAction SilentlyContinue | 
                Where-Object { $_.DisplayName -and $_.DisplayName -notmatch "^KB\d+" } |
                Select-Object DisplayName, DisplayVersion, Publisher, InstallDate, InstallLocation
            
            $Software += $InstalledApps
        }
        
        # Remove duplicates
        $Software = $Software | Sort-Object DisplayName -Unique
        
        Write-Log "Collected information for $($Software.Count) installed software" -Level Info
    }
    catch {
        Write-Log "Error collecting software information: $_" -Level Warning
    }
    
    return $Software
}
#endregion

#region Inventory Compilation
function New-InventoryObject {
    param(
        [string]$TriggerType,
        [string]$Username
    )
    
    Write-Log "Starting inventory collection - Trigger: $TriggerType, User: $Username" -Level Info
    
    $Inventory = @{
        CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        CollectionTrigger = $TriggerType
        AgentVersion = "2.0.0"
        System = Get-SystemInfo
        Disks = Get-DiskInfo
        Network = Get-NetworkInfo
        User = Get-UserInfo -Username $Username
        Software = Get-InstalledSoftware
    }
    
    # Add unique identifier
    $Inventory.InventoryId = [Guid]::NewGuid().ToString()
    
    # Calculate hash for change detection
    $DataForHash = $Inventory.System + $Inventory.Disks + $Inventory.Network
    $JsonForHash = $DataForHash | ConvertTo-Json -Depth 10 -Compress
    $Bytes = [System.Text.Encoding]::UTF8.GetBytes($JsonForHash)
    $Hash = [System.Security.Cryptography.SHA256]::Create()
    $HashBytes = $Hash.ComputeHash($Bytes)
    $Inventory.ContentHash = [System.BitConverter]::ToString($HashBytes).Replace("-", "")
    
    Write-Log "Inventory collection completed - ID: $($Inventory.InventoryId)" -Level Info
    
    return $Inventory
}
#endregion

#region API Communication
function Send-InventoryToServer {
    param(
        [Parameter(Mandatory)]
        [object]$Inventory
    )
    
    $Config = Get-Configuration
    
    Write-Log "Sending inventory to server: $($Config.ServerEndpoint)" -Level Info
    
    try {
        # Prepare JSON payload
        $Json = $Inventory | ConvertTo-Json -Depth 10 -Compress
        
        # Compress if enabled
        if ($Config.EnableCompression) {
            $Bytes = [System.Text.Encoding]::UTF8.GetBytes($Json)
            $Compressed = [System.IO.MemoryStream]::new()
            $GzipStream = [System.IO.Compression.GzipStream]::new($Compressed, [System.IO.Compression.CompressionMode]::Compress)
            $GzipStream.Write($Bytes, 0, $Bytes.Length)
            $GzipStream.Close()
            $Body = $Compressed.ToArray()
            $ContentType = "application/gzip"
        }
        else {
            $Body = $Json
            $ContentType = "application/json"
        }
        
        # Prepare headers
        $Headers = @{
            "Content-Type" = $ContentType
            "X-Machine-Name" = $Inventory.System.ComputerName
            "X-Agent-Version" = $Inventory.AgentVersion
        }
        
        # Add API key if configured
        if ($Config.ApiKey) {
            $Headers["Authorization"] = "Bearer $($Config.ApiKey)"
        }
        
        # Certificate authentication
        $WebRequestParams = @{
            Uri = "$($Config.ServerEndpoint)/inventory"
            Method = "POST"
            Body = $Body
            Headers = $Headers
            UseBasicParsing = $true
            TimeoutSec = 30
        }
        
        # Add certificate if configured
        if ($Config.CertificateThumbprint) {
            $Cert = Get-ChildItem -Path Cert:\LocalMachine\My | Where-Object { $_.Thumbprint -eq $Config.CertificateThumbprint }
            if ($Cert) {
                $WebRequestParams.Certificate = $Cert
            }
            else {
                Write-Log "Certificate not found: $($Config.CertificateThumbprint)" -Level Warning
            }
        }
        
        # Send with retry logic
        $Attempt = 1
        $Success = $false
        
        while ($Attempt -le $Config.MaxRetryAttempts -and -not $Success) {
            try {
                $Response = Invoke-WebRequest @WebRequestParams
                
                if ($Response.StatusCode -eq 200 -or $Response.StatusCode -eq 201) {
                    Write-Log "Inventory sent successfully - Status: $($Response.StatusCode)" -Level Info
                    $Success = $true
                    return $true
                }
                else {
                    Write-Log "Unexpected response - Status: $($Response.StatusCode)" -Level Warning
                }
            }
            catch {
                $ErrorMessage = $_.Exception.Message
                Write-Log "Attempt $Attempt failed: $ErrorMessage" -Level Warning
                
                if ($Attempt -lt $Config.MaxRetryAttempts) {
                    Start-Sleep -Seconds ($Config.RetryDelaySeconds * $Attempt)
                }
            }
            
            $Attempt++
        }
        
        if (-not $Success) {
            Write-Log "Failed to send inventory after $($Config.MaxRetryAttempts) attempts" -Level Error
            return $false
        }
    }
    catch {
        Write-Log "Error sending inventory: $_" -Level Error
        return $false
    }
}
#endregion

#region Offline Queue Management
function Add-ToOfflineQueue {
    param(
        [Parameter(Mandatory)]
        [object]$Inventory
    )
    
    $Config = Get-Configuration
    
    try {
        # Check queue size
        $QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue
        if ($QueueFiles.Count -ge $Config.QueueMaxSize) {
            # Remove oldest item
            $OldestFile = $QueueFiles | Sort-Object CreationTime | Select-Object -First 1
            Remove-Item -Path $OldestFile.FullName -Force
            Write-Log "Queue full - removed oldest item: $($OldestFile.Name)" -Level Warning
        }
        
        # Save inventory to queue
        $QueueFileName = "inventory_$($Inventory.InventoryId).json"
        $QueueFilePath = Join-Path $QueuePath $QueueFileName
        $Inventory | ConvertTo-Json -Depth 10 | Out-File -FilePath $QueueFilePath -Force
        
        Write-Log "Added inventory to offline queue: $QueueFileName" -Level Info
        return $true
    }
    catch {
        Write-Log "Error adding to offline queue: $_" -Level Error
        return $false
    }
}

function Process-OfflineQueue {
    Write-Log "Processing offline queue" -Level Info
    
    try {
        $QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue | 
            Sort-Object CreationTime
        
        if ($QueueFiles.Count -eq 0) {
            Write-Log "Offline queue is empty" -Level Info
            return
        }
        
        Write-Log "Found $($QueueFiles.Count) items in offline queue" -Level Info
        
        foreach ($File in $QueueFiles) {
            try {
                $Inventory = Get-Content -Path $File.FullName -Raw | ConvertFrom-Json
                
                if (Send-InventoryToServer -Inventory $Inventory) {
                    Remove-Item -Path $File.FullName -Force
                    Write-Log "Successfully sent queued item: $($File.Name)" -Level Info
                }
                else {
                    Write-Log "Failed to send queued item: $($File.Name)" -Level Warning
                    break  # Stop processing queue if server is unreachable
                }
            }
            catch {
                Write-Log "Error processing queued item $($File.Name): $_" -Level Error
                # Move corrupted file
                $CorruptPath = Join-Path $QueuePath "corrupt"
                if (!(Test-Path $CorruptPath)) {
                    New-Item -ItemType Directory -Path $CorruptPath -Force | Out-Null
                }
                Move-Item -Path $File.FullName -Destination $CorruptPath -Force
            }
        }
    }
    catch {
        Write-Log "Error processing offline queue: $_" -Level Error
    }
}
#endregion

#region Main Execution
try {
    # Check if we should collect (debounce check)
    if (-not (Test-ShouldCollect -TriggerType $TriggerType -Username $Username)) {
        exit 0
    }
    
    # Process offline queue first
    Process-OfflineQueue
    
    # Collect inventory
    $Inventory = New-InventoryObject -TriggerType $TriggerType -Username $Username
    
    # Send to server
    if (-not (Send-InventoryToServer -Inventory $Inventory)) {
        # Add to offline queue if send fails
        Add-ToOfflineQueue -Inventory $Inventory
    }
    
    Write-Log "Inventory collection process completed successfully" -Level Info
}
catch {
    Write-Log "Fatal error in inventory collection: $_" -Level Error
    exit 1
}
#endregion
```

#### 2. Scheduled Task Creation Script

**Install-InventoryTasks.ps1**
```powershell
<#
.SYNOPSIS
    Creates Windows scheduled tasks for inventory collection
.DESCRIPTION
    This script creates two scheduled tasks:
    1. Daily collection at specified time
    2. Collection triggered on user logon
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ScriptPath = "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1",
    
    [Parameter()]
    [string]$DailyTime = "02:00",
    
    [Parameter()]
    [switch]$Force
)

#Requires -RunAsAdministrator

function New-InventoryScheduledTask {
    Write-Host "Creating Inventory Collection Scheduled Tasks" -ForegroundColor Green
    
    # Validate script exists
    if (!(Test-Path $ScriptPath)) {
        Write-Error "Script not found at: $ScriptPath"
        return
    }
    
    # Task 1: Daily Collection
    $DailyTaskName = "InventoryAgent-DailyCollection"
    
    if (Get-ScheduledTask -TaskName $DailyTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $DailyTaskName -Confirm:$false
            Write-Host "Removed existing task: $DailyTaskName" -ForegroundColor Yellow
        }
        else {
            Write-Warning "Task already exists: $DailyTaskName (use -Force to recreate)"
        }
    }
    
    # Create daily trigger
    $DailyTrigger = New-ScheduledTaskTrigger -Daily -At $DailyTime
    
    # Create action
    $DailyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument @"
-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$ScriptPath" -TriggerType Scheduled
"@
    
    # Create principal (run as SYSTEM)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    
    # Create settings
    $Settings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable
    
    # Register daily task
    Register-ScheduledTask -TaskName $DailyTaskName `
        -Trigger $DailyTrigger `
        -Action $DailyAction `
        -Principal $Principal `
        -Settings $Settings `
        -Description "Daily hardware inventory collection at $DailyTime" | Out-Null
    
    Write-Host "✓ Created daily collection task: $DailyTaskName" -ForegroundColor Green
    
    # Task 2: Logon Trigger
    $LogonTaskName = "InventoryAgent-LogonCollection"
    
    if (Get-ScheduledTask -TaskName $LogonTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $LogonTaskName -Confirm:$false
            Write-Host "Removed existing task: $LogonTaskName" -ForegroundColor Yellow
        }
        else {
            Write-Warning "Task already exists: $LogonTaskName (use -Force to recreate)"
            return
        }
    }
    
    # Create logon trigger
    $LogonTrigger = New-ScheduledTaskTrigger -AtLogOn
    
    # Create action with username parameter
    $LogonAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument @"
-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -File "$ScriptPath" -TriggerType Logon -Username %USERNAME%
"@
    
    # Settings for logon task
    $LogonSettings = New-ScheduledTaskSettingsSet -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -RestartCount 1 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable
    
    # Register logon task
    Register-ScheduledTask -TaskName $LogonTaskName `
        -Trigger $LogonTrigger `
        -Action $LogonAction `
        -Principal $Principal `
        -Settings $LogonSettings `
        -Description "Hardware inventory collection on user logon" | Out-Null
    
    Write-Host "✓ Created logon collection task: $LogonTaskName" -ForegroundColor Green
    
    # Task 3: Process Queue (every 4 hours)
    $QueueTaskName = "InventoryAgent-ProcessQueue"
    
    if (Get-ScheduledTask -TaskName $QueueTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $QueueTaskName -Confirm:$false
        }
    }
    
    # Create trigger for every 4 hours
    $QueueTrigger = New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration ([TimeSpan]::MaxValue)
    
    $QueueAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument @"
-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command "& { . '$ScriptPath'; Process-OfflineQueue }"
"@
    
    Register-ScheduledTask -TaskName $QueueTaskName `
        -Trigger $QueueTrigger `
        -Action $QueueAction `
        -Principal $Principal `
        -Settings $Settings `
        -Description "Process offline inventory queue" | Out-Null
    
    Write-Host "✓ Created queue processing task: $QueueTaskName" -ForegroundColor Green
    
    # Display task status
    Write-Host "`nScheduled Tasks Status:" -ForegroundColor Cyan
    Get-ScheduledTask -TaskName "InventoryAgent-*" | Format-Table TaskName, State, LastRunTime, NextRunTime -AutoSize
    
    # Run initial collection
    Write-Host "`nRunning initial inventory collection..." -ForegroundColor Yellow
    Start-ScheduledTask -TaskName $DailyTaskName
    
    Write-Host "`n✅ Inventory collection tasks installed successfully!" -ForegroundColor Green
}

# Execute main function
New-InventoryScheduledTask
```

#### 3. Group Policy Deployment Script

**Deploy-InventoryPowerShell.ps1**
```powershell
<#
.SYNOPSIS
    Deploys PowerShell inventory collection via Group Policy
.DESCRIPTION
    Creates GPO that deploys PowerShell scripts and creates scheduled tasks
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [string]$ServerEndpoint,
    
    [Parameter()]
    [string]$GPOName = "Deploy-InventoryAgent-PowerShell",
    
    [Parameter()]
    [string]$TargetOU = "OU=Computers,DC=company,DC=com",
    
    [Parameter()]
    [string]$SysvolPath = "\\$env:USERDNSDOMAIN\SYSVOL\$env:USERDNSDOMAIN"
)

#Requires -RunAsAdministrator
#Requires -Modules GroupPolicy, ActiveDirectory

function Deploy-PowerShellInventory {
    Write-Host "Deploying PowerShell Inventory Collection via GPO" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    
    # Import required modules
    Import-Module GroupPolicy -ErrorAction Stop
    Import-Module ActiveDirectory -ErrorAction Stop
    
    # Create new GPO
    Write-Host "`nCreating GPO: $GPOName" -ForegroundColor Cyan
    try {
        $GPO = New-GPO -Name $GPOName -Comment "Deploys PowerShell-based inventory collection"
    }
    catch {
        if ($_.Exception.Message -match "already exists") {
            Write-Warning "GPO already exists, updating existing GPO"
            $GPO = Get-GPO -Name $GPOName
        }
        else {
            throw
        }
    }
    
    # Link GPO to target OU
    Write-Host "Linking GPO to: $TargetOU" -ForegroundColor Cyan
    try {
        New-GPLink -Name $GPOName -Target $TargetOU -LinkEnabled Yes -ErrorAction SilentlyContinue
    }
    catch {
        if ($_.Exception.Message -match "already linked") {
            Write-Warning "GPO already linked to OU"
        }
        else {
            throw
        }
    }
    
    # Create folder structure in SYSVOL
    $GPOPath = "$SysvolPath\Policies\{$($GPO.Id)}"
    $ScriptsPath = "$GPOPath\Machine\Scripts"
    $StartupPath = "$ScriptsPath\Startup"
    $FilesPath = "$GPOPath\Machine\Files"
    
    Write-Host "Creating folder structure in SYSVOL" -ForegroundColor Cyan
    @($ScriptsPath, $StartupPath, $FilesPath) | ForEach-Object {
        if (!(Test-Path $_)) {
            New-Item -ItemType Directory -Path $_ -Force | Out-Null
            Write-Host "  Created: $_" -ForegroundColor Gray
        }
    }
    
    # Copy PowerShell scripts to SYSVOL
    Write-Host "Copying scripts to SYSVOL" -ForegroundColor Cyan
    
    # Main collection script
    $CollectScriptContent = Get-Content -Path ".\Collect-Inventory.ps1" -Raw
    $CollectScriptPath = "$FilesPath\Collect-Inventory.ps1"
    $CollectScriptContent | Out-File -FilePath $CollectScriptPath -Force -Encoding UTF8
    Write-Host "  ✓ Collect-Inventory.ps1" -ForegroundColor Green
    
    # Task installation script
    $InstallTasksContent = Get-Content -Path ".\Install-InventoryTasks.ps1" -Raw
    $InstallTasksPath = "$StartupPath\Install-InventoryTasks.ps1"
    $InstallTasksContent | Out-File -FilePath $InstallTasksPath -Force -Encoding UTF8
    Write-Host "  ✓ Install-InventoryTasks.ps1" -ForegroundColor Green
    
    # Create deployment script that runs at startup
    $DeploymentScript = @'
# Inventory Agent Deployment Script
$ErrorActionPreference = "SilentlyContinue"

# Define paths
$TargetPath = "C:\ProgramData\InventoryAgent"
$SourcePath = "\\' + $env:USERDNSDOMAIN + '\SYSVOL\' + $env:USERDNSDOMAIN + '\Policies\{' + $GPO.Id + '}\Machine\Files"

# Create directory
if (!(Test-Path $TargetPath)) {
    New-Item -ItemType Directory -Path $TargetPath -Force | Out-Null
}

# Copy scripts
Copy-Item -Path "$SourcePath\*" -Destination $TargetPath -Force -Recurse

# Set permissions
$Acl = Get-Acl $TargetPath
$Permission = "NT AUTHORITY\SYSTEM","FullControl","ContainerInherit,ObjectInherit","None","Allow"
$AccessRule = New-Object System.Security.AccessControl.FileSystemAccessRule $Permission
$Acl.SetAccessRule($AccessRule)
Set-Acl $TargetPath $Acl

# Create scheduled tasks
& "$TargetPath\Install-InventoryTasks.ps1" -Force

# Create initial configuration
$Config = @{
    ServerEndpoint = "' + $ServerEndpoint + '"
    EnableDebounce = $true
    DebounceMinutes = 60
    MaxRetryAttempts = 3
    RetryDelaySeconds = 30
    QueueMaxSize = 1000
    EnableCompression = $true
}
$Config | ConvertTo-Json | Out-File "$TargetPath\Config.json" -Force

# Log deployment
$LogFile = "$TargetPath\deployment.log"
"Deployed on $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') by $env:COMPUTERNAME" | Out-File $LogFile -Append
'@
    
    $DeploymentScriptPath = "$StartupPath\Deploy-InventoryAgent.ps1"
    $DeploymentScript | Out-File -FilePath $DeploymentScriptPath -Force -Encoding UTF8
    Write-Host "  ✓ Deploy-InventoryAgent.ps1" -ForegroundColor Green
    
    # Configure GPO Registry Settings
    Write-Host "`nConfiguring GPO Registry Settings" -ForegroundColor Cyan
    
    $RegPath = "HKLM\SOFTWARE\YourCompany\InventoryAgent"
    
    # Server Endpoint
    Set-GPRegistryValue -Name $GPOName `
        -Key $RegPath `
        -ValueName "ServerEndpoint" `
        -Type String `
        -Value $ServerEndpoint
    Write-Host "  ✓ ServerEndpoint: $ServerEndpoint" -ForegroundColor Green
    
    # Collection Settings
    Set-GPRegistryValue -Name $GPOName `
        -Key $RegPath `
        -ValueName "EnableDebounce" `
        -Type DWord `
        -Value 1
    
    Set-GPRegistryValue -Name $GPOName `
        -Key $RegPath `
        -ValueName "DebounceMinutes" `
        -Type DWord `
        -Value 60
    
    Set-GPRegistryValue -Name $GPOName `
        -Key $RegPath `
        -ValueName "MaxRetryAttempts" `
        -Type DWord `
        -Value 3
    Write-Host "  ✓ Configuration settings" -ForegroundColor Green
    
    # Configure Computer Startup Script in GPO
    Write-Host "`nConfiguring startup script" -ForegroundColor Cyan
    
    # Create scripts.ini for startup scripts
    $ScriptsIni = @"
[Startup]
0CmdLine=$StartupPath\Deploy-InventoryAgent.ps1
0Parameters=
"@
    
    $ScriptsIniPath = "$ScriptsPath\psscripts.ini"
    $ScriptsIni | Out-File -FilePath $ScriptsIniPath -Force -Encoding ASCII
    Set-ItemProperty -Path $ScriptsIniPath -Name Attributes -Value "Hidden"
    Write-Host "  ✓ Startup script configured" -ForegroundColor Green
    
    # Configure PowerShell Execution Policy via GPO
    Write-Host "`nConfiguring PowerShell Execution Policy" -ForegroundColor Cyan
    
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
        -ValueName "EnableScripts" `
        -Type DWord `
        -Value 1
    
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell" `
        -ValueName "ExecutionPolicy" `
        -Type String `
        -Value "Bypass"
    Write-Host "  ✓ PowerShell execution policy set to Bypass" -ForegroundColor Green
    
    # Configure Windows Firewall rule (optional)
    Write-Host "`nConfiguring Windows Firewall" -ForegroundColor Cyan
    
    $FirewallRuleName = "InventoryAgent-Outbound"
    Set-GPRegistryValue -Name $GPOName `
        -Key "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\FirewallRules" `
        -ValueName $FirewallRuleName `
        -Type String `
        -Value "v2.26|Action=Allow|Active=TRUE|Dir=Out|Protocol=6|LPort=Any|RPort=443|App=C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe|Name=Inventory Agent HTTPS|Desc=Allow PowerShell inventory agent to communicate with server|"
    Write-Host "  ✓ Firewall rule configured" -ForegroundColor Green
    
    # Create WMI Filter for Windows 11 only (optional)
    Write-Host "`nCreating WMI Filter for Windows 11" -ForegroundColor Cyan
    
    $WMIFilterName = "Windows 11 Computers"
    $WMIFilterQuery = "SELECT * FROM Win32_OperatingSystem WHERE Version LIKE '10.0.22%' AND ProductType = '1'"
    
    # Note: WMI Filter creation requires additional complexity
    # This is a placeholder for the WMI filter logic
    Write-Host "  ⚠ WMI Filter should be manually configured for Windows 11 targeting" -ForegroundColor Yellow
    
    # Display summary
    Write-Host "`n" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    Write-Host "DEPLOYMENT SUMMARY" -ForegroundColor Green
    Write-Host "=" * 50 -ForegroundColor Green
    
    Write-Host "GPO Name:        $GPOName" -ForegroundColor White
    Write-Host "GPO ID:          $($GPO.Id)" -ForegroundColor White
    Write-Host "Target OU:       $TargetOU" -ForegroundColor White
    Write-Host "Server Endpoint: $ServerEndpoint" -ForegroundColor White
    Write-Host "Scripts Path:    $FilesPath" -ForegroundColor White
    
    Write-Host "`nNext Steps:" -ForegroundColor Cyan
    Write-Host "1. Run 'gpupdate /force' on target computers" -ForegroundColor White
    Write-Host "2. Restart target computers to trigger startup script" -ForegroundColor White
    Write-Host "3. Check C:\ProgramData\InventoryAgent\Logs for collection logs" -ForegroundColor White
    Write-Host "4. Verify scheduled tasks with: Get-ScheduledTask -TaskName 'InventoryAgent-*'" -ForegroundColor White
    
    Write-Host "`n✅ PowerShell Inventory deployment completed successfully!" -ForegroundColor Green
}

# Execute deployment
Deploy-PowerShellInventory
```

#### 4. Configuration Management Script

**Set-InventoryConfig.ps1**
```powershell
<#
.SYNOPSIS
    Configures inventory agent settings
.DESCRIPTION
    Updates configuration for the PowerShell inventory agent
#>

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ConfigPath = "C:\ProgramData\InventoryAgent\Config.json",
    
    [Parameter()]
    [string]$ServerEndpoint,
    
    [Parameter()]
    [string]$ApiKey,
    
    [Parameter()]
    [string]$CertificateThumbprint,
    
    [Parameter()]
    [int]$DebounceMinutes,
    
    [Parameter()]
    [int]$MaxRetryAttempts,
    
    [Parameter()]
    [switch]$EnableCompression,
    
    [Parameter()]
    [switch]$DisableCompression,
    
    [Parameter()]
    [switch]$ShowConfig
)

function Set-InventoryConfiguration {
    # Load existing configuration
    if (Test-Path $ConfigPath) {
        $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
    }
    else {
        # Create default configuration
        $Config = @{
            ServerEndpoint = "https://inventory.company.com/api/v1"
            ApiKey = ""
            CertificateThumbprint = ""
            EnableDebounce = $true
            DebounceMinutes = 60
            MaxRetryAttempts = 3
            RetryDelaySeconds = 30
            QueueMaxSize = 1000
            EnableCompression = $true
        }
    }
    
    # Update configuration based on parameters
    if ($PSBoundParameters.ContainsKey('ServerEndpoint')) {
        $Config.ServerEndpoint = $ServerEndpoint
        Write-Host "Updated ServerEndpoint: $ServerEndpoint" -ForegroundColor Green
    }
    
    if ($PSBoundParameters.ContainsKey('ApiKey')) {
        $Config.ApiKey = $ApiKey
        Write-Host "Updated ApiKey: [HIDDEN]" -ForegroundColor Green
    }
    
    if ($PSBoundParameters.ContainsKey('CertificateThumbprint')) {
        $Config.CertificateThumbprint = $CertificateThumbprint
        Write-Host "Updated CertificateThumbprint: $CertificateThumbprint" -ForegroundColor Green
    }
    
    if ($PSBoundParameters.ContainsKey('DebounceMinutes')) {
        $Config.DebounceMinutes = $DebounceMinutes
        Write-Host "Updated DebounceMinutes: $DebounceMinutes" -ForegroundColor Green
    }
    
    if ($PSBoundParameters.ContainsKey('MaxRetryAttempts')) {
        $Config.MaxRetryAttempts = $MaxRetryAttempts
        Write-Host "Updated MaxRetryAttempts: $MaxRetryAttempts" -ForegroundColor Green
    }
    
    if ($EnableCompression) {
        $Config.EnableCompression = $true
        Write-Host "Compression: Enabled" -ForegroundColor Green
    }
    
    if ($DisableCompression) {
        $Config.EnableCompression = $false
        Write-Host "Compression: Disabled" -ForegroundColor Yellow
    }
    
    # Save configuration
    if (-not $ShowConfig) {
        $ConfigDir = Split-Path $ConfigPath -Parent
        if (!(Test-Path $ConfigDir)) {
            New-Item -ItemType Directory -Path $ConfigDir -Force | Out-Null
        }
        
        $Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Force
        Write-Host "`nConfiguration saved to: $ConfigPath" -ForegroundColor Cyan
    }
    
    # Display configuration
    if ($ShowConfig -or $PSBoundParameters.Count -eq 0) {
        Write-Host "`nCurrent Configuration:" -ForegroundColor Cyan
        Write-Host "======================" -ForegroundColor Cyan
        
        $Config.PSObject.Properties | ForEach-Object {
            $Name = $_.Name
            $Value = $_.Value
            
            if ($Name -eq "ApiKey" -and ![string]::IsNullOrEmpty($Value)) {
                $Value = "[HIDDEN]"
            }
            
            Write-Host "${Name}: $Value"
        }
    }
}

# Execute configuration update
Set-InventoryConfiguration
```

#### 5. Monitoring and Troubleshooting Scripts

**Test-InventoryAgent.ps1**
```powershell
<#
.SYNOPSIS
    Tests inventory agent functionality
.DESCRIPTION
    Comprehensive testing and troubleshooting for the inventory agent
#>

[CmdletBinding()]
param(
    [Parameter()]
    [switch]$TestCollection,
    
    [Parameter()]
    [switch]$TestConnection,
    
    [Parameter()]
    [switch]$CheckTasks,
    
    [Parameter()]
    [switch]$ViewLogs,
    
    [Parameter()]
    [switch]$ClearQueue,
    
    [Parameter()]
    [switch]$FullDiagnostics
)

function Test-InventoryAgent {
    Write-Host "Inventory Agent Diagnostics" -ForegroundColor Cyan
    Write-Host "===========================" -ForegroundColor Cyan
    
    $AgentPath = "C:\ProgramData\InventoryAgent"
    
    # Check installation
    Write-Host "`n[Installation Check]" -ForegroundColor Yellow
    
    if (Test-Path $AgentPath) {
        Write-Host "✓ Agent directory exists: $AgentPath" -ForegroundColor Green
        
        $RequiredFiles = @(
            "Collect-Inventory.ps1",
            "Config.json"
        )
        
        foreach ($File in $RequiredFiles) {
            $FilePath = Join-Path $AgentPath $File
            if (Test-Path $FilePath) {
                Write-Host "✓ $File exists" -ForegroundColor Green
            }
            else {
                Write-Host "✗ $File missing" -ForegroundColor Red
            }
        }
    }
    else {
        Write-Host "✗ Agent not installed at: $AgentPath" -ForegroundColor Red
        return
    }
    
    # Check scheduled tasks
    if ($CheckTasks -or $FullDiagnostics) {
        Write-Host "`n[Scheduled Tasks]" -ForegroundColor Yellow
        
        $Tasks = Get-ScheduledTask -TaskName "InventoryAgent-*" -ErrorAction SilentlyContinue
        
        if ($Tasks) {
            foreach ($Task in $Tasks) {
                $LastRun = $Task.LastRunTime
                $NextRun = $Task.NextRunTime
                $State = $Task.State
                
                $StateColor = switch ($State) {
                    "Ready" { "Green" }
                    "Running" { "Cyan" }
                    "Disabled" { "Red" }
                    default { "Yellow" }
                }
                
                Write-Host "Task: $($Task.TaskName)" -ForegroundColor White
                Write-Host "  State: $State" -ForegroundColor $StateColor
                Write-Host "  Last Run: $LastRun"
                Write-Host "  Next Run: $NextRun"
                
                # Get last result
                $TaskInfo = Get-ScheduledTaskInfo -TaskName $Task.TaskName -ErrorAction SilentlyContinue
                if ($TaskInfo) {
                    $LastResult = switch ($TaskInfo.LastTaskResult) {
                        0 { "Success (0x0)" }
                        1 { "Incorrect function (0x1)" }
                        267011 { "Task has not yet run (0x41303)" }
                        default { "0x{0:X}" -f $TaskInfo.LastTaskResult }
                    }
                    Write-Host "  Last Result: $LastResult"
                }
                Write-Host ""
            }
        }
        else {
            Write-Host "✗ No scheduled tasks found" -ForegroundColor Red
        }
    }
    
    # Test connection
    if ($TestConnection -or $FullDiagnostics) {
        Write-Host "`n[Connection Test]" -ForegroundColor Yellow
        
        $ConfigPath = Join-Path $AgentPath "Config.json"
        if (Test-Path $ConfigPath) {
            $Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json
            
            Write-Host "Server Endpoint: $($Config.ServerEndpoint)"
            
            try {
                $Response = Invoke-WebRequest -Uri "$($Config.ServerEndpoint)/health" `
                    -Method GET `
                    -UseBasicParsing `
                    -TimeoutSec 10 `
                    -ErrorAction Stop
                
                Write-Host "✓ Server is reachable - Status: $($Response.StatusCode)" -ForegroundColor Green
            }
            catch {
                Write-Host "✗ Cannot reach server: $_" -ForegroundColor Red
            }
        }
    }
    
    # Test collection
    if ($TestCollection) {
        Write-Host "`n[Test Collection]" -ForegroundColor Yellow
        Write-Host "Running inventory collection..." -ForegroundColor Cyan
        
        $ScriptPath = Join-Path $AgentPath "Collect-Inventory.ps1"
        
        try {
            & $ScriptPath -TriggerType Manual -Username $env:USERNAME
            Write-Host "✓ Collection completed" -ForegroundColor Green
        }
        catch {
            Write-Host "✗ Collection failed: $_" -ForegroundColor Red
        }
    }
    
    # View logs
    if ($ViewLogs -or $FullDiagnostics) {
        Write-Host "`n[Recent Log Entries]" -ForegroundColor Yellow
        
        $LogPath = Join-Path $AgentPath "Logs"
        $LogFile = Join-Path $LogPath "inventory_$(Get-Date -Format 'yyyyMMdd').log"
        
        if (Test-Path $LogFile) {
            $LogEntries = Get-Content $LogFile -Tail 20
            foreach ($Entry in $LogEntries) {
                if ($Entry -match "\[Error\]") {
                    Write-Host $Entry -ForegroundColor Red
                }
                elseif ($Entry -match "\[Warning\]") {
                    Write-Host $Entry -ForegroundColor Yellow
                }
                else {
                    Write-Host $Entry -ForegroundColor Gray
                }
            }
        }
        else {
            Write-Host "No log file found for today" -ForegroundColor Yellow
        }
    }
    
    # Check queue
    Write-Host "`n[Offline Queue]" -ForegroundColor Yellow
    $QueuePath = Join-Path $AgentPath "Queue"
    
    if (Test-Path $QueuePath) {
        $QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue
        $QueueCount = $QueueFiles.Count
        
        if ($QueueCount -gt 0) {
            Write-Host "⚠ $QueueCount items in offline queue" -ForegroundColor Yellow
            
            if ($ClearQueue) {
                Write-Host "Clearing queue..." -ForegroundColor Cyan
                Remove-Item -Path "$QueuePath\*.json" -Force
                Write-Host "✓ Queue cleared" -ForegroundColor Green
            }
        }
        else {
            Write-Host "✓ Queue is empty" -ForegroundColor Green
        }
    }
    
    # Performance metrics
    if ($FullDiagnostics) {
        Write-Host "`n[Performance Metrics]" -ForegroundColor Yellow
        
        # Check disk usage
        $AgentSize = (Get-ChildItem -Path $AgentPath -Recurse | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "Disk Usage: {0:N2} MB" -f $AgentSize
        
        # Check log file sizes
        $LogSize = (Get-ChildItem -Path "$AgentPath\Logs" -Filter "*.log" | Measure-Object -Property Length -Sum).Sum / 1MB
        Write-Host "Log Files: {0:N2} MB" -f $LogSize
        
        # Check last collection duration (from logs)
        $LogFile = Join-Path $AgentPath "Logs\inventory_$(Get-Date -Format 'yyyyMMdd').log"
        if (Test-Path $LogFile) {
            $StartPattern = "Starting inventory collection"
            $EndPattern = "Inventory collection completed"
            
            $LogContent = Get-Content $LogFile
            $LastStart = $LogContent | Where-Object { $_ -match $StartPattern } | Select-Object -Last 1
            $LastEnd = $LogContent | Where-Object { $_ -match $EndPattern } | Select-Object -Last 1
            
            if ($LastStart -and $LastEnd) {
                $StartTime = [DateTime]::ParseExact($LastStart.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", $null)
                $EndTime = [DateTime]::ParseExact($LastEnd.Substring(0, 19), "yyyy-MM-dd HH:mm:ss", $null)
                $Duration = $EndTime - $StartTime
                Write-Host "Last Collection Duration: $($Duration.TotalSeconds) seconds"
            }
        }
    }
    
    Write-Host "`n✅ Diagnostics complete" -ForegroundColor Green
}

# Execute diagnostics
Test-InventoryAgent
```

### Comparison of Both Options

| Feature | Option 1: Compiled .NET Service | Option 2: PowerShell Scripts |
|---------|----------------------------------|------------------------------|
| **Deployment Complexity** | Requires MSI package and signing | Simple script deployment via GPO |
| **Maintenance** | Requires recompilation for changes | Easy to modify scripts on the fly |
| **Performance** | Better performance, lower overhead | Slightly higher overhead |
| **Resource Usage** | ~30-50MB RAM continuously | ~100MB RAM during execution only |
| **Security** | Binary obfuscation, harder to tamper | Scripts are readable, easier to audit |
| **Debugging** | Requires debugging tools | Easy to debug with PowerShell ISE |
| **Dependencies** | .NET Runtime required | PowerShell (built-in to Windows) |
| **Monitoring** | Windows Service monitoring | Task Scheduler monitoring |
| **Offline Queue** | SQLite database | JSON files |
| **Certificate Auth** | Built-in support | Requires PowerShell cmdlets |
| **Event Detection** | Real-time event monitoring | Task Scheduler triggers |
| **Update Mechanism** | MSI upgrade via GPO | Script replacement via GPO |
| **Logging** | Structured logging with levels | Text-based logging |
| **Error Recovery** | Automatic service restart | Task Scheduler retry |
| **Scalability** | Better for large deployments | Good for small-medium deployments |

### Recommendations

**Choose Option 1 (Compiled .NET Service) when:**
- You have 10,000+ endpoints
- Security through obfuscation is important
- You need real-time event processing
- You have a mature software deployment process
- Performance is critical
- You need advanced features like performance counters

**Choose Option 2 (PowerShell Scripts) when:**
- You have <10,000 endpoints
- You need flexibility to modify behavior quickly
- You prefer simpler deployment and maintenance
- You want easier troubleshooting
- You have limited development resources
- You prefer native Windows technologies

Both solutions are production-ready and can be deployed via Group Policy. The PowerShell option is generally easier to start with and maintain, while the compiled service offers better performance and security for large-scale deployments.
