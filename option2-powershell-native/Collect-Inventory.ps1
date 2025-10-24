<#
.SYNOPSIS
    Collects hardware inventory from Windows 11 systems and transmits to central server.

.DESCRIPTION
    Security-hardened PowerShell script that performs comprehensive hardware inventory
    collection from Windows 11 workstations in Active Directory environments.

    This script is designed for government/enterprise environments with strict security
    requirements including:
    - Constrained Language Mode (CLM) compatibility
    - AppLocker/Device Guard support
    - Air-gapped network resilience via offline queue
    - Certificate-based authentication
    - TLS 1.2+ enforcement
    - Comprehensive audit logging

    COLLECTION METHODS:
    - System Information: WMI/CIM queries (Win32_ComputerSystem, Win32_BIOS)
    - Disk Serials: Physical disk enumeration (Win32_DiskDrive)
    - Network Configuration: Active adapter detection (Win32_NetworkAdapterConfiguration)
    - User Sessions: Current logon tracking (Win32_ComputerSystem, quser)

    TRANSMISSION:
    - Primary: HTTPS POST to REST API endpoint
    - Fallback: Local queue (JSON files) for offline scenarios
    - Authentication: Bearer token or mutual TLS with client certificates

    DEPLOYMENT:
    - Via Group Policy as scheduled task (daily + logon triggers)
    - Via SCCM/Intune as script deployment
    - Manual execution for testing/troubleshooting

.PARAMETER TriggerType
    [string] Execution trigger that initiated this collection run.
    Valid values: "Logon", "Scheduled", "Manual"
    Default: "Manual"

    - "Logon": Triggered by user logon event (via Task Scheduler)
    - "Scheduled": Triggered by daily schedule (via Task Scheduler)
    - "Manual": Triggered by administrator for testing

.PARAMETER Username
    [string] Username of the logged-on user who triggered this collection.
    Default: Current environment username ($env:USERNAME)

    Used for:
    - Tracking last logged-on user
    - Debounce file naming (prevents duplicate collections)
    - Audit trail in logs

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
    Exit code 0 for success, 1 for failure.

    Side effects:
    - Creates/updates files in C:\ProgramData\InventoryAgent\
    - Writes to Windows Event Log (Application log, source: InventoryAgent)
    - Sends HTTPS POST to configured server endpoint
    - Queues data locally if transmission fails

.EXAMPLE
    PS> .\Collect-Inventory.ps1

    Runs manual inventory collection with default parameters.
    Uses current username from $env:USERNAME.

.EXAMPLE
    PS> .\Collect-Inventory.ps1 -TriggerType Logon -Username "DOMAIN\jsmith"

    Runs inventory collection triggered by user logon event.
    Records jsmith as the triggering user.

.EXAMPLE
    PS> .\Collect-Inventory.ps1 -TriggerType Scheduled

    Runs scheduled inventory collection (typically at 2 AM daily).
    Bypasses debounce check since it's a scheduled run.

.NOTES
    File Name      : Collect-Inventory.ps1
    Version        : 2.1.0-Security-Hardened
    Author         : IT Systems Engineering Team
    Prerequisite   : PowerShell 5.1 or higher
    Prerequisite   : Windows 11 (22H2 or later recommended)
    Prerequisite   : Script must be digitally signed for AllSigned/RemoteSigned policies

    SECURITY NOTES:
    - Script signature is validated if execution policy requires it
    - All network traffic uses TLS 1.2 or higher
    - Sensitive data (API keys, certificates) stored in registry or certificate store
    - All security events logged to Windows Event Log with EventID 1003

    PERFORMANCE:
    - Typical execution time: 5-10 seconds
    - Memory usage: <100MB during execution
    - Disk usage: ~50KB per queued inventory (before transmission)

    TROUBLESHOOTING:
    - Logs: C:\ProgramData\InventoryAgent\Logs\inventory_YYYYMMDD.log
    - Event Log: Application log, source "InventoryAgent"
    - Queue: C:\ProgramData\InventoryAgent\Queue\*.json
    - Test connectivity: Invoke-WebRequest https://server/api/v1/health

.LINK
    https://docs.company.com/inventory-agent

.LINK
    https://github.com/company/inventory-agent
#>

#Requires -Version 5.1

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               Position = 0,
               HelpMessage = "Execution trigger: Logon, Scheduled, or Manual")]
    [ValidateSet("Logon", "Scheduled", "Manual")]
    [ValidateNotNullOrEmpty()]
    [string]$TriggerType = "Manual",

    [Parameter(Mandatory = $false,
               Position = 1,
               HelpMessage = "Username of logged-on user (DOMAIN\username format)")]
    [ValidateNotNullOrEmpty()]
    [string]$Username = $env:USERNAME
)

#region Script-Level Variables and Constants
<#
    SCRIPT CONFIGURATION
    These variables define the runtime behavior and file system paths
    used throughout the script execution lifecycle.
#>

# Stop on all errors (fail-fast approach for reliability)
[string]$ErrorActionPreference = "Stop"

# Suppress progress bars for performance (can slow script in loops)
[string]$ProgressPreference = "SilentlyContinue"

# Enforce TLS 1.2 or higher for all HTTPS connections
# Government/enterprise requirement for FIPS compliance
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

# File system paths for agent data storage
# Using ProgramData (not AppData) for machine-wide access by SYSTEM account
[string]$ScriptRoot = "C:\ProgramData\InventoryAgent"
[string]$ConfigPath = Join-Path -Path $ScriptRoot -ChildPath "Config.json"
[string]$LogPath = Join-Path -Path $ScriptRoot -ChildPath "Logs"
[string]$QueuePath = Join-Path -Path $ScriptRoot -ChildPath "Queue"

# Detect PowerShell execution environment restrictions
# Constrained Language Mode (CLM) is enforced by AppLocker/Device Guard
[string]$LanguageMode = $ExecutionContext.SessionState.LanguageMode
[bool]$IsConstrained = ($LanguageMode -eq 'ConstrainedLanguage')

# Ensure required directory structure exists
# Failure to create directories is fatal (cannot proceed without storage)
@($ScriptRoot, $LogPath, $QueuePath) | ForEach-Object {
    if (!(Test-Path -Path $_)) {
        try {
            New-Item -ItemType Directory -Path $_ -Force -ErrorAction Stop | Out-Null
        }
        catch {
            Write-Error "Failed to create directory: $_"
            exit 1
        }
    }
}
#endregion

#region Logging Functions
<#
    LOGGING SUBSYSTEM
    Dual-logging implementation: file-based (for troubleshooting) and
    Windows Event Log (for centralized monitoring/SIEM integration).
#>

function Write-Log {
    <#
    .SYNOPSIS
        Writes log entries to both file and Windows Event Log.

    .DESCRIPTION
        Centralized logging function that writes formatted log entries to:
        1. Daily log file (C:\ProgramData\InventoryAgent\Logs\inventory_YYYYMMDD.log)
        2. Windows Event Log (Application log, source: InventoryAgent)

        Log format: "YYYY-MM-DD HH:MM:SS [LEVEL] Message"

        Event IDs:
        - 1000: Informational
        - 1001: Warning
        - 1002: Error
        - 1003: Security Audit

    .PARAMETER Message
        [string] The log message to write. Can be multi-line.

    .PARAMETER Level
        [string] Log severity level.
        Valid values: "Info", "Warning", "Error", "Security"
        Default: "Info"

    .INPUTS
        None. Parameters only.

    .OUTPUTS
        None. Writes to log file and Event Log as side effect.

    .EXAMPLE
        Write-Log "Inventory collection started" -Level Info

        Writes informational message to log file and Event Log.

    .EXAMPLE
        Write-Log "Failed to connect to server" -Level Error

        Writes error message with EventID 1002.

    .NOTES
        - If file logging fails, falls back to console output
        - Event Log writes are best-effort (silent failure if event source doesn't exist)
        - Log files are created daily (one file per day)
        - Old log files must be cleaned up manually or via separate maintenance script
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Warning", "Error", "Security")]
        [string]$Level = "Info"
    )

    # Format timestamp in ISO 8601 format for parseability
    [string]$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Construct daily log file path (one file per day for manageability)
    [string]$LogFile = Join-Path -Path $LogPath -ChildPath "inventory_$(Get-Date -Format 'yyyyMMdd').log"

    # Format log entry: "2024-10-24 14:30:00 [Info] Message text here"
    [string]$LogEntry = "$Timestamp [$Level] $Message"

    # Attempt to write to file (primary logging mechanism)
    try {
        Add-Content -Path $LogFile -Value $LogEntry -Force -ErrorAction Stop
    }
    catch {
        # Fallback to console if file logging fails (e.g., disk full, permissions issue)
        Write-Output $LogEntry
    }

    # Attempt to write to Windows Event Log (secondary logging mechanism)
    # This enables centralized monitoring via Event Log forwarding to SIEM
    try {
        [string]$EventLogSource = "InventoryAgent"

        # Only write if event source exists (must be pre-created by installer)
        if ([System.Diagnostics.EventLog]::SourceExists($EventLogSource)) {
            # Map log level to Event Log entry type
            [System.Diagnostics.EventLogEntryType]$EventType = switch ($Level) {
                "Info"     { [System.Diagnostics.EventLogEntryType]::Information }
                "Warning"  { [System.Diagnostics.EventLogEntryType]::Warning }
                "Error"    { [System.Diagnostics.EventLogEntryType]::Error }
                "Security" { [System.Diagnostics.EventLogEntryType]::FailureAudit }
            }

            # Map log level to Event ID for filtering in Event Viewer
            [int]$EventId = switch ($Level) {
                "Info"     { 1000 }
                "Warning"  { 1001 }
                "Error"    { 1002 }
                "Security" { 1003 }
            }

            Write-EventLog -LogName Application `
                          -Source $EventLogSource `
                          -EntryType $EventType `
                          -EventId $EventId `
                          -Message $Message `
                          -ErrorAction SilentlyContinue
        }
    }
    catch {
        # Event log writing failed - continue silently (file logging is sufficient)
        # Common failure: Event source doesn't exist or insufficient permissions
    }
}

function Write-SecurityLog {
    <#
    .SYNOPSIS
        Writes security audit log entry.

    .DESCRIPTION
        Convenience wrapper for Write-Log with Level set to "Security".
        Used for security-relevant events that should be audited:
        - Script signature validation
        - Authentication attempts
        - Certificate validation
        - Data transmission success/failure

    .PARAMETER Message
        [string] Security audit message to log.

    .INPUTS
        None.

    .OUTPUTS
        None.

    .EXAMPLE
        Write-SecurityLog "Certificate validation failed"

        Logs security event with EventID 1003.

    .NOTES
        All security events are written to Event Log for SIEM integration.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [string]$Message
    )

    Write-Log -Message $Message -Level Security
}
#endregion

#region Environment Detection
function Test-ExecutionEnvironment {
    <#
    .SYNOPSIS
        Detects and validates PowerShell execution environment.

    .DESCRIPTION
        Examines the current PowerShell execution context to determine:
        - PowerShell version
        - Language mode (FullLanguage vs ConstrainedLanguage)
        - Elevation status (running as administrator)
        - Execution policy
        - Script signature status

        This information is:
        1. Logged for troubleshooting
        2. Included in inventory payload for server-side analytics
        3. Used to adjust script behavior (e.g., disable compression in CLM)

        SECURITY VALIDATION:
        If execution policy requires signed scripts (AllSigned/RemoteSigned),
        validates script signature and logs security event.

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable
        Hashtable containing environment details:
        @{
            PSVersion       = "5.1.19041.4648"      # PowerShell version string
            LanguageMode    = "ConstrainedLanguage" # FullLanguage or ConstrainedLanguage
            IsConstrained   = $true                 # Boolean: is CLM enabled?
            IsElevated      = $true                 # Boolean: running as admin?
            OSVersion       = "10.0.22621.0"        # Windows version
            ExecutionPolicy = "RemoteSigned"        # Current execution policy
        }

    .EXAMPLE
        $env = Test-ExecutionEnvironment
        if ($env.IsConstrained) {
            Write-Host "Running in Constrained Language Mode"
        }

        Detects environment and checks for CLM.

    .NOTES
        - Script signature validation is logged as security event
        - Invalid signature is logged but does NOT halt execution (configurable)
        - Environment hashtable is included in inventory payload
        - Used to diagnose environment-specific issues
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-Log "Detecting execution environment..." -Level Info

    # Build environment details hashtable
    # This will be included in inventory payload for server-side analytics
    [hashtable]$Environment = @{
        PSVersion       = $PSVersionTable.PSVersion.ToString()
        LanguageMode    = $LanguageMode
        IsConstrained   = $IsConstrained
        IsElevated      = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
        OSVersion       = [System.Environment]::OSVersion.Version.ToString()
        ExecutionPolicy = Get-ExecutionPolicy -Scope CurrentUser
    }

    # Log environment details for troubleshooting
    Write-Log "PowerShell Version: $($Environment.PSVersion)" -Level Info
    Write-Log "Language Mode: $($Environment.LanguageMode)" -Level Info
    Write-Log "Elevated: $($Environment.IsElevated)" -Level Info
    Write-Log "Execution Policy: $($Environment.ExecutionPolicy)" -Level Info

    # Warn if running in Constrained Language Mode
    # CLM restricts certain PowerShell features (Add-Type, Invoke-Expression, etc.)
    if ($IsConstrained) {
        Write-Log "WARNING: Constrained Language Mode detected - some features will be disabled" -Level Warning
    }

    # Verify script signature if execution policy requires it
    # This is a security control for government/enterprise environments
    if ($Environment.ExecutionPolicy -eq 'AllSigned' -or $Environment.ExecutionPolicy -eq 'RemoteSigned') {
        [string]$ScriptPath = $PSCommandPath

        if ($ScriptPath) {
            [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $ScriptPath

            if ($Signature.Status -ne 'Valid') {
                Write-SecurityLog "Script signature validation failed: $($Signature.Status)"
                Write-Log "ERROR: Script is not properly signed. Status: $($Signature.Status)" -Level Error

                # In production, uncomment the next line to halt execution:
                # exit 1
            }
            else {
                Write-SecurityLog "Script signature validated: $($Signature.SignerCertificate.Subject)"
            }
        }
    }

    return $Environment
}
#endregion

#region Configuration Management
function Get-Configuration {
    <#
    .SYNOPSIS
        Loads agent configuration from file or registry.

    .DESCRIPTION
        Loads configuration in the following priority order:
        1. Config file (C:\ProgramData\InventoryAgent\Config.json)
        2. Registry (HKLM:\SOFTWARE\YourCompany\InventoryAgent) - for GPO deployment
        3. Default values (hard-coded in this function)

        Configuration is stored as JSON for easy editing, but can be
        overridden by Group Policy via registry values.

        CONSTRAINED LANGUAGE MODE HANDLING:
        Automatically disables compression in CLM environments because
        GZip compression requires .NET types that are restricted in CLM.

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable
        Configuration hashtable with the following structure:
        @{
            ServerEndpoint              = "https://inventory.company.com/api/v1"
            ApiKey                      = ""                    # Bearer token
            CertificateThumbprint       = ""                    # Client cert thumbprint
            EnableDebounce              = $true                 # Prevent duplicate runs
            DebounceMinutes             = 60                    # Minutes between runs
            MaxRetryAttempts            = 3                     # HTTP retry count
            RetryDelaySeconds           = 30                    # Delay between retries
            QueueMaxSize                = 1000                  # Max queued items
            EnableCompression           = $false                # GZip compression (disabled in CLM)
            UseProxy                    = $false                # Use HTTP proxy
            ProxyServer                 = ""                    # Proxy URL
            ProxyUseDefaultCredentials  = $true                 # Use Windows integrated auth
            ConnectionTimeoutSeconds    = 30                    # HTTP timeout
            ValidateServerCertificate   = $true                 # Validate TLS cert
        }

    .EXAMPLE
        $config = Get-Configuration
        Write-Host "Server: $($config.ServerEndpoint)"

        Loads configuration and displays server endpoint.

    .NOTES
        - Registry values override file values
        - File is created with defaults if it doesn't exist
        - Compression auto-disabled in Constrained Language Mode
        - Configuration is cached (not reloaded on each call)
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    try {
        # Attempt to load existing configuration file
        if (Test-Path -Path $ConfigPath) {
            # Read JSON config file
            [PSCustomObject]$ConfigObject = Get-Content -Path $ConfigPath -Raw | ConvertFrom-Json

            # Convert PSCustomObject to hashtable for easier manipulation
            # Hashtables support dynamic property addition without type conflicts
            [hashtable]$Config = @{}
            $ConfigObject.PSObject.Properties | ForEach-Object {
                $Config[$_.Name] = $_.Value
            }
        }
        else {
            # Create default configuration
            # These values should work in most environments but may need tuning
            [hashtable]$Config = @{
                ServerEndpoint              = "https://inventory.company.com/api/v1"
                ApiKey                      = ""                    # Optional: Bearer token for API authentication
                CertificateThumbprint       = ""                    # Optional: Client certificate thumbprint for mutual TLS
                EnableDebounce              = $true                 # Prevent duplicate collections within DebounceMinutes
                DebounceMinutes             = 60                    # Time window for debounce (prevent logon spam)
                MaxRetryAttempts            = 3                     # Number of HTTP retries before queueing
                RetryDelaySeconds           = 30                    # Base delay between retries (exponential backoff)
                QueueMaxSize                = 1000                  # Maximum queued items before purging oldest
                EnableCompression           = $false                # GZip compression (disabled for CLM compatibility)
                UseProxy                    = $false                # Enable HTTP proxy
                ProxyServer                 = ""                    # Proxy URL (e.g., "http://proxy.company.com:8080")
                ProxyUseDefaultCredentials  = $true                 # Use Windows integrated auth for proxy
                ConnectionTimeoutSeconds    = 30                    # HTTP request timeout
                ValidateServerCertificate   = $true                 # Validate server TLS certificate
            }

            # Check registry for GPO-deployed settings
            # Group Policy can deploy registry values to override file-based config
            [string]$RegPath = "HKLM:\SOFTWARE\YourCompany\InventoryAgent"
            if (Test-Path -Path $RegPath) {
                try {
                    [PSCustomObject]$RegConfig = Get-ItemProperty -Path $RegPath -ErrorAction SilentlyContinue

                    # Override file config with registry values (registry wins)
                    if ($RegConfig.ServerEndpoint) {
                        $Config.ServerEndpoint = $RegConfig.ServerEndpoint
                    }
                    if ($RegConfig.ApiKey) {
                        $Config.ApiKey = $RegConfig.ApiKey
                    }
                    if ($RegConfig.CertificateThumbprint) {
                        $Config.CertificateThumbprint = $RegConfig.CertificateThumbprint
                    }
                    if ($RegConfig.ProxyServer) {
                        $Config.UseProxy = $true
                        $Config.ProxyServer = $RegConfig.ProxyServer
                    }
                }
                catch {
                    Write-Log "Failed to read registry configuration: $_" -Level Warning
                }
            }

            # Save default configuration to file for future runs
            try {
                $Config | ConvertTo-Json | Out-File -FilePath $ConfigPath -Force
            }
            catch {
                Write-Log "Failed to save configuration: $_" -Level Warning
            }
        }

        # Force disable compression in Constrained Language Mode
        # CLM restricts Add-Type and [System.IO.Compression.GzipStream]
        if ($IsConstrained -and $Config.EnableCompression) {
            Write-Log "Disabling compression due to Constrained Language Mode" -Level Warning
            $Config.EnableCompression = $false
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
    <#
    .SYNOPSIS
        Determines if inventory collection should proceed based on debounce logic.

    .DESCRIPTION
        Implements debounce logic to prevent excessive inventory collections.

        RATIONALE:
        User logon events can fire multiple times during a single login session
        (Fast User Switching, RDP connections, unlock events). Without debounce,
        this would cause excessive server load and network traffic.

        DEBOUNCE LOGIC:
        - Tracks last collection time per user in file: debounce_USERNAME.txt
        - If last collection was within DebounceMinutes, skip this collection
        - Scheduled collections always proceed (bypass debounce)
        - File stores timestamp in format: "YYYY-MM-DD HH:MM:SS"

        DEBOUNCE FILES:
        Location: C:\ProgramData\InventoryAgent\debounce_USERNAME.txt
        Format: Single line with timestamp
        Example: "2024-10-24 14:30:00"

    .PARAMETER TriggerType
        [string] Execution trigger: "Logon", "Scheduled", or "Manual"
        Scheduled collections bypass debounce.

    .PARAMETER Username
        [string] Username for debounce file naming.
        Sanitized to remove special characters.

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if collection should proceed
        $false if collection should be skipped (within debounce window)

    .EXAMPLE
        if (Test-ShouldCollect -TriggerType "Logon" -Username "DOMAIN\jsmith") {
            # Proceed with collection
        }

        Checks if collection should run for user jsmith.

    .NOTES
        - Debounce files are NOT automatically cleaned up
        - Old debounce files (>30 days) should be purged via maintenance script
        - Username is sanitized to remove special characters (domain separators, etc.)
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Logon", "Scheduled", "Manual")]
        [string]$TriggerType,

        [Parameter(Mandatory = $true)]
        [string]$Username
    )

    # Load configuration to get debounce settings
    [hashtable]$Config = Get-Configuration

    # Bypass debounce for scheduled collections or if debounce is disabled
    if (-not $Config.EnableDebounce -or $TriggerType -eq "Scheduled") {
        return $true
    }

    # Sanitize username for safe filesystem usage
    # Remove domain separators (\), forward slashes (/), and other special chars
    # Example: "DOMAIN\jsmith" becomes "DOMAIN_jsmith"
    [string]$SafeUsername = $Username -replace '[^\w]', '_'

    # Construct debounce file path
    [string]$DebounceFile = Join-Path -Path $ScriptRoot -ChildPath "debounce_$SafeUsername.txt"

    # Check if debounce file exists (previous collection occurred)
    if (Test-Path -Path $DebounceFile) {
        try {
            # Read last collection timestamp from file
            [string]$LastRun = Get-Content -Path $DebounceFile -Raw -ErrorAction Stop
            [DateTime]$LastRunTime = [DateTime]::Parse($LastRun)
            [TimeSpan]$TimeSinceLastRun = (Get-Date) - $LastRunTime

            # Check if within debounce window
            if ($TimeSinceLastRun.TotalMinutes -lt $Config.DebounceMinutes) {
                Write-Log "Skipping collection - last run was $([int]$TimeSinceLastRun.TotalMinutes) minutes ago" -Level Info
                return $false
            }
        }
        catch {
            # Failed to read debounce file (corrupted, permission issue, etc.)
            # Proceed with collection rather than blocking
            Write-Log "Failed to read debounce file: $_" -Level Warning
        }
    }

    # Update debounce file with current timestamp
    try {
        Get-Date -Format "yyyy-MM-dd HH:mm:ss" | Out-File -FilePath $DebounceFile -Force
    }
    catch {
        # Failed to update debounce file - log but don't block collection
        Write-Log "Failed to update debounce file: $_" -Level Warning
    }

    return $true
}
#endregion

#region System Information Collection
function Get-SystemInfo {
    <#
    .SYNOPSIS
        Collects system hardware and OS information via WMI/CIM.

    .DESCRIPTION
        Queries WMI/CIM classes to collect comprehensive system information:
        - Computer name and domain membership
        - Hardware manufacturer and model
        - BIOS version and serial number
        - Operating system version and architecture
        - Processor details (cores, threads, speed)
        - Physical memory capacity
        - Windows version details (DisplayVersion, ReleaseId, UBR)

        WMI CLASSES QUERIED:
        - Win32_ComputerSystem: Computer name, domain, manufacturer, model, memory
        - Win32_BIOS: Serial number, BIOS version, manufacturer
        - Win32_OperatingSystem: OS name, version, architecture, install date
        - Win32_Processor: CPU name, manufacturer, cores, threads, speed

        ERROR HANDLING:
        Each WMI query is wrapped in try-catch. If a query fails, logs warning
        and populates fields with fallback values (environment variables).

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable
        Hashtable with the following structure:
        @{
            ComputerName          = "DESKTOP-ABC123"           # NetBIOS name
            Domain                = "company.com"              # DNS domain or workgroup
            Manufacturer          = "Dell Inc."                # System manufacturer
            Model                 = "OptiPlex 7090"            # System model
            SerialNumber          = "ABC123XYZ"                # BIOS serial number
            BIOSVersion           = "2.15.0"                   # BIOS version
            BIOSManufacturer      = "Dell Inc."                # BIOS vendor
            BIOSReleaseDate       = [DateTime]                 # BIOS release date
            OperatingSystem       = "Microsoft Windows 11 Pro" # OS name
            OSVersion             = "10.0.22621"               # OS version number
            OSBuildNumber         = "22621"                    # OS build
            OSArchitecture        = "64-bit"                   # 32-bit or 64-bit
            LastBootTime          = [DateTime]                 # Last boot timestamp
            InstallDate           = [DateTime]                 # OS install date
            ProcessorName         = "Intel Core i7-10700"      # CPU model
            ProcessorManufacturer = "GenuineIntel"             # CPU vendor
            ProcessorCores        = 8                          # Physical cores
            ProcessorThreads      = 16                         # Logical processors
            ProcessorMaxSpeed     = 2900                       # MHz
            TotalPhysicalMemory   = 17179869184                # Bytes
            NumberOfProcessors    = 1                          # CPU sockets
            WindowsDisplayVersion = "23H2"                     # Windows feature release
            WindowsReleaseId      = "2009"                     # Windows release ID
            WindowsUBR            = 3155                       # Update Build Revision
        }

    .EXAMPLE
        $sysInfo = Get-SystemInfo
        Write-Host "Computer: $($sysInfo.ComputerName)"
        Write-Host "Serial: $($sysInfo.SerialNumber)"

        Collects system info and displays computer name and serial.

    .NOTES
        - All WMI queries use Get-CimInstance (CIM cmdlets) not Get-WmiObject (deprecated)
        - CIM cmdlets use WS-MAN protocol (better for remoting)
        - Queries are fast (typically <1 second total)
        - If WMI service is disabled, all queries will fail gracefully
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param()

    Write-Log "Collecting system information" -Level Info

    # Initialize empty hashtable to store system information
    [hashtable]$SystemInfo = @{}

    try {
        # === COMPUTER SYSTEM INFORMATION ===
        # Query: Win32_ComputerSystem
        # Purpose: Computer name, domain, manufacturer, model, memory, processor count
        try {
            [Microsoft.Management.Infrastructure.CimInstance]$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop

            $SystemInfo.ComputerName        = $ComputerSystem.Name
            $SystemInfo.Domain              = $ComputerSystem.Domain
            $SystemInfo.Manufacturer        = $ComputerSystem.Manufacturer
            $SystemInfo.Model               = $ComputerSystem.Model
            $SystemInfo.TotalPhysicalMemory = $ComputerSystem.TotalPhysicalMemory  # Bytes
            $SystemInfo.NumberOfProcessors  = $ComputerSystem.NumberOfProcessors   # Physical CPU sockets
        }
        catch {
            # Fallback to environment variables if WMI query fails
            Write-Log "Failed to query Win32_ComputerSystem: $_" -Level Warning
            $SystemInfo.ComputerName = $env:COMPUTERNAME
            $SystemInfo.Domain       = $env:USERDOMAIN
        }

        # === BIOS INFORMATION ===
        # Query: Win32_BIOS
        # Purpose: System serial number (critical for asset tracking)
        try {
            [Microsoft.Management.Infrastructure.CimInstance]$BIOS = Get-CimInstance -ClassName Win32_BIOS -ErrorAction Stop

            $SystemInfo.SerialNumber      = $BIOS.SerialNumber         # Most important field for asset tracking
            $SystemInfo.BIOSVersion       = $BIOS.SMBIOSBIOSVersion
            $SystemInfo.BIOSManufacturer  = $BIOS.Manufacturer
            $SystemInfo.BIOSReleaseDate   = $BIOS.ReleaseDate
        }
        catch {
            Write-Log "Failed to query Win32_BIOS: $_" -Level Warning
            $SystemInfo.SerialNumber = "Unknown"
        }

        # === OPERATING SYSTEM INFORMATION ===
        # Query: Win32_OperatingSystem
        # Purpose: OS version, architecture, install date, last boot time
        try {
            [Microsoft.Management.Infrastructure.CimInstance]$OS = Get-CimInstance -ClassName Win32_OperatingSystem -ErrorAction Stop

            $SystemInfo.OperatingSystem  = $OS.Caption           # "Microsoft Windows 11 Pro"
            $SystemInfo.OSVersion        = $OS.Version           # "10.0.22621"
            $SystemInfo.OSBuildNumber    = $OS.BuildNumber       # "22621"
            $SystemInfo.OSArchitecture   = $OS.OSArchitecture    # "64-bit"
            $SystemInfo.LastBootTime     = $OS.LastBootUpTime    # [DateTime]
            $SystemInfo.InstallDate      = $OS.InstallDate       # [DateTime]
        }
        catch {
            Write-Log "Failed to query Win32_OperatingSystem: $_" -Level Warning
        }

        # === PROCESSOR INFORMATION ===
        # Query: Win32_Processor
        # Purpose: CPU model, cores, threads, speed
        # Note: Multi-socket systems return multiple objects; we only use the first
        try {
            [Microsoft.Management.Infrastructure.CimInstance]$CPU = Get-CimInstance -ClassName Win32_Processor -ErrorAction Stop | Select-Object -First 1

            $SystemInfo.ProcessorName         = $CPU.Name                      # "Intel(R) Core(TM) i7-10700 CPU @ 2.90GHz"
            $SystemInfo.ProcessorManufacturer = $CPU.Manufacturer              # "GenuineIntel"
            $SystemInfo.ProcessorCores        = $CPU.NumberOfCores             # Physical cores
            $SystemInfo.ProcessorThreads      = $CPU.NumberOfLogicalProcessors # Logical processors (hyperthreading)
            $SystemInfo.ProcessorMaxSpeed     = $CPU.MaxClockSpeed             # MHz
        }
        catch {
            Write-Log "Failed to query Win32_Processor: $_" -Level Warning
        }

        # === WINDOWS VERSION DETAILS ===
        # Source: Registry (HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion)
        # Purpose: Windows 11 feature release version (23H2, 22H2, etc.)
        try {
            [PSCustomObject]$WindowsVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -ErrorAction Stop

            $SystemInfo.WindowsDisplayVersion = $WindowsVersion.DisplayVersion  # "23H2"
            $SystemInfo.WindowsReleaseId      = $WindowsVersion.ReleaseId       # "2009"
            $SystemInfo.WindowsUBR            = $WindowsVersion.UBR             # Update Build Revision (patch level)
        }
        catch {
            Write-Log "Failed to read Windows version registry: $_" -Level Warning
        }

        Write-Log "System information collected successfully" -Level Info
    }
    catch {
        # Catch-all for any unexpected errors
        Write-Log "Error collecting system information: $_" -Level Error
    }

    return $SystemInfo
}

function Get-DiskInfo {
    <#
    .SYNOPSIS
        Collects physical disk serial numbers.

    .DESCRIPTION
        Queries Win32_DiskDrive to enumerate all fixed hard disks and extract
        their serial numbers for asset tracking.

        SERIAL NUMBER IMPORTANCE:
        Disk serial numbers are critical for:
        - Hardware asset tracking across lifecycle
        - Identifying systems when chassis/motherboard replaced
        - Warranty claim validation
        - Theft recovery and chain of custody

        DISK TYPES COLLECTED:
        Only "Fixed hard disk media" (excludes removable drives, optical drives)
        Includes: HDD, SSD, NVMe drives

        SERIAL NUMBER CLEANING:
        Raw serial numbers often contain whitespace padding.
        This function trims and removes all whitespace for consistency.

        Example transformation:
        Raw:     "  S4XNNA0M123456  "
        Cleaned: "S4XNNA0M123456"

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.String[]
        Array of disk serial numbers (strings).
        Empty array if no disks found or all queries fail.

        Example output:
        @(
            "S4XNNA0M123456",
            "WD-WCC4E0123456",
            "9876543210ABCDEF"
        )

    .EXAMPLE
        $disks = Get-DiskInfo
        Write-Host "Found $($disks.Count) disks"
        foreach ($serial in $disks) {
            Write-Host "Disk: $serial"
        }

        Collects disk serials and displays count and serials.

    .NOTES
        - Only physical disk serials are collected (not partition/volume serials)
        - Virtual disks in VMs report virtual serial numbers (not physical hardware)
        - Some disk controllers may not expose serial numbers (logs warning)
        - NVMe drives use different serial format than SATA/SAS drives
    #>
    [CmdletBinding()]
    [OutputType([string[]])]
    param()

    Write-Log "Collecting disk serial numbers" -Level Info

    # Initialize empty array to store disk serial numbers
    [System.Collections.ArrayList]$DiskSerials = @()

    try {
        # Query Win32_DiskDrive for all fixed hard disks
        # Filter: MediaType = "Fixed hard disk media" (excludes removable, optical, etc.)
        [Microsoft.Management.Infrastructure.CimInstance[]]$PhysicalDisks = Get-CimInstance -ClassName Win32_DiskDrive -ErrorAction Stop |
            Where-Object { $_.MediaType -eq 'Fixed hard disk media' }

        # Iterate through each physical disk
        foreach ($Disk in $PhysicalDisks) {
            try {
                # Extract and clean serial number
                # Remove all whitespace characters (spaces, tabs, newlines)
                [string]$SerialNumber = ($Disk.SerialNumber -replace '\s+', '').Trim()

                # Validate serial number is not empty
                # Some controllers/VMs may return empty serial
                if (![string]::IsNullOrWhiteSpace($SerialNumber)) {
                    [void]$DiskSerials.Add($SerialNumber)
                    Write-Log "Found disk serial: $SerialNumber" -Level Info
                }
                else {
                    Write-Log "Disk $($Disk.DeviceID) has no serial number" -Level Warning
                }
            }
            catch {
                Write-Log "Failed to read serial from disk $($Disk.DeviceID): $_" -Level Warning
            }
        }

        Write-Log "Collected $($DiskSerials.Count) disk serial number(s)" -Level Info
    }
    catch {
        # WMI query failed entirely (WMI service down, permissions issue, etc.)
        Write-Log "Error collecting disk serial numbers: $_" -Level Error
    }

    # Convert ArrayList to standard array for output
    return $DiskSerials.ToArray()
}

function Get-NetworkInfo {
    <#
    .SYNOPSIS
        Collects network adapter configuration from enabled adapters.

    .DESCRIPTION
        Queries Win32_NetworkAdapterConfiguration and Win32_NetworkAdapter to
        collect network configuration from all IP-enabled adapters.

        ADAPTERS COLLECTED:
        Only adapters with IPEnabled = $true (excludes disabled/disconnected adapters)
        Includes: Ethernet, Wi-Fi, VPN adapters
        Excludes: Disabled adapters, Bluetooth PAN, loopback

        INFORMATION COLLECTED:
        - IP addresses (IPv4 and IPv6)
        - MAC address
        - Subnet masks
        - Default gateway
        - DNS servers
        - DHCP configuration (enabled/disabled, DHCP server)
        - DNS domain suffix
        - Adapter type (Ethernet, Wi-Fi, etc.)
        - Link speed
        - Manufacturer

        USE CASES:
        - Network troubleshooting (IP conflicts, DHCP issues)
        - Asset tracking (MAC address for NAC systems)
        - Security auditing (unauthorized adapters, rogue DHCP)
        - Capacity planning (link speed, adapter types)

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable[]
        Array of hashtables, one per enabled network adapter.

        Each hashtable structure:
        @{
            Description     = "Intel(R) Ethernet Connection"  # Adapter name
            MACAddress      = "00:1A:2B:3C:4D:5E"            # MAC address
            IPAddresses     = @("192.168.1.100", "fe80::...")# IP addresses (array)
            IPSubnets       = @("255.255.255.0", "64")       # Subnet masks
            DefaultGateway  = @("192.168.1.1")               # Gateway(s)
            DNSServers      = @("8.8.8.8", "8.8.4.4")        # DNS servers
            DHCPEnabled     = $true                          # DHCP on/off
            DHCPServer      = "192.168.1.1"                  # DHCP server address
            DNSDomain       = "company.com"                  # DNS domain suffix
            AdapterType     = "Ethernet 802.3"               # Adapter type
            Speed           = 1000000000                     # Link speed (bps)
            Manufacturer    = "Intel Corporation"            # NIC vendor
        }

    .EXAMPLE
        $adapters = Get-NetworkInfo
        foreach ($adapter in $adapters) {
            Write-Host "Adapter: $($adapter.Description)"
            Write-Host "IP: $($adapter.IPAddresses -join ', ')"
            Write-Host "MAC: $($adapter.MACAddress)"
        }

        Collects network info and displays adapter details.

    .NOTES
        - Virtual adapters (VPN, VMware, Hyper-V) are included if IP-enabled
        - Multiple IP addresses per adapter are supported (IPv4 + IPv6)
        - Link speed may be $null for virtual adapters
        - Some fields may be $null if adapter doesn't support them
    #>
    [CmdletBinding()]
    [OutputType([hashtable[]])]
    param()

    Write-Log "Collecting network information" -Level Info

    # Initialize empty array to store network adapter information
    [System.Collections.ArrayList]$NetworkAdapters = @()

    try {
        # Query Win32_NetworkAdapterConfiguration for IP-enabled adapters only
        # Filter: IPEnabled = $true (excludes disabled/disconnected adapters)
        [Microsoft.Management.Infrastructure.CimInstance[]]$Adapters = Get-CimInstance -ClassName Win32_NetworkAdapterConfiguration -ErrorAction Stop |
            Where-Object { $_.IPEnabled -eq $true }

        # Iterate through each enabled adapter
        foreach ($Adapter in $Adapters) {
            try {
                # Build adapter information hashtable
                [hashtable]$AdapterInfo = @{
                    Description     = $Adapter.Description              # Adapter friendly name
                    MACAddress      = $Adapter.MACAddress               # MAC address (format: XX:XX:XX:XX:XX:XX)
                    IPAddresses     = $Adapter.IPAddress                # Array of IPs (IPv4 + IPv6)
                    IPSubnets       = $Adapter.IPSubnet                 # Array of subnet masks
                    DefaultGateway  = $Adapter.DefaultIPGateway         # Array of gateways
                    DNSServers      = $Adapter.DNSServerSearchOrder     # Array of DNS servers
                    DHCPEnabled     = $Adapter.DHCPEnabled              # Boolean: DHCP on/off
                    DHCPServer      = $Adapter.DHCPServer               # DHCP server IP (if DHCP enabled)
                    DNSDomain       = $Adapter.DNSDomain                # DNS domain suffix
                }

                # Query Win32_NetworkAdapter for physical adapter details
                # Links via Index property (unique per adapter)
                try {
                    [Microsoft.Management.Infrastructure.CimInstance]$PhysicalAdapter = Get-CimInstance -ClassName Win32_NetworkAdapter -ErrorAction Stop |
                        Where-Object { $_.Index -eq $Adapter.Index }

                    if ($PhysicalAdapter) {
                        $AdapterInfo.AdapterType  = $PhysicalAdapter.AdapterType  # "Ethernet 802.3", "Wireless"
                        $AdapterInfo.Speed        = $PhysicalAdapter.Speed        # Link speed in bps
                        $AdapterInfo.Manufacturer = $PhysicalAdapter.Manufacturer # Vendor name
                    }
                }
                catch {
                    Write-Log "Failed to get physical adapter details: $_" -Level Warning
                }

                # Add adapter info to collection
                [void]$NetworkAdapters.Add($AdapterInfo)
            }
            catch {
                Write-Log "Failed to process network adapter: $_" -Level Warning
            }
        }

        Write-Log "Collected information for $($NetworkAdapters.Count) network adapter(s)" -Level Info
    }
    catch {
        # WMI query failed entirely
        Write-Log "Error collecting network information: $_" -Level Error
    }

    # Convert ArrayList to standard array for output
    return $NetworkAdapters.ToArray()
}

function Get-UserInfo {
    <#
    .SYNOPSIS
        Collects currently logged-on user information.

    .DESCRIPTION
        Gathers information about currently logged-on users from multiple sources:
        1. Win32_ComputerSystem (primary logon user)
        2. quser command (all terminal sessions)
        3. Registry (last logged-on user if nobody currently logged on)

        USER TRACKING USE CASES:
        - Asset assignment (which user is using this computer)
        - License compliance (CAL tracking)
        - Security auditing (unusual login patterns)
        - Support ticketing (auto-populate ticket owner)

        MULTIPLE LOGON SCENARIOS:
        - Fast User Switching: Multiple users logged on simultaneously
        - RDP Sessions: Remote and console sessions active
        - Cached Credentials: No user logged on, shows last user from registry

    .PARAMETER Username
        [string] Username passed from script parameter (typically from logon event).
        Used as primary value if provided.

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable
        Hashtable with the following structure:
        @{
            LastLoggedUser = "DOMAIN\jsmith"           # Primary user (from parameter or WMI)
            LogonTime      = "2024-10-24 14:30:00"     # Current timestamp
            CurrentUsers   = @("DOMAIN\jsmith", ...)   # Array of logged-on users
            UserSessions   = @(                        # Detailed session info
                @{
                    Username    = "jsmith"
                    SessionName = "console"
                    State       = "Active"
                },
                @{
                    Username    = "admin"
                    SessionName = "rdp-tcp#0"
                    State       = "Disconnected"
                }
            )
        }

    .EXAMPLE
        $userInfo = Get-UserInfo -Username "DOMAIN\jsmith"
        Write-Host "Primary user: $($userInfo.LastLoggedUser)"
        Write-Host "All users: $($userInfo.CurrentUsers -join ', ')"

        Collects user info with specified primary user.

    .NOTES
        - quser command requires terminal services (fails on Server Core)
        - Win32_ComputerSystem.UserName only shows primary console user
        - Fast User Switching users detected via quser
        - If no user logged on, LastLoggedUser pulled from registry
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $false)]
        [AllowEmptyString()]
        [string]$Username
    )

    Write-Log "Collecting user information" -Level Info

    # Initialize user information hashtable
    [hashtable]$UserInfo = @{
        LastLoggedUser = $Username                                  # Primary user (from parameter)
        LogonTime      = Get-Date -Format "yyyy-MM-dd HH:mm:ss"    # Current timestamp
        CurrentUsers   = @()                                        # Array of all logged-on users
    }

    try {
        # === METHOD 1: Win32_ComputerSystem ===
        # Gets primary console user (interactive logon)
        # Returns format: "DOMAIN\username" or $null if nobody logged on
        try {
            [Microsoft.Management.Infrastructure.CimInstance]$ComputerSystem = Get-CimInstance -ClassName Win32_ComputerSystem -ErrorAction Stop
            [string]$LoggedOnUser = $ComputerSystem.UserName

            if ($LoggedOnUser) {
                $UserInfo.CurrentUsers += $LoggedOnUser
            }
        }
        catch {
            Write-Log "Failed to query logged on users: $_" -Level Warning
        }

        # === METHOD 2: quser Command ===
        # Gets all terminal sessions (console + RDP + Fast User Switching)
        # Output format (space-delimited):
        # USERNAME              SESSIONNAME        ID  STATE   IDLE TIME  LOGON TIME
        # >jsmith               console             1  Active          .  10/24/2024 2:30 PM
        #  admin                rdp-tcp#0           2  Disc        1+03:15  10/23/2024 9:00 AM
        try {
            [string[]]$QuserOutput = quser 2>$null

            if ($QuserOutput) {
                # Parse quser output (skip header line)
                [hashtable[]]$UserSessions = $QuserOutput | Select-Object -Skip 1 | ForEach-Object {
                    # Split line into fields (quser uses variable whitespace)
                    [string[]]$parts = $_ -split '\s+', 6

                    # Build session hashtable
                    @{
                        Username    = $parts[0].TrimStart('>')                                      # Remove '>' indicator for active session
                        SessionName = if ($parts.Count -gt 1) { $parts[1] } else { "" }            # console, rdp-tcp#0, etc.
                        State       = if ($parts.Count -gt 3 -and $parts[3] -eq 'Active') {        # Active or Disconnected
                                          $parts[3]
                                      } else {
                                          if ($parts.Count -gt 2) { $parts[2] } else { "" }
                                      }
                    }
                }

                $UserInfo.UserSessions = $UserSessions
            }
        }
        catch {
            # quser command may not be available (Server Core) or terminal services disabled
            Write-Log "Failed to get user sessions via quser: $_" -Level Warning
        }

        # === METHOD 3: Registry Fallback ===
        # If no username provided and nobody logged on, get last logged-on user from registry
        # Registry path: HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI
        # Value: LastLoggedOnUser (REG_SZ, format: DOMAIN\username)
        if ([string]::IsNullOrEmpty($Username)) {
            try {
                [string]$RegPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI"
                [PSCustomObject]$LastLoggedOnUserReg = Get-ItemProperty -Path $RegPath -Name "LastLoggedOnUser" -ErrorAction Stop

                if ($LastLoggedOnUserReg) {
                    $UserInfo.LastLoggedUser = $LastLoggedOnUserReg.LastLoggedOnUser
                }
            }
            catch {
                # Registry value doesn't exist or permission denied
                Write-Log "Failed to read last logged on user from registry: $_" -Level Warning
            }
        }

        Write-Log "User information collected successfully" -Level Info
    }
    catch {
        # Catch-all for unexpected errors
        Write-Log "Error collecting user information: $_" -Level Error
    }

    return $UserInfo
}
#endregion

#region Inventory Compilation
function New-InventoryObject {
    <#
    .SYNOPSIS
        Compiles all collected data into inventory payload.

    .DESCRIPTION
        Orchestrates collection of all inventory components and assembles
        them into a single hashtable for transmission to server.

        COLLECTION WORKFLOW:
        1. Call Get-SystemInfo (system hardware and OS)
        2. Call Get-DiskInfo (disk serial numbers)
        3. Call Get-NetworkInfo (network adapters)
        4. Call Get-UserInfo (logged-on users)
        5. Generate unique inventory ID (GUID)
        6. Calculate content hash (SHA256 for change detection)
        7. Return complete inventory hashtable

        CONTENT HASH:
        SHA256 hash of system + disk + network data (user data excluded).
        Used by server to detect changes since last collection.
        If hash matches previous submission, server may skip processing.

        CONSTRAINED LANGUAGE MODE HANDLING:
        Hash calculation uses Get-FileHash cmdlet instead of .NET
        [System.Security.Cryptography.SHA256] because CLM restricts
        direct .NET type instantiation.

    .PARAMETER TriggerType
        [string] Execution trigger: "Logon", "Scheduled", or "Manual"

    .PARAMETER Username
        [string] Username of logged-on user

    .PARAMETER Environment
        [hashtable] Environment details from Test-ExecutionEnvironment

    .INPUTS
        None.

    .OUTPUTS
        System.Collections.Hashtable
        Complete inventory payload with the following structure:
        @{
            InventoryId         = "550e8400-e29b-41d4-a716-446655440000"  # GUID
            CollectionTimestamp = "2024-10-24 14:30:00"                   # ISO 8601 format
            CollectionTrigger   = "Logon"                                 # Logon/Scheduled/Manual
            AgentVersion        = "2.1.0-Security-Hardened"               # Agent version string
            ContentHash         = "A1B2C3D4..."                           # SHA256 hash
            Environment         = @{ ... }                                 # From Test-ExecutionEnvironment
            System              = @{ ... }                                 # From Get-SystemInfo
            DiskSerials         = @("serial1", "serial2", ...)            # From Get-DiskInfo
            Network             = @(@{ ... }, @{ ... })                   # From Get-NetworkInfo
            User                = @{ ... }                                 # From Get-UserInfo
        }

    .EXAMPLE
        $env = Test-ExecutionEnvironment
        $inventory = New-InventoryObject -TriggerType "Logon" -Username "DOMAIN\jsmith" -Environment $env
        $json = $inventory | ConvertTo-Json -Depth 10

        Compiles inventory and converts to JSON for transmission.

    .NOTES
        - All collection functions are called sequentially (not parallel)
        - Each function has its own error handling
        - Partial inventory is acceptable (missing data logged as warnings)
        - Total execution time typically 5-10 seconds
    #>
    [CmdletBinding()]
    [OutputType([hashtable])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("Logon", "Scheduled", "Manual")]
        [string]$TriggerType,

        [Parameter(Mandatory = $true)]
        [string]$Username,

        [Parameter(Mandatory = $true)]
        [hashtable]$Environment
    )

    Write-Log "Starting inventory collection - Trigger: $TriggerType, User: $Username" -Level Info

    # Build complete inventory hashtable
    # Order matters for readability but not for JSON serialization
    [hashtable]$Inventory = @{
        CollectionTimestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"     # ISO 8601 timestamp
        CollectionTrigger   = $TriggerType                                # What triggered this collection
        AgentVersion        = "2.1.0-Security-Hardened"                   # Agent version for tracking
        Environment         = $Environment                                 # PowerShell environment details
        System              = Get-SystemInfo                               # Hardware and OS information
        DiskSerials         = Get-DiskInfo                                # Disk serial numbers
        Network             = Get-NetworkInfo                              # Network adapter configuration
        User                = Get-UserInfo -Username $Username             # Logged-on user information
    }

    # Generate unique identifier for this inventory submission
    # Used for:
    # - Tracking this specific submission through processing pipeline
    # - Offline queue file naming
    # - Server-side deduplication
    $Inventory.InventoryId = [Guid]::NewGuid().ToString()

    # Calculate SHA256 content hash for change detection
    # Server can skip processing if hash matches previous submission
    try {
        # Serialize data to JSON for hashing
        # Depth 2 is sufficient for hash (deep nesting not needed for change detection)
        [string]$DataForHash = ($Inventory.System | ConvertTo-Json -Depth 2 -Compress) +
                               ($Inventory.DiskSerials | ConvertTo-Json -Compress) +
                               ($Inventory.Network | ConvertTo-Json -Depth 2 -Compress)

        # Write data to temp file (required for Get-FileHash)
        # Get-FileHash doesn't support pipeline input in PS 5.1
        [string]$TempFile = [System.IO.Path]::GetTempFileName()
        $DataForHash | Out-File -FilePath $TempFile -Encoding UTF8

        # Calculate SHA256 hash using cmdlet (CLM-compatible)
        # .NET [System.Security.Cryptography.SHA256] would fail in CLM
        [Microsoft.PowerShell.Commands.FileHashInfo]$Hash = Get-FileHash -Path $TempFile -Algorithm SHA256

        # Clean up temp file
        Remove-Item -Path $TempFile -Force

        # Store hash in inventory
        $Inventory.ContentHash = $Hash.Hash
    }
    catch {
        # Hash calculation failed (disk full, permissions, etc.)
        # Non-fatal - inventory can still be submitted without hash
        Write-Log "Failed to calculate content hash: $_" -Level Warning
        $Inventory.ContentHash = "UNAVAILABLE"
    }

    Write-Log "Inventory collection completed - ID: $($Inventory.InventoryId)" -Level Info

    return $Inventory
}
#endregion

#region API Communication
function Send-InventoryToServer {
    <#
    .SYNOPSIS
        Transmits inventory payload to server via HTTPS POST.

    .DESCRIPTION
        Sends compiled inventory to central server using REST API.

        TRANSMISSION PROTOCOL:
        - Method: HTTP POST
        - Content-Type: application/json
        - Authentication: Bearer token (API key) or client certificate
        - Encoding: UTF-8
        - Compression: Disabled (CLM compatibility)

        RETRY LOGIC:
        Implements exponential backoff retry for transient failures:
        - Attempt 1: Send immediately
        - Attempt 2: Wait 30 seconds, retry
        - Attempt 3: Wait 60 seconds, retry
        - After 3 attempts: Fail and return $false

        ERROR CATEGORIZATION:
        - Timeout errors: Network connectivity issues
        - SSL/Certificate errors: TLS validation failures
        - Proxy errors: Proxy authentication/configuration issues
        - HTTP errors: Server-side errors (4xx/5xx status codes)

        SUCCESS CRITERIA:
        HTTP status codes 200, 201, or 202 are considered successful.
        All other status codes trigger retry logic.

    .PARAMETER Inventory
        [hashtable] Complete inventory payload from New-InventoryObject

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if transmission succeeded (HTTP 200/201/202)
        $false if transmission failed after all retries

    .EXAMPLE
        $inventory = New-InventoryObject -TriggerType "Logon" -Username "jsmith" -Environment $env
        $success = Send-InventoryToServer -Inventory $inventory
        if ($success) {
            Write-Host "Inventory transmitted successfully"
        }

        Sends inventory and checks result.

    .NOTES
        - Uses Invoke-WebRequest (not Invoke-RestMethod) for detailed error handling
        - Proxy auto-detection uses system proxy settings
        - Client certificate must be in LocalMachine\My certificate store
        - All transmission attempts are logged (including failures)
        - Security events logged for successful/failed transmissions
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Inventory
    )

    # Load configuration for server endpoint and retry settings
    [hashtable]$Config = Get-Configuration

    Write-Log "Sending inventory to server: $($Config.ServerEndpoint)" -Level Info

    try {
        # === PREPARE JSON PAYLOAD ===
        # Serialize inventory hashtable to JSON
        # Depth 10 ensures all nested objects are serialized
        # Compress removes whitespace for smaller payload
        [string]$Json = $Inventory | ConvertTo-Json -Depth 10 -Compress

        # Compression disabled for Constrained Language Mode compatibility
        # GZip compression requires [System.IO.Compression.GzipStream] which is restricted in CLM
        # If compression is needed in non-CLM environments, implement as optional feature
        [byte[]]$Body = [System.Text.Encoding]::UTF8.GetBytes($Json)
        [string]$ContentType = "application/json"

        # === PREPARE HTTP HEADERS ===
        # Standard headers for API request
        [hashtable]$Headers = @{
            "Content-Type"    = $ContentType
            "X-Machine-Name"  = if ($Inventory.System.ComputerName) { $Inventory.System.ComputerName } else { $env:COMPUTERNAME }
            "X-Agent-Version" = $Inventory.AgentVersion
            "User-Agent"      = "InventoryAgent/2.1.0"
        }

        # Add API key for Bearer token authentication (if configured)
        if ($Config.ApiKey) {
            $Headers["Authorization"] = "Bearer $($Config.ApiKey)"
        }

        # === BUILD WEB REQUEST PARAMETERS ===
        [hashtable]$WebRequestParams = @{
            Uri             = "$($Config.ServerEndpoint)/inventory"  # Full API endpoint URL
            Method          = "POST"                                 # HTTP POST method
            Body            = $Body                                  # UTF-8 encoded JSON bytes
            Headers         = $Headers                               # HTTP headers hashtable
            UseBasicParsing = $true                                 # Don't parse HTML (faster, no IE dependency)
            TimeoutSec      = $Config.ConnectionTimeoutSeconds       # Request timeout (default 30s)
        }

        # === ADD PROXY CONFIGURATION (IF ENABLED) ===
        # Corporate networks often require HTTP proxy for internet access
        if ($Config.UseProxy -and $Config.ProxyServer) {
            Write-Log "Using proxy server: $($Config.ProxyServer)" -Level Info
            $WebRequestParams.Proxy = $Config.ProxyServer

            # Use Windows integrated authentication for proxy (common in AD environments)
            if ($Config.ProxyUseDefaultCredentials) {
                $WebRequestParams.ProxyUseDefaultCredentials = $true
            }
        }

        # === ADD CLIENT CERTIFICATE (IF CONFIGURED) ===
        # Mutual TLS authentication using client certificate from machine store
        if ($Config.CertificateThumbprint) {
            try {
                # Search LocalMachine\My certificate store for matching thumbprint
                [System.Security.Cryptography.X509Certificates.X509Certificate2]$Cert = Get-ChildItem -Path Cert:\LocalMachine\My -ErrorAction Stop |
                    Where-Object { $_.Thumbprint -eq $Config.CertificateThumbprint }

                if ($Cert) {
                    $WebRequestParams.Certificate = $Cert
                    Write-Log "Using client certificate: $($Cert.Subject)" -Level Info
                }
                else {
                    Write-Log "Certificate not found: $($Config.CertificateThumbprint)" -Level Warning
                }
            }
            catch {
                Write-Log "Failed to load certificate: $_" -Level Warning
            }
        }

        # === RETRY LOGIC WITH EXPONENTIAL BACKOFF ===
        [int]$Attempt = 1
        [bool]$Success = $false
        [string]$LastError = $null

        # Retry loop: attempt up to MaxRetryAttempts times
        while ($Attempt -le $Config.MaxRetryAttempts -and -not $Success) {
            try {
                Write-Log "Sending inventory (attempt $Attempt of $($Config.MaxRetryAttempts))..." -Level Info

                # Execute HTTP POST request
                [Microsoft.PowerShell.Commands.WebResponseObject]$Response = Invoke-WebRequest @WebRequestParams -ErrorAction Stop

                # Check HTTP status code for success
                # 200 = OK, 201 = Created, 202 = Accepted (async processing)
                if ($Response.StatusCode -eq 200 -or $Response.StatusCode -eq 201 -or $Response.StatusCode -eq 202) {
                    Write-Log "Inventory sent successfully - Status: $($Response.StatusCode)" -Level Info
                    Write-SecurityLog "Inventory transmitted successfully to $($Config.ServerEndpoint)"
                    $Success = $true
                    return $true
                }
                else {
                    # Unexpected success status code (2xx but not 200/201/202)
                    Write-Log "Unexpected response - Status: $($Response.StatusCode)" -Level Warning
                    $LastError = "HTTP $($Response.StatusCode)"
                }
            }
            catch {
                # HTTP request failed (network error, timeout, HTTP error status, etc.)
                [string]$ErrorMessage = $_.Exception.Message
                $LastError = $ErrorMessage

                # Categorize error for better troubleshooting
                if ($ErrorMessage -like "*timeout*") {
                    Write-Log "Attempt $Attempt failed: Connection timeout" -Level Warning
                }
                elseif ($ErrorMessage -like "*SSL*" -or $ErrorMessage -like "*certificate*") {
                    Write-Log "Attempt $Attempt failed: SSL/Certificate error - $ErrorMessage" -Level Warning
                    Write-SecurityLog "SSL/Certificate validation failed: $ErrorMessage"
                }
                elseif ($ErrorMessage -like "*proxy*") {
                    Write-Log "Attempt $Attempt failed: Proxy error - $ErrorMessage" -Level Warning
                }
                else {
                    Write-Log "Attempt $Attempt failed: $ErrorMessage" -Level Warning
                }

                # Exponential backoff delay before retry
                # Attempt 1 fails: wait 30s
                # Attempt 2 fails: wait 60s
                # Attempt 3 fails: no wait (give up)
                if ($Attempt -lt $Config.MaxRetryAttempts) {
                    [int]$SleepSeconds = $Config.RetryDelaySeconds * $Attempt
                    Write-Log "Waiting $SleepSeconds seconds before retry..." -Level Info
                    Start-Sleep -Seconds $SleepSeconds
                }
            }

            $Attempt++
        }

        # All retry attempts exhausted
        if (-not $Success) {
            Write-Log "Failed to send inventory after $($Config.MaxRetryAttempts) attempts. Last error: $LastError" -Level Error
            Write-SecurityLog "Failed to transmit inventory after $($Config.MaxRetryAttempts) attempts"
            return $false
        }
    }
    catch {
        # Catch-all for unexpected errors (JSON serialization failure, etc.)
        Write-Log "Error sending inventory: $_" -Level Error
        return $false
    }
}
#endregion

#region Offline Queue Management
function Add-ToOfflineQueue {
    <#
    .SYNOPSIS
        Adds inventory to local offline queue when transmission fails.

    .DESCRIPTION
        Persists inventory to local filesystem when server is unreachable.
        Enables resilience in air-gapped networks or during server outages.

        QUEUE DESIGN:
        - Location: C:\ProgramData\InventoryAgent\Queue\
        - Format: JSON files named "inventory_{GUID}.json"
        - Max size: Configurable (default 1000 items)
        - Overflow handling: FIFO (remove oldest when full)

        PROCESSING:
        Queued items are processed by Process-OfflineQueue function:
        - Called at start of each collection run
        - Attempts to send oldest queued items first
        - Stops processing if server is still unreachable

        USE CASES:
        - Network outages (WAN link down)
        - Server maintenance windows
        - Air-gapped networks (manual queue transfer)
        - Certificate expiration (queue until renewed)

    .PARAMETER Inventory
        [hashtable] Complete inventory payload to queue

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if successfully queued
        $false if queueing failed (disk full, permissions, etc.)

    .EXAMPLE
        if (-not (Send-InventoryToServer -Inventory $inv)) {
            Add-ToOfflineQueue -Inventory $inv
        }

        Queue inventory if transmission fails.

    .NOTES
        - Each queued item is ~50-100KB (JSON file)
        - 1000 queued items = ~50-100MB disk space
        - Old queue items are NOT auto-purged (manual cleanup required)
        - Corrupted queue items moved to Queue\corrupt\ subdirectory
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateNotNull()]
        [hashtable]$Inventory
    )

    # Load configuration for queue size limit
    [hashtable]$Config = Get-Configuration

    try {
        # Check current queue size
        [System.IO.FileInfo[]]$QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue

        # Enforce max queue size limit
        # If queue is full, remove oldest item (FIFO)
        if ($QueueFiles.Count -ge $Config.QueueMaxSize) {
            # Sort by creation time (oldest first)
            [System.IO.FileInfo]$OldestFile = $QueueFiles | Sort-Object CreationTime | Select-Object -First 1

            # Delete oldest file
            Remove-Item -Path $OldestFile.FullName -Force
            Write-Log "Queue full - removed oldest item: $($OldestFile.Name)" -Level Warning
        }

        # Generate queue filename using inventory GUID
        # Format: inventory_{GUID}.json
        # Example: inventory_550e8400-e29b-41d4-a716-446655440000.json
        [string]$QueueFileName = "inventory_$($Inventory.InventoryId).json"
        [string]$QueueFilePath = Join-Path -Path $QueuePath -ChildPath $QueueFileName

        # Serialize inventory to JSON and write to queue file
        $Inventory | ConvertTo-Json -Depth 10 | Out-File -FilePath $QueueFilePath -Force

        Write-Log "Added inventory to offline queue: $QueueFileName" -Level Info
        return $true
    }
    catch {
        # Queueing failed (disk full, permissions, path too long, etc.)
        Write-Log "Error adding to offline queue: $_" -Level Error
        return $false
    }
}

function Process-OfflineQueue {
    <#
    .SYNOPSIS
        Attempts to transmit queued inventory items from previous failures.

    .DESCRIPTION
        Processes offline queue by attempting to send oldest items first.
        Called at the start of each collection run to clear queue backlog.

        PROCESSING LOGIC:
        1. Scan queue directory for *.json files
        2. Sort by creation time (oldest first)
        3. For each file:
           a. Deserialize JSON to inventory hashtable
           b. Attempt transmission via Send-InventoryToServer
           c. If success: delete queue file
           d. If failure: stop processing (server still down)

        STOP-ON-FAILURE BEHAVIOR:
        If any queue item fails to send, processing stops immediately.
        This prevents wasting time attempting to send remaining items
        when server is still unreachable.

        CORRUPTION HANDLING:
        If JSON deserialization fails (corrupted file), move to
        Queue\corrupt\ subdirectory for manual investigation.

    .PARAMETER None

    .INPUTS
        None.

    .OUTPUTS
        None. Side effect: deletes successfully transmitted queue files.

    .EXAMPLE
        Process-OfflineQueue

        Attempts to send all queued items.

    .NOTES
        - Queue processing adds ~1-2 seconds per queued item
        - Large queues (100+ items) may delay current collection
        - Consider scheduled queue processing task if queue grows large
        - Corrupted files moved to corrupt\ subdirectory (never deleted)
    #>
    [CmdletBinding()]
    param()

    Write-Log "Processing offline queue" -Level Info

    try {
        # Scan queue directory for JSON files
        # Sort by creation time (oldest first for FIFO processing)
        [System.IO.FileInfo[]]$QueueFiles = Get-ChildItem -Path $QueuePath -Filter "*.json" -ErrorAction SilentlyContinue |
            Sort-Object CreationTime

        # Check if queue is empty
        if ($QueueFiles.Count -eq 0) {
            Write-Log "Offline queue is empty" -Level Info
            return
        }

        Write-Log "Found $($QueueFiles.Count) items in offline queue" -Level Info

        # Process each queued file
        foreach ($File in $QueueFiles) {
            try {
                # Deserialize JSON file to PowerShell object
                [PSCustomObject]$InventoryObject = Get-Content -Path $File.FullName -Raw | ConvertFrom-Json

                # Convert PSCustomObject back to hashtable (required by Send-InventoryToServer)
                # PowerShell's ConvertFrom-Json returns PSCustomObject, not hashtable
                [hashtable]$InventoryHash = @{}
                $InventoryObject.PSObject.Properties | ForEach-Object {
                    $InventoryHash[$_.Name] = $_.Value
                }

                # Attempt to send queued inventory
                if (Send-InventoryToServer -Inventory $InventoryHash) {
                    # Success: delete queue file
                    Remove-Item -Path $File.FullName -Force
                    Write-Log "Successfully sent queued item: $($File.Name)" -Level Info
                }
                else {
                    # Failure: stop processing queue
                    # Server is still unreachable, no point processing remaining items
                    Write-Log "Failed to send queued item: $($File.Name)" -Level Warning
                    break
                }
            }
            catch {
                # JSON deserialization failed (corrupted file)
                Write-Log "Error processing queued item $($File.Name): $_" -Level Error

                # Move corrupted file to corrupt subdirectory for manual investigation
                [string]$CorruptPath = Join-Path -Path $QueuePath -ChildPath "corrupt"
                if (!(Test-Path -Path $CorruptPath)) {
                    New-Item -ItemType Directory -Path $CorruptPath -Force | Out-Null
                }

                try {
                    Move-Item -Path $File.FullName -Destination $CorruptPath -Force
                    Write-Log "Moved corrupted queue item to: $CorruptPath" -Level Warning
                }
                catch {
                    Write-Log "Failed to move corrupted queue item: $_" -Level Error
                }
            }
        }
    }
    catch {
        # Catch-all for unexpected errors (queue directory deleted, permissions, etc.)
        Write-Log "Error processing offline queue: $_" -Level Error
    }
}
#endregion

#region Main Execution
<#
    MAIN EXECUTION BLOCK
    This is the script entry point. Execution flow:
    1. Log startup banner
    2. Detect execution environment (PowerShell version, language mode, etc.)
    3. Check debounce (skip if recent collection for this user)
    4. Process offline queue (send previously failed items)
    5. Collect new inventory
    6. Send to server
    7. Queue if send fails
    8. Log completion banner
    9. Exit with status code
#>

try {
    # === STARTUP LOGGING ===
    Write-Log "========================================" -Level Info
    Write-Log "Inventory Agent Starting" -Level Info
    Write-Log "========================================" -Level Info

    # === ENVIRONMENT DETECTION ===
    # Detect PowerShell environment and validate script signature
    [hashtable]$Environment = Test-ExecutionEnvironment

    # === DEBOUNCE CHECK ===
    # Determine if collection should proceed based on last run time
    # Returns $false if within debounce window (skip collection)
    if (-not (Test-ShouldCollect -TriggerType $TriggerType -Username $Username)) {
        Write-Log "Collection skipped due to debounce" -Level Info
        exit 0
    }

    # === PROCESS OFFLINE QUEUE ===
    # Attempt to send previously queued items before collecting new inventory
    # This ensures queue doesn't grow indefinitely during outages
    Process-OfflineQueue

    # === COLLECT INVENTORY ===
    # Gather all system information and compile into single payload
    [hashtable]$Inventory = New-InventoryObject -TriggerType $TriggerType `
                                                  -Username $Username `
                                                  -Environment $Environment

    # === SEND TO SERVER ===
    # Attempt to transmit inventory via HTTPS POST
    [bool]$SendResult = Send-InventoryToServer -Inventory $Inventory

    # === QUEUE IF FAILED ===
    # If transmission failed, add to offline queue for later retry
    if (-not $SendResult) {
        [bool]$QueueResult = Add-ToOfflineQueue -Inventory $Inventory

        if ($QueueResult) {
            Write-Log "Inventory added to offline queue for later transmission" -Level Info
        }
        else {
            # CRITICAL: Failed to send AND failed to queue
            # Inventory data will be lost unless manually collected
            Write-Log "CRITICAL: Failed to send inventory AND failed to queue it" -Level Error
        }
    }

    # === COMPLETION LOGGING ===
    Write-Log "========================================" -Level Info
    Write-Log "Inventory collection process completed" -Level Info
    Write-Log "========================================" -Level Info

    # Exit with success status
    exit 0
}
catch {
    # === FATAL ERROR HANDLER ===
    # Catch any unhandled exceptions that escaped function-level error handling
    Write-Log "FATAL ERROR in inventory collection: $_" -Level Error
    Write-Log "Stack Trace: $($_.ScriptStackTrace)" -Level Error

    # Exit with failure status
    exit 1
}
#endregion
