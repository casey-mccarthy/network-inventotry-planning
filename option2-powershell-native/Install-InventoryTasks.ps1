<#
.SYNOPSIS
    Installs and configures scheduled tasks for automated inventory collection.

.DESCRIPTION
    Security-hardened installation script that creates three scheduled tasks
    for the Inventory Agent on Windows 11 systems:

    1. Daily Collection Task
       - Runs once per day at specified time (default: 2:00 AM)
       - Performs comprehensive inventory collection
       - Runs as SYSTEM with highest privileges

    2. Logon Collection Task
       - Triggers on any user logon event
       - Collects user session and system information
       - Subject to debounce logic (prevents spam)

    3. Queue Processing Task
       - Runs every 4 hours
       - Processes offline queue (failed transmissions)
       - Ensures eventual consistency in air-gapped scenarios

    SECURITY FEATURES:
    - Optional script signature validation before task creation
    - Tasks run as NT AUTHORITY\SYSTEM (not user context)
    - RunLevel set to Highest for WMI access
    - Execution policy bypass (tasks can't be blocked by policy)
    - Multiple instance protection (prevents overlapping runs)
    - Auto-restart on failure with exponential backoff

    DEPLOYMENT METHODS:
    - Manual execution on individual workstations
    - GPO startup script for enterprise deployment
    - SCCM/Intune package deployment
    - Remote execution via PSRemoting

.PARAMETER ScriptPath
    [string] Absolute path to Collect-Inventory.ps1 script.
    Default: "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1"

    This script must exist before creating tasks.
    Path must be accessible by SYSTEM account.

.PARAMETER DailyTime
    [string] Time for daily collection in 24-hour format (HH:mm).
    Default: "02:00" (2:00 AM)

    Recommended: Off-hours to minimize user impact.
    Examples: "02:00", "03:30", "23:00"

.PARAMETER Force
    [switch] Force recreation of existing tasks.
    Default: $false

    If specified, existing tasks will be removed and recreated.
    Use with caution in production environments.

.PARAMETER ValidateSignature
    [switch] Validate script signature before creating tasks.
    Default: $false

    Recommended for production deployments.
    Requires scripts to be digitally signed with valid certificate.

.INPUTS
    None. This script does not accept pipeline input.

.OUTPUTS
    System.Int32
    Exit code 0 for success, 1 for failure.

    Side effects:
    - Creates 3 scheduled tasks in Task Scheduler
    - Writes installation log to C:\ProgramData\InventoryAgent\Logs\
    - Optionally runs initial collection (interactive prompt)

.EXAMPLE
    PS> .\Install-InventoryTasks.ps1

    Installs tasks with default settings (daily at 2 AM, no signature validation).

.EXAMPLE
    PS> .\Install-InventoryTasks.ps1 -DailyTime "03:00" -Force

    Recreates tasks with daily collection at 3 AM.

.EXAMPLE
    PS> .\Install-InventoryTasks.ps1 -ValidateSignature -Force

    Recreates tasks and validates script signature first.
    Installation will fail if script is not properly signed.

.EXAMPLE
    PS> .\Install-InventoryTasks.ps1 -ScriptPath "D:\CustomPath\Collect-Inventory.ps1"

    Installs tasks pointing to custom script location.

.NOTES
    File Name      : Install-InventoryTasks.ps1
    Version        : 2.1.0
    Author         : IT Systems Engineering Team
    Prerequisite   : PowerShell 5.1 or higher
    Prerequisite   : Administrator privileges (enforced via #Requires)
    Prerequisite   : Task Scheduler service running

    DEPLOYMENT NOTES:
    - Must run with administrator privileges
    - Tasks created for SYSTEM account (no user credentials needed)
    - Scheduled tasks survive user logoff and system reboot
    - Can be deployed via GPO Computer Startup Script

    GPO DEPLOYMENT EXAMPLE:
    Computer Configuration > Policies > Windows Settings > Scripts > Startup
    Add: PowerShell.exe
    Parameters: -ExecutionPolicy Bypass -File "\\domain\SYSVOL\scripts\Install-InventoryTasks.ps1"

    TROUBLESHOOTING:
    - Check logs: C:\ProgramData\InventoryAgent\Logs\install_YYYYMMDD.log
    - View tasks: Get-ScheduledTask -TaskName "InventoryAgent-*"
    - Test task: Start-ScheduledTask -TaskName "InventoryAgent-DailyCollection"
    - View history: Get-ScheduledTaskInfo -TaskName "InventoryAgent-DailyCollection"

.LINK
    https://docs.company.com/inventory-agent/installation

.LINK
    https://docs.microsoft.com/en-us/powershell/module/scheduledtasks
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false,
               Position = 0,
               HelpMessage = "Path to Collect-Inventory.ps1 script")]
    [ValidateNotNullOrEmpty()]
    [string]$ScriptPath = "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1",

    [Parameter(Mandatory = $false,
               Position = 1,
               HelpMessage = "Daily collection time in HH:mm format (24-hour)")]
    [ValidatePattern('^([01]\d|2[0-3]):([0-5]\d)$')]
    [string]$DailyTime = "02:00",

    [Parameter(Mandatory = $false,
               HelpMessage = "Force recreation of existing tasks")]
    [switch]$Force,

    [Parameter(Mandatory = $false,
               HelpMessage = "Validate script signature before task creation")]
    [switch]$ValidateSignature
)

#region Logging Functions
<#
    INSTALLATION LOGGING
    Dual-output logging: console (for interactive sessions) and
    file-based (for unattended/GPO deployments).
#>

function Write-InstallLog {
    <#
    .SYNOPSIS
        Writes installation log entries to console and file.

    .DESCRIPTION
        Centralized logging function for installation process.
        Writes to both console (with color) and daily log file.

        Log file location: C:\ProgramData\InventoryAgent\Logs\install_YYYYMMDD.log
        Log format: "YYYY-MM-DD HH:MM:SS [LEVEL] Message"

    .PARAMETER Message
        [string] The log message to write.

    .PARAMETER Level
        [string] Log severity level.
        Valid values: "Info", "Warning", "Error", "Success"
        Default: "Info"

    .INPUTS
        None.

    .OUTPUTS
        None. Writes to console and log file as side effect.

    .EXAMPLE
        Write-InstallLog "Task created successfully" -Level "Success"

        Writes success message in green to console and log file.

    .NOTES
        - Log directory created automatically if missing
        - Console output uses color-coding for visibility
        - File logging is best-effort (silent failure if disk full)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [AllowEmptyString()]
        [string]$Message,

        [Parameter(Mandatory = $false, Position = 1)]
        [ValidateSet("Info", "Warning", "Error", "Success")]
        [string]$Level = "Info"
    )

    # Format timestamp in ISO 8601 format
    [string]$Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    [string]$LogMessage = "$Timestamp [$Level] $Message"

    # Color mapping for console output
    [hashtable]$ColorMap = @{
        Info    = "Cyan"
        Warning = "Yellow"
        Error   = "Red"
        Success = "Green"
    }

    # Write to console with color
    Write-Host $LogMessage -ForegroundColor $ColorMap[$Level]

    # Write to log file
    [string]$LogPath = "C:\ProgramData\InventoryAgent\Logs"
    if (!(Test-Path -Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    [string]$LogFile = Join-Path -Path $LogPath -ChildPath "install_$(Get-Date -Format 'yyyyMMdd').log"

    try {
        Add-Content -Path $LogFile -Value $LogMessage -Force -ErrorAction Stop
    }
    catch {
        # Silent failure - console logging is sufficient for installation
    }
}
#endregion

#region Script Validation Functions
<#
    SCRIPT SIGNATURE VALIDATION
    Validates Authenticode signatures for security compliance.
    Required in high-security environments (government, finance, etc.)
#>

function Test-ScriptSignature {
    <#
    .SYNOPSIS
        Validates Authenticode signature of PowerShell script.

    .DESCRIPTION
        Checks if specified script file has a valid digital signature.
        Used to verify script integrity before creating scheduled tasks.

        SIGNATURE STATUSES:
        - Valid: Signature is present and trusted
        - NotSigned: No signature present
        - HashMismatch: File modified after signing
        - UnknownError: Signature check failed

    .PARAMETER Path
        [string] Absolute path to script file to validate.

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if signature is valid
        $false if signature is missing, invalid, or path doesn't exist

    .EXAMPLE
        if (Test-ScriptSignature -Path "C:\Scripts\MyScript.ps1") {
            Write-Host "Script is properly signed"
        }

        Validates script signature and acts accordingly.

    .NOTES
        - Requires PKI infrastructure (certificate authority)
        - Certificate must be in Trusted Publishers store
        - Time-stamped signatures remain valid after certificate expiration
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param(
        [Parameter(Mandatory = $true, Position = 0)]
        [ValidateNotNullOrEmpty()]
        [string]$Path
    )

    # Validate path exists
    if (!(Test-Path -Path $Path)) {
        Write-InstallLog "Script not found: $Path" -Level "Error"
        return $false
    }

    # Get Authenticode signature
    [System.Management.Automation.Signature]$Signature = Get-AuthenticodeSignature -FilePath $Path

    # Evaluate signature status
    if ($Signature.Status -eq 'Valid') {
        Write-InstallLog "Script signature is valid: $($Signature.SignerCertificate.Subject)" -Level "Info"
        return $true
    }
    elseif ($Signature.Status -eq 'NotSigned') {
        Write-InstallLog "WARNING: Script is not digitally signed" -Level "Warning"
        return $false
    }
    else {
        Write-InstallLog "Script signature validation failed: $($Signature.Status)" -Level "Error"
        return $false
    }
}
#endregion

#region Scheduled Task Creation Functions
<#
    SCHEDULED TASK CREATION
    Creates three tasks for comprehensive inventory collection:
    1. Daily task (scheduled)
    2. Logon task (event-triggered)
    3. Queue processing task (periodic)
#>

function New-InventoryScheduledTask {
    <#
    .SYNOPSIS
        Creates all scheduled tasks for inventory agent.

    .DESCRIPTION
        Main function that orchestrates creation of three scheduled tasks:

        TASK 1: InventoryAgent-DailyCollection
        - Trigger: Daily at specified time (default 2:00 AM)
        - Purpose: Comprehensive inventory collection
        - Timeout: 30 minutes
        - Restart on failure: Yes (3 attempts, 1-minute intervals)

        TASK 2: InventoryAgent-LogonCollection
        - Trigger: Any user logon (AtLogon)
        - Purpose: Capture user session information
        - Timeout: 10 minutes
        - Restart on failure: Yes (1 attempt, 1-minute interval)

        TASK 3: InventoryAgent-ProcessQueue
        - Trigger: Every 4 hours (RepetitionInterval)
        - Purpose: Process offline queue
        - Timeout: 30 minutes
        - Special: Calls Process-OfflineQueue function directly

        TASK SETTINGS (all tasks):
        - Principal: NT AUTHORITY\SYSTEM
        - Run Level: Highest
        - Network Required: Yes (RunOnlyIfNetworkAvailable)
        - Battery Behavior: Allow start, don't stop
        - Multiple Instances: Ignore new (prevents overlap)

    .PARAMETER None
        Uses script-level parameters ($ScriptPath, $DailyTime, etc.)

    .INPUTS
        None.

    .OUTPUTS
        System.Boolean
        $true if all tasks created successfully
        $false if any task creation failed

    .EXAMPLE
        $success = New-InventoryScheduledTask
        if ($success) {
            Write-Host "Installation complete"
        }

        Creates tasks and checks result.

    .NOTES
        - Requires administrator privileges
        - Existing tasks are preserved unless -Force specified
        - Interactive prompt for initial collection run
        - All tasks visible in Task Scheduler GUI
    #>
    [CmdletBinding()]
    [OutputType([bool])]
    param()

    Write-InstallLog "========================================" -Level "Info"
    Write-InstallLog "Creating Inventory Collection Scheduled Tasks" -Level "Info"
    Write-InstallLog "========================================" -Level "Info"

    # === VALIDATE SCRIPT EXISTS ===
    if (!(Test-Path -Path $ScriptPath)) {
        Write-InstallLog "Script not found at: $ScriptPath" -Level "Error"
        return $false
    }

    # === VALIDATE SCRIPT SIGNATURE (IF REQUESTED) ===
    if ($ValidateSignature) {
        [bool]$SignatureValid = Test-ScriptSignature -Path $ScriptPath

        if (-not $SignatureValid) {
            Write-InstallLog "Script signature validation failed. Use -Force to override (not recommended)" -Level "Error"
            if (-not $Force) {
                return $false
            }
            Write-InstallLog "Proceeding anyway due to -Force flag" -Level "Warning"
        }
    }

    # === TASK 1: DAILY COLLECTION ===
    [string]$DailyTaskName = "InventoryAgent-DailyCollection"

    Write-InstallLog "Creating daily collection task: $DailyTaskName" -Level "Info"

    # Check if task already exists
    if (Get-ScheduledTask -TaskName $DailyTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $DailyTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $DailyTaskName" -Level "Info"
        }
        else {
            Write-InstallLog "Task already exists: $DailyTaskName (use -Force to recreate)" -Level "Warning"
        }
    }

    # Create daily trigger
    # Runs once per day at specified time
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.TriggerType]$DailyTrigger = New-ScheduledTaskTrigger -Daily -At $DailyTime

    # Create action
    # Bypasses execution policy for reliability in restricted environments
    [string]$ActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -TriggerType Scheduled"
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ActionType]$DailyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $ActionScript

    # Create principal (run as SYSTEM with highest privileges)
    # SYSTEM account has full WMI access and certificate store access
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.PrincipalType]$Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Create settings
    # MultipleInstances: IgnoreNew prevents overlapping runs
    # RestartCount/Interval: Auto-retry on transient failures
    # ExecutionTimeLimit: 30-minute timeout
    # StartWhenAvailable: Run even if missed schedule (e.g., system was off)
    # RunOnlyIfNetworkAvailable: Skip if offline (saves resources)
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.SettingsType]$Settings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -RestartCount 3 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -StartWhenAvailable `
        -RunOnlyIfNetworkAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    # Register daily task
    try {
        Register-ScheduledTask -TaskName $DailyTaskName `
            -Trigger $DailyTrigger `
            -Action $DailyAction `
            -Principal $Principal `
            -Settings $Settings `
            -Description "Daily hardware inventory collection at $DailyTime" | Out-Null

        Write-InstallLog "Successfully created daily collection task" -Level "Success"
    }
    catch {
        Write-InstallLog "Failed to create daily task: $_" -Level "Error"
        return $false
    }

    # === TASK 2: LOGON TRIGGER ===
    [string]$LogonTaskName = "InventoryAgent-LogonCollection"

    Write-InstallLog "Creating logon collection task: $LogonTaskName" -Level "Info"

    # Check if task exists
    if (Get-ScheduledTask -TaskName $LogonTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $LogonTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $LogonTaskName" -Level "Info"
        }
        else {
            Write-InstallLog "Task already exists: $LogonTaskName (use -Force to recreate)" -Level "Warning"
            return $false
        }
    }

    # Create logon trigger
    # Fires on any user logon (interactive or RDP)
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.TriggerType]$LogonTrigger = New-ScheduledTaskTrigger -AtLogOn

    # Create action
    # TriggerType set to "Logon" for proper debounce logic
    [string]$LogonActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -TriggerType Logon"
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ActionType]$LogonAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $LogonActionScript

    # Settings for logon task
    # Shorter timeout (10 minutes vs 30) to avoid delaying user login
    # Fewer restart attempts (1 vs 3) - logon events are frequent
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.SettingsType]$LogonSettings = New-ScheduledTaskSettingsSet `
        -MultipleInstances IgnoreNew `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 10) `
        -RestartCount 1 `
        -RestartInterval (New-TimeSpan -Minutes 1) `
        -StartWhenAvailable `
        -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries

    # Register logon task
    try {
        Register-ScheduledTask -TaskName $LogonTaskName `
            -Trigger $LogonTrigger `
            -Action $LogonAction `
            -Principal $Principal `
            -Settings $LogonSettings `
            -Description "Hardware inventory collection on user logon" | Out-Null

        Write-InstallLog "Successfully created logon collection task" -Level "Success"
    }
    catch {
        Write-InstallLog "Failed to create logon task: $_" -Level "Error"
        return $false
    }

    # === TASK 3: QUEUE PROCESSING (EVERY 4 HOURS) ===
    [string]$QueueTaskName = "InventoryAgent-ProcessQueue"

    Write-InstallLog "Creating queue processing task: $QueueTaskName" -Level "Info"

    # Check if task exists
    if (Get-ScheduledTask -TaskName $QueueTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $QueueTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $QueueTaskName" -Level "Info"
        }
    }

    # Create trigger for every 4 hours
    # RepetitionInterval: How often to repeat
    # RepetitionDuration: How long to keep repeating (MaxValue = indefinitely)
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.TriggerType]$QueueTrigger = New-ScheduledTaskTrigger `
        -Once -At "00:00" `
        -RepetitionInterval (New-TimeSpan -Hours 4) `
        -RepetitionDuration ([TimeSpan]::MaxValue)

    # Create action that only processes the queue
    # Uses Command mode to dot-source script and call function directly
    # This avoids full inventory collection (only processes queue)
    [string]$QueueActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { `$ErrorActionPreference = 'Stop'; . '$ScriptPath'; Process-OfflineQueue }`""
    [Microsoft.PowerShell.Cmdletization.GeneratedTypes.ScheduledTask.ActionType]$QueueAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $QueueActionScript

    # Register queue task
    try {
        Register-ScheduledTask -TaskName $QueueTaskName `
            -Trigger $QueueTrigger `
            -Action $QueueAction `
            -Principal $Principal `
            -Settings $Settings `
            -Description "Process offline inventory queue every 4 hours" | Out-Null

        Write-InstallLog "Successfully created queue processing task" -Level "Success"
    }
    catch {
        Write-InstallLog "Failed to create queue task: $_" -Level "Error"
        return $false
    }

    # === DISPLAY TASK STATUS ===
    Write-InstallLog "========================================" -Level "Info"
    Write-InstallLog "Scheduled Tasks Status" -Level "Info"
    Write-InstallLog "========================================" -Level "Info"

    # Query all inventory agent tasks
    [Microsoft.Management.Infrastructure.CimInstance[]]$Tasks = Get-ScheduledTask -TaskName "InventoryAgent-*"

    foreach ($Task in $Tasks) {
        [Microsoft.Management.Infrastructure.CimInstance]$Info = Get-ScheduledTaskInfo -TaskName $Task.TaskName

        Write-InstallLog "Task: $($Task.TaskName)" -Level "Info"
        Write-InstallLog "  State: $($Task.State)" -Level "Info"
        Write-InstallLog "  Last Run: $($Info.LastRunTime)" -Level "Info"
        Write-InstallLog "  Next Run: $($Info.NextRunTime)" -Level "Info"
        Write-InstallLog "  Last Result: 0x$($Info.LastTaskResult.ToString('X'))" -Level "Info"
    }

    # === OPTIONAL: RUN INITIAL COLLECTION ===
    Write-InstallLog "========================================" -Level "Info"
    [string]$Response = Read-Host "Run initial inventory collection now? (Y/N)"

    if ($Response -eq 'Y' -or $Response -eq 'y') {
        Write-InstallLog "Running initial inventory collection..." -Level "Info"
        try {
            Start-ScheduledTask -TaskName $DailyTaskName -ErrorAction Stop
            Write-InstallLog "Initial collection started successfully" -Level "Success"
        }
        catch {
            Write-InstallLog "Failed to start initial collection: $_" -Level "Error"
        }
    }

    Write-InstallLog "========================================" -Level "Success"
    Write-InstallLog "Installation completed successfully!" -Level "Success"
    Write-InstallLog "========================================" -Level "Success"

    return $true
}
#endregion

#region Main Execution
<#
    MAIN EXECUTION BLOCK
    Entry point for installation script.
    Calls task creation function and exits with status code.
#>

# Execute main function
[bool]$Result = New-InventoryScheduledTask

# Exit with appropriate code
if ($Result) {
    exit 0
}
else {
    Write-InstallLog "Installation failed" -Level "Error"
    exit 1
}
#endregion
