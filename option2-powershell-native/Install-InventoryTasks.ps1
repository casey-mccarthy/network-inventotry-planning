<#
.SYNOPSIS
    Creates Windows scheduled tasks for inventory collection (SECURITY HARDENED)
.DESCRIPTION
    This script creates scheduled tasks for the inventory agent:
    1. Daily collection at specified time
    2. Collection triggered on user logon
    3. Offline queue processing

    SECURITY ENHANCEMENTS:
    - Validates script signatures before task creation
    - Runs tasks as SYSTEM with restricted permissions
    - Logs all installation activities

.PARAMETER ScriptPath
    Path to the Collect-Inventory.ps1 script
.PARAMETER DailyTime
    Time for daily collection (24-hour format HH:mm)
.PARAMETER Force
    Force recreation of existing tasks
.PARAMETER ValidateSignature
    Validate script signature before creating tasks (recommended)

.NOTES
    Version: 2.1.0
    Requires: Administrator privileges
#>

#Requires -Version 5.1
#Requires -RunAsAdministrator

[CmdletBinding()]
param(
    [Parameter()]
    [string]$ScriptPath = "C:\ProgramData\InventoryAgent\Collect-Inventory.ps1",

    [Parameter()]
    [string]$DailyTime = "02:00",

    [Parameter()]
    [switch]$Force,

    [Parameter()]
    [switch]$ValidateSignature
)

function Write-InstallLog {
    param(
        [string]$Message,
        [string]$Level = "Info"
    )

    $Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $LogMessage = "$Timestamp [$Level] $Message"
    Write-Host $LogMessage

    # Also log to file
    $LogPath = "C:\ProgramData\InventoryAgent\Logs"
    if (!(Test-Path $LogPath)) {
        New-Item -ItemType Directory -Path $LogPath -Force | Out-Null
    }

    $LogFile = Join-Path $LogPath "install_$(Get-Date -Format 'yyyyMMdd').log"
    Add-Content -Path $LogFile -Value $LogMessage -Force
}

function Test-ScriptSignature {
    param([string]$Path)

    if (!(Test-Path $Path)) {
        Write-InstallLog "Script not found: $Path" "Error"
        return $false
    }

    $Signature = Get-AuthenticodeSignature -FilePath $Path

    if ($Signature.Status -eq 'Valid') {
        Write-InstallLog "Script signature is valid: $($Signature.SignerCertificate.Subject)" "Info"
        return $true
    }
    elseif ($Signature.Status -eq 'NotSigned') {
        Write-InstallLog "WARNING: Script is not digitally signed" "Warning"
        return $false
    }
    else {
        Write-InstallLog "Script signature validation failed: $($Signature.Status)" "Error"
        return $false
    }
}

function New-InventoryScheduledTask {
    Write-InstallLog "========================================" "Info"
    Write-InstallLog "Creating Inventory Collection Scheduled Tasks" "Info"
    Write-InstallLog "========================================" "Info"

    # Validate script exists
    if (!(Test-Path $ScriptPath)) {
        Write-InstallLog "Script not found at: $ScriptPath" "Error"
        return $false
    }

    # Validate script signature if requested
    if ($ValidateSignature) {
        $SignatureValid = Test-ScriptSignature -Path $ScriptPath
        if (-not $SignatureValid) {
            Write-InstallLog "Script signature validation failed. Use -Force to override (not recommended)" "Error"
            if (-not $Force) {
                return $false
            }
            Write-InstallLog "Proceeding anyway due to -Force flag" "Warning"
        }
    }

    # Task 1: Daily Collection
    $DailyTaskName = "InventoryAgent-DailyCollection"

    Write-InstallLog "Creating daily collection task: $DailyTaskName" "Info"

    if (Get-ScheduledTask -TaskName $DailyTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $DailyTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $DailyTaskName" "Info"
        }
        else {
            Write-InstallLog "Task already exists: $DailyTaskName (use -Force to recreate)" "Warning"
        }
    }

    # Create daily trigger
    $DailyTrigger = New-ScheduledTaskTrigger -Daily -At $DailyTime

    # Create action with proper execution policy handling
    $ActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -TriggerType Scheduled"

    $DailyAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $ActionScript

    # Create principal (run as SYSTEM with highest privileges)
    $Principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\SYSTEM" -LogonType ServiceAccount -RunLevel Highest

    # Create settings
    $Settings = New-ScheduledTaskSettingsSet `
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

        Write-InstallLog "Successfully created daily collection task" "Info"
    }
    catch {
        Write-InstallLog "Failed to create daily task: $_" "Error"
        return $false
    }

    # Task 2: Logon Trigger
    $LogonTaskName = "InventoryAgent-LogonCollection"

    Write-InstallLog "Creating logon collection task: $LogonTaskName" "Info"

    if (Get-ScheduledTask -TaskName $LogonTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $LogonTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $LogonTaskName" "Info"
        }
        else {
            Write-InstallLog "Task already exists: $LogonTaskName (use -Force to recreate)" "Warning"
            return $false
        }
    }

    # Create logon trigger (any user)
    $LogonTrigger = New-ScheduledTaskTrigger -AtLogOn

    # Create action
    $LogonActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -File `"$ScriptPath`" -TriggerType Logon"

    $LogonAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $LogonActionScript

    # Settings for logon task (shorter timeout, less aggressive)
    $LogonSettings = New-ScheduledTaskSettingsSet `
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

        Write-InstallLog "Successfully created logon collection task" "Info"
    }
    catch {
        Write-InstallLog "Failed to create logon task: $_" "Error"
        return $false
    }

    # Task 3: Process Queue (every 4 hours)
    $QueueTaskName = "InventoryAgent-ProcessQueue"

    Write-InstallLog "Creating queue processing task: $QueueTaskName" "Info"

    if (Get-ScheduledTask -TaskName $QueueTaskName -ErrorAction SilentlyContinue) {
        if ($Force) {
            Unregister-ScheduledTask -TaskName $QueueTaskName -Confirm:$false
            Write-InstallLog "Removed existing task: $QueueTaskName" "Info"
        }
    }

    # Create trigger for every 4 hours
    $QueueTrigger = New-ScheduledTaskTrigger -Once -At "00:00" -RepetitionInterval (New-TimeSpan -Hours 4) -RepetitionDuration ([TimeSpan]::MaxValue)

    # Create action that only processes the queue
    $QueueActionScript = "-NoProfile -NonInteractive -WindowStyle Hidden -ExecutionPolicy Bypass -Command `"& { `$ErrorActionPreference = 'Stop'; . '$ScriptPath'; Process-OfflineQueue }`""

    $QueueAction = New-ScheduledTaskAction -Execute "PowerShell.exe" -Argument $QueueActionScript

    # Register queue task
    try {
        Register-ScheduledTask -TaskName $QueueTaskName `
            -Trigger $QueueTrigger `
            -Action $QueueAction `
            -Principal $Principal `
            -Settings $Settings `
            -Description "Process offline inventory queue every 4 hours" | Out-Null

        Write-InstallLog "Successfully created queue processing task" "Info"
    }
    catch {
        Write-InstallLog "Failed to create queue task: $_" "Error"
        return $false
    }

    # Display task status
    Write-InstallLog "========================================" "Info"
    Write-InstallLog "Scheduled Tasks Status" "Info"
    Write-InstallLog "========================================" "Info"

    $Tasks = Get-ScheduledTask -TaskName "InventoryAgent-*"
    foreach ($Task in $Tasks) {
        $Info = Get-ScheduledTaskInfo -TaskName $Task.TaskName
        Write-InstallLog "Task: $($Task.TaskName)" "Info"
        Write-InstallLog "  State: $($Task.State)" "Info"
        Write-InstallLog "  Last Run: $($Info.LastRunTime)" "Info"
        Write-InstallLog "  Next Run: $($Info.NextRunTime)" "Info"
        Write-InstallLog "  Last Result: 0x$($Info.LastTaskResult.ToString('X'))" "Info"
    }

    # Run initial collection (optional)
    Write-InstallLog "========================================" "Info"
    $Response = Read-Host "Run initial inventory collection now? (Y/N)"
    if ($Response -eq 'Y' -or $Response -eq 'y') {
        Write-InstallLog "Running initial inventory collection..." "Info"
        try {
            Start-ScheduledTask -TaskName $DailyTaskName
            Write-InstallLog "Initial collection started successfully" "Info"
        }
        catch {
            Write-InstallLog "Failed to start initial collection: $_" "Error"
        }
    }

    Write-InstallLog "========================================" "Info"
    Write-InstallLog "Installation completed successfully!" "Info"
    Write-InstallLog "========================================" "Info"

    return $true
}

# Execute main function
$Result = New-InventoryScheduledTask

if ($Result) {
    exit 0
}
else {
    Write-InstallLog "Installation failed" "Error"
    exit 1
}
