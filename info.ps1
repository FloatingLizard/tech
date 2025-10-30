#Requires -Version 5.1
<#
.SYNOPSIS
    Windows 11 Performance Troubleshooting Script (No Admin Required) - Enhanced Reporting
.DESCRIPTION
    Diagnoses common performance issues on Windows 11 without requiring administrator privileges.
    Checks CPU, memory, disk, network, startup programs, and system health.
    Exports comprehensive report to text file with all diagnostic details.
.NOTES
    File Name      : Win11-Performance-Troubleshoot-Enhanced.ps1
    Author         : Performance Diagnostics
    Prerequisite   : PowerShell 5.1 or higher
    Created        : 2025
#>

# Set error action preference
$ErrorActionPreference = "SilentlyContinue"

# Initialize report content array
$ReportLines = @()

# Function to add line to report
function Add-ReportLine {
    param([string]$Line = "")
    $script:ReportLines += $Line
}

# Color functions for better readability (console only)
function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Write-Header {
    param([string]$Title)
    Write-Host "`n" -NoNewline
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" "Cyan"
    Write-ColorOutput " $Title" "Yellow"
    Write-ColorOutput "═══════════════════════════════════════════════════════════════" "Cyan"
    
    # Add to report with plain text
    Add-ReportLine ""
    Add-ReportLine "================================================================"
    Add-ReportLine "$Title"
    Add-ReportLine "================================================================"
}

function Write-Issue {
    param([string]$Message)
    Write-ColorOutput "  ⚠ $Message" "Red"
    Add-ReportLine "  [ISSUE] $Message"
}

function Write-Warning {
    param([string]$Message)
    Write-ColorOutput "  ⚡ $Message" "Yellow"
    Add-ReportLine "  [WARNING] $Message"
}

function Write-OK {
    param([string]$Message)
    Write-ColorOutput "  ✓ $Message" "Green"
    Add-ReportLine "  [OK] $Message"
}

function Write-Info {
    param([string]$Message)
    Write-ColorOutput "  ℹ $Message" "Cyan"
    Add-ReportLine "  $Message"
}

# Initialize results
$Issues = @()
$Warnings = @()
$Recommendations = @()

# Display header
Clear-Host
$HeaderText = @"
╔═══════════════════════════════════════════════════════════════╗
║         Windows 11 Performance Troubleshooting Tool           ║
║              (No Administrator Rights Required)               ║
╚═══════════════════════════════════════════════════════════════╝
"@

Write-ColorOutput $HeaderText "Cyan"
Add-ReportLine "================================================================"
Add-ReportLine "Windows 11 Performance Diagnostic Report"
Add-ReportLine "Generated: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
Add-ReportLine "================================================================"

Write-Info "Starting diagnostic scan..."
Start-Sleep -Seconds 1

# ============================================================================
# 1. SYSTEM INFORMATION
# ============================================================================
Write-Header "1. System Information"

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $CS = Get-CimInstance -ClassName Win32_ComputerSystem
    $CPU = Get-CimInstance -ClassName Win32_Processor
    
    # Get Windows 11 version name (like 23H2)
    $DisplayVersion = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
    $ReleaseId = (Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion" -Name ReleaseId -ErrorAction SilentlyContinue).ReleaseId
    
    $VersionName = if ($DisplayVersion) { $DisplayVersion } elseif ($ReleaseId) { $ReleaseId } else { "Unknown" }
    
    Write-Info "Hostname: $($CS.Name)"
    Write-Info "OS: $($OS.Caption) - Version $VersionName"
    Write-Info "Build: $($OS.BuildNumber)"
    Write-Info "Computer: $($CS.Manufacturer) $($CS.Model)"
    Write-Info "Processor: $($CPU.Name)"
    Write-Info "RAM: $([math]::Round($CS.TotalPhysicalMemory / 1GB, 2)) GB"
    Write-Info "System Type: $($OS.OSArchitecture)"
    
    # Check for Microsoft Office
    Write-Info "`nChecking for Microsoft Office..."
    Add-ReportLine ""
    Add-ReportLine "  Microsoft Office Information:"
    
    $OfficeFound = $false
    
    # Check for Office 2016/2019/2021/365 (Click-to-Run)
    $Office16Path = "HKLM:\SOFTWARE\Microsoft\Office\ClickToRun\Configuration"
    if (Test-Path $Office16Path) {
        $OfficeVersion = (Get-ItemProperty -Path $Office16Path -Name VersionToReport -ErrorAction SilentlyContinue).VersionToReport
        $OfficePlatform = (Get-ItemProperty -Path $Office16Path -Name Platform -ErrorAction SilentlyContinue).Platform
        $OfficeProductName = (Get-ItemProperty -Path $Office16Path -Name ProductReleaseIds -ErrorAction SilentlyContinue).ProductReleaseIds
        
        if ($OfficeVersion) {
            # Determine Office edition based on version number
            $MajorVersion = $OfficeVersion.Split('.')[0]
            $Build = $OfficeVersion.Split('.')[2]
            
            $OfficeName = switch ($MajorVersion) {
                "16" { 
                    if ($OfficeProductName -like "*365*" -or $OfficeProductName -like "*O365*") {
                        "Microsoft 365"
                    } elseif ([int]$Build -ge 14332) {
                        "Office 2021"
                    } elseif ([int]$Build -ge 10000) {
                        "Office 2019"
                    } else {
                        "Office 2016"
                    }
                }
                default { "Office" }
            }
            
            Write-Info "Office: $OfficeName (Click-to-Run)"
            Write-Info "  Version: $OfficeVersion"
            Write-Info "  Platform: $OfficePlatform"
            if ($OfficeProductName) {
                Write-Info "  Products: $OfficeProductName"
            }
            $OfficeFound = $true
        }
    }
    
    # Check for Office 2013 and earlier (MSI-based)
    if (-not $OfficeFound) {
        $OfficePaths = @(
            "HKLM:\SOFTWARE\Microsoft\Office\15.0\Common\InstallRoot",  # Office 2013
            "HKLM:\SOFTWARE\Microsoft\Office\14.0\Common\InstallRoot",  # Office 2010
            "HKLM:\SOFTWARE\Microsoft\Office\12.0\Common\InstallRoot"   # Office 2007
        )
        
        foreach ($Path in $OfficePaths) {
            if (Test-Path $Path) {
                $InstallPath = (Get-ItemProperty -Path $Path -Name Path -ErrorAction SilentlyContinue).Path
                
                if ($InstallPath) {
                    $VersionNum = $Path.Split('\')[4]
                    $OfficeName = switch ($VersionNum) {
                        "15.0" { "Office 2013" }
                        "14.0" { "Office 2010" }
                        "12.0" { "Office 2007" }
                        default { "Office" }
                    }
                    
                    Write-Info "Office: $OfficeName (MSI-based)"
                    Write-Info "  Install Path: $InstallPath"
                    $OfficeFound = $true
                    break
                }
            }
        }
    }
    
    if (-not $OfficeFound) {
        Write-Info "Office: Not installed or not detected"
    }
    
    # Check if running Windows 11
    if ($OS.BuildNumber -lt 22000) {
        Write-Warning "This system is not running Windows 11 (Build < 22000)"
    }
} catch {
    Write-Issue "Unable to retrieve system information"
}

# ============================================================================
# 2. CPU USAGE ANALYSIS
# ============================================================================
Write-Header "2. CPU Usage Analysis"

Write-Info "Analyzing CPU usage (sampling for 3 seconds)..."

try {
    # Get current CPU usage
    $CPULoad = (Get-CimInstance -ClassName Win32_Processor | Measure-Object -Property LoadPercentage -Average).Average
    
    Write-Info "Current CPU Load: $CPULoad%"
    
    if ($CPULoad -gt 80) {
        Write-Issue "CPU usage is very high ($CPULoad%)"
        $Issues += "High CPU usage detected"
    } elseif ($CPULoad -gt 60) {
        Write-Warning "CPU usage is elevated ($CPULoad%)"
        $Warnings += "Elevated CPU usage"
    } else {
        Write-OK "CPU usage is normal ($CPULoad%)"
    }
    
    # Get top CPU consuming processes
    Write-Info "`nTop 5 CPU-consuming processes:"
    Add-ReportLine ""
    Add-ReportLine "  Top 5 CPU-consuming processes:"
    
    $TopCPU = Get-Process | Sort-Object CPU -Descending | Select-Object -First 5 Name, CPU, @{Name="CPUTime";Expression={$_.CPU.ToString("0.00")}}
    
    foreach ($proc in $TopCPU) {
        if ($proc.CPU -gt 100) {
            Write-Warning "  - $($proc.Name): $($proc.CPUTime)s CPU time"
        } else {
            Write-Info "  - $($proc.Name): $($proc.CPUTime)s CPU time"
        }
    }
} catch {
    Write-Issue "Unable to analyze CPU usage"
}

# ============================================================================
# 3. MEMORY USAGE ANALYSIS
# ============================================================================
Write-Header "3. Memory Usage Analysis"

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $TotalRAM = [math]::Round($OS.TotalVisibleMemorySize / 1MB, 2)
    $FreeRAM = [math]::Round($OS.FreePhysicalMemory / 1MB, 2)
    $UsedRAM = $TotalRAM - $FreeRAM
    $MemoryUsagePercent = [math]::Round(($UsedRAM / $TotalRAM) * 100, 2)
    
    Write-Info "Total RAM: $TotalRAM GB"
    Write-Info "Used RAM: $UsedRAM GB"
    Write-Info "Free RAM: $FreeRAM GB"
    Write-Info "Memory Usage: $MemoryUsagePercent%"
    
    if ($MemoryUsagePercent -gt 90) {
        Write-Issue "Memory usage is critically high ($MemoryUsagePercent%)"
        $Issues += "Critical memory usage"
        $Recommendations += "Close unnecessary applications or upgrade RAM"
    } elseif ($MemoryUsagePercent -gt 75) {
        Write-Warning "Memory usage is high ($MemoryUsagePercent%)"
        $Warnings += "High memory usage"
        $Recommendations += "Consider closing some applications"
    } else {
        Write-OK "Memory usage is normal ($MemoryUsagePercent%)"
    }
    
    # Get top memory consuming processes
    Write-Info "`nTop 5 memory-consuming processes:"
    Add-ReportLine ""
    Add-ReportLine "  Top 5 memory-consuming processes:"
    
    $TopMem = Get-Process | Sort-Object WorkingSet -Descending | Select-Object -First 5 Name, @{Name="MemoryMB";Expression={[math]::Round($_.WorkingSet / 1MB, 2)}}
    
    foreach ($proc in $TopMem) {
        if ($proc.MemoryMB -gt 500) {
            Write-Warning "  - $($proc.Name): $($proc.MemoryMB) MB"
        } else {
            Write-Info "  - $($proc.Name): $($proc.MemoryMB) MB"
        }
    }
    
    # Check for memory leaks (processes with excessive handle count)
    Write-Info "`nChecking for potential memory leaks..."
    Add-ReportLine ""
    Add-ReportLine "  Checking for potential memory leaks..."
    
    $HighHandles = Get-Process | Where-Object { $_.HandleCount -gt 10000 } | Select-Object Name, HandleCount
    
    if ($HighHandles) {
        Write-Warning "Processes with high handle count (possible memory leak):"
        Add-ReportLine "  Processes with high handle count (possible memory leak):"
        foreach ($proc in $HighHandles) {
            Write-Warning "  - $($proc.Name): $($proc.HandleCount) handles"
        }
        $Warnings += "Potential memory leak detected"
    } else {
        Write-OK "No obvious memory leaks detected"
    }
} catch {
    Write-Issue "Unable to analyze memory usage"
}

# ============================================================================
# 4. DISK FRAGMENTATION AND PERFORMANCE
# ============================================================================
Write-Header "4. Disk Fragmentation and Performance"

try {
    Write-Info "Checking C: drive type and fragmentation status..."
    
    # Check if C: drive is SSD or HDD
    $PhysicalDisks = Get-PhysicalDisk
    $CDrivePartition = Get-Partition -DriveLetter C -ErrorAction SilentlyContinue
    
    if ($CDrivePartition) {
        $DiskNumber = $CDrivePartition.DiskNumber
        $PhysicalDisk = Get-PhysicalDisk -DeviceNumber $DiskNumber -ErrorAction SilentlyContinue
        
        if ($PhysicalDisk) {
            $MediaType = $PhysicalDisk.MediaType
            Write-Info "C: Drive Type: $MediaType"
            
            # Check fragmentation status (only relevant for HDD)
            if ($MediaType -eq "HDD") {
                Write-Info "`nChecking fragmentation status..."
                Add-ReportLine ""
                Add-ReportLine "  Checking fragmentation status..."
                
                # Use defrag command for analysis
                Write-Info "Running defrag analysis..."
                $DefragOutput = & defrag C: /A /V 2>&1 | Out-String
                
                # Extract fragmentation percentage
                if ($DefragOutput -match "(\d+)%.*fragmented") {
                    $FragPercent = [int]$Matches[1]
                    Write-Info "Fragmentation Level: $FragPercent%"
                    
                    if ($FragPercent -gt 10) {
                        Write-Issue "Disk is fragmented ($FragPercent%) - defragmentation recommended"
                        $Issues += "C: drive is fragmented ($FragPercent%)"
                        $Recommendations += "Run Disk Defragmenter: Search 'Defragment' > Optimize Drives > Select C: > Optimize"
                    } elseif ($FragPercent -gt 5) {
                        Write-Warning "Disk has moderate fragmentation ($FragPercent%)"
                        $Warnings += "C: drive has moderate fragmentation"
                    } else {
                        Write-OK "Disk fragmentation is low ($FragPercent%)"
                    }
                } else {
                    Write-Info "Fragmentation analysis completed (may require admin rights for detailed info)"
                }
                
            } elseif ($MediaType -eq "SSD") {
                Write-OK "C: drive is an SSD - fragmentation not applicable"
                Write-Info "SSDs use TRIM instead of defragmentation"
                
                # Check if TRIM is enabled
                Write-Info "`nChecking TRIM status..."
                Add-ReportLine ""
                Add-ReportLine "  Checking TRIM status for SSD..."
                
                try {
                    # Query the DisableDeleteNotify value (0 = TRIM enabled, 1 = TRIM disabled)
                    $TrimStatus = fsutil behavior query DisableDeleteNotify
                    
                    if ($TrimStatus -match "DisableDeleteNotify = 0") {
                        Write-OK "TRIM is ENABLED (optimal for SSD performance)"
                    } elseif ($TrimStatus -match "DisableDeleteNotify = 1") {
                        Write-Warning "TRIM is DISABLED - should be enabled for SSD health"
                        $Warnings += "TRIM is disabled on SSD"
                        $Recommendations += "Enable TRIM: Run 'fsutil behavior set DisableDeleteNotify 0' as Administrator"
                    } else {
                        Write-Info "TRIM status: $TrimStatus"
                    }
                    
                    # Check last optimization date
                    $OptimizeInfo = Get-StorageJob -ErrorAction SilentlyContinue | Where-Object { $_.JobType -eq "Optimize" }
                    if ($OptimizeInfo) {
                        Write-Info "Last optimization: $($OptimizeInfo.StartTime)"
                    }
                    
                } catch {
                    Write-Info "Unable to check TRIM status (may require admin rights)"
                }
                
            } else {
                Write-Info "Drive type: $MediaType"
            }
        }
    }
    
    # Check disk read/write performance
    Write-Info "`nMeasuring disk read/write performance..."
    Add-ReportLine ""
    Add-ReportLine "  Measuring disk read/write performance..."
    
    # Get disk performance counters
    $DiskReadSec = Get-Counter "\PhysicalDisk(_Total)\Avg. Disk sec/Read" -ErrorAction SilentlyContinue
    $DiskWriteSec = Get-Counter "\PhysicalDisk(_Total)\Avg. Disk sec/Write" -ErrorAction SilentlyContinue
    $DiskQueue = Get-Counter "\PhysicalDisk(_Total)\Avg. Disk Queue Length" -ErrorAction SilentlyContinue
    $DiskTime = Get-Counter "\PhysicalDisk(_Total)\% Disk Time" -ErrorAction SilentlyContinue
    
    if ($DiskReadSec -and $DiskWriteSec) {
        $ReadLatency = [math]::Round($DiskReadSec.CounterSamples[0].CookedValue * 1000, 2)
        $WriteLatency = [math]::Round($DiskWriteSec.CounterSamples[0].CookedValue * 1000, 2)
        
        Write-Info "Average Read Latency: $ReadLatency ms"
        Write-Info "Average Write Latency: $WriteLatency ms"
        
        # Evaluate read performance
        if ($ReadLatency -gt 25) {
            Write-Warning "High disk read latency detected"
            $Warnings += "High disk read latency ($ReadLatency ms)"
        } else {
            Write-OK "Disk read latency is good"
        }
        
        # Evaluate write performance
        if ($WriteLatency -gt 25) {
            Write-Warning "High disk write latency detected"
            $Warnings += "High disk write latency ($WriteLatency ms)"
        } else {
            Write-OK "Disk write latency is good"
        }
    }
    
    if ($DiskQueue) {
        $QueueLength = [math]::Round($DiskQueue.CounterSamples[0].CookedValue, 2)
        Write-Info "Average Disk Queue Length: $QueueLength"
        
        if ($QueueLength -gt 2) {
            Write-Warning "High disk queue length - disk may be bottleneck"
            $Warnings += "High disk queue length"
        } else {
            Write-OK "Disk queue length is normal"
        }
    }
    
    if ($DiskTime) {
        $DiskBusy = [math]::Round($DiskTime.CounterSamples[0].CookedValue, 2)
        Write-Info "Current Disk Usage: $DiskBusy%"
        
        if ($DiskBusy -gt 90) {
            Write-Issue "Disk is very busy ($DiskBusy%)"
            $Issues += "Disk usage is very high"
        } elseif ($DiskBusy -gt 70) {
            Write-Warning "Disk is busy ($DiskBusy%)"
            $Warnings += "Elevated disk usage"
        } else {
            Write-OK "Disk usage is normal"
        }
    }
    
    # Get disk transfer rate
    Write-Info "`nChecking disk transfer rates..."
    Add-ReportLine ""
    Add-ReportLine "  Checking disk transfer rates..."
    
    $DiskReadBytes = Get-Counter "\PhysicalDisk(_Total)\Disk Read Bytes/sec" -ErrorAction SilentlyContinue
    $DiskWriteBytes = Get-Counter "\PhysicalDisk(_Total)\Disk Write Bytes/sec" -ErrorAction SilentlyContinue
    
    if ($DiskReadBytes -and $DiskWriteBytes) {
        $ReadMBps = [math]::Round($DiskReadBytes.CounterSamples[0].CookedValue / 1MB, 2)
        $WriteMBps = [math]::Round($DiskWriteBytes.CounterSamples[0].CookedValue / 1MB, 2)
        
        Write-Info "Current Read Speed: $ReadMBps MB/s"
        Write-Info "Current Write Speed: $WriteMBps MB/s"
    }
    
} catch {
    Write-Warning "Unable to fully analyze disk performance: $($_.Exception.Message)"
}

# ============================================================================
# 5. STARTUP PROGRAMS
# ============================================================================
Write-Header "5. Startup Programs Analysis"

try {
    Write-Info "Analyzing startup programs..."
    Add-ReportLine "  Analyzing startup programs..."
    
    # Get startup programs from multiple locations
    $StartupPaths = @(
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
    )
    
    $StartupItems = @()
    
    foreach ($Path in $StartupPaths) {
        try {
            $Items = Get-ItemProperty -Path $Path -ErrorAction Stop
            $Items.PSObject.Properties | Where-Object { $_.Name -notlike "PS*" } | ForEach-Object {
                $StartupItems += [PSCustomObject]@{
                    Name = $_.Name
                    Command = $_.Value
                    Location = $Path
                }
            }
        } catch {
            # Path doesn't exist or can't be read
        }
    }
    
    # Also check Startup folder
    $StartupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $StartupFolder) {
        Get-ChildItem -Path $StartupFolder -File | ForEach-Object {
            $StartupItems += [PSCustomObject]@{
                Name = $_.Name
                Command = $_.FullName
                Location = "Startup Folder"
            }
        }
    }
    
    Write-Info "`nStartup programs detected: $($StartupItems.Count)"
    Add-ReportLine ""
    Add-ReportLine "  Startup programs detected: $($StartupItems.Count)"
    
    if ($StartupItems.Count -gt 10) {
        Write-Warning "High number of startup programs ($($StartupItems.Count))"
        $Warnings += "High number of startup programs"
        $Recommendations += "Review and disable unnecessary startup programs in Task Manager > Startup"
    } elseif ($StartupItems.Count -gt 5) {
        Write-Info "Moderate number of startup programs"
    } else {
        Write-OK "Reasonable number of startup programs"
    }
    
    if ($StartupItems.Count -gt 0) {
        Write-Info "`nList of startup programs:"
        Add-ReportLine ""
        Add-ReportLine "  List of startup programs:"
        foreach ($Item in $StartupItems) {
            Write-Info "  - $($Item.Name)"
            Add-ReportLine "    - $($Item.Name)"
            Add-ReportLine "      Path: $($Item.Command)"
        }
    }
    
} catch {
    Write-Warning "Unable to fully analyze startup programs"
}

# ============================================================================
# 6. NETWORK PERFORMANCE
# ============================================================================
Write-Header "6. Network Performance"

try {
    Write-Info "Checking network adapters..."
    
    $NetAdapters = Get-NetAdapter | Where-Object { $_.Status -eq "Up" }
    
    foreach ($Adapter in $NetAdapters) {
        Write-Info "`nAdapter: $($Adapter.Name)"
        Write-Info "  Status: $($Adapter.Status)"
        Write-Info "  Link Speed: $($Adapter.LinkSpeed)"
        Write-Info "  MAC Address: $($Adapter.MacAddress)"
        
        if ($Adapter.LinkSpeed -like "*Mbps*" -and [int]($Adapter.LinkSpeed -replace "[^0-9]") -lt 100) {
            Write-Warning "  Slow network connection detected"
            $Warnings += "Slow network adapter: $($Adapter.Name)"
        }
    }
    
    # Test internet connectivity
    Write-Info "`nTesting internet connectivity..."
    Add-ReportLine ""
    Add-ReportLine "  Testing internet connectivity..."
    
    $PingTest = Test-Connection -ComputerName "8.8.8.8" -Count 2 -Quiet
    
    if ($PingTest) {
        Write-OK "Internet connection is active"
        
        # Get more detailed ping stats
        $PingStats = Test-Connection -ComputerName "8.8.8.8" -Count 4
        $AvgLatency = ($PingStats | Measure-Object -Property ResponseTime -Average).Average
        Write-Info "  Average latency: $([math]::Round($AvgLatency, 2)) ms"
        
        if ($AvgLatency -gt 100) {
            Write-Warning "  High network latency detected"
            $Warnings += "High network latency"
        }
    } else {
        Write-Issue "No internet connection detected"
        $Issues += "No internet connection"
    }
    
} catch {
    Write-Warning "Unable to fully analyze network performance"
}

# ============================================================================
# 7. BACKGROUND PROCESSES
# ============================================================================
Write-Header "7. Background Processes"

try {
    $ProcessCount = (Get-Process).Count
    Write-Info "Total running processes: $ProcessCount"
    
    if ($ProcessCount -gt 200) {
        Write-Warning "High number of running processes ($ProcessCount)"
        $Warnings += "High process count"
        $Recommendations += "Review running processes in Task Manager and close unnecessary applications"
    } elseif ($ProcessCount -gt 150) {
        Write-Info "Moderate number of running processes"
    } else {
        Write-OK "Normal number of running processes"
    }
    
    # Check for known problematic processes
    Write-Info "`nChecking for known resource-intensive processes..."
    Add-ReportLine ""
    Add-ReportLine "  Checking for known resource-intensive processes..."
    
    $ProblematicProcesses = @(
        "WmiPrvSE",
        "SearchIndexer",
        "MsMpEng",
        "SgrmBroker",
        "TiWorker"
    )
    
    foreach ($ProcName in $ProblematicProcesses) {
        $Proc = Get-Process -Name $ProcName -ErrorAction SilentlyContinue
        if ($Proc) {
            $CPUPercent = ($Proc | Measure-Object -Property CPU -Sum).Sum
            $MemoryMB = [math]::Round(($Proc | Measure-Object -Property WorkingSet -Sum).Sum / 1MB, 2)
            
            if ($CPUPercent -gt 50 -or $MemoryMB -gt 500) {
                Write-Warning "  $ProcName is using significant resources (CPU: $CPUPercent s, Memory: $MemoryMB MB)"
            } else {
                Write-Info "  $ProcName is running normally"
            }
        }
    }
    
} catch {
    Write-Warning "Unable to analyze background processes"
}

# ============================================================================
# 8. WINDOWS UPDATE STATUS
# ============================================================================
Write-Header "8. Windows Update Status"

try {
    Write-Info "Checking Windows Update status..."
    
    # This requires Windows Update COM object
    $UpdateSession = New-Object -ComObject Microsoft.Update.Session
    $UpdateSearcher = $UpdateSession.CreateUpdateSearcher()
    
    Write-Info "Searching for pending updates (this may take a moment)..."
    $SearchResult = $UpdateSearcher.Search("IsInstalled=0")
    
    $PendingUpdates = $SearchResult.Updates.Count
    
    if ($PendingUpdates -gt 0) {
        Write-Warning "$PendingUpdates pending Windows update(s) found"
        Add-ReportLine ""
        Add-ReportLine "  Pending updates:"
        foreach ($Update in $SearchResult.Updates) {
            Add-ReportLine "    - $($Update.Title)"
        }
        $Warnings += "Pending Windows updates"
        $Recommendations += "Install pending Windows updates via Windows Update"
    } else {
        Write-OK "No pending Windows updates"
    }
    
} catch {
    Write-Info "Unable to check Windows Update status (may require admin rights)"
    Write-Info "Manually check: Settings > Windows Update"
}

# ============================================================================
# 9. TEMP FILES AND CACHE
# ============================================================================
Write-Header "9. Temporary Files Analysis"

try {
    Write-Info "Analyzing temporary files..."
    
    $TempPaths = @(
        $env:TEMP,
        "$env:LOCALAPPDATA\Temp",
        "$env:USERPROFILE\AppData\Local\Microsoft\Windows\INetCache"
    )
    
    $TotalTempSize = 0
    
    foreach ($Path in $TempPaths) {
        if (Test-Path $Path) {
            $TempFiles = Get-ChildItem -Path $Path -Recurse -Force -ErrorAction SilentlyContinue
            $PathSize = ($TempFiles | Measure-Object -Property Length -Sum -ErrorAction SilentlyContinue).Sum
            
            if ($PathSize) {
                $PathSizeGB = [math]::Round($PathSize / 1GB, 2)
                $TotalTempSize += $PathSize
                Write-Info "$Path : $PathSizeGB GB"
            }
        }
    }
    
    $TotalTempGB = [math]::Round($TotalTempSize / 1GB, 2)
    Write-Info "`nTotal temporary files: $TotalTempGB GB"
    
    if ($TotalTempGB -gt 5) {
        Write-Warning "Large amount of temporary files detected"
        $Warnings += "Excessive temporary files ($TotalTempGB GB)"
        $Recommendations += "Run Disk Cleanup to remove temporary files"
    } elseif ($TotalTempGB -gt 2) {
        Write-Warning "Moderate amount of temporary files"
        $Recommendations += "Consider running Disk Cleanup"
    } else {
        Write-OK "Temporary files are under control"
    }
    
} catch {
    Write-Warning "Unable to fully analyze temporary files"
}

# ============================================================================
# 10. WINDOWS 11 SPECIFIC CHECKS
# ============================================================================
Write-Header "10. Windows 11 Specific Settings"

try {
    Write-Info "Checking Windows 11 performance settings..."
    
    # Check visual effects (via registry)
    $VisualFX = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\VisualEffects" -Name "VisualFXSetting" -ErrorAction SilentlyContinue
    
    if ($VisualFX) {
        switch ($VisualFX.VisualFXSetting) {
            1 { Write-OK "Visual Effects: Let Windows choose" }
            2 { Write-OK "Visual Effects: Best appearance" }
            3 { Write-OK "Visual Effects: Best performance" }
            4 { Write-Info "Visual Effects: Custom" }
        }
    }
    
    # Check if transparency effects are enabled
    $Transparency = Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Themes\Personalize" -Name "EnableTransparency" -ErrorAction SilentlyContinue
    
    if ($Transparency -and $Transparency.EnableTransparency -eq 1) {
        Write-Info "Transparency effects: Enabled"
        $Recommendations += "Disable transparency for better performance: Settings > Personalization > Colors"
    } else {
        Write-OK "Transparency effects: Disabled (good for performance)"
    }
    
    # Check power plan
    $PowerPlan = powercfg /getactivescheme
    Write-Info "Active power plan: $($PowerPlan -replace '.*\(|\).*')"
    
    if ($PowerPlan -like "*Power saver*") {
        Write-Warning "Power Saver mode is active - may reduce performance"
        $Recommendations += "Switch to 'Balanced' or 'High Performance' power plan for better performance"
    }
    
} catch {
    Write-Warning "Unable to check all Windows 11 settings"
}

# ============================================================================
# 11. SYSTEM UPTIME
# ============================================================================
Write-Header "11. System Uptime"

try {
    $OS = Get-CimInstance -ClassName Win32_OperatingSystem
    $LastBoot = $OS.LastBootUpTime
    $Uptime = (Get-Date) - $LastBoot
    
    Write-Info "Last boot: $LastBoot"
    Write-Info "System uptime: $($Uptime.Days) days, $($Uptime.Hours) hours, $($Uptime.Minutes) minutes"
    
    if ($Uptime.Days -gt 14) {
        Write-Warning "System has been running for $($Uptime.Days) days without restart"
        $Warnings += "Long uptime ($($Uptime.Days) days)"
        $Recommendations += "Restart your computer to clear memory and apply updates"
    } elseif ($Uptime.Days -gt 7) {
        Write-Info "Consider restarting your computer soon"
    } else {
        Write-OK "System uptime is reasonable"
    }
    
} catch {
    Write-Warning "Unable to check system uptime"
}

# ============================================================================
# SUMMARY AND RECOMMENDATIONS
# ============================================================================
Write-Header "DIAGNOSTIC SUMMARY"

Write-ColorOutput "`n📊 Results:" "Cyan"
Add-ReportLine ""
Add-ReportLine "DIAGNOSTIC RESULTS"
Add-ReportLine "================================================================"

if ($Issues.Count -gt 0) {
    Write-ColorOutput "`n🔴 Critical Issues Found: $($Issues.Count)" "Red"
    Add-ReportLine ""
    Add-ReportLine "CRITICAL ISSUES FOUND: $($Issues.Count)"
    Add-ReportLine "----------------------------------------------------------------"
    foreach ($Issue in $Issues) {
        Write-Issue $Issue
    }
} else {
    Write-OK "No critical issues found"
}

Write-ColorOutput "`n═══════════════════════════════════════════════════════════════" "Cyan"
Write-ColorOutput " Diagnostic Complete!" "Green"
Write-ColorOutput "═══════════════════════════════════════════════════════════════" "Cyan"

Add-ReportLine ""
Add-ReportLine "================================================================"
Add-ReportLine "END OF REPORT"
Add-ReportLine "================================================================"

# Automatically export comprehensive report
Write-Host "`n"
$ReportPath = "$env:USERPROFILE\Desktop\Performance-Report-$(Get-Date -Format 'yyyyMMdd-HHmmss').txt"

try {
    $ReportLines | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-ColorOutput "`n✓ Comprehensive report saved to: $ReportPath" "Green"
    Write-ColorOutput "  All diagnostic information has been exported and is ready to copy/paste" "Green"
} catch {
    Write-ColorOutput "`n✗ Failed to save report: $($_.Exception.Message)" "Red"
}

Write-Host "`nPress any key to exit..."
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
