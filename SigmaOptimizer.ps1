Import-Module .\OpenAI_SigmaModule.psm1 -Force
Import-Module .\SigmaRuleTests.psm1 -Force
Import-Module Invoke-ArgFuscator

#add unrelated logs section
$unrelatedLogs = Get-Content -Path ".\config\unrelatedLogs.txt" -Raw

function Insert-MissingTags {
    param(
        [Parameter(Mandatory=$true)]
        [string[]]$RuleBlock,
        [Parameter(Mandatory=$true)]
        [bool]$HasAuthor,
        [Parameter(Mandatory=$true)]
        [bool]$HasDate
    )

    $newBlock = @()
    $foundId = $false
    foreach ($line in $RuleBlock) {
        if ($line -match "^\s*id:") {
            if (-not $foundId) {
                $foundId = $true
                $newBlock += "id: $(New-Guid)"
            }
        }
        else {
            $newBlock += $line
        }
    }
    
    if (-not $foundId) {
        $tempBlock = @()
        $inserted = $false
        foreach ($line in $newBlock) {
            $tempBlock += $line
            if (-not $inserted -and $line -match "^\s*title:") {
                $tempBlock += "id: $(New-Guid)"
                $inserted = $true
            }
        }
        $newBlock = $tempBlock
    }
    
    $levelIndex = -1
    for ($i = 0; $i -lt $newBlock.Count; $i++) {
        if ($newBlock[$i] -match "^\s*level:") {
            $levelIndex = $i
            break
        }
    }
    if ($levelIndex -eq -1) { $levelIndex = $newBlock.Count }
    
    $insertLines = @()
    if (-not $HasAuthor) {
        $insertLines += "author: Yusuke Nakajima"
    }
    if (-not $HasDate) {
        $insertLines += "date: $(Get-Date -Format 'yyyy-MM-dd')"
    }
    
    if ($insertLines.Count -gt 0) {
        $before = $newBlock[0..($levelIndex - 1)]
        $after = $newBlock[$levelIndex..($newBlock.Count - 1)]
        $newBlock = $before + $insertLines + $after
    }
    
    return $newBlock
}

function Extract-SigmaRules {
    param(
        [Parameter(Mandatory=$true)]
        [string]$SigmaOutput
    )
    
    $rules = @()         
    $currentRule = @()   
    $extracting = $false 
    
    $hasAuthor = $false
    $hasDate   = $false
    
    foreach ($line in $SigmaOutput -split "`n") {
        
        if ($line -match "^\s*author:") {
            $line = "author: Yusuke Nakajima"
            $hasAuthor = $true
        }
        
        if ($line -match "^\s*date:") {
            $line = "date: $(Get-Date -Format 'yyyy-MM-dd')"
            $hasDate = $true
        }
        
        if ($line -match "^\s*title:") {
            
            if ($extracting -eq $true -and $currentRule.Count -gt 0) {
                $currentRule = Insert-MissingTags -RuleBlock $currentRule -HasAuthor $hasAuthor -HasDate $hasDate
                $rules += ($currentRule -join "`n")
                $currentRule = @()
            }
            $extracting = $true

            $hasAuthor = $false
            $hasDate = $false
        }
        
        if ($extracting) {
            $currentRule += $line
        }
        
        if ($line -match "^\s*level:") {
            if ($extracting) {
                $currentRule = Insert-MissingTags -RuleBlock $currentRule -HasAuthor $hasAuthor -HasDate $hasDate
                $rules += ($currentRule -join "`n")
                $currentRule = @()
                $extracting = $false
            }
        }
    }
    
    if ($currentRule.Count -gt 0) {
        $currentRule = Insert-MissingTags -RuleBlock $currentRule -HasAuthor $hasAuthor -HasDate $hasDate
        $rules += ($currentRule -join "`n")
    }
    
    return $rules
}

function Generate-CandidateSummary {
    param(
        [Parameter(Mandatory=$true)]
        [array]$CandidateResults
    )
    
    $summaryText = ""
    foreach ($candidate in $CandidateResults) {
        $summaryText += "#### Candidate $($candidate.CandidateIndex) ####`n`n"
        $summaryText += "##### Rule #####`n"
        $summaryText += "$($candidate.RuleText)`n`n"
        $summaryText += "##### Coverage #####`n"
        $summaryText += "$($candidate.Coverage)`n`n"
        $summaryText += "##### Detectable Events #####`n"
        $summaryText += "$($candidate.DetectionResult)`n`n"
    }
    return $summaryText
}

function Print-FormattedTable {
    param (
        [Parameter(Mandatory = $true)]
        [array]$Data
    )
    if ($Data.Count -eq 0) {
        Write-Host "No data to display."
        return
    }
    
    $properties = $Data[0].psobject.Properties.Name
    $widths = @{}

    foreach ($prop in $properties) {
        $maxWidth = $prop.Length
        foreach ($row in $Data) {
            $valueStr = $row.$prop.ToString()
            if ($valueStr.Length -gt $maxWidth) {
                $maxWidth = $valueStr.Length
            }
        }
        $widths[$prop] = $maxWidth
    }

    $headerLine = "|"
    $separatorLine = "+"
    foreach ($prop in $properties) {
        $headerLine += " " + $prop.PadRight($widths[$prop]) + " |"
        $separatorLine += "-" * ($widths[$prop] + 2) + "+"
    }

    Write-Host $separatorLine -ForegroundColor Cyan
    Write-Host $headerLine -ForegroundColor Cyan
    Write-Host $separatorLine -ForegroundColor Cyan

    foreach ($row in $Data) {
        $line = "|"
        foreach ($prop in $properties) {
            $valueStr = $row.$prop.ToString()
            if ($valueStr -match '^\d+%?$') {
                $line += " " + $valueStr.PadLeft($widths[$prop]) + " |"
            }
            else {
                $line += " " + $valueStr.PadRight($widths[$prop]) + " |"
            }
        }
        Write-Host $line
    }

    Write-Host $separatorLine -ForegroundColor Cyan
}

function Print-IterationSummary {
    param(
        [Parameter(Mandatory=$true)]
        [array]$Data
    )

    $groupedResults = $Data | Group-Object -Property Iteration | Sort-Object Name

    foreach ($group in $groupedResults) {
        Write-Host "===== Iteration $($group.Name) Summary =====" -ForegroundColor Cyan
        $candidates = $group.Group | Select-Object CandidateIndex, DetectionResult, FpCount
        Print-FormattedTable -Data $candidates
        Write-Host ""
    }
}

# Block network traffic
Write-Host "Block all external traffic to safely execute files and acquire logs`n" -ForegroundColor Green
New-NetFirewallRule -DisplayName "Block Internet" -Direction Outbound -Action Block -Enabled True -Profile Any | Out-Null

$detectionFieldsFile = ".\config\detection_fields.txt"
if (Test-Path $detectionFieldsFile) {
    $detectionFields = Get-Content -Path $detectionFieldsFile
} else {
    Write-Output "detection_fields.txt not found. Exiting script."
    exit
}

# Remove all files in the logs folder before execution
$logDir = "logs"
if (Test-Path $logDir) {
    Remove-Item "$logDir\*" -Force -Recurse
    # Write-Output "All files in '$logDir' have been removed."
} else {
    New-Item -ItemType Directory -Path $logDir | Out-Null
    Write-Output "Directory '$logDir' created."
}

# Prompt the user for execution environment (ps for PowerShell, cmd for CMD) and the command to execute
$envChoice = Read-Host "Choose execution environment (ps for PowerShell, cmd for CMD)"
$command = Read-Host "Enter the command to execute"
$commandCount = 1

if ($envChoice -eq "ps") {
    $startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"$command`"" -Wait

    if ($IsObfuscation -eq $true) {
        foreach ($obsCmd in $ObfuscateCommand) {
            Write-Output "Executing obfuscated command in PowerShell process: $obsCmd"
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"$obsCmd`"" -Wait
            $commandCount++
        }
    }
} elseif ($envChoice -eq "cmd") {
    $startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$command`"" -Wait

    try {
        $ObfuscateCommand = Invoke-ArgFuscator -Command $command -n 1
        $IsObfuscation = $true
    } catch {
        # Write-Error "Error in Invoke-ArgFuscator: $_"
        $ObfuscateCommand = ""
        $IsObfuscation = $false
    }
    if ($IsObfuscation -eq $true) {
        foreach ($obsCmd in $ObfuscateCommand) {
            Write-Output "Executing obfuscated command in CMD process: $obsCmd"
            Start-Process -FilePath "cmd.exe" -ArgumentList "/c `"$obsCmd`"" -Wait
            $commandCount++
        }
    }
} else {
    $startTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"$command`"" -Wait

    if ($IsObfuscation -eq $true) {
        foreach ($obsCmd in $ObfuscateCommand) {
            Write-Output "Executing obfuscated command in PowerShell process: $obsCmd"
            Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile", "-Command", "`"$obsCmd`"" -Wait
            $commandCount++
        }
    }
}

Start-Sleep -Seconds 2

$endTime = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
Write-Host "Start time: $startTime, End time: $endTime`n" -ForegroundColor Green

if ($envChoice -eq "cmd") {
    $defaultLogSources = @('Application', 'Security', 'System', 'Microsoft-Windows-Sysmon/Operational')
} else {
    $defaultLogSources = @('Application', 'Security', 'System', 'Microsoft-Windows-Sysmon/Operational', 'Windows Powershell')
}

Write-Host "Select the log sources to use:" -ForegroundColor Cyan
for ($i = 0; $i -lt $defaultLogSources.Count; $i++) {
    Write-Host "$($i+1). $($defaultLogSources[$i])"
}

$logSourcePrompt = "`nEnter the numbers corresponding to the log sources you want to use, separated by commas (Press Enter for all):"
$inputNumbers = Read-Host $logSourcePrompt

if ($inputNumbers -and $inputNumbers.Trim() -ne "") {
    $numbers = $inputNumbers -split "\s*,\s*" | ForEach-Object { [int]$_ }
    $logSources = @()
    foreach ($num in $numbers) {
        if ($num -ge 1 -and $num -le $defaultLogSources.Count) {
            $logSources += $defaultLogSources[$num - 1]
        }
    }
    if ($logSources.Count -eq 0) {
        $logSources = $defaultLogSources
    }
} else {
    $logSources = $defaultLogSources
}

Write-Host "Using log sources: $($logSources -join ', ')`n" -ForegroundColor Yellow


if (!(Test-Path $logDir)) {
    New-Item -ItemType Directory -Path $logDir | Out-Null
}

$combinedXml = @{}  # Hashtable to store logs (XML strings) for each log source

foreach ($logName in $logSources) {
    try {

        $sanitizedLogName = $logName -replace '[\\/]', '_'
        $evtxPath = "$logDir\$sanitizedLogName.evtx"
        # Export EVTX using wevtutil
        wevtutil epl $logName $evtxPath 2> $null
        
        $events = Get-WinEvent -FilterHashtable @{
            LogName   = $logName;
            StartTime = $startTime;
            EndTime   = $endTime
        } -ErrorAction Stop

        if ($events) {
            $logEntries = @()  # Store logs for each log source
            $powershellCount = 0

            foreach ($event in $events) {
                $xml = $event.ToXml()
                # Write-Host "$xml"
                
                # Exclude logs containing "powershell" in cmd environment
                if ($envChoice -eq "cmd" -and $xml.ToLower() -match "powershell") {
                    continue
                }

                # Limit PowerShell logs to a maximum of 5
                if ($logName -match "powershell") {
                    if ($powershellCount -ge 5) { continue }
                    $powershellCount++
                }

                $logEntries += $xml
            }
            if ($logEntries.Count -gt 0) {
                $combinedXml[$logName] = $logEntries
            }
        }
    } catch {
        Write-Output "Error retrieving logs from '$logName': $_"
    }
}

foreach ($logName in $combinedXml.Keys) {
    $finalLog += "### $logName Log ###`n"
    # Index variable to count log entries
    $logIndex = 1
    foreach ($xmlString in $combinedXml[$logName]) {
        try {
            $xmlDoc = [xml]$xmlString
        } catch {
            $finalLog += "  [XML parse error]`n"
            continue
        }

        # Check if conhost.exe is present in the log
        $containsConhost = $false

        # Check System node elements
        if ($xmlDoc.Event.System) {
            foreach ($node in $xmlDoc.Event.System.ChildNodes) {
                if ($node.InnerText -match "conhost.exe") {
                    $containsConhost = $true
                    break
                }
            }
        }

        # Check EventData node elements
        if ($xmlDoc.Event.EventData -and -not $containsConhost) {
            foreach ($dataNode in $xmlDoc.Event.EventData.Data) {
                if ($dataNode.'#text' -match "conhost.exe") {
                    $containsConhost = $true
                    break
                }
            }
        }

        # If conhost.exe is found, skip this log entry
        if ($containsConhost) {
            continue
        }

        # Append log if conhost.exe is NOT found
        $finalLog += "#### log $logIndex ####`n"
        $logIndex++

        # Append System node elements
        if ($xmlDoc.Event.System) {
            foreach ($node in $xmlDoc.Event.System.ChildNodes) {
                $key = $node.Name
                if ($baseKeysList -contains $key) {
                    $value = $node.InnerText
                    $finalLog += "${key}: $value`n"
                }
            }
        }

        # Append EventData node elements
        if ($xmlDoc.Event.EventData) {
            foreach ($dataNode in $xmlDoc.Event.EventData.Data) {
                $key = $dataNode.Name
                if ($detectionFields -contains $key) {
                    $value = $dataNode.'#text'
                    $finalLog += "${key}: $value`n"
                }
            }
        }
        $finalLog += "`n"
    }
    $finalLog += "`n"
}

# Append unrelated logs to final_log
$finalLog += "`n" + $unrelatedLogs

# Save to file
$finalLog | Out-File -FilePath "final_log.txt" -Encoding utf8
Write-Output "The logs, including unrelated logs, have been saved to final_log.txt."

$startTime = "`"$startTime +09:00`""
$endTime = "`"$endTime +09:00`""


$aggregatedCandidateResults = @()  
$allIterationResults = @()         
$currentIteration = 1
$maxIterations = 3
$coverage = 0

Write-Host "Turn on Internet access to use LLM`n" -ForegroundColor Green
Remove-NetFirewallRule -DisplayName "Block Internet" | Out-Null
Start-Sleep -Seconds 3

while (($currentIteration -le $maxIterations) -and ($coverage -le 100)) {
    if ($currentIteration -eq 1) {
        Write-Host "`nGenerating Sigma Rule (Iteration $currentIteration) ...`n" -ForegroundColor Green
        $sigmaOutput = New-SigmaRule -evtxLog $finalLog
    }
    else {
        $confirmation = Read-Host "Generate new Sigma Rule based on previous rules? (y/n)"
        Write-Host "`nGenerating Sigma Rule (Iteration $currentIteration) ...`n" -ForegroundColor Green
        
        if ($confirmation -eq "n") {
            Write-Host "Exiting iteration loop." -ForegroundColor Yellow
            break
        }
        
        if (Test-Path "detection_result.txt") {
            $testTxtContent = Get-Content -Path "detection_result.txt" -Raw
        }
        else {
            $testTxtContent = ""
        }

        $candidateSummaryText = Generate-CandidateSummary -CandidateResults $aggregatedCandidateResults
        
        $finalLog += "`n`n### Old Sigma Rules and Detection Summaries ###`n`n" + $candidateSummaryText

        $sigmaOutput = New-SigmaRule -evtxLog $finalLog -Iteration $currentIteration
    }
    
    $sigmaCandidates = Extract-SigmaRules -SigmaOutput $sigmaOutput
    
    $candidateIndex = 1
    foreach ($candidate in $sigmaCandidates) {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $outputFile = ".\rules\generate_rules\generated_sigmarule_${timestamp}_$candidateIndex.yml"
        $candidate | Out-File -Encoding utf8 $outputFile

        Write-Output "============= Sigma Rule ================="
        Write-Output ""
        Write-Output "$candidate"
        Write-Output ""
        Write-Output "=========================================="
        Write-Output "Executing Sigma rule test for $outputFile`n"

        $sigma_test_result = Invoke-SigmaRuleTests -RulesPath ".\rules\generate_rules" -SpecificFile "$outputFile"
        
        $confirmationHayabusa = Read-Host "Execute Hayabusa with this Sigma rule? (y/n)"
        $candidateDetectionResult = ""

        if (($sigma_test_result -eq $true) -and ($confirmationHayabusa -eq "y")) {
            $hayabusaPath = ".\hayabusa.exe"
            $arguments = @(
                "csv-timeline",
                "--no-wizard",
                "--timeline-start", $startTime,
                "--timeline-end", $endTime,
                "--enable-all-rules",
                "--rules", $outputFile,
                "--directory", ".\logs\",
                "--clobber",
                "--output", "detection_result.txt"
            )
            try {
                Write-Host "Executing: $hayabusaPath $($arguments -join ' ')`n" -ForegroundColor Blue
                $hayabusaOutput = & $hayabusaPath $arguments 2>&1
                $ansiPattern = "(\x1B\[[0-9;]*[A-Za-z])"
                $cleanOutput = $hayabusaOutput -replace $ansiPattern, ""
                $lines = $cleanOutput -split "`n"
                $patternLine = "(?i)Events\s+with\s+hits\s*/\s*Total\s+events:"
                $targetLine = $lines | Where-Object { $_ -imatch $patternLine }
                if ($targetLine) {
                    if ($targetLine -imatch "(?i)Events\s+with\s+hits\s*/\s*Total\s+events:\s*(\d+)\s*/") {
                        $hits = $matches[1]
                        if ($hits -eq 0) {
                            Write-Host "No event hits." -ForegroundColor Red
                        } else {
                            Write-Host "Events with hits: $hits" -ForegroundColor Green
                        }
                        $coverage = [math]::Floor($hits / ($commandCount * 2.5) * 100)
                        # Write-Host "Coverage is $coverage%`n" -ForegroundColor Green
                        $candidateDetectionResult = "Hits: $hits"
                    }
                    else {
                        Write-Host "Failed to extract hits value from target line." -ForegroundColor Red
                        $candidateDetectionResult = "Detection failed"
                    }
                }
                else {
                    Write-Host "Target line with 'Events with hits / Total events:' not found." -ForegroundColor Red
                    $candidateDetectionResult = "Detection failed"
                    $coverage = "0"
                }
            } catch {
                Write-Host "Error: Failed to execute $hayabusaPath" -ForegroundColor Red
                Write-Host $_.Exception.Message
                $candidateDetectionResult = "Detection failed"
                $coverage = "0"
            }
        }
        else {
            Write-Host "Tests failed or hayabusa execution skipped for $outputFile." -ForegroundColor Yellow
            $candidateDetectionResult = "Test failed / Skipped for Syntax Error"
            $coverage = "0"
        }

        # check FP count for .\benign_evtx_logs\*
        $confirmationCheckFP = Read-Host "Check how much FP is generated by the rules you create? (y/n)"

        if ($confirmationCheckFP -eq "y") {
            $hayabusaPath = ".\hayabusa.exe"
            $arguments = @(
                "csv-timeline",
                "--no-wizard",
                "--enable-all-rules",
                "--rules", $outputFile,
                "--directory", ".\benign_evtx_logs\",
                "--clobber",
                "--output", "fp_check_result.txt"
            )
            try {
                Write-Host "Executing: $hayabusaPath $($arguments -join ' ')`n" -ForegroundColor Blue
                $hayabusaOutput = & $hayabusaPath $arguments 2>&1
                $ansiPattern = "(\x1B\[[0-9;]*[A-Za-z])"
                $cleanOutput = $hayabusaOutput -replace $ansiPattern, ""
                $lines = $cleanOutput -split "`n"
                $patternLine = "(?i)Events\s+with\s+hits\s*/\s*Total\s+events:"
                $targetLine = $lines | Where-Object { $_ -imatch $patternLine }
                if ($targetLine) {
                    if ($targetLine -imatch "(?i)Events\s+with\s+hits\s*/\s*Total\s+events:\s*(\d+)\s*/") {
                        $hits = $matches[1]
                        if ($hits -eq 0) {
                            Write-Host "No event hits." -ForegroundColor Green
                        } else {
                            Write-Host "The number of FP: $hits" -ForegroundColor Red
                        }
                        $fpCount = "The number of FP: $hits"
                    }
                    else {
                        Write-Host "Failed to extract hits value from target line." -ForegroundColor Red
                        $candidateDetectionResult = "Detection failed"
                    }
                }
                else {
                    Write-Host "Target line with 'Events with hits / Total events:' not found." -ForegroundColor Red
                    $candidateDetectionResult = "Detection failed"
                    $coverage = "0"
                }
            } catch {
                Write-Host "Error: Failed to execute $hayabusaPath" -ForegroundColor Red
                Write-Host $_.Exception.Message
            }
        }


        $candidateResult = [PSCustomObject]@{
            Iteration       = $currentIteration
            CandidateIndex  = $candidateIndex
            RuleText        = $candidate
            DetectionResult = $candidateDetectionResult
            Coverage        = "$coverage%"
            FpCount         = $fpCount
        }
        $aggregatedCandidateResults += $candidateResult
        $allIterationResults += $candidateResult

        $candidateIndex++
    }

    Print-IterationSummary -Data ($aggregatedCandidateResults | Select-Object Iteration, CandidateIndex, DetectionResult, FpCount)
    Write-Host "`n"

    $currentIteration++
}