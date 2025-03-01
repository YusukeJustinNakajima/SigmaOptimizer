# SigmaRuleTests.psm1
<#
.SYNOPSIS
    Module for Sigma Rule YAML file tests using Pester.
.DESCRIPTION
    This module provides functions to retrieve and parse Sigma rule YAML files from the "rules" folder.
    It also defines Pester tests for the following:
      - Forbidden trademark checks.
      - 'title' が最初のキーであることの確認。
      - オプションの 'license' フィールドが文字列であることの検証。
      - 重複する detection ロジックの存在チェック。
      - ファイル名の規約チェック.
    テスト実行は Invoke-SigmaRuleTests 関数で行います。
    ※特定ファイルのみテストする場合は、-SpecificFile パラメーターにファイルパスを指定してください。
#>

Import-Module Pester -ErrorAction SilentlyContinue
Import-Module powershell-yaml -ErrorAction SilentlyContinue

# ルールファイルを取得する関数
function Get-RuleFiles {
    [CmdletBinding()]
    param (
        [string]$RulesPath = ".\rules",
        [string]$SpecificFile
    )
    if ($SpecificFile) {
        # $SpecificFile が絶対パスでなければ、$PSScriptRoot と組み合わせる
        if (-not ([System.IO.Path]::IsPathRooted($SpecificFile))) {
            $SpecificFile = Join-Path $PSScriptRoot $SpecificFile
        }
        if (Test-Path $SpecificFile) {
            $files = @(Get-Item -Path $SpecificFile | Select-Object -ExpandProperty FullName)
            # Write-Host "[DEBUG] Specified file '$($SpecificFile)' found."
        }
        else {
            Write-Host "[DEBUG] Specified file '$($SpecificFile)' not found."
            $files = @()
        }
    }
    else {
        $files = Get-ChildItem -Path $RulesPath -Filter *.yml -Recurse | Select-Object -ExpandProperty FullName
    }
    # Write-Host "[DEBUG] Found $($files.Count) YAML file(s)."
    return $files
}

# 指定ファイルの内容を取得する関数（UTF-8 BOM 対応）
function Get-RuleContent {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    $bytes = [System.IO.File]::ReadAllBytes($FilePath)
    $content = [System.Text.Encoding]::UTF8.GetString($bytes)
    return $content
}

# YAMLテキストを OrderedDictionary に変換する関数
function Get-YamlObject {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    $yamlText = Get-RuleContent -FilePath $FilePath
    try {
        $yamlObj = ConvertFrom-Yaml $yamlText
        $orderedYaml = [System.Collections.Specialized.OrderedDictionary]::new()
        foreach ($key in $yamlObj.Keys) {
            $orderedYaml[$key] = $yamlObj[$key]
        }
        return $orderedYaml
    }
    catch {
        Write-Host -ForegroundColor Red "[ERROR] Failed to parse YAML for file: $FilePath"
        return $null
    }
}

# OrderedDictionaryまたはハッシュテーブルの最初のキーを取得する関数
function Get-FirstKey {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]
        [hashtable]$Hashtable
    )
    if ($Hashtable -is [System.Collections.Specialized.OrderedDictionary] -and $Hashtable.Count -gt 0) {
        return $Hashtable.Keys[0]
    }
    elseif ($Hashtable -and $Hashtable.Count -gt 0) {
        return ($Hashtable.Keys | Select-Object -First 1)
    }
    return $null
}

function Get-FirstKeyFromFile {
    param(
        [Parameter(Mandatory)]
        [string]$FilePath
    )
    $lines = Get-Content -Path $FilePath -Encoding utf8
    foreach ($line in $lines) {
        # 空行やコメント行（# で始まる行）はスキップ
        if ($line.Trim() -eq "" -or $line.Trim().StartsWith("#")) {
            continue
        }
        # "キー:" の形式を探す（スペースの扱いに注意）
        if ($line -match '^\s*([^:\s]+)\s*:') {
            return $matches[1]
        }
    }
    return $null
}


# Pester テストを実行する関数
function Invoke-SigmaRuleTests {
    [CmdletBinding()]
    param (
        [string]$RulesPath = ".\rules",
        [string]$SpecificFile = ""
    )

    # SpecificFile が相対パスの場合、絶対パスに変換
    if ($SpecificFile -and -not ([System.IO.Path]::IsPathRooted($SpecificFile))) {
        $SpecificFile = Join-Path $PSScriptRoot $SpecificFile
    }

    # Pester テストスクリプトのテンプレート
    $testScriptTemplate = @"
Describe 'Sigma Rule Tests' {

    Context 'Trademark Compliance' {
        It 'should not contain forbidden trademarks' {
            `$files = Get-RuleFiles -RulesPath "$RulesPath" -SpecificFile "$SpecificFile"
            `$violatingFiles = @()
            foreach (`$file in `$files) {
                `$content = Get-RuleContent -FilePath `$file
                foreach (`$tm in @('MITRE ATT&CK', 'ATT&CK')) {
                    if (`$content -match [regex]::Escape(`$tm)) {
                        Write-Host -ForegroundColor Yellow "File $($file) contains trademark $($tm)"
                        `$violatingFiles += `$file
                        break
                    }
                }
            }
            (`$violatingFiles.Count) | Should -BeExactly 0 -Because "No rule file should contain forbidden trademark references."
        }
    }

    Context 'Title in First Line' {
        It 'should have "title" as the first key in the YAML file' {
            `$files = Get-RuleFiles -RulesPath "$RulesPath" -SpecificFile "$SpecificFile"
            `$faultyFiles = @()
            foreach (`$file in `$files) {
                `$firstKey = Get-FirstKeyFromFile -FilePath `$file
                if (`$firstKey -ne "title") {
                    Write-Host -ForegroundColor Yellow "File $($file): first key is '$($firstKey)' (expected 'title')."
                    `$faultyFiles += `$file
                }
            }
            (`$faultyFiles.Count) | Should -BeExactly 0 -Because "Every rule file should have 'title' as the first key."
        }
    }


    Context 'Optional License Field' {
        It 'should have license as a string if present' {
            `$files = Get-RuleFiles -RulesPath "$RulesPath" -SpecificFile "$SpecificFile"
            `$faultyFiles = @()
            foreach (`$file in `$files) {
                `$yamlObj = Get-YamlObject -FilePath `$file
                if (`$yamlObj -is [hashtable] -and `$yamlObj.ContainsKey("license")) {
                    if (-not (`$yamlObj.license -is [string])) {
                        Write-Host -ForegroundColor Yellow "File $($file) has a malformed license field."
                        `$faultyFiles += `$file
                    }
                }
            }
            (`$faultyFiles.Count) | Should -BeExactly 0 -Because "License field must be a string if present."
        }
    }

    Context 'Duplicate Detections' {
        It 'should not have duplicate detection logic among rule files' {
            `$files = Get-RuleFiles -RulesPath "$RulesPath" -SpecificFile "$SpecificFile"
            `$detections = @{}
            `$duplicateFiles = @()
            foreach (`$file in `$files) {
                `$yamlObj = Get-YamlObject -FilePath `$file
                if (`$yamlObj -is [hashtable] -and `$yamlObj.ContainsKey("detection")) {
                    `$detJson = `$yamlObj.detection | ConvertTo-Json -Depth 10
                    foreach (`$key in `$detections.Keys) {
                        if (`$detections[`$key] -eq `$detJson) {
                            Write-Host -ForegroundColor Yellow "Duplicate detection logic found in $($file) and $($key)"
                            `$duplicateFiles += `$file
                            break
                        }
                    }
                    if (-not (`$duplicateFiles -contains `$file)) {
                        `$detections[`$file] = `$detJson
                    }
                }
            }
            (`$duplicateFiles.Count) | Should -BeExactly 0 -Because "There should be no duplicate detection logic among rule files."
        }
    }

    Context "File Name Tests" {
        It "should have valid file names and logsource fields" {
            `$faultyRules = @()
            `$nameHash = @{}
            `$filenamePattern = '^[a-z0-9_]{10,90}\.yml$'
            `$files = Get-RuleFiles -RulesPath "$RulesPath" -SpecificFile "$SpecificFile"
            foreach (`$file in `$files) {
                `$filename = [System.IO.Path]::GetFileName(`$file)
                `$yamlObj = Get-YamlObject -FilePath `$file

                # ファイル名の重複チェック
                if (`$nameHash.ContainsKey(`$filename)) {
                    Write-Host -ForegroundColor Yellow "File $($file) is a duplicate file name."
                    `$faultyRules += `$file
                }
                else {
                    `$nameHash[`$filename] = `$true
                }

                # 拡張子のチェック
                if (-not `$filename.EndsWith(".yml")) {
                    Write-Host -ForegroundColor Yellow "File $($file) has an invalid extension (expected .yml)."
                    `$faultyRules += `$file
                }

                # ファイル名の長さチェック
                `$len = `$filename.Length
                if (`$len -gt 90) {
                    Write-Host -ForegroundColor Yellow "File $($file) has a file name too long (>90 characters)."
                    `$faultyRules += `$file
                }
                elseif (`$len -lt 14) {
                    Write-Host -ForegroundColor Yellow "File $($file) has a file name too short (<14 characters)."
                    `$faultyRules += `$file
                }

                # 正規表現とアンダースコアが含まれているかのチェック
                if (`$filename -notmatch `$filenamePattern -or `$filename -notmatch "_") {
                    Write-Host -ForegroundColor Yellow "File $($file) has a file name that doesn't match our standard."
                    `$faultyRules += `$file
                }

                # logsource の検証
                `$logsource = `$yamlObj.logsource
                if (`$logsource) {
                    `$validProducts = @("windows", "macos", "linux", "aws", "azure", "gcp", "m365", "okta", "onelogin", "github")
                    `$validCategories = @("process_creation", "image_load", "file_event", "registry_set", "registry_add", "registry_event",
                                        "registry_delete", "registry_rename", "process_access", "driver_load", "dns_query",
                                        "ps_script", "ps_module", "ps_classic_start", "pipe_created", "network_connection",
                                        "file_rename", "file_delete", "file_change", "file_access", "create_stream_hash",
                                        "create_remote_thread", "dns", "firewall", "webserver")
                    `$validServices = @("auditd", "modsecurity", "diagnosis-scripted", "firewall-as", "msexchange-management",
                                    "security", "system", "taskscheduler", "terminalservices-localsessionmanager", "windefend",
                                    "wmi", "codeintegrity-operational", "bits-client", "applocker", "dns-server-analytic",
                                    "bitlocker", "capi2", "certificateservicesclient-lifecycle-system", "pim")
                    foreach (`$key in `$logsource.Keys) {
                        `$value = `$logsource[`$key]
                        if (`$key -eq "definition") { continue }
                        if (`$key -eq "product") {
                            if (`$validProducts -notcontains `$value) {
                                Write-Host -ForegroundColor Red "[ERROR] Invalid product '$($value)' found in logsource in file $($file)!"
                                `$faultyRules += `$file
                                continue
                            }
                        }
                        if (`$key -eq "category") {
                            if (`$validCategories -notcontains `$value) {
                                Write-Host -ForegroundColor Red "[ERROR] Invalid category '$($value)' found in logsource in file $($file)!"
                                `$faultyRules += `$file
                                continue
                            }
                        }
                        if (`$key -eq "service") {
                            if (`$validServices -notcontains `$value) {
                                Write-Host -ForegroundColor Red "[ERROR] Invalid service '$($value)' found in logsource in file $($file)!"
                                `$faultyRules += `$file
                                continue
                            }
                        }
                    }
                }
                else {
                    Write-Host -ForegroundColor Yellow "File $($file) does not contain a logsource field."
                    `$faultyRules += `$file
                }
            }
            (`$faultyRules.Count) | Should -BeExactly 0 -Because "All rule file names and logsource fields must meet the naming conventions."
        }
    }
}
"@

    # 一時ファイルにテストスクリプトを書き出し、Invoke-Pester を実行
    $tempTestFile = Join-Path $env:TEMP "TempSigmaTests.ps1"
    $testScriptTemplate | Out-File -FilePath $tempTestFile -Encoding utf8

    # Pester を実行
    $testResult = Invoke-Pester -Script $tempTestFile -PassThru

    # 一時ファイル削除（使用中の場合は少し待機）
    Start-Sleep -Seconds 1
    Remove-Item $tempTestFile -Force

    if ($testResult.FailedCount -eq 0) {
        Write-Host -ForegroundColor Green "All tests passed successfully!"
        return $true
    } else {
        Write-Host -ForegroundColor Red "Some tests failed!"
        return $false
    }
}

Export-ModuleMember -Function Invoke-SigmaRuleTests
