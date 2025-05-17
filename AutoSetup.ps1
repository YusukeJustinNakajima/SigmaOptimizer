# ====== Configuration Section ======
# Set OpenAI API Key as an environment variable (modify if needed)
$env:OPENAI_APIKEY = "your_api_key_here"

# Required PowerShell modules
$requiredModules = @("Pester", "powershell-yaml", "Invoke-ArgFuscator")

# GitHub repository information
$downloadUrl = "https://github.com/Yamato-Security/hayabusa/releases/download/v3.1.0/hayabusa-3.1.0-win-x64.zip"
$zipFile = "hayabusa-3.1.0-win-x64.zip"
$extractPath = "hayabusa-3.1.0"

# Tar file to extract
$tarFile = "benign_evtx_logs/win10-client.tgz"
$tarExtractPath = "benign_evtx_logs/"

# ====== Install Required Modules ======
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Output "Installing module: $module"
        if ($module -eq "Pester") {
            Install-Module -Name "Pester" -RequiredVersion "5.7.1" -Force -AllowClobber -SkipPublisherCheck
        } else {
            Install-Module -Name $module -Force -SkipPublisherCheck
        }
    } else {
        Write-Output "Module already installed: $module"
    }
}

# ====== Download the Latest Hayabusa ZIP ======
if ($downloadUrl) {
    Write-Output "Downloading from: $downloadUrl"

    # Download ZIP file
    Invoke-WebRequest -Uri $downloadUrl -OutFile $zipFile

    # Remove existing folder (cleanup)
    if (Test-Path $extractPath) {
        Remove-Item -Recurse -Force $extractPath
    }

    # Extract ZIP
    Expand-Archive -Path $zipFile -DestinationPath $extractPath -Force

    # Find the `.exe` file
    $exeFile = Get-ChildItem -Path $extractPath -Filter "*.exe" -File -Recurse | Select-Object -First 1

    if ($exeFile) {
        # Copy to the current directory as "hayabusa.exe"
        $destinationPath = ".\hayabusa.exe"
        Copy-Item -Path $exeFile.FullName -Destination $destinationPath -Force
        Write-Output "Copied: $($exeFile.Name) to $destinationPath"
    } else {
        Write-Output "No .exe files found in the extracted folder."
    }

    # Cleanup (delete ZIP file)
    Remove-Item $zipFile -Force
} else {
    Write-Output "Download URL not found."
}

# ====== Extract benign_evtx_logs/win10-client.tgz ======
if (Test-Path $tarFile) {
    Write-Output "Extracting $tarFile to $tarExtractPath"

    # Extract using tar
    tar -xvzf $tarFile -C $tarExtractPath

    Write-Output "Extraction completed."
} else {
    Write-Output "Tar file $tarFile not found."
}
