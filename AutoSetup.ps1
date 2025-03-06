# ====== Configuration Section ======
# Set OpenAI API Key as an environment variable (modify if needed)
$env:OPENAI_APIKEY = "your_api_key_here"

# Required PowerShell modules
$requiredModules = @("Pester", "powershell-yaml", "Invoke-ArgFuscator")

# GitHub repository information
$repo = "Yamato-Security/hayabusa"
$apiUrl = "https://api.github.com/repos/$repo/releases/latest"
$zipFile = "hayabusa-latest.zip"
$extractPath = "hayabusa-latest"

# Tar file to extract
$tarFile = "benign_evtx_logs/win10-client.tgz"
$tarExtractPath = "benign_evtx_logs/"

# ====== Install Required Modules ======
foreach ($module in $requiredModules) {
    if (-not (Get-Module -ListAvailable -Name $module)) {
        Write-Output "Installing module: $module"
        Install-Module -Name $module -Force -SkipPublisherCheck
    } else {
        Write-Output "Module already installed: $module"
    }
}

# ====== Download the Latest Hayabusa ZIP ======
$response = Invoke-RestMethod -Uri $apiUrl -Headers @{"Accept"="application/vnd.github.v3+json"}

# Retrieve the download URL for the latest ZIP file
$downloadUrl = $response.assets | Where-Object { $_.name -match "win-x64.zip" } | Select-Object -ExpandProperty browser_download_url

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
