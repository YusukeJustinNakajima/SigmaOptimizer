# OpenAISigmaModule.psm1

# OpenAI API settings
$script:apiUrl = "https://api.openai.com/v1/chat/completions"
$script:apiKey = $env:OPENAI_APIKEY
$script:headers = @{
    "Content-Type"  = "application/json"
    "Authorization" = "Bearer $script:apiKey"
}

$script:llmRole_iteration_first = Get-Content -Path ".\prompts\prompt_for_first_generation.txt" -Raw
$script:llmRole_iteration_after_second = Get-Content -Path ".\prompts\prompt_for_after_second_generation.txt" -Raw
$script:expected_output = Get-Content -Path ".\prompts\expected_outputs.txt" -Raw
$script:unexpected_output = Get-Content -Path ".\prompts\unexpected_outputs.txt" -Raw

$script:llmRole_iteration_first = $script:llmRole_iteration_first + $script:expected_output + $script:unexpected_output
$script:llmRole_iteration_after_second = $script:llmRole_iteration_after_second + $script:expected_output + $script:unexpected_output

function Invoke-OpenAIRequest {
    param (
        [string]$model,
        [string]$roleContent,
        [string]$userContent
    )

    if ([string]::IsNullOrWhiteSpace($roleContent) -or [string]::IsNullOrWhiteSpace($userContent)) {
        Write-Output "Error: One or more input parameters are null or empty."
        return $null
    }

    if ($model -eq "gpt-4o") {
        $body = @{
            model = $model
            messages = @(
                @{ role = "system"; content = $roleContent }
                @{ role = "user"; content = $userContent }
            )
        } | ConvertTo-Json -Depth 10
    } elseif ($model -eq "o1-mini") {
        $combinedContent = "$roleContent`n`n"
        $combinedContent += "$userContent`n`n"
        $body = @{
            model = $model
            messages = @(
                @{ role = "user"; content = $combinedContent }
            )
        } | ConvertTo-Json -Depth 10
    } else {
        $combinedContent = "$roleContent`n`n"
        $combinedContent += "$userContent`n`n"
        $body = @{
            model = $model
            messages = @(
                @{ role = "developer"; content = $combinedContent }
            )
        } | ConvertTo-Json -Depth 10
    }
    
    try {
        $response = Invoke-RestMethod -Uri $script:apiUrl -Headers $script:headers -Method Post -Body $body
        return $response.choices[0].message.content
    }
    catch {
        Write-Output "API Request Error: $_"
        return $null
    }
}

function New-SigmaRule { 
    param ( 
        [string]$evtxLog,
        [int]$Iteration = 1  # Default to 1 if not provided
    ) 

    # Check if $evtxLog is valid
    if ([string]::IsNullOrWhiteSpace($evtxLog)) { 
        Write-Output "Error: No valid logs found for Sigma rule generation." 
        return $null 
    } 

    # Use a different role prompt for iterations greater than 1
    if ($Iteration -gt 1) {
        $roleContentToUse = $script:llmRole_iteration_after_second
    }
    else {
        $roleContentToUse = $script:llmRole_iteration_first
    }

    $sigmaRule = Invoke-OpenAIRequest -model "o1-mini" -roleContent $roleContentToUse -userContent $evtxLog

    if ($sigmaRule) { 
        return $sigmaRule 
    } 
    else { 
        Write-Output "Failed to generate Sigma Rule." 
        return $null 
    } 
}

Export-ModuleMember -Function Invoke-OpenAIRequest, New-SigmaRule