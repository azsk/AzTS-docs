# Standard configurations

$AzureEnvironmentToADAuthUrlMap = @{
    "AzureCloud" = "https://login.microsoftonline.com";
    "AzureGovernmentCloud" = "https://login.microsoftonline.us";
}

$AzureEnvironmentToKuduConsoleUrlMap = @{
    "AzureCloud" = "https://{0}.scm.azurewebsites.net";
    "AzureGovernmentCloud" = "https://{0}.scm.azurewebsites.us";
}

function Configure-WebUI
{
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage="TenantID of the subscription where Azure Tenant Security Solution is to be installed.")]
        $TenantId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Name of the Resource Group where setup resources will be created.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="Name of the web app deployed in azure for Azure Tenant Security Solution.")]
        $UIAppName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="URL of the Web API")]
        $ApiUrl,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="ClientId of the web app deployed in azure for Azure Tenant Security Solution.")]
        $UIClientId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage="ClientId of the web api deployed in azure for Azure Tenant Security Solution.")]
        $WebApiClientId,

	[string]
        [Parameter(Mandatory = $true, HelpMessage="Azure environment in which Azure Tenant Security Solution needs to be installed. The acceptable values for this parameter are: AzureCloud, AzureGovernmentCloud")]
        [ValidateSet("AzureCloud", "AzureGovernmentCloud")]
        $AzureEnvironmentName
    )

    $AzureADAuthUrl = $AzureEnvironmentToADAuthUrlMap.$AzureEnvironmentName
    $KuduConsoleUrl = $AzureEnvironmentToKuduConsoleUrlMap.$AzureEnvironmentName
    
    Write-Host "Configuring AzTS UI for $AzureEnvironmentName..."
    
    $baseDir = Get-Location
    $configFile = "runtime-configuration-initial.js"
    $configFilePath = "${baseDir}\${configFile}"
    $configJs = @"
window.__UI_CONFIGURATION_INITIAL__ = {
    "tenantId": "$TenantId",
    "webAPI": "$ApiUrl",
    "clientId": "$UIClientId",
    "apiClientId": "$WebApiClientId",
    "azureADAuthURL": "$AzureADAuthUrl"
};

window.__UI_CONFIGURATION_EXTENDED__ = {};
"@

    $configJs | Set-Content $configFilePath

    $webApp = Get-AzWebApp -Name $UIAppName -ResourceGroupName $ScanHostRGName
    [xml]$publishingProfile = Get-AzWebAppPublishingProfile -WebApp $webApp
    $username = $publishingProfile.publishData.publishProfile[0].userName
    $password = $publishingProfile.publishData.publishProfile[0].userPWD
    $base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username, $password)))
    $userAgent = "powershell/1.0"
    
    $uploadUrl = $([string]::Join("/", $([string]::Format($KuduConsoleUrl, $UIAppName)), "api/vfs/site/wwwroot", ${configFile}))

    Invoke-RestMethod -Uri $uploadUrl -Headers @{Authorization=("Basic {0}" -f $base64AuthInfo); 'If-Match'='*'} -UserAgent $userAgent -Method PUT -InFile $configFilePath -ContentType "multipart/form-data"

    Reset-AzWebAppPublishingProfile -Name $UIAppName -ResourceGroupName $ScanHostRGName
    
    If((test-path $configFilePath))
    {
        Remove-Item -Force -Path $configFilePath
    }
}