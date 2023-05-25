# Standard configurations

$AzureEnvironmentToADAuthUrlMap = @{
    "AzureCloud" = "https://login.microsoftonline.com";
    "AzureGovernmentCloud" = "https://login.microsoftonline.us";
}

$AzureEnvironmentToKuduConsoleUrlMap = @{
    "AzureCloud" = "https://{0}.scm.azurewebsites.net";
    "AzureGovernmentCloud" = "https://{0}.scm.azurewebsites.us";
}

function GetAuthHeader {
        [psobject] $headers = $null
        try 
        {
            $resourceAppIdUri = "https://management.azure.com/"
            $rmContext = Get-AzContext
            $authResult = [Microsoft.Azure.Commands.Common.Authentication.AzureSession]::Instance.AuthenticationFactory.Authenticate(
            $rmContext.Account,
            $rmContext.Environment,
            $rmContext.Tenant,
            [System.Security.SecureString] $null,
            "Never",
            $null,
            $resourceAppIdUri); 

            $header = "Bearer " + $authResult.AccessToken
            $headers = @{"Authorization"=$header; 'If-Match'='*';}
        }
        catch 
        {
            Write-Host "Error occurred while fetching auth header. ErrorMessage [$($_)]" -ForegroundColor $([Constants]::MessageType.Error)   
        }

        return($headers)
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
    $userAgent = "powershell/1.0"
    
    $uploadUrl = $([string]::Join("/", $([string]::Format($KuduConsoleUrl, $UIAppName)), "api/vfs/site/wwwroot", ${configFile}))
    [psobject] $headers = GetAuthHeader
    Invoke-RestMethod -Uri $uploadUrl -Headers $headers -UserAgent $userAgent -Method PUT -InFile $configFilePath -ContentType "multipart/form-data"
    
    Reset-AzWebAppPublishingProfile -Name $UIAppName -ResourceGroupName $ScanHostRGName

    # Configure Staging slot
    $webAppSlot = Get-AzWebAppSlot -ResourceGroupName $ScanHostRGName -Name $UIAppName
    if ($webAppSlot -ne $null)
    {
        # Only one staging slot is deployed as part of deployment
        $webAppSlot = $webAppSlot | Select -First 1 
        $slotName = $webAppSlot.Name.Split("/")[1]
        $slotFullName = $UIAppName + "-" + $slotName 

        $slotUploadUrl = $([string]::Join("/", $([string]::Format($KuduConsoleUrl, $slotFullName)), "api/vfs/site/wwwroot", ${configFile}))
        [psobject] $headersSlot = GetAuthHeader
        Invoke-RestMethod -Uri $slotUploadUrl -Headers $headersSlot -UserAgent $userAgent -Method PUT -InFile $configFilePath -ContentType "multipart/form-data"

        Reset-AzWebAppSlotPublishingProfile -ResourceGroupName $ScanHostRGName -Name $UIAppName -Slot $slotName
    }
    
    If((test-path $configFilePath))
    {
        Remove-Item -Force -Path $configFilePath
    }
}