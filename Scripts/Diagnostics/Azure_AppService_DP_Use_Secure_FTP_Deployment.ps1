$debug = $true

function Get-AppServiceFtpState()
{
  <#
    .SYNOPSIS
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .DESCRIPTION
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service to be remediated.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .INPUTS
    None
    .OUTPUTS
    Dictionary whose keys are App Service slot names, and whose values are the corresponding slot FTP settings.
    .EXAMPLE
    PS> Get-AppServiceFtpState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $AppServiceName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

  $ftpConfigs = [ordered]@{ "Production" = $appService.SiteConfig.FtpsState }

  # List of slots in Get-AzWebAppSlot has full slot name. SiteConfig is blank on those.
  # So we have to get just the bare slot name, then call Get-AzWebAppSlot for it to get the SiteConfig and FtpsState.
  ForEach ($slotNameRaw in (Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName).Name)
  {
    $slotName = $slotNameRaw.Replace($AppServiceName + "/", "")
    $slot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName -Slot $slotName
    $ftpConfigs = $ftpConfigs + @{ $slotName = $slot.SiteConfig.FtpsState }
  }

  return $ftpConfigs
}

function Set-AppServiceFtpState()
{
  <#
    .SYNOPSIS
    This command sets the FTP state for the App Service.
    .DESCRIPTION
    This command sets the FTP state for the App Service.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .PARAMETER SlotName
    If a non-production slot's FTP state is being set, provide the slot name. To set the default production slot FTP state, do not specify this parameter.
    .PARAMETER FtpState
    The FTP State to set. Either "Disabled" or "FtpsOnly". Defaults to "Disabled".
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-AppServiceFtpState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName" -SlotName "MyNonProductionSlotName" -FtpState "Disabled"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $AppServiceName,
    [Parameter(Mandatory = $false)]
    [string]
    $SlotName,
    [Parameter(Mandatory = $false)]
    [string]
    $FtpState = "Disabled"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  if ([string]::IsNullOrWhiteSpace($SlotName))
  {
    # No slot name so we're setting the app service itself
    Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName -FtpsState $FtpState
  }
  else
  {
    # Check if the slot name that was passed is prepended with the App Service Name and slash
    # Get-AzWebAppSlot returns slots in that format, but Set-AzWebAppSlot wants only the slot name without the prepended app svc name and slash
    # Mitigate possible corner case here by checking for app svc name AND slash
    if ($SlotName.StartsWith($AppServiceName + "/"))
    {
      $SlotName = $SlotName.Replace($AppServiceName + "/", "")
    }

    Write-Debug -Debug:$debug -Message "SlotName = $SlotName"
    Set-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName -Slot $SlotName -FtpsState $FtpState
  }
}
function Get-FTPAuthSetting()
{
  <#
    .SYNOPSIS
    This command shows whether FTP Basic Auth is Enabled for input resourceId
    .DESCRIPTION
    This command shows whether FTP Basic Auth is Enabled for input resourceId
    .PARAMETER ResourceId
    The Azure ResourceId for App Service
    NOTE: For App service, non-production slots, corresponding ResourceId needs to be passed to this function
    .INPUTS
    The Azure ResourceId
    .OUTPUTS
    Boolean indicating whether FTP Basic Auth is Enabled for input resourceId
    .EXAMPLE
    PS> Get-FTPAuthSetting
    .LINK
    None
  #>
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceId
  )
    $cloudEnvironmentResourceManagerUrl = (Get-AzContext).Environment.ResourceManagerUrl
    $accessToken = Get-AzAccessToken -ResourceUrl $cloudEnvironmentResourceManagerUrl
    $header = "Bearer " + $accessToken.Token
    $headers = @{"Authorization"=$header;"Content-Type"="application/json";}
    [PSObject] $fTPAuthSetting = New-Object PSObject

    $updateFTPAuthSettingsUri = "$($cloudEnvironmentResourceManagerUrl)$($ResourceId)/basicPublishingCredentialsPolicies/ftp?api-version=2022-03-01"
    $response = Invoke-WebRequest -Method Get -Uri $updateFTPAuthSettingsUri -Headers $headers -UseBasicParsing -ContentType "application/json" -ErrorAction Stop
    $fTPAuthSetting = $response.Content | ConvertFrom-Json

    $isFTPBasicAuthEnabled = $fTPAuthSetting.properties.allow

    return $isFTPBasicAuthEnabled
}

