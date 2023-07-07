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

$SubscriptionId = "15d91b70-4875-4f81-a720-1f34be240eb5"
$ResourceGroupName = "DataReadiness-Production"
$AppServiceName = "pecodrapi"
$SlotName = "pecodrapi-uat"

Write-Debug -Debug:$debug -Message "Get current App Service FTP State for production and any non-production slots"
Get-AppServiceFtpState `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $ResourceGroupName `
  -AppServiceName $AppServiceName

Write-Debug -Debug:$debug -Message "Set FTP State for non-production slot to Disabled"
Set-AppServiceFtpState `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $ResourceGroupName `
  -AppServiceName $AppServiceName `
  -SlotName $SlotName `
  -FtpState "Disabled"

Write-Debug -Debug:$debug -Message "Get updated App Service FTP State for production and any non-production slots"
Get-AppServiceFtpState `
  -SubscriptionId $SubscriptionId `
  -ResourceGroupName $ResourceGroupName `
  -AppServiceName $AppServiceName
