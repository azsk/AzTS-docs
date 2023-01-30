<##########################################
Overview:
  This file contains functions to help remediate App Services FTP State insecure configurations. These functions will work equally on Web Apps or Function Apps.

ControlId: 
  Azure_AppService_DP_Use_Secure_FTP_Deployment

DisplayName:
  Remediate Azure App Service insecure FTP issues.

Pre-requisites:
  1. Authenticated to Azure
  2. At least Contributor role on App Service

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_AppService_DP_Use_Secure_FTP_Deployment.ps1```
  3. Call the functions with arguments

Examples:
  GetFtpState -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroupName "MyResourceGroup" -AppName "MyAppServiceName"
########################################
#>

function Get-FtpState()
{
  <#
    .SYNOPSIS
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .DESCRIPTION
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group containing the App Service.
    .PARAMETER AppName
    The App Service name.
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $AppName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppName

  $ftpConfigs = [ordered]@{ "Production" = $appService.SiteConfig.FtpsState }

  # List of slots in Get-AzWebAppSlot has full slot name. SiteConfig is blank on those.
  # So we have to get just the bare slot name, then call Get-AzWebAppSlot for it to get the SiteConfig and FtpsState.
  ForEach ($slotNameRaw in (Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName).Name)
  {
    $slotName = $slotNameRaw.Replace($AppName + "/", "")
    $slot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName -Slot $slotName
    $ftpConfigs = $ftpConfigs + @{ $slotName = $slot.SiteConfig.FtpsState }
  }

  return $ftpConfigs
}

function Set-FtpState()
{
  <#
    .SYNOPSIS
    This command sets the FTP state for the App Service.
    .DESCRIPTION
    This command sets the FTP state for the App Service.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group containing the App Service.
    .PARAMETER AppName
    The App Service name.
    .PARAMETER SlotName
    If a Slot FTP State is being set, provide the slot name.
    .PARAMETER FtpState
    The FTP State to set. Either "Disabled" or "FtpsOnly". Defaults to "Disabled".
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $AppName,
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
    Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppName -FtpsState $FtpState
  }
  else
  {
    if ($SlotName.StartsWith($AppName))
    {
      $SlotName = $SlotName.Replace($AppName + "/", "")
    }

    Set-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName -Slot $SlotName -FtpsState $FtpState
  }
}

function Get-AppServiceAllPossiblePublicIps()
{
  <#
  .SYNOPSIS
  This command returns a comma-delimited string of all the POSSIBLE public IPs for the App Service.
  .DESCRIPTION
  This command returns a comma-delimited string of all the POSSIBLE public IPs for the App Service. Use this command and its output to set network access rules on other services, such as Key Vault when all public access is not enabled.
  .PARAMETER SubscriptionId
  The Azure subscription ID containing the App Service.
  .PARAMETER ResourceGroupName
  The Resource Group containing the App Service.
  .PARAMETER AppName
  The App Service name.
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string]
  $SubscriptionId,
  [Parameter(Mandatory = $true)]
  [string]
  $ResourceGroupName,
  [Parameter(Mandatory = $true)]
  [string]
  $AppName
)
  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppName

  $appService.PossibleOutboundIpAddresses
}

function Get-AppServiceAllCurrentPublicIps()
{
  <#
  .SYNOPSIS
  This command returns a comma-delimited string of all the CURRENT public IPs for the App Service.
  .DESCRIPTION
  This command returns a comma-delimited string of all the CURRENT public IPs for the App Service. These are the public IPs the App Service is currently using; they are a subset of all POSSIBLE public IPs.
  .PARAMETER SubscriptionId
  The Azure subscription ID containing the App Service.
  .PARAMETER ResourceGroupName
  The Resource Group containing the App Service.
  .PARAMETER AppName
  The App Service name.
#>

[CmdletBinding()]
param (
  [Parameter(Mandatory = $true)]
  [string]
  $SubscriptionId,
  [Parameter(Mandatory = $true)]
  [string]
  $ResourceGroupName,
  [Parameter(Mandatory = $true)]
  [string]
  $AppName
)
  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppName

  $appService.OutboundIpAddresses
}