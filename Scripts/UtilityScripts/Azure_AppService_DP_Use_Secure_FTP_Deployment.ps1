<##########################################
Overview:
  This file contains functions to help remediate data factory plaintext secret issues

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
  GetDataSetNamesAndParameters -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroup "MyResourceGroup" -DataFactoryName "MyDataFactoryName"
########################################
#>

function GetFtpState()
{
  $rgName = "Patrick"
  $appName = "plzm-eus-app-1"

  $psSite = Get-AzWebApp -ResourceGroupName $rgName -Name $appName

  $ftpConfigs = @{ "Production" = $psSite.SiteConfig.FtpsState }

  ForEach ($slotName in (Get-AzWebAppSlot -ResourceGroupName $rgName -Name $appName | Select-Object "Name"))
  {
    #Write-Output $slotName
    $slotConfig = @{ $slotName = ((Get-AzWebAppSlot -ResourceGroupName $rgName -Name $appName -Slot $slotName).SiteConfig.FtpsState) }
    $ftpConfigs = $ftpConfigs + $slotConfig
  }

  return $ftpConfigs
}

function GetCurrentFtpState()
{
  <#
    .SYNOPSIS
    This command shows the current FTP state for the App Service.
    .DESCRIPTION
    This command shows the current FTP state for the App Service.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroup
        The Resource Group containing the App Service.
    .PARAMETER AppName
        The App Service name.
    .PARAMETER IsFunctionApp
        Whether the App Service is a Function (true) or a Webapp (false). Defaults to true.
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroup,
    [Parameter(Mandatory = $true)]
    [string]
    $AppName,
    [Parameter(Mandatory = $false)]
    [bool]
    $IsFunctionApp = $true
  )

  if ($IsFunctionApp) {
    az functionapp config show --verbose `
      --subscription $subscriptionId `
      -g $resourceGroupName `
      -n $appName `
      -o tsv `
      --query 'ftpsState'
  }
  else {

    az webapp config show --verbose `
      --subscription $subscriptionId `
      -g $resourceGroupName `
      -n $appName `
      -o tsv `
      --query 'ftpsState'
  }
}

function SetFtpState()
{
  <#
    .SYNOPSIS
    This command sets the FTP state for the App Service.
    .DESCRIPTION
    This command sets the FTP state for the App Service.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroup
        The Resource Group containing the App Service.
    .PARAMETER AppName
        The App Service name.
    .PARAMETER FtpState
        The FTP State to set. Either "Disabled" or "FtpsOnly". Defaults to "Disabled".
    .PARAMETER IsFunctionApp
        Whether the App Service is a Function (true) or a Webapp (false). Defaults to true.
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroup,
    [Parameter(Mandatory = $true)]
    [string]
    $AppName,
    [Parameter(Mandatory = $false)]
    [string]
    $FtpState = "Disabled",
    [Parameter(Mandatory = $false)]
    [bool]
    $IsFunctionApp = $true
  )

  if ($IsFunctionApp) {
    az functionapp config set --verbose `
      --subscription $subscriptionId `
      -g $resourceGroupName `
      -n $appName `
      --ftps-state $FtpState
  }
  else {
    az webapp config set --verbose `
      --subscription $subscriptionId `
      -g $resourceGroupName `
      -n $appName `
      --ftps-state $FtpState
  }
}