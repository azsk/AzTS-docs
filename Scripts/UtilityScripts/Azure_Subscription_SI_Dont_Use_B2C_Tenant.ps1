<##########################################
Overview:
  This file contains functions to help remediate B2C tenant or RP

ControlId: 
  Azure_Subscription_SI_Dont_Use_B2C_Tenant

DisplayName:
  Remediate Azure AD B2C tenant/RP issues

Pre-requisites:
  1. Authenticated to Azure
  2. At least Contributor role on subscription

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_Subscription_SI_Dont_Use_B2C_Tenant.ps1```
  3. Call the functions with arguments

Examples:
########################################
#>

function UnregisterAADRP()
{
  <#
    .SYNOPSIS
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    .DESCRIPTION
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  az provider unregister --verbose `
    --subscription $SubscriptionId `
    --namespace Microsoft.AzureActiveDirectory `
    --wait
}

function ListRegisteredResourceProviders()
{
  <#
    .SYNOPSIS
    This command lists the Resource Providers registered on the Subscription.
    .DESCRIPTION
    This command lists the Resource Providers registered on the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  az provider list --verbose `
    --subscription $SubscriptionId `
    --query "[?registrationState=='Registered'].namespace"
}

function ListAADB2CTenants()
{
  <#
    .SYNOPSIS
    This command lists the AAD B2C tenants in the Subscription.
    .DESCRIPTION
    This command lists the AAD B2C tenants in the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $apiVersionAad = "2022-03-01-preview"

  az rest --verbose `
    --url "https://management.azure.com/subscriptions/$SubscriptionId/providers/Microsoft.AzureActiveDirectory/b2cDirectories?api-version=$apiVersionAad"

}