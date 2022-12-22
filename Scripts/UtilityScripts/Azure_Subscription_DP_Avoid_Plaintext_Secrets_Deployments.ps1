<##########################################
Overview:
  This file contains functions to help remediate ARM deployment plaintext secret issues

ControlId: 
  Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments

DisplayName:
  Remediate Azure Deployment plaintext secret issues.

Pre-requisites:
  1. Authenticated to Azure
  2. At least Contributor role on subscription

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments.ps1```
  3. Call the functions with arguments

Examples:
########################################
#>


function GetRGDeployment()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Resource Group.
    .DESCRIPTION
    This command lists ARM deployments for the Resource Group.
    .PARAMETER SubscriptionId
        The Azure subscription ID.
    .PARAMETER ResourceGroup
        The Resource Group to which Deployments were run.
    .PARAMETER DeploymentName
        The Deployment name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DeploymentName
  )

  az deployment group show --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    -n $DeploymentName
}

function GetRGDeploymentOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Resource Group.
    .DESCRIPTION
    This command lists ARM deployments for the Resource Group.
    .PARAMETER SubscriptionId
        The Azure subscription ID.
    .PARAMETER ResourceGroup
        The Resource Group to which Deployments were run.
    .PARAMETER DeploymentName
        The Deployment name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DeploymentName
  )

  az deployment operation group list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    -n $DeploymentName
}

function ListRGDeployments()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Resource Group.
    .DESCRIPTION
    This command lists ARM deployments for the Resource Group.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .PARAMETER ResourceGroup
    The Resource Group to which Deployments were run.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroup
  )

  az deployment group list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup
}

function ListRGDeploymentsAndOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Resource Group.
    .DESCRIPTION
    This command lists ARM deployments for the Resource Group.
    .PARAMETER SubscriptionId
        The Azure subscription ID.
    .PARAMETER ResourceGroup
        The Resource Group to which Deployments were run.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroup
  )

  $deployments = "$(az deployment group list --verbose --subscription $SubscriptionId -g $ResourceGroup)" | ConvertFrom-Json

  foreach ($deployment in $deployments)
  {
    Write-Debug -Debug:$true -Message ("Deployment: " + $deployment.Name)

    az deployment operation group list --verbose --subscription $SubscriptionId -g $ResourceGroup --name $deployment.Name

    Write-Host ""
  }
}

function ListSubscriptionDeployments()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Subscription.
    .DESCRIPTION
    This command lists ARM deployments for the Subscription.
    .PARAMETER SubscriptionId
        The Azure subscription ID.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  az deployment sub list --verbose `
    --subscription $SubscriptionId
}

function ListSubscriptionDeploymentsAndOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments for the Subscription.
    .DESCRIPTION
    This command lists ARM deployments for the Subscription.
    .PARAMETER SubscriptionId
        The Azure subscription ID.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $deployments = "$(az deployment sub list --verbose --subscription $SubscriptionId)" | ConvertFrom-Json

  foreach ($deployment in $deployments)
  {
    Write-Debug -Debug:$true -Message ("Deployment: " + $deployment.Name)

    az deployment operation sub list --verbose --subscription $SubscriptionId --name $deployment.Name

    Write-Host ""
  }
}