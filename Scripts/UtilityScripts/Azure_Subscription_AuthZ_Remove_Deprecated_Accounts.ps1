<##########################################
Overview:
  This file contains functions to help remediate invalid/deleted user role assignment issues.

ControlId: 
  Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

DisplayName:
  Remediate invalid/obsolete/deleted account role assignment issues.

Pre-requisites:
  1. Authenticated to Azure

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_Subscription_AuthZ_Remove_Deprecated_Accounts.ps1```
  3. Call the functions with arguments

Examples:
  GetDataSets -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroup "MyResourceGroup" -DataFactoryName "MyDataFactoryName"
########################################
#>

function GetDeletedUser()
{
  <#
    .SYNOPSIS
    This command shows a deleted user.
    .DESCRIPTION
    This command shows a deleted user. This is helpful when trying to translate a scanner status message user GUID to a human display name in order to locate the user on a list of assignments.
    .PARAMETER DeletedUserId
        The user GUID for the deleted user.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $DeletedUserId
  )

  az rest --method "GET" --headers "Content-Type=application/json" --verbose `
    --url "https://graph.microsoft.com/v1.0/directory/deletedItems/$DeletedUserId" `
    | ConvertFrom-Json
}