$debug = $true

function Get-DeletedUser() {
  <#
    .SYNOPSIS
    This command shows a deleted user.
    .DESCRIPTION
    This command shows a deleted user. This is helpful when trying to translate a scanner status message user GUID to a human display name in order to locate the user on a list of assignments.
    This command requires the Microsoft.Graph SDK. See installation instructions: https://learn.microsoft.com/powershell/microsoftgraph/installation?view=graph-powershell-1.0#installation
    .PARAMETER DeletedUserId
    The user GUID for the deleted user.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Get-DeletedUser -DeletedUserId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None`
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $DeletedObjectId
  )

  Connect-MgGraph

  Get-MgDirectoryDeletedItem -DirectoryObjectId $DeletedObjectId
}
