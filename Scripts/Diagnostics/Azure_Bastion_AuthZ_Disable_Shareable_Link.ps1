$debug = $true

function Update-BastionDisableShareableLink() {
  <#
  .SYNOPSIS
  This function updates an Azure Bastion host to set the ShareableLink feature to the specified state.
  .DESCRIPTION
  This function updates an Azure Bastion host to set the ShareableLink feature to the specified state.
  .PARAMETER SubscriptionId
  The Azure subscription ID containing the Bastion host.
  .PARAMETER ResourceGroupName
  The Resource Group name containing the Bastion host.
  .PARAMETER BastionHostName
  The Bastion host name.
  .PARAMETER ShareableLinkEnabled
  Boolean for whether shareable link should be enabled. Defaults to false.
  .INPUTS
  None
  .OUTPUTS
  None
  .EXAMPLE
  PS> Update-BastionDisableShareableLink -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -BastionHostName "MyKBastionHostName" -ShareableLinkEnabled $false
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
    $BastionHostName,
    [Parameter(Mandatory = $false)]
    [bool]
    $ShareableLinkEnabled = $false
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $apiVersion = "2022-09-01"

  # Get bastion
  $method = "GET"
  
  $json = (Invoke-AzRestMethod `
      -Subscription $SubscriptionId `
      -ResourceGroupName $ResourceGroupName `
      -ResourceProviderName 'Microsoft.Network' `
      -ResourceType 'bastionHosts' `
      -Name $BastionHostName `
      -ApiVersion $apiVersion `
      -Method $method).Content | ConvertFrom-Json
  
  # Update shareable setting
  $json.properties.enableShareableLink = $ShareableLinkEnabled
  
  # Get JSON payload for update call
  $jsonUpdated = $json | ConvertTo-Json -Depth 100
  
  # Update bastion
  $method = "PUT"
  $payload = $jsonUpdated
  
  Invoke-AzRestMethod `
    -Subscription $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -ResourceProviderName 'Microsoft.Network' `
    -ResourceType 'bastionHosts' `
    -Name $BastionHostName `
    -ApiVersion $apiVersion `
    -Method $method `
    -Payload $payload
}

function Remove-SharedLinksForVmsInRg() {
  <#
  .SYNOPSIS
  This function deletes the shared links for all VMs in the specified VM Resource Group from the Bastion Host.
  .DESCRIPTION
  This function deletes the shared links for all VMs in the specified VM Resource Group from the Bastion Host.
  .PARAMETER SubscriptionId
  The Azure subscription ID containing the Bastion host.
  .PARAMETER BastionResourceGroupName
  The Resource Group name containing the Bastion host.
  .PARAMETER BastionHostName
  The Bastion host name.
  .PARAMETER VmResourceGroupName
  The Resource Group name containing the VMs whose shared links to delete from the Bastion Host.
  .INPUTS
  None
  .OUTPUTS
  None
  .EXAMPLE
  PS> Remove-SharedLinksForVmsInRg -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -BastionHostName "MyKBastionHostName" -ShareableLinkEnabled $false
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
    $BastionResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $BastionHostName,
    [Parameter(Mandatory = $true)]
    [string]
    $VmResourceGroupName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $apiVersion = "2022-09-01"

  # Get all VM resource IDs in specified VM resource group
  $vmResourceIds = "$(az vm list -g $VmResourceGroupName --query '[].id')" | ConvertFrom-Json
  
  # Prepare JSON payload
  $payload = "{'vms': ["
  foreach ($vmResourceId in $vmResourceIds) {
    $payload += "{'vm': {'id': '" + $vmResourceId + "'}},"
  }
  $payload += "]}"
  
  # Delete shareable links REST API call
  $path = "/subscriptions/$SubscriptionId/resourceGroups/$BastionResourceGroupName/providers" + `
    "/Microsoft.Network/bastionHosts/$BastionHostName/deleteShareableLinks?api-version=$apiVersion"
  $method = "POST"

  Invoke-AzRestMethod `
    -Path "$path" `
    -Method "$method" `
    -Payload "$payload"  
}
