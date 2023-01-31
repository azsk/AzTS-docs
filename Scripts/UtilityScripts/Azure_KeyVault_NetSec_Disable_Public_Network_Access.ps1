<##########################################
Overview:
  This file contains functions to help remediate Key Vault public network access remediations.

ControlId: 
  Azure_KeyVault_NetSec_Disable_Public_Network_Access

DisplayName:
  Remediate Azure Key Vault public network access issues.

Pre-requisites:
  1. Authenticated to Azure
  2. At least Contributor role on Key Vault

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_KeyVault_NetSec_Disable_Public_Network_Access.ps1```
  3. Call the functions with arguments

Examples:
  Set-KeyVaultPublicNetworkAccessEnabledForMe -SubscriptionId "MySubscriptionId" -ResourceGroupName "MyResourceGroup" KeyVaultName "MyKeyVaultName"
########################################
#>

function Set-KeyVaultPublicNetworkAccessEnabledForMe()
{
  <#
    .SYNOPSIS
    This command updates a Key Vault to enable public network access for the public IP address of the machine (or its internet-facing proxy) that this is being run on.
    .DESCRIPTION
    This command updates a Key Vault to enable public network access for the public IP address of the machine (or its internet-facing proxy) that this is being run on. All existing IP address and VNet rules are maintained.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
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
    $KeyVaultName
  )

  # ##################################################
  # Get my public IP address
  $myPublicIpAddress = Invoke-RestMethod http://ipinfo.io/json | Select -exp ip
  $myPublicIpAddress += "/32"
  Write-Debug -Debug:$true -Message "Got my public IP address: $myPublicIpAddress."
  # ##################################################

  Set-KeyVaultPublicNetworkAccessEnabledForIpAddress `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -KeyVaultName $KeyVaultName `
    -PublicIpAddress $myPublicIpAddress
}

function Set-KeyVaultPublicNetworkAccessEnabledForIpAddresses()
{
  <#
    .SYNOPSIS
    This command updates a Key Vault to enable public network access for the specified array of public IP addresses.
    .DESCRIPTION
    This command updates a Key Vault to enable public network access for the specified array of public IP addresses. All existing IP address and VNet rules are maintained.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER PublicIpAddresses
    An array of public IP address to grant access to the Key Vault.
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
    $KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string[]]
    $PublicIpAddresses
  )

  ForEach ($publicIpAddress in $PublicIpAddresses)
  {
    Set-KeyVaultPublicNetworkAccessEnabledForIpAddress `
      -SubscriptionId $SubscriptionId `
      -ResourceGroupName $ResourceGroupName `
      -KeyVaultName $KeyVaultName `
      -PublicIpAddress $publicIpAddress
  }
}

function Set-KeyVaultPublicNetworkAccessEnabledForIpAddress()
{
  <#
    .SYNOPSIS
    This command updates a Key Vault to enable public network access for the specified public IP address.
    .DESCRIPTION
    This command updates a Key Vault to enable public network access for the specified public IP address. All existing IP address and VNet rules are maintained.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER PublicIpAddress
    The public IP address to grant access to the Key Vault.
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
    $KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string]
    $PublicIpAddress
  )

  # We are targeting the following final state for the Key Vault:
  # Public Network Access: Enabled
  # Default Action: Deny
  # IP Address range: What is currently on the Key Vault PLUS (if not already) the current public IP address
  # VNet rules: Maintain what is currently on the Key Vault - the context here is public network access, no op on VNet rules

  $azureProfile = Set-AzContext -Subscription $SubscriptionId

  # ##################################################
  # Ensure Key Vault has public network access Enabled
  # NOTE: while we should do this last, after network ACLs are set, there is a bug in Get-AzKeyVault. If public network access is disabled, then Get-AzKeyVault does NOT!! return current network ACLs,
  #       which means if we leave public network access Disabled and retrieve the KV, then... all existing network ACLs will be wiped out!
  #       So we ensure the KV has public network access Enabled first, so that we don't accidentally wipe out all existing network ACLs.
  # https://github.com/Azure/azure-powershell/issues/20744

  $keyVault = Get-AzKeyVault -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $VaultName

  If ($keyVault.PublicNetworkAccess -ne "Enabled")
  {
    Write-Debug -Debug:$true -Message "Update Key Vault to enable public network access so that the specified public source IPs can access the Key Vault."
    Update-AzKeyVault `
      -InputObject $keyVault `
      -PublicNetworkAccess Enabled
  }
  Else
  {
    Write-Debug -Debug:$true -Message "Key Vault has public network access enabled, so specified public source IPs can access the Key Vault. No change will be made."
  }
  # ##################################################


  # ##################################################
  # Ensure Key Vault has the needed network ACL rules and default action Deny

  $keyVault = Get-AzKeyVault -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $VaultName

  $ipAddressRange = $keyVault.NetworkAcls.IpAddressRanges ?? @()

  # Assume we need to update the KV to get to our final state - i.e. we assume worst case here
  $needToUpdateIps = $true
  $needToUpdateDefaultAction = $true

  # Check if the Key Vault network ACLs already contain my public IP address
  If ($ipAddressRange.Count -gt 0 -and $ipAddressRange.Contains($PublicIpAddress))
  {
    $needToUpdateIps = $false
    Write-Debug -Debug:$true -Message "Current Key Vault public IP address range already contains $PublicIpAddress, no change will be made to source IP network ACLs."
  }
  Else
  {
    $needToUpdateIps = $true  # Yes, this is redundant to start condition above. Regardless, set explicitly here in case someone changes the start condition later.
    $ipAddressRange += $PublicIpAddress
    Write-Debug -Debug:$true -Message "Added my public IP address $PublicIpAddress for new complete source IP address range: $ipAddressRange."
  }

  # Check if the Key Vault default action is already Deny
  If ($keyVault.NetworkAcls.DefaultAction -ne "Deny")
  {
    $needToUpdateDefaultAction = $true  # Yes, this is redundant to start condition above. Regardless, set explicitly here in case someone changes the start condition later.
    Write-Debug -Debug:$true -Message "Current Key Vault default network ACL action is not Deny, and it will be changed to Deny."
  }
  Else
  {
    $needToUpdateDefaultAction = $false
    Write-Debug -Debug:$true -Message "Current Key Vault default network ACL action is already Deny, so it will not be changed."
  }

  # If either the source IPs or the default action need to be updated, do that here
  If ($needToUpdateIps -or $needToUpdateDefaultAction)
  {
    Write-Debug -Debug:$true -Message "Update Key Vault network access rules."

    If ($keyVault.NetworkAcls.VirtualNetworkResourceIds.Count -eq 0)
    {
      Write-Debug -Debug:$true -Message "Update Key Vault network access rules for specified source IPs network access rules and default action Deny."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroupName `
        -VaultName $KeyVaultName `
        -DefaultAction Deny `
        -Bypass AzureServices `
        -IpAddressRange $ipAddressRange
    }
    else
    {
      Write-Debug -Debug:$true -Message "Update Key Vault network access rules for specified source IPs and existing VNet network access rules and default action Deny."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroup $ResourceGroupName `
        -VaultName $KeyVaultName `
        -DefaultAction Deny `
        -Bypass AzureServices `
        -IpAddressRange $ipAddressRange `
        -VirtualNetworkResourceId $keyVault.NetworkAcls.VirtualNetworkResourceIds
    }
  }
}

function Get-AppServiceAllPossibleOutboundPublicIps()
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

function Get-AppServiceAllCurrentOutboundPublicIps()
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
