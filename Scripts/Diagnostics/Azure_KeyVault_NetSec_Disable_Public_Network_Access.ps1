$debug = $true

function Set-KeyVaultNetworkRulesFromServiceTags() {
  <#
    .SYNOPSIS
    This function is a single-call way to set Key Vault network access rules for the CIDRs corresponding to the specified Azure Service Tags.
    .DESCRIPTION
    This function is a single-call way to set Key Vault network access rules for the CIDRs corresponding to the specified Azure Service Tags.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER ServiceTags
    A string array of Azure Service Tags such as AzureCloud.westus2.
    .PARAMETER Action
    How to handle any existing Key Vault network access rules. Allowable values are Merge or Replace. In the case of Merge, de-duplication is handled by this function. Default is Merge.
    .PARAMETER ConsolidateCidrsIfNeeded
    If the specified Service Tags result in more than 1,000 CIDRs, the function will attempt to consolidate CIDRs into fewer, larger CIDRs to fit into Key Vault's 1,000-rule limit. Default is false.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultNetworkRulesFromServiceTags -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName" -ServiceTags @("AzureCloud.eastus2", "AzureCloud.westus2") -Action "Replace" -ConsolidateCidrsIfNeeded $true
    .LINK
    None
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
    $ServiceTags,
    [Parameter(Mandatory = $false)]
    [string]
    [ValidateSet("Merge", "Replace")]
    $Action = "Merge",
    [Parameter(Mandatory = $false)]
    [bool]
    $ConsolidateCidrsIfNeeded = $false
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Write-Debug -Debug:$debug -Message "Set-KeyVaultNetworkRulesFromServiceTags :: $ServiceTags"

  $cidrs = Get-AzurePublicIpv4RangesForServiceTags -ServiceTags $ServiceTags

  Set-KeyVaultNetworkRulesFromCidrs `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -KeyVaultName $KeyVaultName `
    -Cidrs $cidrs `
    -Action $Action `
    -ConsolidateCidrsIfNeeded $ConsolidateCidrsIfNeeded
}

function Set-KeyVaultNetworkRulesFromCidrs() {
  <#
    .SYNOPSIS
    This function is a single-call way to set Key Vault network access rules for the specified CIDRs.
    .DESCRIPTION
    This function is a single-call way to set Key Vault network access rules for the specified CIDRs.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER Cidrs
    A string array of CIDRs to set on network access rules.
    .PARAMETER Action
    How to handle any existing Key Vault network access rules. Allowable values are Merge or Replace. In the case of Merge, de-duplication is handled by this function. Default is Merge.
    .PARAMETER ConsolidateCidrsIfNeeded
    If the specified CIDRs exceed 1,000, the function will attempt to consolidate CIDRs into fewer, larger CIDRs to fit into Key Vault's 1,000-rule limit. Default is false.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultNetworkRulesFromCidrs -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName" -Cidrs @("23.45.67.89", "40.16.23.0/24") -Action "Replace" -ConsolidateCidrsIfNeeded $true
    .LINK
    None
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
    $Cidrs,
    [Parameter(Mandatory = $false)]
    [string]
    [ValidateSet("Merge", "Replace")]
    $Action = "Merge",
    [Parameter(Mandatory = $false)]
    [bool]
    $ConsolidateCidrsIfNeeded = $false
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Write-Debug -Debug:$debug -Message ("Set-KeyVaultNetworkRulesFromCidrs :: " + $Cidrs.Count + " CIDRs")

  $keyVault = Get-AzKeyVault -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName

  $cidrsInitial = [System.Collections.ArrayList]@()

  $cidrsInitial.AddRange($Cidrs)

  if (($Action -eq "Merge") -and ($keyVault.NetworkAcls.IpAddressRanges)) {
    $cidrsInitial.AddRange($keyVault.NetworkAcls.IpAddressRanges)
  }


  $cidrsBinary = [System.Collections.ArrayList]@()

  foreach ($cidr in $cidrsInitial) {
    $cidrBinary = ConvertTo-BinaryIpAddress -IpAddress $cidr
    #Write-Debug -Debug:$debug -Message ("CIDR " + $cidr + " = Binary " + $cidrBinary)
    $cidrsBinary += $cidrBinary
  }

  Write-Debug -Debug:$debug -Message ("cidrsBinary count before sort/unique: " + $cidrsBinary.Count)
  $cidrsBinary = $cidrsBinary | Sort-Object | Get-Unique
  Write-Debug -Debug:$debug -Message ("cidrsBinary count after sort/unique: " + $cidrsBinary.Count)

  $cidrsSortedUnique = [System.Collections.ArrayList]@()

  foreach ($cidrBinary in $cidrsBinary) {
    $cidr = ConvertFrom-BinaryIpAddress -IpAddress $cidrBinary
    #Write-Debug -Debug:$debug -Message ("Binary " + $cidrBinary + " = CIDR " + $cidr)
    $cidrsSortedUnique += $cidr
  }

  Write-Debug -Debug:$debug -Message ("cidrsSortedUnique count: " + $cidrsSortedUnique.Count)

  if ($cidrsSortedUnique.Count -gt 1000 -and $ConsolidateCidrsIfNeeded) {
    Write-Debug -Debug:$debug -Message "Condense CIDR Ranges needed since over 1,000 CIDRs and KV is limited to 1,000"
    $cidrsSortedUnique = Get-CondensedCidrRanges -CidrRanges $cidrsSortedUnique -MaxSizePrefix 8 -AddCidrToSingleIPs $true
  }
  else {
    Write-Debug -Debug:$debug -Message "Condense CIDR Ranges not needed"
  }

  Write-Debug -Debug:$debug -Message ("cidrsSortedUnique count is " + $cidrsSortedUnique.Count)

  if ($cidrsSortedUnique.Count -gt 1000) {
    Write-Debug -Debug:$debug -Message "List of CIDRs exceeds 1,000. Key Vault has a maximum of 1,000 network access rules. Please try again with fewer CIDrs. No changes were made to Key Vault."
  }
  else {
    Write-Debug -Debug:$debug -Message "Now starting to add CIDRs to Key Vault. This will take several minutes."
    # Remove all current KV network access rules
    # This is needed because no Azure KV Powershell cmdlet supports ADDING a range
    # Update-AzKeyVaultNetworkRuleSet REPLACES what's there - no option to add
    # Update-AzKeyVaultNetworkRuleSet also has a limit of 127 rules, whereas KV supports 1,000...
    # Update-AzKeyVault does not accept a network rule object and does not allow for network rule updating
    # There is no way to manage Key Vault network access rules with Powershell except wipe existing and then
    # write new rules, whether we merge them as above or just replace with new ones

    Write-Debug -Debug:$debug -Message "Remove existing network rules first"

    if ($keyVault.NetworkAcls.VirtualNetworkResourceIds.Count -eq 0) {
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange @()
    }
    else {
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange @() `
        -VirtualNetworkResourceId $keyVault.NetworkAcls.VirtualNetworkResourceIds
    }

    # Now add new rules. Again, would be best to do this as a batch, but Azure Powershell for KV --does not support-- this when we have >127 rules.
    foreach ($cidr in $cidrsSortedUnique) {
      Write-Debug -Debug:$debug -Message "Adding CIDR $cidr"
      Add-AzKeyVaultNetworkRule `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange $cidr
    }

    Write-Debug -Debug:$debug -Message "Done!"
  }
}

function Get-AppServiceAllPossibleOutboundPublicIps() {
  <#
    .SYNOPSIS
    This command returns a comma-delimited string of all the POSSIBLE public IPs for the App Service.
    .DESCRIPTION
    This command returns a comma-delimited string of all the POSSIBLE public IPs for the App Service. Use this command and its output to set network access rules on other services, such as Key Vault when all public access is not enabled. NOTE that this is not reliable for Consumption or Premium plan Functions - please see the control documentation for details.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .INPUTS
    None
    .OUTPUTS
    Text with the App Service's possible outbound public IP addresses.
    .EXAMPLE
    PS> Get-AppServiceAllPossibleOutboundPublicIps -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName"
    .LINK
    None
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
    $AppServiceName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

  $appService.PossibleOutboundIpAddresses
}

function Get-AppServiceAllCurrentOutboundPublicIps() {
  <#
    .SYNOPSIS
    This command returns a comma-delimited string of all the CURRENT public IPs for the App Service.
    .DESCRIPTION
    This command returns a comma-delimited string of all the CURRENT public IPs for the App Service. These are the public IPs the App Service is currently using; they are a subset of all POSSIBLE public IPs. NOTE that this is not reliable for Consumption or Premium plan Functions - please see the control documentation for details.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .INPUTS
    None
    .OUTPUTS
    Text with the App Service's current outbound public IP addresses.
    .EXAMPLE
    PS> Get-AppServiceAllCurrentOutboundPublicIps -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName"
    .LINK
    None
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
    $AppServiceName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

  $appService.OutboundIpAddresses
}

function Set-KeyVaultSecurePublicNetworkSettings() {
  <#
    .SYNOPSIS
    This command updates an existing Key Vault to enable public network access with default action Deny, and to allow trusted Azure services.
    .DESCRIPTION
    This command updates an existing Key Vault to enable public network access with default action Deny, and to allow trusted Azure services. This corresponds to the "Allow public access from specific virtual network and IP addresses" setting in the Azure portal. Use this to configure the Key Vault's overall network settings apart from individual rules.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultSecurePublicNetworkSettings -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName"
    .LINK
    None
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

  $profile = Set-AzContext -Subscription $SubscriptionId

  $apiVersion = "2022-07-01"

  $payload = `
    '
  {
    "properties": {
      "networkAcls": {
      "defaultAction": "Deny",
      "bypass": "AzureServices"
      },
      "publicNetworkAccess": "Enabled"
    }
  }
  '

  $result = Invoke-AzRestMethod `
    -Subscription $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -ResourceProviderName 'Microsoft.KeyVault' `
    -ResourceType 'vaults' `
    -Name $KeyVaultName `
    -ApiVersion $apiVersion `
    -Method PATCH `
    -Payload $payload


  if ("200" -ne $result.StatusCode) {
    Write-Debug -Debug:$debug -Message "Result status code was " + $result.StatusCode
    $result
  }
  else {
    Write-Debug -Debug:$debug -Message "Result status code was " + $result.StatusCode
  }
}

function Set-KeyVaultPublicNetworkAccessEnabledForMe() {
  <#
    .SYNOPSIS
    This command updates a Key Vault to enable public network access for the public IP address of the machine (or its internet-facing proxy) that this is being run on.
    .DESCRIPTION
    This command updates a Key Vault to enable public network access for the public IP address of the machine (or its internet-facing proxy) that this is being run on. All existing IP address and VNet rules are maintained.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Key Vault.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultPublicNetworkAccessEnabledForMe -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName"
    .LINK
    None
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

  $profile = Set-AzContext -Subscription $SubscriptionId

  $myPublicIpAddress = Get-MyPublicIpAddress

  if ($myPublicIpAddress) {
    Set-KeyVaultNetworkRulesFromCidrs `
      -SubscriptionId $SubscriptionId `
      -ResourceGroupName $ResourceGroupName `
      -KeyVaultName $KeyVaultName `
      -Cidrs @($myPublicIpAddress) `
      -Action "Merge" `
      -ConsolidateCidrsIfNeeded $false

    Write-Debug -Debug:$debug -Message "Added my public IP address $myPublicIpAddress to Key Vault network access rules."
  }
  else {
    Write-Debug -Debug:$debug -Message "Unable to get my public IP address. No change made to Key Vault network access rules."
  }
}

function Remove-KeyVaultNetworkAccessRuleForIpAddress() {
  <#
  .SYNOPSIS
  This command removes a Key Vault network access rule for the specified public IP address.
  .DESCRIPTION
  This command removes a Key Vault network access rule for the specified public IP address.
  .PARAMETER SubscriptionId
  The Azure subscription ID containing the Key Vault.
  .PARAMETER ResourceGroupName
  The Resource Group name containing the Key Vault.
  .PARAMETER KeyVaultName
  The Key Vault name.
  .PARAMETER PublicIpAddress
  The public IP address to match to the rule to be removed. Must be in CIDR format; for a single IP address, put it in form a.b.c.d/32
  .INPUTS
  None
  .OUTPUTS
  None
  .EXAMPLE
  PS> Remove-KeyVaultNetworkAccessRuleForIpAddress -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName" -PublicIpAddress "1.1.1.1"
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
    $KeyVaultName,
    [Parameter(Mandatory = $true)]
    [string]
    $PublicIpAddress
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Write-Debug -Debug:$debug -Message "Removing rule for $PublicIpAddress"

  Remove-AzKeyVaultNetworkRule `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -VaultName $KeyVaultName `
    -IpAddressRange $PublicIpAddress
}

function Get-MyPublicIpAddress() {
  <#
    .SYNOPSIS
    This function reaches out to a third-party web site and gets "my" public IP address, typically the egress address from my local network
    .DESCRIPTION
    This function reaches out to a third-party web site and gets "my" public IP address, typically the egress address from my local network
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> $myPublicIpAddress = Get-MyPublicIpAddress
    .LINK
    None
  #>

  [CmdletBinding()]
  $ipUrl = "https://api.ipify.org"

  $myPublicIpAddress = ""

  # Test whether I can use a public site to get my public IP address
  $statusCode = (Invoke-WebRequest "$ipUrl").StatusCode

  if ("200" -eq "$statusCode") {
    # Get my public IP address
    $myPublicIpAddress = Invoke-RestMethod "$ipUrl"
    $myPublicIpAddress += "/32"

    Write-Debug -Debug:$debug -Message "Got my public IP address: $myPublicIpAddress."
  }
  else {
    Write-Debug -Debug:$debug -Message "Error! Could not get my public IP address."
  }

  return $myPublicIpAddress
}

function Get-AzurePublicIpRanges() {
  <#
    .SYNOPSIS
    This command retrieves the Service Tags with full info from the current Microsoft public IPs file download.
    .DESCRIPTION
    This command retrieves the Service Tags with full info from the current Microsoft public IPs file download.
    .INPUTS
    None
    .OUTPUTS
    Service Tags
    .EXAMPLE
    PS> Get-AzurePublicIpRanges
    .LINK
    None
  #>

  [CmdletBinding()]
  param()

  $fileMatch = "ServiceTags_Public"
  $ipRanges = @()

  $uri = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"

  $response = Invoke-WebRequest -Uri $uri

  $links = $response.Links | Where-Object { $_.href -match $fileMatch }

  if ($links -and $links.Count -gt 0) {
    $link = $links[0]

    if ($link) {
      $jsonUri = $link.href

      $response = Invoke-WebRequest -Uri $jsonUri | ConvertFrom-Json

      if ($response -and $response.values) {
        $ipRanges = $response.values
      }
    }
  }

  return $ipRanges
}

function Get-AzurePublicIpV4Ranges() {
  <#
    .SYNOPSIS
    This command retrieves the Service Tags with full info from the current Microsoft public IPs file download. AddressPrefixes filtered to IPv4 only.
    .DESCRIPTION
    This command retrieves the Service Tags with full info from the current Microsoft public IPs file download. AddressPrefixes filtered to IPv4 only.
    .INPUTS
    None
    .OUTPUTS
    Service Tags
    .EXAMPLE
    PS> Get-AzurePublicIpV4Ranges
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
  )

  $ipRanges = Get-AzurePublicIpRanges

  if ($ipRanges) {
    foreach ($ipRange in $ipRanges) {
      $ipRange.Properties.AddressPrefixes = $ipRange.Properties.AddressPrefixes | Where-Object { $_ -like "*.*.*.*/*" }
    }
  }

  return $ipRanges
}

function Get-AzurePublicIpV4RangesForServiceTags() {
  <#
    .SYNOPSIS
    This command retrieves the IPv4 CIDRs for the specified Service Tags from the current Microsoft public IPs file download.
    .DESCRIPTION
    This command retrieves the IPv4 CIDRs for the specified Service Tags from the current Microsoft public IPs file download.
    .PARAMETER ServiceTags
    An array of one or more Service Tags from the Microsoft Public IP file at https://www.microsoft.com/en-us/download/details.aspx?id=53602.
    .INPUTS
    None
    .OUTPUTS
    Array of IPv4 CIDRs for the specified Service tags
    .EXAMPLE
    PS> Get-AzurePublicIpv4RangesForServiceTags -ServiceTags @("DataFactory.EastUS", "DataFactory.WestUS")
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string[]]
    $ServiceTags
  )

  $ips = @()

  $ipRanges = Get-AzurePublicIpV4Ranges

  if ($ipRanges) {
    foreach ($serviceTag in $ServiceTags) {
      $ipsForServiceTag = ($ipRanges | Where-Object { $_.name -eq $serviceTag })

      $ips += $ipsForServiceTag.Properties.AddressPrefixes
    }
  }

  $ips = $ips | Sort-Object

  return $ips
}

function Test-IsIpInCidr() {
  <#
    .SYNOPSIS
    This function checks if the specified IP address is contained in the specified CIDR.
    .DESCRIPTION
    This function checks if the specified IP address is contained in the specified CIDR.
    .PARAMETER IpAddress
    An IP address like 13.82.13.23 or 13.82.13.23/32
    .PARAMETER Cidr
    A CIDR, i.e. a network address range like 13.82.0.0/16
    .INPUTS
    None
    .OUTPUTS
    A bool indicating whether or not the IP address is contained in the CIDR
    .EXAMPLE
    PS> Test-IsIpInCidr -IpAddress "13.82.13.23/32" -Cidr "13.82.0.0/16"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $IpAddress,
    [Parameter(Mandatory = $true)]
    [string]
    $Cidr
  )

  Write-Debug -Debug:$debug -Message ("Test-IsIpInCidr :: IpAddress=" + $IpAddress + ", Cidr=" + $Cidr)

  $ip = $IpAddress.Split('/')[0]
  $cidrIp = $Cidr.Split('/')[0]
  $cidrBitsToMask = $Cidr.Split('/')[1]

  #Write-Debug -Debug:$debug -Message ("ip=" + $ip + ", cidrIp=" + $cidrIp + ", cidrBitsToMask=" + $cidrBitsToMask)

  [int]$BaseAddress = [System.BitConverter]::ToInt32((([System.Net.IPAddress]::Parse($cidrIp)).GetAddressBytes()), 0)
  [int]$Address = [System.BitConverter]::ToInt32(([System.Net.IPAddress]::Parse($ip).GetAddressBytes()), 0)
  [int]$Mask = [System.Net.IPAddress]::HostToNetworkOrder(-1 -shl (32 - $cidrBitsToMask))

  #Write-Debug -Debug:$debug -Message ("BaseAddress=" + $BaseAddress + ", Address=" + $Address + ", Mask=" + $Mask)

  $result = (($BaseAddress -band $Mask) -eq ($Address -band $Mask))

  #Write-Debug -Debug:$debug -Message ("Result=" + $result)

  return $result
}

function Get-ServiceTagsForAzurePublicIp() {
  <#
    .SYNOPSIS
    This command retrieves the Service Tag(s) for the specified public IP address from the current Microsoft public IPs file download.
    .DESCRIPTION
    This command retrieves the Service Tag(s) for the specified public IP address from the current Microsoft public IPs file download. The output is a hashtable, so to use, set the output equal to a variable (see example) and work with that variable.
    .PARAMETER IpAddress
    An IP address like 13.82.13.23 or 13.82.13.23/32
    .INPUTS
    None
    .OUTPUTS
    Array of IPv4 CIDRs for the specified Service tags
    .EXAMPLE
    PS> $result = Get-ServiceTagsForAzurePublicIp -IpAddress "13.82.13.23"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $IpAddress
  )

  $ipRanges = Get-AzurePublicIpRanges

  $result = @()

  Write-Debug -Debug:$debug -Message "Processing - please wait... this will take a couple of minutes"

  foreach ($ipRange in $ipRanges) {
    $isFound = $false

    $ipRangeName = $ipRange.name
    $region = $ipRange.properties.region
    $cidrs = $ipRange.properties.addressPrefixes | Where-Object { $_ -like "*.*.*.*/*" } # filter to only IPv4

    Write-Debug -Debug:$debug -Message "Checking ipRangeName = $ipRangeName"

    if (!$region) { $region = "(N/A)" }

    foreach ($cidr in $cidrs) {
      $ipIsInCidr = Test-IsIpInCidr -IpAddress $IpAddress -Cidr $cidr

      if ($ipIsInCidr) {
        $result +=
        @{
          Name   = $ipRangeName;
          Region = $region;
          Cidr   = $cidr;
        }

        $isFound = $true
      }

      if ($isFound -eq $true) {
        break
      }
    }
  }

  if ($isFound -eq $false) {
    Write-Debug -Debug:$debug -Message ($IpAddress + ": Not found in any range")
  }

  , ($result | Sort-Object -Property "Name")
}

# ##########
# Following utility methods include code from Chris Grumbles / Microsoft
# Updated logic, functionality, and style conformance
# ##########

function ConvertTo-BinaryIpAddress() {
  <#
    .SYNOPSIS
    This function converts a passed IP Address to binary
    .DESCRIPTION
    This function converts a passed IP Address to binary
    .PARAMETER IpAddress
    An IP address like 13.82.13.23 or 13.82.13.23/32
    .INPUTS
    None
    .OUTPUTS
    Binary IP address string
    .EXAMPLE
    PS> ConvertTo-BinaryIpAddress -IpAddress "13.82.13.23"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $IpAddress
  )

  $ipAddressArray = $IpAddress.Split("/")
  $address = $ipAddressArray[0]

  if ($ipAddressArray.Count -gt 1) {
    $mask = $ipAddressArray[1]
  }
  else {
    $mask = "32"
  }

  $addressBinary = -Join ($address.Split(".") | ForEach-Object { ConvertTo-Binary -RawValue $_ })

  $maskIp = ConvertTo-IPv4MaskString -MaskBits $mask

  $maskBinary = -Join ($maskIp.Split(".") | ForEach-Object { ConvertTo-Binary -RawValue $_ })

  $result = $addressBinary + "/" + $maskBinary

  #Write-Debug -Debug:$debug -Message ("ConvertTo-BinaryIpAddress :: IpAddress = " + $IpAddress + " :: Result = " + $result)

  return $result
}

function ConvertTo-Binary() {
  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $RawValue,
    [Parameter(Mandatory = $false)]
    [string]
    $Padding = "0"
  )

  $result = [System.Convert]::ToString($RawValue, 2).PadLeft(8, $Padding)

  return $result
}

function ConvertFrom-BinaryIpAddress() {
  <#
    .SYNOPSIS
    This function converts a passed binary IP Address to normal CIDR-notation IP Address
    .DESCRIPTION
    This function converts a passed binary IP Address to normal CIDR-notation IP Address
    .PARAMETER IpAddressBinary
    A binary IP address like 11000000101010000000000000000000/11111111111111110000000000000000
    .INPUTS
    None
    .OUTPUTS
    Binary IP address string that is the output of ConvertTo-BinaryIpAddress
    .EXAMPLE
    PS> ConvertFrom-BinaryIpAddress -IpAddressBinary "11000000101010000000000000000000/11111111111111110000000000000000"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $IpAddressBinary
  )

  $ipAddressArray = $IpAddressBinary.Split("/")

  $ipAddress = $ipAddressArray[0]
  $ipArray = @()

  for ($i = 0; $i -lt 4; $i++) {
    $ipArray += $ipAddress.Substring(($i) * 8, 8)
  }

  $ipFinal = $ipArray | ForEach-Object { [System.Convert]::ToByte($_, 2) }
  $ipFinal = $ipFinal -join "."

  if ($ipAddressArray.Count -gt 1) {
    $maskAddress = $ipAddressArray[1]

    $maskArray = @()

    for ($i = 0; $i -lt 4; $i++) {
      $maskArray += $maskAddress.Substring(($i) * 8, 8)
    }

    $maskFinal = $maskArray | ForEach-Object { [System.Convert]::ToByte($_, 2) }
    $maskFinal = $maskFinal -join "."

    $mask = ConvertTo-IPv4MaskBits -MaskString $maskFinal
  }
  #else
  #{
  #  $mask = "32"
  #}

  if ($mask) {
    $result = $ipFinal + "/" + $mask
  }
  else {
    $result = $ipFinal
  }

  #Write-Debug -Debug:$debug -Message ("ConvertFrom-BinaryIpAddress :: IpAddressBinary = " + $IpAddressBinary + " :: Result = " + $result)

  return $result
}

function Get-EndIpForCidr() {
  <#
    .SYNOPSIS
    This function gets the end IP for a passed CIDR
    .DESCRIPTION
    This function gets the end IP for a passed CIDR
    .PARAMETER Cidr
    A CIDR like 13.23.0.0/16
    .INPUTS
    None
    .OUTPUTS
    An IP address like 13.23.254.254/32
    .EXAMPLE
    PS> Get-EndIpForCidr -Cidr "13.23.0.0/16"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $Cidr
  )

  $startIp = $cidr.Split('/')[0]
  $prefix = [Convert]::ToInt32($cidr.Split('/')[1])

  $result = Get-EndIp -StartIp $startIp -Prefix $prefix

  #Write-Debug -Debug:$debug -Message ("Get-EndIpForCidr :: Cidr = " + $Cidr + " :: Result = " + $result)

  return $result
}

function Get-EndIp() {
  <#
    .SYNOPSIS
    This function gets the end IP for a passed start IP and prefix
    .DESCRIPTION
    This function gets the end IP for a passed start IP and prefix
    .PARAMETER StartIp
    An IP address in the CIDR like 13.23.0.0
    .PARAMETER Prefix
    A prefix like 16
    .INPUTS
    None
    .OUTPUTS
    IP Address
    .EXAMPLE
    PS> Get-EndIp -IpAddress "13.23.0.0" -Prefix "16"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $StartIp,
    [Parameter(Mandatory = $true)]
    [string]
    $Prefix
  )

  try {
    $ipCount = ([System.Math]::Pow(2, 32 - $Prefix)) - 1

    $startIpAdd = ([System.Net.IPAddress]$StartIp.Split("/")[0]).GetAddressBytes()

    # reverse bits & recreate IP
    [Array]::Reverse($startIpAdd)
    $startIpAdd = ([System.Net.IPAddress]($startIpAdd -join ".")).Address

    $endIp = [Convert]::ToDouble($startIpAdd + $ipCount)
    $endIp = [System.Net.IPAddress]$endIp

    $result = $endIp.ToString()

    #Write-Debug -Debug:$debug -Message ("Get-EndIp: StartIp = " + $StartIp + " :: Prefix = " + $Prefix + " :: Result = " + $result)

    return $result
  }
  catch {
    Write-Debug -Debug:$debug -Message "Get-EndIp: Could not find end IP for $($StartIp)/$($Prefix)"

    throw
  }
}

function Get-CidrRangeBetweenIps() {
  <#
    .SYNOPSIS
    This function gets CIDR range for a passed set  of IP addresses
    .DESCRIPTION
    This function gets CIDR range for a passed set  of IP addresses
    .PARAMETER IpAddresses
    An array of IP addresses
    .INPUTS
    None
    .OUTPUTS
    A CIDR range as a hashtable with keys startIp, endIp, prefix
    .EXAMPLE
    PS> Get-CidrRangeBetweenIps -IpAddresses @("13.23.13.0", "13.23.14.0")
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string[]]
    $IpAddresses
  )


  $binaryIps = [System.Collections.ArrayList]@()

  foreach ($ipAddress in $IpAddresses) {
    $binaryIp = ConvertTo-BinaryIpAddress -IpAddress $ipAddress
    $binaryIps.Add($binaryIp) | Out-Null
  }

  $binaryIps = $binaryIps | Sort-Object

  $smallestIp = $binaryIps[0]
  $biggestIp = $binaryIps[$binaryIps.Count - 1]

  #Write-Debug -Debug:$debug -Message ("Get-CidrRangeBetweenIps :: IpAddresses = " + $IpAddresses + " :: SmallestIP = " + $smallestIp + " :: BiggestIP = " + $biggestIp)

  for ($i = 0; $i -lt $smallestIp.Length; $i++) {
    if ($smallestIp[$i] -ne $biggestIp[$i]) {
      break
    }
  }

  # deal with /31 as a special case
  if ($i -eq 31) { $i = 30 }

  $baseIp = $smallestIp.Substring(0, $i) + "".PadRight(32 - $i, "0")
  $baseIp2 = (ConvertFrom-BinaryIpAddress -IpAddress $baseIp)

  $result = @{startIp = $baseIp2; prefix = $i; endIp = "" }

  return $result
}

function Get-CidrRanges() {
  <#
    .SYNOPSIS
    This function gets CIDRs for a set of start/end IPs
    .DESCRIPTION
    This function gets CIDRs for a set of start/end IPs
    .PARAMETER IpAddresses
    An array of IP addresses
    .PARAMETER MaxSizePrefix
    Maximum CIDR prefix
    .PARAMETER AddCidrToSingleIPs
    Whether to append /32 to single IP addresses
    .INPUTS
    None
    .OUTPUTS
    An array of CIDRs
    .EXAMPLE
    PS> Get-CidrRanges -IpAddresses @("13.23.13.13", "13.23.13.244") -MaxSizePrefix 32 -AddCidrToSingleIPs $true
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string[]]
    $IpAddresses,
    [Parameter(Mandatory = $false)]
    [int]
    $MaxSizePrefix = 32,
    [Parameter(Mandatory = $false)]
    [bool]
    $AddCidrToSingleIPs = $true
  )

  Write-Debug -Debug:$debug -Message ("Get-CidrRanges: MaxSizePrefix=" + $MaxSizePrefix + ", AddCidrToSingleIPs=" + $AddCidrToSingleIPs + ", IpAddresses=" + $IpAddresses)

  $ipAddressesBinary = [System.Collections.ArrayList]@()
  $ipAddressesSorted = [System.Collections.ArrayList]@()
  [string[]]$cidrRanges = @()

  # Convert each IP address to binary and add to array list
  foreach ($ipAddress in $IpAddresses) {
    $ipAddressBinary = ConvertTo-BinaryIpAddress -IpAddress $ipAddress
    $ipAddressesBinary.Add($ipAddressBinary) | Out-Null
  }

  # Sort the binary IP addresses
  $ipAddressesBinary = $ipAddressesBinary | Sort-Object

  # Convert the now-sorted binary IP addresses back into regular and add to array list
  foreach ($ipAddressBinary in $ipAddressesBinary) {
    $ipAddress = ConvertFrom-BinaryIpAddress -IpAddress $ipAddressBinary
    $ipAddressesSorted.Add($ipAddress) | Out-Null
  }

  $curRange = @{ startIp = $ipAddressesSorted[0]; prefix = 32 }

  for ($i = 0; $i -le $ipAddressesSorted.Count; $i++) {
    if ($i -lt $ipAddressesSorted.Count) {
      $testRange = Get-CidrRangeBetweenIps @($curRange.startIp, $ipAddressesSorted[$i])
    }

    if (($testRange.prefix -lt $MaxSizePrefix) -or ($i -eq $ipAddressesSorted.Count)) {
      # Too big. Apply the existing range & set the current IP to the start                
      $ipToAdd = $curRange.startIp

      if ((-not ($ipToAdd.Contains("/"))) -and (($AddCidrToSingleIPs -eq $true) -or ($curRange.prefix -lt 32))) {
        $ipToAdd += "/" + $curRange.prefix
      }

      $cidrRanges += $ipToAdd

      # reset the range to the current IP
      if ($i -lt $ipAddressesSorted.Count) {
        $curRange = @{ startIp = $ipAddressesSorted[$i]; prefix = 32 }
      }
    }
    else {
      $curRange = $testRange
    }
  }

  return $cidrRanges
}

function Get-CondensedCidrRanges() {
  <#
    .SYNOPSIS
    This function gets condensed CIDRs for a set of initial CIDRs
    .DESCRIPTION
    This function gets condensed CIDRs for a set of initial CIDRs
    .PARAMETER CidrRanges
    An array of CIDRs
    .PARAMETER MaxSizePrefix
    Maximum prefix for condensed CIDRs. This means that the prefix for a result CIDR will be no lower
    than this (bigger network), but can be higher if that is the smallest the CIDR can be.
    .PARAMETER AddCidrToSingleIPs
    Whether to append /32 to single IP addresses
    .INPUTS
    None
    .OUTPUTS
    An array of CIDRs - may be the original ones or consolidated if possible
    .EXAMPLE
    PS> Get-CondensedCidrRanges -CidrRanges @("13.23.13.0/16", "13.23.14.0/16", "13.24.4.0/16") -MaxSizePrefix 8 -AddCidrToSingleIPs $true
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string[]]
    $CidrRanges,
    [Parameter(Mandatory = $false)]
    [int]
    $MaxSizePrefix = 32,
    [Parameter(Mandatory = $false)]
    [bool]
    $AddCidrToSingleIPs = $true
  )

  Write-Debug -Debug:$debug -Message ("Get-CondensedCidrRanges :: MaxSizePrefix = " + $MaxSizePrefix + " :: AddCidrToSingleIPs = " + $AddCidrToSingleIPs + " :: CidrRanges = " + $CidrRanges)

  [string[]]$finalCidrRanges = @()
  $cidrObjs = @()

  # Convert each CIDR to Start/End/Count
  foreach ($cidr in $cidrRanges) {
    $startIp = $cidr.Split('/')[0]
    $prefix = $cidrBitsToMask = [Convert]::ToInt32($cidr.Split('/')[1])
    $ipCount = [Math]::Pow(2, 32 - $cidrBitsToMask)
    $endIp = Get-EndIp -StartIp $startIp -Prefix $prefix

    $cidrObj = @{ startIp = $startIp; endIp = $endIp; prefix = $prefix; ipCount = $ipCount }

    $cidrObjs += $cidrObj
  }

  # Try to merge CIDRs
  $curRange = $cidrObjs[0]

  for ($i = 0; $i -le $cidrObjs.Count; $i++) {
    if ($i -lt $cidrObjs.Count) {
      $testRange = (Get-CidrRangeBetweenIps @($curRange.startIp, $cidrObjs[$i].endIp))

      $testRange.endIp = Get-EndIp -StartIp $testRange.startIp -Prefix $testRange.prefix

      $isSameRange = ($testRange.startIp -eq $curRange.startIp) -and ($testRange.endIp -eq $curRange.endIp)

      if (($testRange.prefix -lt $MaxSizePrefix) -and ($isSameRange -eq $false)) {
        #Write-Debug -Debug:$debug -Message ("Range too big")

        # This range is too big. Apply the existing range & set the current IP to the start
        $cidrToAdd = $curRange.startIp

        #if(($AddCidrToSingleIPs -eq $true) -or ($curRange.prefix -lt 32))
        if ((-not ($cidrToAdd.Contains("/"))) -and (($AddCidrToSingleIPs -eq $true) -or ($curRange.prefix -lt 32))) {
          $cidrToAdd += "/" + $curRange.prefix
        }

        $finalCidrRanges += $cidrToAdd

        # We added one, so reset the range to the current IP range
        if ($i -lt $cidrObjs.Count) {
          $curRange = $cidrObjs[$i]
        }
      }
      else {
        $curRange = $testRange
      }
    }
    else { 
      $cidrToAdd = $curRange.startIp

      if (($AddCidrToSingleIPs -eq $true) -or ($curRange.prefix -lt 32)) {
        $cidrToAdd += "/" + $curRange.prefix
      }

      $finalCidrRanges += $cidrToAdd
    }
  }

  $result = $finalCidrRanges | Get-Unique

  Write-Debug -Debug:$debug -Message ("Get-CondensedCidrRanges :: Result Count = " + $result.Count + " :: Result = " + $result)

  return $result
}

# ##########

# ##########
# Following utility methods include code from Bill Stewart / https://www.itprotoday.com/powershell/working-ipv4-addresses-powershell
# Updated for style conformance and logic
# ##########
function ConvertTo-IPv4MaskString {
  param
  (
    [Parameter(Mandatory = $true)]
    [ValidateRange(0, 32)]
    [Int] $MaskBits
  )

  $mask = ([Math]::Pow(2, $MaskBits) - 1) * [Math]::Pow(2, (32 - $MaskBits))

  $bytes = [BitConverter]::GetBytes([UInt32] $mask)

  (($bytes.Count - 1)..0 | ForEach-Object { [String] $bytes[$_] }) -join "."
}

function Test-IPv4MaskString {
  param
  (
    [Parameter(Mandatory = $true)]
    [String] $MaskString
  )

  $validBytes = '0|128|192|224|240|248|252|254|255'

  $MaskString -match `
  ('^((({0})\.0\.0\.0)|' -f $validBytes) +
    ('(255\.({0})\.0\.0)|' -f $validBytes) +
    ('(255\.255\.({0})\.0)|' -f $validBytes) +
    ('(255\.255\.255\.({0})))$' -f $validBytes)
}

function ConvertTo-IPv4MaskBits {
  param
  (
    [parameter(Mandatory = $true)]
    [ValidateScript({ Test-IPv4MaskString $_ })]
    [String] $MaskString
  )

  $mask = ([IPAddress] $MaskString).Address

  for ( $bitCount = 0; $mask -ne 0; $bitCount++ ) {
    $mask = $mask -band ($mask - 1)
  }

  $bitCount
}
# ##########
