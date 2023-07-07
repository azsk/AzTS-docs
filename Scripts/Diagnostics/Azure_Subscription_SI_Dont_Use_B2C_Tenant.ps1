$debug = $true

function Get-AzureADB2CTenants() {
  <#
    .SYNOPSIS
    This command lists the AAD B2C tenants in the Subscription.
    .DESCRIPTION
    This command lists the AAD B2C tenants in the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Get-AzureADB2CTenants -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $apiVersionAad = "2022-03-01-preview"

  $result = Invoke-AzRestMethod `
    -Subscription $SubscriptionId `
    -ResourceProviderName 'Microsoft.AzureActiveDirectory' `
    -ResourceType 'b2cDirectories' `
    -ApiVersion $apiVersionAad `
    -Method GET

  $tenants = ($result.Content | ConvertFrom-Json).Value

  if ($tenants.Count -gt 0) {
    ForEach ($tenant in $tenants) {
      Write-Debug -Debug:$debug -Message ("B2C Tenant Name: " + $tenant.name)
      Write-Debug -Debug:$debug -Message ("B2C Tenant ID: " + $tenant.id)
    }
  }
  else {
    Write-Debug -Debug:$debug -Message "Subscription contains no B2C tenants."
  }
}

function Get-AzureADB2CResourceProvider() {
  <#
    .SYNOPSIS
    This command shows the Microsoft.AzureActiveDirectory Resource Provider and its registration state on the Subscription.
    .DESCRIPTION
    This command shows the Microsoft.AzureActiveDirectory Resource Provider and its registration state on the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .INPUTS
    None
    .OUTPUTS
    [PSResourceProvider](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psresourceprovider)
    .EXAMPLE
    PS> Get-AzureADB2CResourceProvider -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceProvider -ListAvailable | Where-Object { $_.ProviderNamespace -eq "Microsoft.AzureActiveDirectory" }
}

function Get-RegisteredResourceProviders() {
  <#
    .SYNOPSIS
    This command lists the Resource Providers registered on the Subscription.
    .DESCRIPTION
    This command lists the Resource Providers registered on the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .INPUTS
    None
    .OUTPUTS
    [PSResourceProvider](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psresourceprovider)
    .EXAMPLE
    PS> Get-RegisteredResourceProviders -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceProvider
}

function Unregister-AzureADB2CResoureProvider() {
  <#
    .SYNOPSIS
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    .DESCRIPTION
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    Reference to validate that this RP is for AADB2C: https://learn.microsoft.com/azure/azure-resource-manager/management/azure-services-resource-providers#match-resource-provider-to-service
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Unregister-AzureADB2CResoureProvider -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Unregister-AzResourceProvider -ProviderNamespace "Microsoft.AzureActiveDirectory"
}
