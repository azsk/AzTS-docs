$debug = $true

function Get-SqlManagedInstanceMinimumTlsVersion() {
  <#
    .SYNOPSIS
    This command returns the current state of the specified SQL Managed Instance's MinimalTlsVersion setting.
    .DESCRIPTION
    This command returns the current state of the specified SQL Managed Instance's MinimalTlsVersion setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the SQL Managed Instance.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the SQL Managed Instance.
    .PARAMETER SqlInstanceName
    The SQL Managed Instance name.
    .INPUTS
    None
    .OUTPUTS
    Text with the SQL Managed Instance's current minimal TLS version setting value.
    .EXAMPLE
    PS> Get-SqlManagedInstanceMinimumTlsVersion -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -SqlInstanceName "MySQLManagedInstanceName"
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
    $SqlInstanceName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $instance = Get-AzSqlInstance `
    -ResourceGroupName $ResourceGroupName `
    -Name $SqlInstanceName

  $tlsVersion = $instance.MinimalTlsVersion

  return $tlsVersion
}

function Set-SqlManagedInstanceMinimumTlsVersion() {
  <#
    .SYNOPSIS
    This command sets the specified SQL Managed Instance's MinimalTlsVersion setting.
    .DESCRIPTION
    This command sets the specified SQL Managed Instance's MinimalTlsVersion setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the SQL Managed Instance.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the SQL Managed Instance.
    .PARAMETER SqlInstanceName
    The SQL Managed Instance name.
    .PARAMETER MinimalTlsVersion
    The SQL Managed Instance MinimalTlsVersion setting value.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-SqlManagedInstanceMinimumTlsVersion -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -SqlInstanceName "MySQLManagedInstanceName" -MinimalTlsVersion "1.2"
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
    $SqlInstanceName,
    [Parameter(Mandatory = $false)]
    [string]
    $MinimalTlsVersion = "1.2"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Set-AzSqlInstance `
    -ResourceGroupName $ResourceGroupName `
    -Name $SqlInstanceName `
    -MinimalTlsVersion $TlsVersion
}
