$debug = $true

function Get-MySqlFlexServerSslState() {
  <#
    .SYNOPSIS
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .DESCRIPTION
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
    .INPUTS
    None
    .OUTPUTS
    Text with the current value of server parameter 'require_secure_transport'
    .EXAMPLE
    PS> Get-MySqlFlexServerSslState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -ServerName "MyFlexServerName"
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
    $ServerName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $config = Get-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName
  
  $ssl = $config | `
    Where-Object -FilterScript { $_.Name -eq 'require_secure_transport' }
  
  return $ssl.Value
}

function Set-MySqlFlexServerSslState() {
  <#
    .SYNOPSIS
    This command sets the specified Azure Database for MySQL Flexible Server's Require SSL setting to the specified value.
    .DESCRIPTION
    This command sets the specified Azure Database for MySQL Flexible Server's Require SSL setting to the specified value.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
    .PARAMETER SslSetting
    The MySQL Flexible Server Require SSL setting value.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-MySqlFlexServerSslState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -ServerName "MyFlexServerName" -SslSetting "ON"
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
    $ServerName,
    [Parameter(Mandatory = $false)]
    [string]
    $SslSetting = "ON"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Update-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName `
    -Name 'require_secure_transport' `
    -Value $SslSetting

  Write-Debug -Debug:$debug -Message "Retrieve the Require SSL State value to ensure it was updated correctly:"

  Get-MySqlFlexServerSslState -SubscriptionId "$SubscriptionId" -ResourceGroupName "$ResourceGroupName" -ServerName "$ServerName"
}
