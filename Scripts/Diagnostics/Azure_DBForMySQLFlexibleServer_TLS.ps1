$debug = $true

function Get-MySqlFlexServerTlsVersion() {
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
    Text with the current value of server parameter 'tls_version'
    .EXAMPLE
    PS> Get-MySqlFlexServerTlsVersion -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -ServerName "MyFlexServerName"
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
  
  $tls = $config | `
    Where-Object -FilterScript { $_.Name -eq 'tls_version' }
  
  return $tls.Value
}

function Set-MySqlFlexServerTlsVersion() {
  <#
    .SYNOPSIS
    This command sets the specified Azure Database for MySQL Flexible Server's TLS version. NOTE: this command will restart the MySQL Flexible Server! This will briefly affect availability.
    .DESCRIPTION
    This command sets the specified Azure Database for MySQL Flexible Server's TLS version. NOTE: this command will restart the MySQL Flexible Server! This will briefly affect availability.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
    .PARAMETER TlsVersion
    The MySQL Flexible Server TLS Version setting value.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-MySqlFlexServerTlsVersion -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -ServerName "MyFlexServerName" -TlsVersion "TLSv1.2"
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
    $TlsVersion = "TLSv1.2"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Update-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName `
    -Name 'tls_version' `
    -Value $TlsVersion

  # This is a static server parameter so we must reboot the Flexible Server for the change to take effect
  Write-Debug -Debug:$debug -Message "Since TLSVersion is a static server parameter, the MySQL Flexible Server will now be restarted."
  Write-Debug -Debug:$debug -Message "PLEASE NOTE: this will briefly affect MySQL Flexible Server availability."
  Restart-AzMySqlFlexibleServer -ResourceGroupName $ResourceGroupName -ServerName $ServerName
}
