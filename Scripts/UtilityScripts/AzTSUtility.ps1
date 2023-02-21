<####################################################################################################
Overview:
  This file contains utility functions to help assess and remediate Azure Tenant Security control compliance issues.

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./AzTSUtility.ps1```
  3. Call the functions with the appropriate parameters.
####################################################################################################
#>

# ####################################################################################################
# Azure Powershell Utility Methods

function Install-AzPowershell()
{
    <#
    .SYNOPSIS
    This function installs Azure Powershell on the system where it is run.
    .DESCRIPTION
    This function installs Azure Powershell on the system where it is run. It runs with -Force and -AllowClobber so that confirmation or warning messages are not shown.
  #>

  [CmdletBinding()]
  param ()

  # -Force and -AllowClobber make this run without confirmation or warning messages
  # Ref. https://learn.microsoft.com/powershell/module/powershellget/install-module#description
  Install-Module -Name Az -Scope CurrentUser -Force -AllowClobber
}

function Uninstall-AzPowershell()
{
    <#
    .SYNOPSIS
    This function uninstalls all Azure Powershell packages on the system where it is run.
    .DESCRIPTION
    This function uninstalls all Azure Powershell packages on the system where it is run. If more than one version of a package is installed, all versions will be uninstalled. Use this for a deep cleanout of installed Azure Powershell packages.
  #>

  [CmdletBinding()]
  param ()

  Get-Package | Where-Object { $_.Name -Like 'Az*' } | ForEach-Object { Uninstall-Package -Name $_.Name -AllVersions }
}

# ####################################################################################################

# ####################################################################################################
# Azure_AppService_DP_Use_Secure_FTP_Deployment

function Get-AppServiceFtpState()
{
  <#
    .SYNOPSIS
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .DESCRIPTION
    This command shows the current FTP state for the App Service Production slot and all non-Production slots.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group containing the App Service.
    .PARAMETER AppServiceName
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
    $AppServiceName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

  $ftpConfigs = [ordered]@{ "Production" = $appService.SiteConfig.FtpsState }

  # List of slots in Get-AzWebAppSlot has full slot name. SiteConfig is blank on those.
  # So we have to get just the bare slot name, then call Get-AzWebAppSlot for it to get the SiteConfig and FtpsState.
  ForEach ($slotNameRaw in (Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName).Name)
  {
    $slotName = $slotNameRaw.Replace($AppServiceName + "/", "")
    $slot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName -Slot $slotName
    $ftpConfigs = $ftpConfigs + @{ $slotName = $slot.SiteConfig.FtpsState }
  }

  return $ftpConfigs
}

function Set-AppServiceFtpState()
{
  <#
    .SYNOPSIS
    This command sets the FTP state for the App Service.
    .DESCRIPTION
    This command sets the FTP state for the App Service.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the App Service.
    .PARAMETER ResourceGroupName
    The Resource Group containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .PARAMETER SlotName
    If a Slot FTP State is being set, provide the slot name.
    .PARAMETER FtpState
    The FTP State to set. Either "Disabled" or "FtpsOnly". Defaults to "Disabled".
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
    $AppServiceName,
    [Parameter(Mandatory = $false)]
    [string]
    $SlotName,
    [Parameter(Mandatory = $false)]
    [string]
    $FtpState = "Disabled"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  if ([string]::IsNullOrWhiteSpace($SlotName))
  {
    # No slot name so we're setting the app service itself
    Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName -FtpsState $FtpState
  }
  else
  {
    if ($SlotName.StartsWith($AppServiceName))
    {
      $SlotName = $SlotName.Replace($AppServiceName + "/", "")
    }

    Set-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppServiceName -Slot $SlotName -FtpsState $FtpState
  }
}

# ####################################################################################################

# ####################################################################################################
# Azure_DataFactory_DP_Avoid_Plaintext_Secrets

function Get-DataFactoryV2()
{
  <#
    .SYNOPSIS
    This command shows the data factory.
    .DESCRIPTION
    This command shows the data factory.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Write-Debug -Debug -Message "Check returned ADFV2 object Tags property for plain-text secrets"

  Get-AzDataFactoryV2 -ResourceGroupName $ResourceGroupName -Name $DataFactoryName
}

function Get-DataFactoryV2DataFlows()
{
  <#
    .SYNOPSIS
    This command lists data flow names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists data flow names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2DataFlow -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  #  --query "[].[name, properties.scriptLines, properties.sources, properties.sinks, properties.transformations]"
}

function Get-DataFactoryV2DataSets()
{
  <#
    .SYNOPSIS
    This command lists dataset names and parameters for datasets that have at least one parameter.
    .DESCRIPTION
    This command lists dataset names and parameters for datasets that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2Dataset -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  #  --query "[?@.properties.parameters.*] | [].{dataSetName:name, parameters:properties.parameters}"
}

function Get-DataFactoryV2IntegrationRuntimes()
{
  <#
    .SYNOPSIS
    This command lists pipeline names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists pipeline names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2IntegrationRuntime -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  #  #--query "[?@.parameters.*] | [].{pipelineName:name, parameters:parameters}"
}

function Get-DataFactoryV2LinkedServices()
{
  <#
    .SYNOPSIS
    This command lists linked service names and parameters for linked services that have at least one parameter.
    .DESCRIPTION
    This command lists linked service names and parameters for linked services that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2LinkedService -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  #  --query "[].{name:name, properties_credential:properties.credential, properties_encryptedCredential:properties.encryptedCredential, properties_parameters:properties.parameters}"
}

function Get-DataFactoryV2Pipelines()
{
  <#
    .SYNOPSIS
    This command lists pipeline names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists pipeline names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2Pipeline -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  #  --query "[?@.parameters.*] | [].{pipelineName:name, parameters:parameters}"
}

function Get-DataFactoryV2Triggers()
{
  <#
    .SYNOPSIS
    This command lists triggers.
    .DESCRIPTION
    This command lists triggers. This is to try and locate strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroupName
    The Resource Group containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDataFactoryV2Trigger -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName
}

# ####################################################################################################

# ####################################################################################################
# Azure_DBForMYSQLFlexibleServer_DP_Enable_SSL

function Get-MySqlFlexServerSslState()
{
  <#
    .SYNOPSIS
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .DESCRIPTION
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $ServerName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $config = Get-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName
  
  $ssl = $config | `
    Where-Object -FilterScript {$_.Name -eq 'require_secure_transport'}
  
  return $ssl.Value
}

function Set-MySqlFlexServerSslState()
{
  <#
    .SYNOPSIS
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .DESCRIPTION
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
    .PARAMETER SslSetting
    The MySQL Flexible Server Require SSL setting value.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $ServerName,
      [Parameter(Mandatory=$false)]
      [string]
      $SslSetting = "ON"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Update-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName `
    -Name 'require_secure_transport' `
    -Value $SslSetting
}

# ####################################################################################################

# ####################################################################################################
# Azure_DBForMySQLFlexibleServer_TLS

function Get-MySqlFlexServerTlsVersion()
{
  <#
    .SYNOPSIS
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .DESCRIPTION
    This command returns the current state of the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $ServerName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $config = Get-AzMySqlFlexibleServerConfiguration `
    -ResourceGroupName $ResourceGroupName `
    -ServerName $ServerName
  
  $tls = $config | `
    Where-Object -FilterScript {$_.Name -eq 'tls_version'}
  
  return $tls.Value
}

function Set-MySqlFlexServerTlsVersion()
{
  <#
    .SYNOPSIS
    This command sets the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .DESCRIPTION
    This command sets the specified Azure Database for MySQL Flexible Server's Require SSL setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the MySQL Flexible Server.
    .PARAMETER ResourceGroupName
    The Resource Group containing the MySQL Flexible Server.
    .PARAMETER ServerName
    The MySQL Flexible Server name.
    .PARAMETER TlsVersion
    The MySQL Flexible Server TLS Version setting value.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $ServerName,
      [Parameter(Mandatory=$false)]
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
  Restart-AzMySqlFlexibleServer -ResourceGroupName $ResourceGroupName -ServerName $ServerName
}

# ####################################################################################################

# ####################################################################################################
# Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version

function Get-SqlManagedInstanceMinimumTlsVersion()
{
  <#
    .SYNOPSIS
    This command returns the current state of the specified SQL Managed Instance's MinimalTlsVersion setting.
    .DESCRIPTION
    This command returns the current state of the specified SQL Managed Instance's MinimalTlsVersion setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the SQL Managed Instance.
    .PARAMETER ResourceGroupName
    The Resource Group containing the SQL Managed Instance.
    .PARAMETER SqlInstanceName
    The SQL Managed Instance name.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
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

function Set-SqlManagedInstanceMinimumTlsVersion()
{
  <#
    .SYNOPSIS
    This command sets the specified SQL Managed Instance's MinimalTlsVersion setting.
    .DESCRIPTION
    This command sets the specified SQL Managed Instance's MinimalTlsVersion setting.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the SQL Managed Instance.
    .PARAMETER ResourceGroupName
    The Resource Group containing the SQL Managed Instance.
    .PARAMETER SqlInstanceName
    The SQL Managed Instance name.
    .PARAMETER MinimalTlsVersion
    The SQL Managed Instance MinimalTlsVersion setting value.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $SqlInstanceName,
      [Parameter(Mandatory=$false)]
      [string]
      $MinimalTlsVersion = "1.2"
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Set-AzSqlInstance `
    -ResourceGroupName $ResourceGroupName `
    -Name $SqlInstanceName `
    -MinimalTlsVersion $TlsVersion
}

# ####################################################################################################

# ####################################################################################################
# Azure_KeyVault_NetSec_Disable_Public_Network_Access

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
  .PARAMETER AppServiceName
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
  $AppServiceName
)
  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

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
  .PARAMETER AppServiceName
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
  $AppServiceName
)
  $profile = Set-AzContext -Subscription $SubscriptionId

  $appService = Get-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppServiceName

  $appService.OutboundIpAddresses
}

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

  $profile = Set-AzContext -Subscription $SubscriptionId

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

  $profile = Set-AzContext -Subscription $SubscriptionId

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

  $profile = Set-AzContext -Subscription $SubscriptionId

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

  if ($keyVault.NetworkAcls.IpAddressRanges)
  {
    $ipAddressRange = $keyVault.NetworkAcls.IpAddressRanges
  }
  else
  {
    $ipAddressRange = @()
  }
  # This does not work in Windows Powershell 5.1, only in 7.x
  # $ipAddressRange = $keyVault.NetworkAcls.IpAddressRanges ?? @()

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

# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

function Get-DeletedUser()
{
  <#
    .SYNOPSIS
    This command shows a deleted user.
    .DESCRIPTION
    This command shows a deleted user. This is helpful when trying to translate a scanner status message user GUID to a human display name in order to locate the user on a list of assignments.
    This command requires the Microsoft.Graph SDK. See installation instructions: https://learn.microsoft.com/powershell/microsoftgraph/installation?view=graph-powershell-1.0#installation
    .PARAMETER DeletedUserId
    The user GUID for the deleted user.
  #>

  [CmdletBinding()]
  param (
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory=$true)]
    [string]
    $DeletedObjectId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Connect-MgGraph

  Get-MgDirectoryDeletedItem -DirectoryObjectId $DeletedObjectId
}

# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments

function Get-ResourceGroupDeployment()
{
  <#
    .SYNOPSIS
    This command retrieves ARM deployment(s) for the Resource Group.
    .DESCRIPTION
    This command retrieves ARM deployment(s) for the Resource Group.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .PARAMETER ResourceGroupName
    The Resource Group to which the Deployment was run.
    .PARAMETER DeploymentName
    Optional: a Deployment name. If not specified, all Resource Group deployments will be retrieved.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName,
      [Parameter(Mandatory=$false)]
      [string]
      $DeploymentName = ""
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  if ( $DeploymentName )
  {
    Get-AzResourceGroupDeployment -ResourceGroup $ResourceGroupName -Name $DeploymentName
  }
  else
  {
    Get-AzResourceGroupDeployment -ResourceGroup $ResourceGroupName
  }
}

function Get-ResourceGroupDeploymentOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployment operations for the Resource Group Deployment.
    .DESCRIPTION
    This command lists ARM deployment operations for the Resource Group Deployment.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .PARAMETER ResourceGroupName
    The Resource Group to which the Deployment was run.
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
      $ResourceGroupName,
      [Parameter(Mandatory=$true)]
      [string]
      $DeploymentName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceGroupDeploymentOperation -ResourceGroup $ResourceGroupName -Name $DeploymentName
}

function Get-ResourceGroupDeploymentsAndOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments and operations for the Resource Group.
    .DESCRIPTION
    This command lists ARM deployments and operations for the Resource Group.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
    .PARAMETER ResourceGroupName
    The Resource Group to which Deployments were run.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId,
      [Parameter(Mandatory=$true)]
      [string]
      $ResourceGroupName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $deployments = Get-AzResourceGroupDeployment -ResourceGroup $ResourceGroupName

  foreach ($deployment in $deployments)
  {
    Write-Debug -Debug:$true -Message ("Deployment: " + $deployment.DeploymentName)

    Get-AzResourceGroupDeploymentOperation -ResourceGroup $ResourceGroupName -Name $deployment.DeploymentName
  }
}

function Get-SubscriptionDeployments()
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

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDeployment
}

function Get-SubscriptionDeploymentsAndOperations()
{
  <#
    .SYNOPSIS
    This command lists ARM deployments and operations for the Subscription.
    .DESCRIPTION
    This command lists ARM deployments and operations for the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $deployments = Get-AzDeployment

  foreach ($deployment in $deployments)
  {
    Write-Debug -Debug:$true -Message ("Deployment: " + $deployment.DeploymentName)

    Get-AzDeploymentOperation -DeploymentName $deployment.DeploymentName
  }
}
# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_SI_Dont_Use_B2C_Tenant

function Get-AzureADB2CTenants()
{
  <#
    .SYNOPSIS
    This command lists the AAD B2C tenants in the Subscription.
    .DESCRIPTION
    This command lists the AAD B2C tenants in the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $apiVersionAad = "2022-03-01-preview"

  Invoke-AzRestMethod `
    -Subscription $SubscriptionId `
    -ResourceProviderName 'Microsoft.AzureActiveDirectory' `
    -ResourceType 'b2cDirectories' `
    -ApiVersion $apiVersionAad `
    -Method GET
}

function Get-AzureADB2CResourceProvider()
{
  <#
    .SYNOPSIS
    This command shows the Microsoft.AzureActiveDirectory Resource Provider and its registration state on the Subscription.
    .DESCRIPTION
    This command shows the Microsoft.AzureActiveDirectory Resource Provider and its registration state on the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceProvider -ListAvailable | Where-Object {$_.ProviderNamespace -eq "Microsoft.AzureActiveDirectory"}
}

function Get-RegisteredResourceProviders()
{
  <#
    .SYNOPSIS
    This command lists the Resource Providers registered on the Subscription.
    .DESCRIPTION
    This command lists the Resource Providers registered on the Subscription.
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceProvider
}

function Unregister-AzureADB2CResoureProvider()
{
  <#
    .SYNOPSIS
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    .DESCRIPTION
    This command unregisters the Microsoft.AzureActiveDirectory Resource Provider.
    Reference to validate that this RP is for AADB2C: https://learn.microsoft.com/azure/azure-resource-manager/management/azure-services-resource-providers#match-resource-provider-to-service
    .PARAMETER SubscriptionId
    The Azure subscription ID.
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Unregister-AzResourceProvider -ProviderNamespace "Microsoft.AzureActiveDirectory"
}
# ####################################################################################################

# ####################################################################################################
# Azure_VirtualMachine_SI_Enable_Antimalware

function Get-MDEPreferences() {
  <#
    .SYNOPSIS
    This command returns whether Realtime Monitoring is Disabled as well as connection and signature attributes.
    .DESCRIPTION
    This command returns whether Realtime Monitoring is Disabled as well as connection and signature attributes.
  #>

  [CmdletBinding()]
  param()

  Get-MpPreference | Select-Object DisableRealtimeMonitoring, MeteredConnectionUpdates, Proxy*, Signature*
}

function Get-MDEStatus() {
  <#
    .SYNOPSIS
    This command returns various MDE status properties.
    .DESCRIPTION
    This command returns various MDE status properties.
  #>

  [CmdletBinding()]
  param()

  Get-MpComputerStatus | Select-Object AntispywareEnabled, AntispywareSignatureAge, AntispywareSignatureLastUpdated, AntispywareSignatureVersion, AntivirusEnabled, AntivirusSignatureAge, AntivirusSignatureLastUpdated, AntivirusSignatureVersion, BehaviorMonitorEnabled, DefenderSignaturesOutOfDate, DeviceControlPoliciesLastUpdated, FullScanOverdue, NISEnabled, NISEngineVersion, NISSignatureAge, NISSignatureLastUpdated, NISSignatureVersion, OnAccessProtectionEnabled, QuickScanAge, QuickScanOverdue, QuickScanSignatureVersion, RealTimeProtectionEnabled, RebootRequired
}

function Set-MDESignatureUpdateScheduledTask() {
  <#
    .SYNOPSIS
    This command creates a Windows scheduled task that runs hourly to update MDE signatures.
    .DESCRIPTION
    This command creates a Windows scheduled task that runs hourly to update MDE signatures. MUST BE RUN IN ELEVATED CONTEXT!
  #>

  [CmdletBinding()]
  param()

  # This assumes you have Powershell 7.x+ installed
  $action = New-ScheduledTaskAction -Execute "pwsh.exe" -Argument "-Command Update-MpSignature"
  # This is if you only have Windows Powershell 5.1 installed
  #$action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-Command Update-MpSignature"

  $hourly = (New-TimeSpan -Hours 1)
  $days = (New-TimeSpan -Days 365)
  $trigger = New-ScheduledTaskTrigger -Once -At 12am -RepetitionInterval $hourly -RepetitionDuration $days

  $principal = New-ScheduledTaskPrincipal -GroupId "BUILTIN\Administrators"

  Register-ScheduledTask -Action $action -Trigger $trigger -TaskName "MDE - Hourly Update" -Principal $principal
}

# ####################################################################################################
