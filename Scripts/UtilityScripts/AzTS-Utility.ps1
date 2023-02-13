
# ####################################################################################################
# Powershell Execution Policy

# To run this or other downloaded scripts, you may need to set your Powershell execution policy.
# Reference: https://learn.microsoft.com/powershell/module/microsoft.powershell.core/about/about_execution_policies

# To run a script like this
# Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope CurrentUser

# To then reset the execution policy either to default (Restricted) or RemoteSigned
# Set-ExecutionPolicy -ExecutionPolicy Default -Scope CurrentUser
# Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# ####################################################################################################

# ####################################################################################################
# Azure Powershell Utility Methods

function Remove-AllAzPowershell()
{
  Get-Package | Where-Object { $_.Name -Like 'Az*' } | ForEach-Object { Uninstall-Package -Name $_.Name -AllVersions }
}

function Install-AzPowershell()
{
  Install-Module -Name Az
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

  $ftpConfigs = [ordered]@{ "Production" = $appService.SiteConfig.FtpsState }

  # List of slots in Get-AzWebAppSlot has full slot name. SiteConfig is blank on those.
  # So we have to get just the bare slot name, then call Get-AzWebAppSlot for it to get the SiteConfig and FtpsState.
  ForEach ($slotNameRaw in (Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName).Name)
  {
    $slotName = $slotNameRaw.Replace($AppName + "/", "")
    $slot = Get-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName -Slot $slotName
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
    .PARAMETER AppName
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
    $AppName,
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
    Set-AzWebApp -ResourceGroupName $ResourceGroupName -Name $AppName -FtpsState $FtpState
  }
  else
  {
    if ($SlotName.StartsWith($AppName))
    {
      $SlotName = $SlotName.Replace($AppName + "/", "")
    }

    Set-AzWebAppSlot -ResourceGroupName $ResourceGroupName -Name $AppName -Slot $SlotName -FtpsState $FtpState
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
# Azure_KeyVault_NetSec_Disable_Public_Network_Access

# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_AuthZ_Remove_Deprecated_Accounts

# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_DP_Avoid_Plaintext_Secrets_Deployments

# ####################################################################################################

# ####################################################################################################
# Azure_Subscription_SI_Dont_Use_B2C_Tenant

# ####################################################################################################

# ####################################################################################################
# Azure_VirtualMachine_SI_Enable_Antimalware

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
