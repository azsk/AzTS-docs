using namespace System.Management.Automation

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
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Install-AzPowershell
    .LINK
    None
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
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Uninstall-AzPowershell
    .LINK
    None
  #>

  [CmdletBinding()]
  param ()

  Get-Package | Where-Object { $_.Name -Like 'Az*' } | ForEach-Object { Uninstall-Package -Name $_.Name -AllVersions }
}

# H/T to Kieran Marron https://blog.kieranties.com/2018/03/26/write-information-with-colours
function Write-InformationFormatted()
{
    <#
    .SYNOPSIS
    This function adds text color to Write-Information
    .DESCRIPTION
    This function adds text color to Write-Information
    .PARAMETER MessageData
    The message to write
    .PARAMETER ForegroundColor
    Text color
    .PARAMETER BackgroundColor
    Background color
    .PARAMETER NoNewline
    Switch whether to suppress new line
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Write-InformationFormatted -MessageData "Hello Wordl" -ForegroundColor Blue
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory)]
      [Object]
      $MessageData,
      [ConsoleColor]
      $ForegroundColor = $Host.UI.RawUI.ForegroundColor, # Make sure we use the current colours by default
      [ConsoleColor]
      $BackgroundColor = $Host.UI.RawUI.BackgroundColor,
      [Switch]
      $NoNewline
  )

  $msg = [HostInformationMessage]@{
      Message         = $MessageData
      ForegroundColor = $ForegroundColor
      BackgroundColor = $BackgroundColor
      NoNewline       = $NoNewline.IsPresent
  }

  Write-Information -MessageData $msg -InformationAction Continue
}

# ####################################################################################################

# ####################################################################################################
# Control Utility functions

function Get-MyPublicIpAddress()
{
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

  if ("200" -eq "$statusCode")
  {
    # Get my public IP address
    $myPublicIpAddress = Invoke-RestMethod "$ipUrl"
    $myPublicIpAddress += "/32"

    Write-InformationFormatted -MessageData "Got my public IP address: $myPublicIpAddress."
  }
  else
  {
    Write-InformationFormatted -MessageData "Error! Could not get my public IP address." -ForegroundColor Red
  }

  return $myPublicIpAddress
}

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
    The Azure subscription ID containing the App Service to be remediated.
    .PARAMETER ResourceGroupName
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .INPUTS
    None
    .OUTPUTS
    Dictionary whose keys are App Service slot names, and whose values are the corresponding slot FTP settings.
    .EXAMPLE
    PS> Get-AppServiceFtpState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName"
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
    The Resource Group name containing the App Service.
    .PARAMETER AppServiceName
    The App Service name.
    .PARAMETER SlotName
    If a non-production slot's FTP state is being set, provide the slot name. To set the default production slot FTP state, do not specify this parameter.
    .PARAMETER FtpState
    The FTP State to set. Either "Disabled" or "FtpsOnly". Defaults to "Disabled".
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-AppServiceFtpState -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -AppServiceName "MyAppServiceName" -SlotName "MyNonProductionSlotName" -FtpState "Disabled"
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
    # Check if the slot name that was passed is prepended with the App Service Name and slash
    # Get-AzWebAppSlot returns slots in that format, but Set-AzWebAppSlot wants only the slot name without the prepended app svc name and slash
    # Mitigate possible corner case here by checking for app svc name AND slash
    if ($SlotName.StartsWith($AppServiceName + "/"))
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
    The Resource Group name containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
    .INPUTS
    None
    .OUTPUTS
    Text with the Data Factory name and its Tag names/values.
    .EXAMPLE
    PS> Get-DataFactoryV2 -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DataFactoryName "MyDataFactoryName"
    .LINK
    None
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

  $factory = Get-AzDataFactoryV2 -ResourceGroupName $ResourceGroupName -Name $DataFactoryName

  Write-InformationFormatted -MessageData ("Data Factory: " + $factory.DataFactoryName)

  Write-InformationFormatted -MessageData "Tags:"
  if ($factory.Tags)
  {
    foreach ( $tag in $factory.Tags.GetEnumerator() )
      {
        Write-InformationFormatted -MessageData "$($tag.Key) = $($tag.Value)"
      }
  }
  else
  {
    Write-InformationFormatted -MessageData "Data Factory has no Tags."
  }
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
    The Resource Group name containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
    .INPUTS
    None
    .OUTPUTS
    For each Data Flow, text with the Data Flow name and its script lines, which begin with parameters and default parameter values.
    .EXAMPLE
    PS> Get-DataFactoryV2DataFlows -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DataFactoryName "MyDataFactoryName"
    .LINK
    None
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

  $dataflows = Get-AzDataFactoryV2DataFlow -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $dataFlows.Count -eq 0)
  {
    Write-InformationFormatted -MessageData "Data factory did not contain any Data Flows."
  }
  else
  {
    foreach ($dataflow in $dataflows)
    {
      Write-InformationFormatted -MessageData ("Dataflow: " + $dataflow.Name)
      Write-InformationFormatted -MessageData "Dataflow Script Lines:"
      $dataflows.Properties.ScriptLines
    }
  }

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
    The Resource Group name containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
    .INPUTS
    None
    .OUTPUTS
    For each Dataset, text with the Dataset name and its parameter names and values.
    .EXAMPLE
    PS> Get-DataFactoryV2DataSets -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DataFactoryName "MyDataFactoryName"
    .LINK
    None
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

  $datasets = Get-AzDataFactoryV2Dataset -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $datasets.Count -eq 0)
  {
    Write-InformationFormatted -MessageData "Data factory did not contain any Datasets."
  }
  else
  {
    foreach ($dataset in $datasets)
    {
      Write-InformationFormatted -MessageData ("Dataset: " + $dataset.Name)

      if ($dataset.Properties.Parameters)
      {
        Write-InformationFormatted -MessageData "Parameter Names and Values:"
        foreach ( $param in $dataset.Properties.Parameters.GetEnumerator() )
        {
          Write-InformationFormatted -MessageData "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else
      {
        Write-InformationFormatted -MessageData "Dataset has no Parameters."
      }
    }
  }
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
    The Resource Group name containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
    .INPUTS
    None
    .OUTPUTS
    For each Linked Service, text with the Linked Service name and its parameter names and values.
    .EXAMPLE
    PS> Get-DataFactoryV2LinkedServices -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DataFactoryName "MyDataFactoryName"
    .LINK
    None
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

  $linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $linkedServices.Count -eq 0)
  {
    Write-InformationFormatted -MessageData "Data factory did not contain any Linked Services."
  }
  else
  {
    foreach ($linkedService in $linkedServices)
    {
      Write-InformationFormatted -MessageData ("Linked Service: " + $linkedService.Name)

      if ($linkedService.Properties.Parameters)
      {
        Write-InformationFormatted -MessageData "Parameter Names and Values:"
        foreach ( $param in $linkedService.Properties.Parameters.GetEnumerator() )
        {
          Write-InformationFormatted -MessageData "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else
      {
        Write-InformationFormatted -MessageData "Linked Service has no Parameters."
      }
    }
  }
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
    The Resource Group name containing the Data Factory.
    .PARAMETER DataFactoryName
    The Data Factory name.
    .INPUTS
    None
    .OUTPUTS
    For each Pipeline, text with the Pipeline name and its parameter names and values.
    .EXAMPLE
    PS> Get-DataFactoryV2Pipelines -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DataFactoryName "MyDataFactoryName"
    .LINK
    None
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

  $pipelines = Get-AzDataFactoryV2Pipeline -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $pipelines.Count -eq 0)
  {
    Write-InformationFormatted -MessageData "Data factory did not contain any Pipelines."
  }
  else
  {
    foreach ($pipeline in $pipelines)
    {
      Write-InformationFormatted -MessageData ("Pipeline: " + $pipeline.Name)

      if ($pipeline.Properties.Parameters)
      {
        Write-InformationFormatted -MessageData "Parameter Names and Values:"
        foreach ( $param in $pipeline.Parameters.GetEnumerator() )
        {
          Write-InformationFormatted -MessageData "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else
      {
        Write-InformationFormatted -MessageData "Pipeline has no Parameters."
      }
    }
  }
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

  Write-InformationFormatted -MessageData "Retrieve the Require SSL State value to ensure it was updated correctly:"
  Get-MySqlFlexServerSslState -SubscriptionId "$SubscriptionId" -ResourceGroupName "$ResourceGroupName" -ServerName "$ServerName"
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
  Write-InformationFormatted -MessageData "Since TLSVersion is a static server parameter, the MySQL Flexible Server will now be restarted."
  Write-InformationFormatted -MessageData "PLEASE NOTE: this will briefly affect MySQL Flexible Server availability."
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

function Get-AppServiceAllCurrentOutboundPublicIps()
{
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

function Set-KeyVaultSecurePublicNetworkSettings()
{
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

    Write-InformationFormatted -MessageData "Result status code was " + $result.StatusCode -ForegroundColor Cyan

    if ("200" -ne $result.StatusCode)
    {
      $result
    }
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

  if ($myPublicIpAddress)
  {
    Set-KeyVaultPublicNetworkAccessEnabledForIpAddress `
      -SubscriptionId $SubscriptionId `
      -ResourceGroupName $ResourceGroupName `
      -KeyVaultName $KeyVaultName `
      -PublicIpAddress $myPublicIpAddress

    Write-InformationFormatted -MessageData "Added my public IP address $myPublicIpAddress to Key Vault network access rules." -ForegroundColor Green
  }
  else
  {
    Write-InformationFormatted -MessageData "Unable to get my public IP address. No change made to Key Vault network access rules." -ForegroundColor Red
  }
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
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER PublicIpAddresses
    An array of public IP address to grant access to the Key Vault.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultPublicNetworkAccessEnabledForIpAddresses -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName" -PublicIpAddresses "1.1.1.1","1.1.1.2","1.1.1.3"
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
    $PublicIpAddresses
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $keyVault = Get-AzKeyVault -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName

  $needToUpdate = $false

  if ($keyVault.NetworkAcls.IpAddressRanges)
  {
    $ipAddressRanges = $keyVault.NetworkAcls.IpAddressRanges
  }
  else
  {
    $ipAddressRanges = @()
  }

  foreach($ipAddress in $PublicIpAddresses)
  {
    # Check if the Key Vault network ACLs already contain my public IP address
    If ($ipAddressRanges.Contains($ipAddress))
    {
      Write-InformationFormatted -MessageData "Current Key Vault public IP address range already contains $ipAddress."
    }
    Else
    {
      $ipAddressRanges += $ipAddress
      $needToUpdate = $true
      Write-InformationFormatted -MessageData "Added IP address $ipAddress to Key Vault address address ranges."
    }
  }

  If ($needToUpdate)
  {
    Write-InformationFormatted -MessageData "Update Key Vault network access rules."

    If ($keyVault.NetworkAcls.VirtualNetworkResourceIds.Count -eq 0)
    {
      Write-InformationFormatted -MessageData "Update Key Vault network access rules for specified source IPs network access rules."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange $ipAddressRange
    }
    else
    {
      Write-InformationFormatted -MessageData "Update Key Vault network access rules for specified source IPs and existing VNet network access rules."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange $ipAddressRange `
        -VirtualNetworkResourceId $keyVault.NetworkAcls.VirtualNetworkResourceIds
    }
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
    The Resource Group name containing the Key Vault.
    .PARAMETER KeyVaultName
    The Key Vault name.
    .PARAMETER PublicIpAddress
    The public IP address to grant access to the Key Vault.
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-KeyVaultPublicNetworkAccessEnabledForIpAddress -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -KeyVaultName "MyKeyVaultName" -PublicIpAddress "1.1.1.1"
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
    [string]
    $PublicIpAddress
  )

  # IP Address range: What is currently on the Key Vault PLUS (if not already) the current public IP address
  # VNet rules: Maintain what is currently on the Key Vault - the context here is public network access, no op on VNet rules

  $profile = Set-AzContext -Subscription $SubscriptionId

  $keyVault = Get-AzKeyVault -SubscriptionId $SubscriptionId -ResourceGroupName $ResourceGroupName -VaultName $KeyVaultName

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

  # Check if the Key Vault network ACLs already contain my public IP address
  If ($ipAddressRange.Count -gt 0 -and $ipAddressRange.Contains($PublicIpAddress))
  {
    $needToUpdateIps = $false
    Write-InformationFormatted -MessageData "Current Key Vault public IP address range already contains $PublicIpAddress, no change will be made to source IP network ACLs."
  }
  Else
  {
    $needToUpdateIps = $true  # Yes, this is redundant to start condition above. Regardless, set explicitly here in case someone changes the start condition later.
    $ipAddressRange += $PublicIpAddress
    Write-InformationFormatted -MessageData "Added my public IP address $PublicIpAddress for new complete source IP address range: $ipAddressRange."
  }

  # If the source IPs need to be updated, do that here
  If ($needToUpdateIps)
  {
    Write-InformationFormatted -MessageData "Update Key Vault network access rules."

    If ($keyVault.NetworkAcls.VirtualNetworkResourceIds.Count -eq 0)
    {
      Write-InformationFormatted -MessageData "Update Key Vault network access rules for specified source IPs network access rules."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange $ipAddressRange
    }
    else
    {
      Write-InformationFormatted -MessageData "Update Key Vault network access rules for specified source IPs and existing VNet network access rules."
      Update-AzKeyVaultNetworkRuleSet `
        -SubscriptionId $SubscriptionId `
        -ResourceGroupName $ResourceGroupName `
        -VaultName $KeyVaultName `
        -IpAddressRange $ipAddressRange `
        -VirtualNetworkResourceId $keyVault.NetworkAcls.VirtualNetworkResourceIds
    }
  }
}

function Remove-KeyVaultNetworkAccessRuleForIpAddress()
{
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

  $profile = Set-AzContext -Subscription $SubscriptionId

  Write-InformationFormatted -MessageData "Removing rule for $PublicIpAddress"

  Remove-AzKeyVaultNetworkRule `
    -SubscriptionId $SubscriptionId `
    -ResourceGroupName $ResourceGroupName `
    -VaultName $KeyVaultName `
    -IpAddressRange $PublicIpAddress
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
    [Parameter(Mandatory=$true)]
    [string]
    $DeletedObjectId
  )

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
    .INPUTS
    None
    .OUTPUTS
    [PSResourceGroupDeployment](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psresourcegroupdeployment)
    .EXAMPLE
    PS> Get-ResourceGroupDeployment -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DeploymentName "MyDeploymentName"
    .LINK
    None
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

  if ([string]::IsNullOrWhiteSpace($DeploymentName))
  {
    $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName
  }
  else
  {
    $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $DeploymentName
  }

  foreach ($deployment in $deployments)
  {
    Write-InformationFormatted -MessageData ("Deployment: " + $deployment.DeploymentName) -ForegroundColor Green

    if ( $deployment.Parameters -and $deployment.Parameters.Count -gt 0 )
    {
      Write-InformationFormatted -MessageData ("Parameters:")

      foreach ( $parameter in $deployment.Parameters.GetEnumerator() )
      {
          Write-InformationFormatted -MessageData "$($parameter.Key) = $($parameter.Value.Value)" -ForegroundColor Blue
      }
    }
    else
    {
      Write-InformationFormatted -MessageData "Parameters: Deployment has no Parameters"
    }

    Write-InformationFormatted -MessageData ""
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
    .INPUTS
    None
    .OUTPUTS
    [PSDeploymentOperation](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psdeploymentoperation)
    .EXAMPLE
    PS> Get-ResourceGroupDeploymentOperations -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName" -DeploymentName "MyDeploymentName"
    .LINK
    None
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

  Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroupName -Name $DeploymentName
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
    .INPUTS
    None
    .OUTPUTS
    For each deployment: text with each deployment name, and [PSDeploymentOperation](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psdeploymentoperation)
    .EXAMPLE
    PS> Get-ResourceGroupDeploymentsAndOperations -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ResourceGroupName "MyResourceGroupName"
    .LINK
    None
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

  $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName

  foreach ($deployment in $deployments)
  {
    Write-InformationFormatted -MessageData ("Deployment: " + $deployment.DeploymentName)

    Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroupName -Name $deployment.DeploymentName
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
    .INPUTS
    None
    .OUTPUTS
    [PSDeployment](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psdeployment)
    .EXAMPLE
    PS> Get-SubscriptionDeployments -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
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
    .INPUTS
    None
    .OUTPUTS
    For each deployment: text with each deployment name, and [PSDeploymentOperation](https://learn.microsoft.com/dotnet/api/microsoft.azure.commands.resourcemanager.cmdlets.sdkmodels.psdeploymentoperation)
    .EXAMPLE
    PS> Get-SubscriptionDeploymentsAndOperations -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000"
    .LINK
    None
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
    Write-InformationFormatted -MessageData ("Deployment: " + $deployment.DeploymentName)

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
      [Parameter(Mandatory=$true)]
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

  if ($tenants.Count -gt 0)
  {
    ForEach ($tenant in $tenants)
    {
      Write-InformationFormatted -MessageData ("B2C Tenant Name: " + $tenant.name) -ForegroundColor Green
      Write-InformationFormatted -MessageData ("B2C Tenant ID: " + $tenant.id) -ForegroundColor Blue
      Write-InformationFormatted -MessageData ""
    }
  }
  else
  {
    Write-InformationFormatted -MessageData "Subscription contains no B2C tenants."
  }
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
    .INPUTS
    None
    .OUTPUTS
    Text with names and values of several MDE preference configuration settings.
    .EXAMPLE
    PS> Get-MDEPreferences
    .LINK
    None
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
    .INPUTS
    None
    .OUTPUTS
    Text with names and values of several MDE status properties.
    .EXAMPLE
    PS> Get-MDEStatus
    .LINK
    None
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
    .INPUTS
    None
    .OUTPUTS
    None
    .EXAMPLE
    PS> Set-MDESignatureUpdateScheduledTask
    .LINK
    None
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
