<##########################################
Overview:
  This file contains functions to help remediate data factory plaintext secret issues

ControlId: 
  Azure_DataFactory_DP_Avoid_Plaintext_Secrets

DisplayName:
  Remediate Azure Data Factory plaintext secret issues.

Pre-requisites:
  1. Authenticated to Azure
  2. At least Contributor role on Data Factory

Steps to use:
  1. Download this file
  2. At a Powershell prompt or in your script file, dot-source this file: ```. ./Azure_DataFactory_DP_Avoid_Plaintext_Secrets.ps1```
  3. Call the functions with arguments

Examples:
  GetDataSets -SubscriptionId "00000000-0000-0000-0000-000000000000" -ResourceGroup "MyResourceGroup" -DataFactoryName "MyDataFactoryName"
########################################
#>

function GetFactory()
{
  <#
    .SYNOPSIS
    This command shows the data factory.
    .DESCRIPTION
    This command shows the data factory.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  az datafactory show --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName
}

function GetDataFlows()
{
  <#
    .SYNOPSIS
    This command lists data flow names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists data flow names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
    The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )

  az datafactory data-flow list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName `
    --query "[].[name, properties.scriptLines, properties.sources, properties.sinks, properties.transformations]"
}

function GetDataSets()
{
  <#
    .SYNOPSIS
    This command lists dataset names and parameters for datasets that have at least one parameter.
    .DESCRIPTION
    This command lists dataset names and parameters for datasets that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )
  az datafactory dataset list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName `
    --query "[?@.properties.parameters.*] | [].{dataSetName:name, parameters:properties.parameters}"
}

function GetIntegrationRuntimes()
{
  <#
    .SYNOPSIS
    This command lists pipeline names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists pipeline names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )
  az datafactory integration-runtime list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName #`
    #--query "[?@.parameters.*] | [].{pipelineName:name, parameters:parameters}"
}

function GetLinkedServices()
{
  <#
    .SYNOPSIS
    This command lists linked service names and parameters for linked services that have at least one parameter.
    .DESCRIPTION
    This command lists linked service names and parameters for linked services that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )
  az datafactory linked-service list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName `
    --query "[].{name:name, properties_credential:properties.credential, properties_encryptedCredential:properties.encryptedCredential, properties_parameters:properties.parameters}"
}

function GetPipelines()
{
  <#
    .SYNOPSIS
    This command lists pipeline names and parameters for pipelines that have at least one parameter.
    .DESCRIPTION
    This command lists pipeline names and parameters for pipelines that have at least one parameter. This is to review parameter values to try and locate parameters that may contain strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )
  az datafactory pipeline list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName `
    --query "[?@.parameters.*] | [].{pipelineName:name, parameters:parameters}"
}

function GetTriggers()
{
  <#
    .SYNOPSIS
    This command lists triggers.
    .DESCRIPTION
    This command lists triggers. This is to try and locate strings identified by the control as plaintext secrets.
    .PARAMETER SubscriptionId
        The Azure subscription ID containing the Data Factory.
    .PARAMETER ResourceGroup
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
      $ResourceGroup,
      [Parameter(Mandatory=$true)]
      [string]
      $DataFactoryName
  )
  az datafactory trigger list --verbose `
    --subscription $SubscriptionId `
    -g $ResourceGroup `
    --factory-name $DataFactoryName
}
