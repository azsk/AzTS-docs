$debug = $true

function Get-DataFactoryV2() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $factory = Get-AzDataFactoryV2 -ResourceGroupName $ResourceGroupName -Name $DataFactoryName

  Write-Debug -Debug:$debug -Message ("Data Factory: " + $factory.DataFactoryName)

  Write-Debug -Debug:$debug -Message "Tags:"
  if ($factory.Tags) {
    foreach ( $tag in $factory.Tags.GetEnumerator() ) {
      Write-Debug -Debug:$debug -Message "$($tag.Key) = $($tag.Value)"
    }
  }
  else {
    Write-Debug -Debug:$debug -Message "Data Factory has no Tags."
  }
}

function Get-DataFactoryV2DataFlows() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $dataflows = Get-AzDataFactoryV2DataFlow -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $dataFlows.Count -eq 0) {
    Write-Debug -Debug:$debug -Message "Data factory did not contain any Data Flows."
  }
  else {
    foreach ($dataflow in $dataflows) {
      Write-Debug -Debug:$debug -Message ("Dataflow: " + $dataflow.Name)
      Write-Debug -Debug:$debug -Message "Dataflow Script Lines:"
      $dataflows.Properties.ScriptLines
    }
  }

}

function Get-DataFactoryV2DataSets() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $datasets = Get-AzDataFactoryV2Dataset -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $datasets.Count -eq 0) {
    Write-Debug -Debug:$debug -Message "Data factory did not contain any Datasets."
  }
  else {
    foreach ($dataset in $datasets) {
      Write-Debug -Debug:$debug -Message ("Dataset: " + $dataset.Name)

      if ($dataset.Properties.Parameters) {
        Write-Debug -Debug:$debug -Message "Parameter Names and Values:"
        foreach ( $param in $dataset.Properties.Parameters.GetEnumerator() ) {
          Write-Debug -Debug:$debug -Message "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else {
        Write-Debug -Debug:$debug -Message "Dataset has no Parameters."
      }
    }
  }
}

function Get-DataFactoryV2LinkedServices() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $linkedServices = Get-AzDataFactoryV2LinkedService -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $linkedServices.Count -eq 0) {
    Write-Debug -Debug:$debug -Message "Data factory did not contain any Linked Services."
  }
  else {
    foreach ($linkedService in $linkedServices) {
      Write-Debug -Debug:$debug -Message ("Linked Service: " + $linkedService.Name)

      if ($linkedService.Properties.Parameters) {
        Write-Debug -Debug:$debug -Message "Parameter Names and Values:"
        foreach ( $param in $linkedService.Properties.Parameters.GetEnumerator() ) {
          Write-Debug -Debug:$debug -Message "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else {
        Write-Debug -Debug:$debug -Message "Linked Service has no Parameters."
      }
    }
  }
}

function Get-DataFactoryV2Pipelines() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DataFactoryName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $pipelines = Get-AzDataFactoryV2Pipeline -ResourceGroupName $ResourceGroupName -DataFactoryName $DataFactoryName

  if ( $pipelines.Count -eq 0) {
    Write-Debug -Debug:$debug -Message "Data factory did not contain any Pipelines."
  }
  else {
    foreach ($pipeline in $pipelines) {
      Write-Debug -Debug:$debug -Message ("Pipeline: " + $pipeline.Name)

      if ($pipeline.Properties.Parameters) {
        Write-Debug -Debug:$debug -Message "Parameter Names and Values:"
        foreach ( $param in $pipeline.Parameters.GetEnumerator() ) {
          Write-Debug -Debug:$debug -Message "$($param.Key) = $($param.Value.DefaultValue)"
        }
      }
      else {
        Write-Debug -Debug:$debug -Message "Pipeline has no Parameters."
      }
    }
  }
}
