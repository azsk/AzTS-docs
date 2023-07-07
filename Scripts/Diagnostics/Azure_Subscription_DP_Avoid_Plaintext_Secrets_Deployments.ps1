$debug = $true

function Get-ResourceGroupDeployment() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $false)]
    [string]
    $DeploymentName = ""
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  if ([string]::IsNullOrWhiteSpace($DeploymentName)) {
    $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName
  }
  else {
    $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName -Name $DeploymentName
  }

  foreach ($deployment in $deployments) {
    Write-Debug -Debug:$debug -Message ("Deployment: " + $deployment.DeploymentName)

    if ( $deployment.Parameters -and $deployment.Parameters.Count -gt 0 ) {
      Write-Debug -Debug:$debug -Message ("Parameters:")

      foreach ( $parameter in $deployment.Parameters.GetEnumerator() ) {
        Write-Debug -Debug:$debug -Message "$($parameter.Key) = $($parameter.Value.Value)"
      }
    }
    else {
      Write-Debug -Debug:$debug -Message "Parameters: Deployment has no Parameters"
    }
  }

}

function Get-ResourceGroupDeploymentOperations() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName,
    [Parameter(Mandatory = $true)]
    [string]
    $DeploymentName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroupName -Name $DeploymentName
}

function Get-ResourceGroupDeploymentsAndOperations() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId,
    [Parameter(Mandatory = $true)]
    [string]
    $ResourceGroupName
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $deployments = Get-AzResourceGroupDeployment -ResourceGroupName $ResourceGroupName

  foreach ($deployment in $deployments) {
    Write-Debug -Debug:$debug -Message ("Deployment: " + $deployment.DeploymentName)

    Get-AzResourceGroupDeploymentOperation -ResourceGroupName $ResourceGroupName -Name $deployment.DeploymentName
  }
}

function Get-SubscriptionDeployments() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  Get-AzDeployment
}

function Get-SubscriptionDeploymentsAndOperations() {
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
    [Parameter(Mandatory = $true)]
    [string]
    $SubscriptionId
  )

  $profile = Set-AzContext -Subscription $SubscriptionId

  $deployments = Get-AzDeployment

  foreach ($deployment in $deployments) {
    Write-Debug -Debug:$debug -Message ("Deployment: " + $deployment.DeploymentName)

    Get-AzDeploymentOperation -DeploymentName $deployment.DeploymentName
  }
}
