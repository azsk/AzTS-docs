function Install-AzPowershell() {
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

function Uninstall-AzPowershell() {
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
