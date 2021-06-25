# . ".\Remediate-AnonymousAccessOnContainers.ps1"
# # Remove-AnonymousAccessOnContainers   -FailedControlsPath  'abb5301a-22a4-41f9-9e5f-99badff261f8.json'
# function WrapperScript
# {
    # PARAMETER FailedControlsPath
    # Json file path which contain failed controls detail to remediate.
    $files = @(Get-ChildItem JSONFiles\*.json)
    foreach ($file in $files) {
        Write-Host "Filename is [$($file)]" 
    }
# }
