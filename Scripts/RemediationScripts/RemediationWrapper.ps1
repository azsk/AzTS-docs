# . ".\Remediate-AnonymousAccessOnContainers.ps1"
# # Remove-AnonymousAccessOnContainers   -FailedControlsPath  'abb5301a-22a4-41f9-9e5f-99badff261f8.json'
# function WrapperScript
# {
    # PARAMETER FailedControlsPath
    # Json file path which contain failed controls detail to remediate.
    Connect-AzAccount
    $files = @(Get-ChildItem *.json)
    #$currentLocation = Get-Location
    foreach ($file in $files) {
        #Write-Host "Filename is [$($file)]" 
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        $uniqueControls = $JsonContent.UniqueControlList
	    # Write-Host "SubscriptionId is $($SubscriptionId)"
        foreach ($uniqueControl in $uniqueControls){
            # Write-Host "URL is $($uniqueControl.url)"
            if(-Not( Test-Path ($remediationScriptsLocation + $uniqueControl.file_name) )){
                Invoke-WebRequest -Uri  $uniqueControl.url -OutFile  $uniqueControl.file_name
            }
            . ("./"+$uniqueControl.file_name)
            $commandString = $uniqueControl.init_command + " -FailedControlsPath " + "`'" + $SubscriptionId + ".json" + "`'" 
            # Write-Host "Command is $($commandString)"
            function runCommand($command) {
                if ($command[0] -eq '"') { Invoke-Expression "& $command" }
                else { Invoke-Expression $command }
            }
            runCommand($commandString)
        }
    }
# }
