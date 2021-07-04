# . ".\Remediate-AnonymousAccessOnContainers.ps1"
# # Remove-AnonymousAccessOnContainers   -FailedControlsPath  'abb5301a-22a4-41f9-9e5f-99badff261f8.json'
# function WrapperScript
# {
    # PARAMETER FailedControlsPath
    # Json file path which contain failed controls detail to remediate.
    # Connect-AzAccount
    $files = @(Get-ChildItem FailedControls\*.json)
    #$currentLocation = Get-Location
    $count = 0
    [string]$totalCount = $files.Length
    foreach ($file in $files) {
        $count = $count + 1
        #Write-Host "Filename is [$($file)]" 
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        $uniqueControls = $JsonContent.UniqueControlList
        $countstr = [string]$count
        $str =  "Remediating this Subscription : $($SubscriptionId)  " + $count + "/" + $totalCount
	    Write-Host $str
        foreach ($uniqueControl in $uniqueControls){
            
            # Write-Host "URL is $($uniqueControl.url)"
            # if(-Not( Test-Path ($remediationScriptsLocation + $uniqueControl.file_name) )){
            #     Invoke-WebRequest -Uri  $uniqueControl.url -OutFile  $uniqueControl.file_name
            # }
            Write-Host "    Remediating the control : $($uniqueControl.controlId)"
            # Write-Host "Filename is $($uniqueControl.file_name)"
            . ("./" + "RemediationScripts\" + $uniqueControl.file_name)
            $commandString = $uniqueControl.init_command + " -FailedControlsPath " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" 
            # Write-Host "Command is $($commandString)"
            function runCommand($command) {
                if ($command[0] -eq '"') { Invoke-Expression "& $command" }
                else { Invoke-Expression $command }
            }
            runCommand($commandString)
        }
    }
# }
