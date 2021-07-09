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
        $str =  "Remediating Subscription (" + $count + "/" + $totalCount + "): $($SubscriptionId)  "
	    Write-Host
        Write-Host $str -ForegroundColor $([Constants]::MessageType.Warning)
        foreach ($uniqueControl in $uniqueControls){
            $remediate = $true
            if(Test-Path ($trackerPath) ){
                $trackerUniqueControls = $trackerFileContent.UniqueControlList
                foreach($uniqueControlTracker in $trackerUniqueControls){
                    if($uniqueControlTracker.controlId -eq $uniqueControl.controlId ){
                        if( ($uniqueControl.FailedResourceList.Length -eq $uniqueControlTracker.FailedResourceList.Length)){
                            $remediate = $false
                        }
                    }
                }
            }
            if($remediate){
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
    }

    # display summary
    Write-Host 
    Write-Host 
    Set-PSReadLineOption -Colors @{
        "Parameter"="#ff81f7"
        "Command"="Blue"
        "Error"=[ConsoleColor]::DarkRed
    }
    Write-Host "REMEDIATION SUMMARY"   -ForegroundColor $([Constants]::MessageType.Update)
    $summaryTable = @()
    foreach ($fname in $files) {
        $failedSubsContent =  Get-content -path $fname | ConvertFrom-Json
        $SubscriptionId = $failedSubsContent.SubscriptionId

        $trackerPath = "TrackerFilesGenerated\tracker_"+ $SubscriptionId +".Json"
        $trackerSubsContent =  Get-content -path $trackerPath | ConvertFrom-Json

        
        $failedUniqueControls = $failedSubsContent.UniqueControlList
        $trackerUniqueControls = $trackerSubsContent.UniqueControlList

        foreach ($controlObj in $failedUniqueControls)
        {
            foreach ($trackerControlObj in $trackerUniqueControls)
            {
                if ($controlObj.controlId -eq $trackerControlObj.controlId)
                {
                    $countFailedResources = $controlObj.FailedResourceList.Count
                    $countRemediatedResources = $trackerControlObj.FailedResourceList.Count
                    $summaryTable += [pscustomobject]@{SubscriptionId = $SubscriptionId; ControlId = $controlObj.controlId; FailedResources = $countFailedResources; RemediatedResources = $countRemediatedResources}
                }
            }
        }
       
        
    }

    $summaryTable | Format-Table
# }
class Constants
{
    static [Hashtable] $MessageType = @{
        Error = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info = [System.ConsoleColor]::Cyan
        Update = [System.ConsoleColor]::Green
	    Default = [System.ConsoleColor]::White
    }

    static [string] $DoubleDashLine    = "================================================================================"
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
}
