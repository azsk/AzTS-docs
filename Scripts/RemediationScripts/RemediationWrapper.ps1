# function rollback
# {
#     $files = @(Get-ChildItem FailedControls\*.json)
#     foreach ($file in $files) {
#         $JsonContent =  Get-content -path $file | ConvertFrom-Json
#         $subscriptionId = $JsonContent.SubscriptionId
#         $uniqueControls = $JsonContent.ControlRemediationList
#         $logFiles =  @(Get-ChildItem Rollback\$($subscriptionid.replace("-","_"))\*\*)
#         Write-Host "logfiles" + $logFiles
#         foreach ($logFile in $logFiles){
#             $split = ([String]$logFile).split('\')
#             $controlId = $split[$split.Length - 1]
#             foreach ($uniqueControl in $uniqueControls){
#                 if($uniqueControl.controlId -eq $controlId){
#                     $controlMetadata = $uniqueControl
#                     Write-Host "CM "+$controlMetadata
#                     break
#                 }
#             }
#             . ("./" + "RemediationScripts\" + $controlMetadata.LoadCommand)
#             $rollbackFiles = @(Get-ChildItem $logFile\*.json)
#             foreach ($rollbackFile in $rollbackFiles){
#                 $commandString = $controlMetadata.RollbackCommand + " -SubscriptionId " + "`'" + $subscriptionid + "`'" + " -RollBackType " + "`'" + "EnableAllowBlobPublicAccessOnStorage" + "`'" + " -Path " + "`'" + $rollbackFile + "`'" 
#                 Write-Host $commandString
#                 break;
#                 function runCommand($command) {
#                     if ($command[0] -eq '"') { Invoke-Expression "& $command" }
#                     else { Invoke-Expression $command }
#                 }
#                 runCommand($commandString)
#             }
#         }
#     }
# }
function remediate{
    $files = @(Get-ChildItem FailedControls\*.json)
    $count = 0
    [string]$totalCount = $files.Length
    foreach ($file in $files) {
        $count = $count + 1
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        $uniqueControls = $JsonContent.ControlRemediationList
        $trackerPath = "TrackerFilesGenerated\tracker_" + $($SubscriptionId) +".Json"
        $str =  "Remediating Subscription (" + $count + "/" + $totalCount + "): $($SubscriptionId)  "
        Write-Host $str -ForegroundColor $([Constants]::MessageType.Warning)
        
        foreach ($uniqueControl in $uniqueControls){
            $remediate = $true
            if(Test-Path ($trackerPath) ){
                $trackerUniqueControls = $trackerFileContent.ControlRemediationList
                foreach($uniqueControlTracker in $trackerUniqueControls){
                    if($uniqueControlTracker.controlId -eq $uniqueControl.controlId ){
                        if( ($uniqueControl.FailedResourceList.Length -eq $uniqueControlTracker.FailedResourceList.Length)){
                            $remediate = $false
                        }
                    }
                }
            }
            if($remediate){
                . ("./" + "RemediationScripts\" + $uniqueControl.LoadCommand)       
                $commandString = $uniqueControl.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -RemediationType " + "DisableAllowBlobPublicAccessOnStorage" + " -FailedControlsPath " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + "-AutoRemediation y";
                    Write-Host "Command is $($commandString)"
                function runCommand($command) {
                    if ($command[0] -eq '"') { Invoke-Expression "& $command" }
                    else { Invoke-Expression $command }
                }
                runCommand($commandString)
            }
            
        }
    }

    # Display Summary
    Write-Host 
    Write-Host 
    Set-PSReadLineOption -Colors @{
        "Parameter"="#ff81f7"
        "Command"="Blue"
        "Error"=[ConsoleColor]::DarkRed
    }
    Write-Host "REMEDIATION SUMMARY"   -ForegroundColor $([Constants]::MessageType.Update)
    $summaryTable = @()
    foreach ($file in $files) {
        $failedSubsContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $failedSubsContent.SubscriptionId
        
        $trackerPath = "TrackerFilesGenerated\tracker_"+ $SubscriptionId +".Json"
        $trackerSubsContent =  Get-content -path $trackerPath | ConvertFrom-Json

        
        $failedUniqueControls = $failedSubsContent.ControlRemediationList
        $trackerUniqueControls = $trackerSubsContent.ControlRemediationList

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
}
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

#Execution begins here
$trackerFiles = @(Get-ChildItem TrackerFilesGenerated\*.json)
if($trackerFiles.Length -gt 0){
    $continueRemediation = Read-Host -Prompt "A previous remediation has been detected. Do you want to continue the remediation? (y/n)"
    if($continueRemediation -eq "y"){
        remediate
    }
    else{
        Write-Host "Exiting..."
    }
    # elseif($continueRemediation -eq "n"){
    #     $rollback = Read-Host -Prompt "Do you want to rollback all the remediated controls to the state before the remediation has been done? (y/n)"
    #     if($rollback -eq "y"){
    #         rollback
    #     }
    #     elseif($rollback -eq "n"){
    #         Write-Host "Please select one of the 2 above options."
    #     }
    #     else{
    #         Write-Host "Please enter either y or n"
    #     }
    # }
    # else{
    #     Write-Host "Please enter either y or n"
    # }
}
else{
    $startRemediation = Read-Host -Prompt "Do you want to start remediation? (Press y for Yes)"
    if($startRemediation -eq "y"){
        Write-Host "Proceeding to start the remediation."
        remediate
    }else{
        Write-Host "Exiting"
    }
    
}