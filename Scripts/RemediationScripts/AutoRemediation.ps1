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
        Write-Host $([Constants]::DoubleDashLine)
        $str =  "Starting Remediating Subscription (" + $count + "/" + $totalCount + "): $($SubscriptionId)  "
        Write-Host $str -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Following resources will be remediated :" -ForegroundColor $([Constants]::MessageType.Warning)
        #resource
        $resources = @()
        foreach($uniqueControl in $uniqueControls){
            foreach($failedResources in $uniqueControl.FailedResourceList){
                $resources += [PSCustomObject]@{
                    ControlId = $uniqueControl.ControlId;
                    ResourceGroupName = $failedResources.ResourceGroupName;
                    ResourceName = $failedResources.ResourceName;
                    ResourceId = $failedResources.ResourceId;
                }
            }
        }
        $resources | Format-Table
        $continueRemediation = Read-Host -Prompt "Do you want to continue? (Press y for Yes)";
        if($continueRemediation -ne "y") {continue;}

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
    if($summaryTable.count -gt 0){
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Remediation Summary" -ForegroundColor $([Constants]::MessageType.Update)
        $summaryTable | Format-Table
        Write-Host $([Constants]::SingleDashLine)
    }
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

    static [string] $DoubleDashLine    = "=========================================================================================="
    static [string] $SingleDashLine    = "--------------------------------------------------------------------------------"
}   

function PrintSubscription{
    $failedControlsFiles = @(Get-ChildItem FailedControls\*.json);
    $filesCount = 1;
    foreach($file in $failedControlsFiles){
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        Write-Host $filesCount . $SubscriptionId
        $filesCount = $filesCount + 1
    }
}
function StartOperation{
    $failedControlsFiles = @(Get-ChildItem FailedControls\*.json);
    #$trackerFile = $trackerPath = "TrackerFilesGenerated\tracker_" + $($SubscriptionId) +".Json"
    $filesCount = 1;
    foreach($file in $failedControlsFiles){
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        $trackerFile = "TrackerFilesGenerated\tracker_" + $($SubscriptionId) + ".json"
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Starting operation on Subscription Id: " $SubscriptionId -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)
        # Write-Host "`n"
        # Display unique controls and no of resources.
        $controlRemediationList = $JsonContent.ControlRemediationList
        $controlsTable = @()
        foreach($control in $controlRemediationList){
            $controlsTable+= [PSCustomObject]@{
                ControlId = $control.ControlId;
                NumberOfFailedResources = $control.FailedResourceList.Length;
            }
        }
        $controlsTable | Format-Table
        #DO you want to dry run

        if(Test-Path $trackerFile){
            Write-Host "The remediation operation has already been performed on the subscription. You can check the log file at $($trackerFile)".
            $startRemediation = Read-Host -Prompt "Do you want to again remediate the subscription? (Y/N)";
        }else{
            $startRemediation = Read-Host -Prompt "Do you want to continue remediation? (Y/N)";
        }
        if($startRemediation -eq 'Y'){
            try{
                if(Test-Path $trackerFile){
                    Remove-Item $trackerFile
                }
                $null = New-Item -ItemType File -Path $trackerFile -Force -ErrorAction Stop
                $JsonObjDic = @{}
                $JsonObjDic.Add("SubscriptionId",$SubscriptionId)
                $JsonArray = @()
                foreach($control in $controlRemediationList){
                    $JsonObject = @{}
                    $JsonObject.Add("ControlId",$control.ControlId)
                    $list = New-Object System.Collections.ArrayList
                    $JsonObject.Add("RemediatedResources", $list)
                    $JsonArray+=$JsonObject
                }
                $JsonObjDic.Add("RemediatedList",$JsonArray)
                $JsonObjDic | ConvertTo-json -depth 100  | Out-File $trackerFile
            }catch{
                throw $_.Exception.Message
            }
            foreach($control in $controlRemediationList){
                #$tracker = Get-content -Raw -path $trackerFile | ConvertFrom-Json 
               
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Executing remediation script : " $control.LoadCommand -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "`n"
                Write-Host $([Constants]::DoubleDashLine)

                . ("./" + "RemediationScripts\" + $control.LoadCommand)       
                $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -RemediationType " + "DisableAllowBlobPublicAccessOnStorage" + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + "-AutoRemediation y";
                function runCommand($command) {
                    if ($command[0] -eq '"') { Invoke-Expression "& $command" }
                    else { Invoke-Expression $command }
                }
                runCommand($commandString)

                Write-Host $([Constants]::DoubleDashLine)
            }
        }
        #tracker file formation
        #Do we need tracker file? No
        # Print the remediation summary.
        #$tracker = Get-Content -Raw -Path $trackerFile | ConvertFrom-Json
    }
}
function PrintSummary{
    Write-Host "Remediation Summary" -ForegroundColor $([Constants]::MessageType.Update)
    $trackerFiles = @(Get-ChildItem TrackerFilesGenerated\*.json);
    $remediationSummary = @()
    foreach($file in $trackerFiles){
        $JsonContent = Get-Content -Path $file | ConvertFrom-Json
        foreach($tracker in $JsonContent.RemediatedList){
            $remediationSummary+=[PSCustomObject]@{
                "SubscriptionId" = $JsonContent.SubscriptionId;
                "ControlId" = $tracker.ControlId;
                "NumberOfRemediatedResources" = $tracker.RemediatedResources.Length;
            }
        }
    }
    $remediationSummary | Format-Table
}
#Execution begins here
$introduction = "The Script remediate all the failing scan results for which the metadata has been downloaded. (present at 'FailedControls' folder of the current folder)";
$subscriptionDetails = "The Subscriptions are : ";
Write-Host $introduction -ForegroundColor $([Constants]::MessageType.Info)
Write-Host "Disclaimer : Each remediation script requires different permission to run." -ForegroundColor $([Contants]::MessageType.Warning)
Write-Host "`n"
Write-Host $subscriptionDetails 
PrintSubscription
Write-Host "`n"
Write-Host $([Constants]::DoubleDashLine)
StartOperation
PrintSummary