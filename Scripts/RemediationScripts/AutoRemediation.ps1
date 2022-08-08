function PrintGeneralInformation
{
    $scriptInformation = "**General Information**
[1]. All the failing controls, which have been downloaded using AzTS UI, are present at [$(Get-location)\FailedControls] and same will be referred for remediation.
[2]. Remediation scripts will be used to fix the failing controls in bulk.
[3]. Minimum of contributor role at a subscription level is required for running BRS(Bulk Remediation Scripts) in most of the case, some may even require a higher priviledge access over a subscription";
    Write-Host $([Constants]::DoubleDashLine)
    Write-Host $scriptInformation -ForegroundColor $([Constants]::MessageType.Warning)
    Write-Host $([Constants]::SingleDashLine)
} 

function PrintSubscriptions
{
    $failedControlsFiles = @(Get-ChildItem FailedControls\*.json);
    Write-Host "Following subscriptions will be remediated:"
    $filesCount = 1;
    foreach($file in $failedControlsFiles)
    {
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        Write-Host $filesCount . $SubscriptionId
        $filesCount = $filesCount + 1
    }
}

function StartRemediation($timestamp)
{
    $failedControlsFiles = @(Get-ChildItem FailedControls\*.json);
    foreach($file in $failedControlsFiles)
    {
        $JsonContent =  Get-content -path $file | ConvertFrom-Json
        $SubscriptionId = $JsonContent.SubscriptionId
        $logFile = "LogFiles\" + $($timestamp) + "\log_" + $($SubscriptionId) + ".json"
        #Write-Host $logFile #delete
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Getting failing controls details of Subscription Id: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Info)
        Write-Host $([Constants]::SingleDashLine)

        # Display unique controls and no of resources.
        $controlRemediationList = $JsonContent.ControlRemediationList
        $controlsTable = @()
        foreach($control in $controlRemediationList)
        {
            $count=0;
            foreach($resource in $control.FailedResourceList)
            {
                $controlsTable+= [PSCustomObject]@{
                    'ControlId' = if($count -eq 0) {$control.ControlId} Else {""};
                    'NumberOfFailingResources' = if($count -eq 0) {$control.FailedResourceList.Length} Else {""};
                    'FailingResources' = $resource.ResourceName;
                }
                $count+=1
            }
        }
        $colsProperty = @{Expression={$_.ControlId};Label="Control Id";Width=60;Alignment="left"},
                        @{Expression={$_.NumberOfFailingResources};Label="Number Of Failing Resources";Width=30;Alignment="center"},
                        @{Expression={$_.FailingResources};Label="Failing Resources";Width=30;Alignment="left"}

        Write-Host "Failing Controls Summary" -ForegroundColor $([Constants]::MessageType.Update)
        $controlsTable | Format-Table -Property $colsProperty -Wrap

        #User input for whether to continue with current remediation or noty
        Write-Host $([Constants]::SingleDashLine)
        $startRemediation = Read-Host -Prompt "Do you want to continue remediation? (Y|N)";

        if(($startRemediation -eq 'Y') -or ($startRemediation -eq 'y'))
        {
            Write-Host "User has provided consent to continue the remediation" -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)
#             $remediationLevel = Read-Host -Prompt "At which level you want to perform remediation?
# [1] Subscription: All controls will be remediated in a single flow.
# [2] Control: Confirmation will be asked before remediating each control.
# Press any other key to skip the remediation of current subscription
# Enter the choice (1|2)";
            $remediationLevel = Read-Host -Prompt "There are two ways in all the failing resources for this subscription could be remediated.
[1] All the failing resources will be remediated in a one go.
[2] All the failing resources will be remediated control wise and confirmation will be asked before remediating failing resources against each control.
Press any other key to skip the remediation of current subscription
Enter the choice (1|2)";
            Write-Host $([Constants]::SingleDashLine)

            #Create new log file for the current subscription
            try
            {
                if(Test-Path $logFile)
                {
                    Remove-Item $logFile
                }
                $null = New-Item -ItemType File -Path $logFile -Force -ErrorAction Stop
                $logFileSchema = @{}
                $logFileSchema.Add("SubscriptionId", $SubscriptionId)
                $controlList = @()
                foreach($control in $controlRemediationList)
                {
                    $jsonObject = @{}
                    $jsonObject.Add("ControlId", $control.ControlId)
                    $jsonObject.Add("NumberOfFailingResources", $control.FailedResourceList.Length)
                    $remediatedResources = New-Object System.Collections.ArrayList
                    $jsonObject.Add("RemediatedResources", $remediatedResources)
                    $skippedResources = New-Object System.Collections.ArrayList
                    $jsonObject.Add("SkippedResources", $skippedResources)
                    $jsonObject.Add("RollbackFile", [String]::Empty)
                    $controlList += $jsonObject
                }
                $logFileSchema.Add("ControlList", $controlList)
                $logFileSchema | ConvertTo-json -depth 100  | Out-File $logFile
            }
            catch
            {
                throw $_.Exception.Message
            }

            # variable to track unexecuted resources
            foreach($control in $controlRemediationList)
            { 
                $skippedResources = @();
                if(($remediationLevel -ne '1') -and ($remediationLevel -ne '2'))
                {
                    break;
                }
                if($remediationLevel -eq '2'){
                    $controlLevelRemediation =  Read-Host -Prompt "Do you want to remediate failing resources of control id: [$($control.ControlId)]? (Y|N)"
                    if(($controlLevelRemediation -ne 'Y') -and ($controlLevelRemediation -ne 'y'))
                    {
                        #enter into log 
                        foreach($failedResource in $control.FailedResourceList)
                        {
                            $resource = @{}
                            $resource.Add("ResourceGroupName", $failedResource.ResourceGroupName)
                            $resource.Add("ResourceName", $failedResource.ResourceName)
                            $skippedResources += $resource
                        }
                        $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
                        foreach($logControl in $log.ControlList)
                        {
                            if($logControl.ControlId -eq $control.ControlId){
                                $logControl.SkippedResources=$skippedResources
                            }
                        }
                        $log | ConvertTo-json -depth 100  | Out-File $logFile

                        Write-Host $([Constants]::SingleDashLine)
                        Write-Host "Skipped remediation of failing resources of control id: [$($control.ControlId)]" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)

                        continue;
                    }
                }
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Remediating Control Id [$($control.ControlId)] using [$($control.LoadCommand)] Bulk Remediation Script..." -ForegroundColor $([Constants]::MessageType.Info)
                
                [string]$timeStampString = $timestamp
                . ("./" + "RemediationScripts\" + $control.LoadCommand)
                $commandString =""
                if($control.ControlId -eq "Azure_Storage_AuthN_Dont_Allow_Anonymous"){
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -RemediationType " + "DisableAllowBlobPublicAccessOnStorage" + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_AppService_Config_Disable_Remote_Debugging") {
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" +  " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_AppService_DP_Dont_Allow_HTTP_Access") {
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" +  " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_AppService_DP_Use_Secure_TLS_Version") {
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" +  " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }
                function runCommand($command) {
                    if ($command[0] -eq '"') { Invoke-Expression "& $command" }
                    else { Invoke-Expression $command }
                }
                runCommand($commandString)
                Write-Host "Completed remediation of Control Id [$($control.ControlId)] using [$($control.LoadCommand)] Bulk Remediation Script." -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine)
            }

            # add skipped resources to the log and print the completion message when remediation operation for particular subscription is finished.
           if(($remediationLevel -eq 1) -or ($remediationLevel -eq 2))
           {
                Write-Host "Completed remediation of Subscription Id: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Update)
                Write-Host $([Constants]::SingleDashLine) 
           }
           else
           {
                #tracking unexecuted resources
                foreach($control in $controlRemediationList)
                {
                    $skippedResources = @();
                    foreach($failedResource in $control.FailedResourceList)
                    {
                        $resource = @{}
                        $resource.Add("ResourceGroupName",$failedResource.ResourceGroupName)
                        $resource.Add("ResourceName", $failedResource.ResourceName)
                        $skippedResources += $resource
                        #Write-Host $skippedResources
                    }
                    $log =  Get-content -Raw -path $logFile | ConvertFrom-Json
                    foreach($logControl in $log.ControlList)
                    {
                        if($logControl.ControlId -eq $control.ControlId)
                        {
                            #$logControl.RemediatedResources=$logResources
                            $logControl.SkippedResources=$skippedResources
                        }
                    }
                    $log | ConvertTo-json -depth 100  | Out-File $logFile
                }
                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Skipped remediation of Subscription Id: [$($SubscriptionId)]" -ForegroundColor $([Constants]::MessageType.Warning)
                Write-Host $([Constants]::SingleDashLine)
           }
        }
    }
}

function PrintRemediationSummary($timestamp)
{
    $logFiles = @(Get-ChildItem LogFiles\$($timestamp)\*.json);
    if($logFiles.Count -eq 0)
    {
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "None of the failing controls have been remediated." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
    else
    {
        Write-Host "Remediation Summary" -ForegroundColor $([Constants]::MessageType.Update)
        $remediationSummary = @()
        foreach($logFile in $logFiles)
        {
            $log = Get-Content -Path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList)
            {
                $remediationSummary+=[PSCustomObject]@{
                    "SubscriptionId" = $log.SubscriptionId;
                    "ControlId" = $logControl.ControlId;
                    "NumberOfFailingResources"= $logControl.NumberOfFailingResources;
                    "NumberOfRemediatedResources" = $logControl.RemediatedResources.Length;
                    "NumberOfSkippedResources" = $logControl.SkippedResources.Length;
                }
            }
        }
        $remediationSummary | Format-Table -Wrap
        Write-Host "More details can be found at folder [$(Get-location)/LogFiles]" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "NOTE: You need to scan the remediated subscriptions again using AzTS UI to get the updated results in AzTS UI." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
    }
}

function SetExecutionPolicy
{
    #Check for execution policy settings
    $executionPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if(($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::Restricted) -or ($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::Undefined) -or ($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::AllSigned))
    {
        Write-Host "Currently PowerShell execution policy is set to '$executionPolicy' mode. `n The policy to be set to 'RemoteSigned'. `nSelect Y to change policy for current user [Y/N]: " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
        $executionPolicyAns = Read-Host 

        if($executionPolicyAns.Trim().ToLower() -eq "y" )
        {
            Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
            Write-Host "Execution Policy is set to Remote Signed." -ForegroundColor $([Constants]::MessageType.Update)
        }
        else 
        {
            Write-Host "Terminating the current execution of script as Execution Policy is not set to Remote Signed." -ForegroundColor $([Constants]::MessageType.Error)
            return 
        }
    }
}

function StartExecution
{
    $timestamp = $(get-date -f MMddyyyyHHmmss)
    $directory = "$(Get-location)/LogFiles/$($timestamp)"
    $null = New-Item -Type Directory -path $directory -Force -ErrorAction Stop
    SetExecutionPolicy
    PrintGeneralInformation
    PrintSubscriptions
    StartRemediation ($timestamp)
    PrintRemediationSummary($timestamp)
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

StartExecution