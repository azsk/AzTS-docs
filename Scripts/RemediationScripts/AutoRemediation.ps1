function PrintGeneralInformation
{
    $scriptInformation = "**General Information**
[1]. All the failing controls, which have been downloaded using AzTS UI, are present at [$(Get-location)\FailedControls] and same will be referred for remediation.
[2]. Remediation scripts will be used to fix the failing controls in bulk.
[3]. Minimum of contributor role at a subscription level is required for running BRS (Bulk Remediation Scripts) in most of the case, some may even require a higher priviledge access over a subscription.";
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
        Write-Host ("$($filesCount). $($SubscriptionId)")
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
        Write-Host "Getting failing controls details of Subscription Id: [$($SubscriptionId)]..." -ForegroundColor $([Constants]::MessageType.Info)
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

        Write-Host "Failing Controls Summary:" -ForegroundColor $([Constants]::MessageType.Update)
        $controlsTable | Format-Table -Property $colsProperty -Wrap

        #User input for whether to continue with current remediation or noty
        Write-Host $([Constants]::SingleDashLine)
        $startRemediation = Read-Host -Prompt "Do you want to continue remediation? (Y|N)";

        if($startRemediation -eq 'Y')
        {
            Write-Host "User has provided consent to continue the remediation." -ForegroundColor $([Constants]::MessageType.Update)
            Write-Host $([Constants]::SingleDashLine)

            $remediationLevel = Read-Host -Prompt "You can choose one of the following mode to remediate non-compliant resources:
[1] Remediate all the failing resources in a single go for all controls.
[2] Remediate failing resources control wise, confirmation will be needed before remediating failing resources against each control.
Press any other key to skip the remediation of resources in current subscription.
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
                $logFileSchema | ConvertTo-json -depth 10  | Out-File $logFile
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
                    Write-Host $([Constants]::SingleDashLine)
                    if($controlLevelRemediation -ne 'Y')
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
                        $log | ConvertTo-json -depth 10  | Out-File $logFile

                        Write-Host "Skipped remediation of failing resources of control id: [$($control.ControlId)]" -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        continue;
                    }
                }
                
                [string]$timeStampString = $timestamp
                . ("./" + "RemediationScripts\" + $control.LoadCommand)
                $commandString =""
                if($control.ControlId -eq "Azure_Storage_AuthN_Dont_Allow_Anonymous"){
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -RemediationType " + "DisableAllowBlobPublicAccessOnStorage" + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }
                elseif (($control.ControlId -eq "Azure_Storage_DP_Encrypt_In_Transit") -or 
                ($control.ControlId -eq "Azure_AppService_Config_Disable_Remote_Debugging") -or
                ($control.ControlId -eq "Azure_AppService_DP_Dont_Allow_HTTP_Access") -or
                ($control.ControlId -eq "Azure_AppService_DP_Use_Secure_TLS_Version") -or
                ($control.ControlId -eq "Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN") -or
                ($control.ControlId -eq "Azure_APIManagement_DP_Use_HTTPS_URL_Scheme") -or
                ($control.ControlId -eq "Azure_CloudService_SI_Disable_RemoteDesktop_Access") -or
                ($control.ControlId -eq "Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel") -or
                ($control.ControlId -eq "Azure_SQLDatabase_DP_Enable_TDE")) {
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" +  " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_KubernetesService_AuthN_Enabled_AAD") {
                    Write-Host "[$($control.LoadCommand)] Bulk Remediation Script requires user inputs at some points to execute properly.`n" -ForegroundColor $([Constants]::MessageType.Warning)
                    $proceedWithRemediation = Read-Host -Prompt "Do you want to proceed with remediation for the control [$($control.ControlId)]? (Y|N)"
                    Write-Host $([Constants]::SingleDashLine)
                    if($proceedWithRemediation -ne 'Y')
                    {
                        Write-Host "Skipped remediation of failing resources of control id: [$($control.ControlId)]." -ForegroundColor $([Constants]::MessageType.Warning)
                        Write-Host $([Constants]::SingleDashLine)
                        continue;
                    }
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" +  " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_ContainerRegistry_Config_Enable_Security_Scanning") {
                    Write-Host "Object Id for the Security Scanner Identity is required to execute the [$($control.LoadCommand)] Bulk Remediation Script." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host "Object Id of the Security Scanner Identity can be found in the status reason column against the failing control result in AzTS UI.`n" -ForegroundColor $([Constants]::MessageType.Warning)
                    $ObjectId = Read-Host "Enter the Object Id of the security scanner identity"
                    Write-Host $([Constants]::SingleDashLine)
                    $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -ObjectId " + "`'" + $ObjectId +  "`'" + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }elseif ($control.ControlId -eq "Azure_AppService_DP_Use_Secure_FTP_Deployment") {
                    Write-Host "Secured FTP State for the App Service(s) is required to execute the [$($control.LoadCommand)] Bulk Remediation Script." -ForegroundColor $([Constants]::MessageType.Warning)
                    $userInputforFTPState = Read-Host "You can choose one of the following mode to remediate non-compliant resources:
                    [1] Remediate failing resorces by configuring FTP State as FtpsOnly on the production slot and all non-production slots for all App Services.
                    [2] Remediate failing resorces by configuring FTP State as Disabled on the production slot and all non-production slots for all App Services.
                    Enter the choice (1|2)";
                    $FTPState=""
                    if($userInputforFTPState -eq "1"){
                        $FTPState="FTPSOnly"
                    }
                    elseif ($userInputforFTPState -eq "2"){
                        $FTPState="Disabled"
                    }
                    Write-Host $([Constants]::SingleDashLine)
                   $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'" + " -FTPState " + "`'" + $FTPState +  "`'" + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -PerformPreReqCheck"+ " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";              
                }
                elseif($control.ControlId -eq "Azure_FrontDoor_CDNProfile_DP_Use_Secure_TLS_Version_Trial"){
                        $commandString = $control.InitCommand + " -SubscriptionId " +  "`'" + $SubscriptionId +  "`'"  + " -Path " + "`'" + "FailedControls\" +  $SubscriptionId + ".json" + "`'" + " -AutoRemediation" + " -TimeStamp " + "`'" + $timeStampString +  "`'";
                }
                else{
                    Write-Host "Skipped remediation of failing resources of control id: [$($control.ControlId)], because remediation support for this control hasn't been added yet." -ForegroundColor $([Constants]::MessageType.Warning)
                    Write-Host $([Constants]::SingleDashLine)
                    continue;
                }

                Write-Host "Remediating Control Id [$($control.ControlId)] using [$($control.LoadCommand)] Bulk Remediation Script..." -ForegroundColor $([Constants]::MessageType.Info)
                
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
                    $log | ConvertTo-json -depth 10  | Out-File $logFile
                }
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
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Remediation Summary:`n" -ForegroundColor $([Constants]::MessageType.Info)
        $remediationSummary = @()
        foreach($logFile in $logFiles)
        {
            $log = Get-Content -Path $logFile | ConvertFrom-Json
            foreach($logControl in $log.ControlList)
            {
                $remediationSummary+=[PSCustomObject]@{
                    "Subscription Id" = $log.SubscriptionId;
                    "Control Id" = $logControl.ControlId;
                    "Number Of Failing Resources"= $logControl.NumberOfFailingResources;
                    "Number Of Remediated Resources" = $logControl.RemediatedResources.Length;
                    "Number Of Skipped Resources" = $logControl.SkippedResources.Length;
                }
            }
        }
        $remediationSummary | Format-Table -Wrap
        Write-Host $([Constants]::DoubleDashLine)
        Write-Host "Note: 
1. You need to scan the remediated subscriptions again using AzTS UI to get the updated results in AzTS UI.
2. To rollback the changes, individual BRS needs to be run and rollback command needs to be executed. The file required for rollback could be found in the detailed logs folder." -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::SingleDashLine)
        Write-Host "Detailed logs have been exported to the path [$(Get-location)/LogFiles/$($timestamp)]" -ForegroundColor $([Constants]::MessageType.Warning)
        Write-Host $([Constants]::DoubleDashLine)
    }
}

function SetExecutionPolicy
{
    #Check for execution policy settings
    $executionPolicy = Get-ExecutionPolicy -Scope CurrentUser
    if(($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::Restricted) -or ($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::Undefined) -or ($executionPolicy -eq [Microsoft.PowerShell.ExecutionPolicy]::AllSigned))
    {
        Write-Host "Currently PowerShell execution policy is set to '$executionPolicy' mode. `n The policy to be set to 'RemoteSigned'. `nSelect Y to change policy for current user (Y|N): " -ForegroundColor $([Constants]::MessageType.Warning) -NoNewline
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

    static [String] $DoubleDashLine = "========================================================================================================================"
    static [String] $SingleDashLine = "------------------------------------------------------------------------------------------------------------------------"
} 

StartExecution