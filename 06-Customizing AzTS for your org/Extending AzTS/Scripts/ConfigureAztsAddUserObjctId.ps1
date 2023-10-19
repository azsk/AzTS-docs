<###
# Overview:
    This script is used to add user's object id into configuration for enable/disable features of AzTS in a Subscription. 

# Instructions to execute the script:
        1. Download the script and AztsControlConfigurationForUserObjectAddition json file.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to add user's object id into configuration for enable/disable features of AzTS in a Subscription. Refer `Examples`, below.

# Examples:
    To add user's object id into configuration of AzTS:
        Update-AzTSConfigurationValues -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForUserObjectAddition.json" -FeatureName "CMET"  -ConfigurationValues "00000000-xxxx-0000-xxxx-000000000001,00000000-xxxx-0000-xxxx-000000000002,00000000-xxxx-0000-xxxx-000000000003"

###>

function Update-AzTSConfigurationValues {
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "File path for Azts Control Configuration file AztsControlConfiguration.json.")]
        $FilePath = "./AztsControlConfigurationForUserObjectAddition.json",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to be Enabled/Disabled. Values for this parameter are 'CMET', 'MG Compliance Initiate Editor'")]
        $FeatureName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Pass multiple Configuration Value as comma seperated")]
        $ConfigurationValues
    )

    $inputParams = $PSBoundParameters
    $logger = [Logger]::new($SubscriptionId)     
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Update-AzTSConfigurationValues `r`nInput Parameters: $(($inputParams | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage("Starting AzTS Configuration update for $FeatureName. This may take 5 mins...", $([Constants]::MessageType.Info))
   
     
    #checking if ConfigurationValues enetered is having single or multiple values
    if ( !$ConfigurationValues.Contains(",")) {
        $ConfigurationValues += ",";
    }

    #Splitting the UserObjectIds from (,)
    [System.Collections.ArrayList] $UserObjectIdsArray = $ConfigurationValues.Split(',').Trim();

    # Set the context to host subscription
    Set-AzContext -SubscriptionId  $SubscriptionId | Out-null
    
    # AzTS resources name preparation
    $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ScanHostRGName;
    $ResourceIdHash = get-hash($ResourceId)
    $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()

    $logger.PublishLogMessage($([Constants]::SingleDashLine))
    $logger.PublishLogMessage("Loading File: [$($FilePath)]...")

    # Getting Control Configuration from file path
    if (-not (Test-Path -Path $FilePath)) {
        $logger.PublishCustomMessage("ERROR: File - $($FilePath) not found. Exiting...", $([Constants]::MessageType.Error))
        $logger.PublishLogMessage($([Constants]::SingleDashLine))
        break
    }

    $JsonContent = Get-content -path $FilePath | ConvertFrom-Json

    $logger.PublishLogMessage("Loading File: [$($FilePath)] completed.")
    $logger.PublishLogMessage($([Constants]::SingleDashLine))

    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $FeatureName) }
    if ($null -ne $FilteredfeatureSetting) {
     

        #Checking if any Dependent Features needs to be enabled
        foreach ($dependentConfiguration in $FilteredfeatureSetting.ConfigurationDependencies) {
            $IntPrivilegedEditorIds = @()
            $NewAppSettings = @{}
            $NewConfigurationList = @{}

            $featureName = $dependentConfiguration.ComponentName + $ResourceHash;
            
            #Getting Existing configuration value
            $AzTSAppConfigurationSettings = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $featureName -ErrorAction Stop
        
            foreach ($Configuration in $dependentConfiguration.Configuration) {
                if ($null -ne $AzTSAppConfigurationSettings) {

                    #Splitting the UserObjectIds from (,)
                    [System.Collections.ArrayList] $UserObjectIdsArray = $ConfigurationValues.Split(',').Trim();
                    $IntPrivilegedEditorIds = @()
                    # Existing app settings
                    $AppSettings = $AzTSAppConfigurationSettings.SiteConfig.AppSettings

                    # Moving existing app settings in new app settings list to avoid being overridden                
                    ForEach ($appSetting in $AppSettings) {
                        $NewAppSettings[$appSetting.Name] = $appSetting.Value

                        #Checking if Configuration Key exist to get the exisiting array value
                        if ($appSetting.Name.Contains($Configuration)) {

                            $appSettingNameArray = $appSetting.Name.Split('_');
                            $IntPrivilegedEditorIds += $appSettingNameArray[6];   

                            #checking if the Configuration value exist (Key and Value) to avoid duplication
                            if ($UserObjectIdsArray.Contains($appSetting.Value)) {
                                $UserObjectIdsArray.Remove($appSetting.Value);
                            }            
                        }
                    }
                    
                    #If exisitng configuration values does not exist, then setting it to 0
                    if ($IntPrivilegedEditorIds.Count -eq 0) {
                        $IntPrivilegedEditorIds = 0
                    }
                    
                    #Fetching max value
                    $IntPrivilegedEditorIdsMaxValue = ($IntPrivilegedEditorIds | Measure-Object -Maximum).Maximum

                    
                    #Adding user object id into configuration
                    foreach ($UserObjectId in $UserObjectIdsArray) { 
                        if ($UserObjectId -ne "") {                       
                            $NewAppSettings["$Configuration$IntPrivilegedEditorIdsMaxValue"] = $UserObjectId
                            $NewConfigurationList["$Configuration$IntPrivilegedEditorIdsMaxValue"] = $UserObjectId
                            $IntPrivilegedEditorIdsMaxValue++
                        }
                    }
                    
                }
            }

            try 
            {
                if ($UserObjectIdsArray.Count -gt 0) {
                    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
                    $logger.PublishCustomMessage("Updating below configuration for: [$($FeatureName)]...", $([Constants]::MessageType.Info))
                    $logger.PublishLogMessage($NewConfigurationList)
                    #Write-Host  $(( $NewConfigurationList | Format-Table).TrimEnd()) -ForegroundColor $([Constants]::MessageType.Info) 
                    $(( $NewConfigurationList | Out-String).TrimEnd()) | Write-Host -ForegroundColor $([Constants]::MessageType.Info)
                    #Updating the new configuration values
                    $AzTSAppConfigurationSettings = Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $FeatureName -AppSettings $NewAppSettings -ErrorAction Stop

                    $logger.PublishCustomMessage("`r`nUpdated configuration for: [$($FeatureName)]." , $([Constants]::MessageType.Update))
                }
                else {
                    $logger.PublishCustomMessage("Entered configurations are already present in $FeatureName.", $([Constants]::MessageType.Update))
                    break
                }
            }
            catch {
                $logger.PublishCustomMessage("Error occurred while updating Configuration. Error: $($_)", $([Constants]::MessageType.Error))
                break
            }         
        }        

        $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
        $logger.PublishCustomMessage("Configuration completed successfully." , $([Constants]::MessageType.Update))
        $logger.PublishLogFilePath()
    }
    else {
        $availableFeatureName = $JsonContent.FeatureName -join ", "
        $logger.PublishCustomMessage("The value entered for FeatureName: $FeatureName is invalid. Valid values are [$availableFeatureName]. Exiting..." , $([Constants]::MessageType.Error))
        $logger.PublishLogFilePath()
    }
}


function get-hash([string]$textToHash) {
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach ($byte in $hashByteArray) {
        $result += "{0:X2}" -f $byte
    }
    return $result;
}

class Constants {
    static [Hashtable] $MessageType = @{
        Error   = [System.ConsoleColor]::Red
        Warning = [System.ConsoleColor]::Yellow
        Info    = [System.ConsoleColor]::Cyan
        Update  = [System.ConsoleColor]::Green
        Default = [System.ConsoleColor]::White
    }

    static [string] $DoubleDashLine = "================================================================================"
    static [string] $SingleDashLine = "--------------------------------------------------------------------------------"
}

class Logger {
    [string] $logFilePath = "";

    Logger([string] $HostSubscriptionId) {
        $logFolerPath = "$([Environment]::GetFolderPath('LocalApplicationData'))\AzTS\FeatureUpdate\Subscriptions\$($HostSubscriptionId.replace('-','_'))";
        $logFileName = "\$('ConfigurationUpdateLogs_' + $(Get-Date).ToString('yyyyMMddhhmm') + '.txt')";
        $this.logFilePath = $logFolerPath + $logFileName
        # Create folder if not exist
        if (-not (Test-Path -Path $logFolerPath)) {
            New-Item -ItemType Directory -Path $logFolerPath | Out-Null
        }
        # Create log file
        
        New-Item -Path $this.logFilePath -ItemType File | Out-Null
        
    }

    PublishCustomMessage ([string] $message, [string] $foregroundColor) {
        $($message) | Add-Content $this.logFilePath -PassThru | Write-Host -ForegroundColor $foregroundColor
    }

    PublishCustomMessage ([string] $message) {
        $($message) | Add-Content $this.logFilePath -PassThru | Write-Host -ForegroundColor White
    }

    PublishLogMessage ([string] $message) {
        $($message) | Add-Content $this.logFilePath
    }

    PublishLogMessage ([hashtable] $message) {
        $($message) | Format-Table -Wrap -AutoSize  | Out-File $this.logFilePath -Append utf8 -Width 100
    }

    PublishLogFilePath() {
        Write-Host $([Constants]::DoubleDashLine)"`r`nLogs have been exported to: $($this.logFilePath)`n"$([Constants]::DoubleDashLine) -ForegroundColor Cyan
    }
}