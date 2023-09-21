<###
# Overview:
    This script is used to enable/disable features of AzTS in a Subscription. 

# Instructions to execute the script:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable/disable features of AzTS in the Subscription. Refer `Examples`, below.

# Examples:
    To Enable features of AzTS:
           Configure-CustomControlAdditionPrerequisites -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForFeatureExtension.json" -FeatureName "CMET"  -FeatureActionType "Enable"

    To Disable features of AzTS:
           Configure-CustomControlAdditionPrerequisites -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForFeatureExtension.json" -FeatureName "CMET"  -FeatureActionType "Disable"

###>
function Configure-CustomControlAdditionPrerequisites {
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "File path for Azts COntrol Configuration JSON file AztsControlConfiguration.json .")]
        $FilePath,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to be Enabled/Disabled. Values for this parameter are 'CMET', 'CMET_Bulk_Edit', 'MG_Processor', 'PIM_API','MG_Compliance_Initiate_Editor'")]
        $FeatureName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on Azts Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType
    )

    # Set the context to host subscription
    Write-Host "Setting up az context to AzTS host subscription id." -ForegroundColor $([Constants]::MessageType.Info)
    Set-AzContext -SubscriptionId  $SubscriptionId
    Write-Host $([Constants]::DoubleDashLine)
    
    # AzTS resources name preparation
    $ResourceId = '/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId, $ScanHostRGName;
    $ResourceIdHash = get-hash($ResourceId)
    $ResourceHash = $ResourceIdHash.Substring(0, 5).ToString().ToLower()

    Write-Host $([Constants]::SingleDashLine)
    Write-Host "Loading input JSOn from file path: [$($FilePath)]..." -ForegroundColor $([Constants]::MessageType.Info)
    Write-Host $([Constants]::SingleDashLine)

    # Getting Control Configuration JSOn from file path
    if (-not (Test-Path -Path $FilePath)) {
        Write-Host "ERROR: Input file - $($FilePath) not found. Exiting..." -ForegroundColor $([Constants]::MessageType.Error)
        break
    }
    $JsonContent = Get-content -path $FilePath | ConvertFrom-Json

    foreach ($feature in $JsonContent) {  
        if ($featureName -ieq $feature.FeatureName) {

            #Checking if feature needs to be enabled
            if ($FeatureActionType -ieq "Enable") {   
                if (($feature.DependentFeaturesForEnabling -ne $null) -and ($feature.DependentFeaturesForEnabling -ne "")) {
                    $DependentFeaturesForEnabling = @()
                    foreach ($resource in $feature.DependentFeaturesForEnabling) { 
                        $DependentFeaturesForEnabling += $resource 
                    } 
                    Write-Host "For enabling feature $FeatureName following feature needs to be enabled $DependentFeaturesForEnabling." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
                     
                    $userInput = Read-Host -Prompt "(Y|N)"

                    if ($userInput -ne "Y") {
                        Write-Host  "Azts Feature $FeatureName will not be enabled in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                        break
                    }
                }

                #Checking if any Dependent Features needs to be enabled
                foreach ($DependentFeature in $feature.DependentFeaturesForEnabling) {

                    #Filtering Dependent feature configuration
                    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $DependentFeature) }

                    foreach ($resource in $FilteredfeatureSetting.ConfigurationDependenciesForEnabling) {

                        #Creating a hashtable for storing the configuration
                        $ConfigurationHashtable = [hashtable]@{};
                        $featureName = $resource.ComponentName + $ResourceHash;
                        foreach ($Configuration in $resource.Configuration) {
                                        
                            #replace value for configuration
                            if ( $Configuration.ConfigurationValue -ieq "##HostSubscriptionId##") {
                                $Configuration.ConfigurationValue = $SubscriptionId;
                            }

                            if ( $Configuration.ConfigurationValue -ieq "##HostResourceGroupName##") {
                                $Configuration.ConfigurationValue = $ScanHostRGName;
                            }

                            if ( $Configuration.ConfigurationValue -ieq "##AppName##") {
                                $Configuration.ConfigurationValue = $featureName;
                            }

                            $ConfigurationHashtable[$Configuration.ConfigurationName] = $Configuration.ConfigurationValue
                        }

                        #calling function to validate if keys exist
                        $FeatureEnabled = Validate-AppSetting -SubscriptionId $SubscriptionId -ScanHostRGName $ScanHostRGName -WebAppName $featureName -AppSettings $ConfigurationHashtable -FeatureActionType $FeatureActionType

                        #If FeatureEnabled = true means all the configuration keys & values are already present in Configuration, need to enable again
                        if ( -not $FeatureEnabled) {
                            try {
                                # calling function to update the values
                                Configure-ModifyAppSetting -SubscriptionId $SubscriptionId -ScanHostRGName $ScanHostRGName -WebAppName $featureName -AppSettings $ConfigurationHashtable -FeatureActionType $FeatureActionType
                            }
                            catch {
                                Write-Host "Error occurred while updating Configuration. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                                break
                            }
                        }
                                                                                            
                    }
                }       
                     
                #Enabling the feature
                foreach ($resource in $feature.ConfigurationDependenciesForEnabling) {
                                
                    $ConfigurationHashtable = [hashtable]@{};
                    $featureName = $resource.ComponentName + $ResourceHash;
                    foreach ($Configuration in $resource.Configuration) {
                                        
                        #replace value for configuration
                        if ( $Configuration.ConfigurationValue -ieq "##HostSubscriptionId##") {
                            $Configuration.ConfigurationValue = $SubscriptionId;
                        }

                        if ( $Configuration.ConfigurationValue -ieq "##HostResourceGroupName##") {
                            $Configuration.ConfigurationValue = $ScanHostRGName;
                        }

                        if ( $Configuration.ConfigurationValue -ieq "##AppName##") {
                            $Configuration.ConfigurationValue = $featureName;
                        }

                        $ConfigurationHashtable[$Configuration.ConfigurationName] = $Configuration.ConfigurationValue
                    }

                    try {
                        # calling function to update the values
                        Configure-ModifyAppSetting -SubscriptionId $SubscriptionId -ScanHostRGName $ScanHostRGName -WebAppName $featureName -AppSettings $ConfigurationHashtable -FeatureActionType $FeatureActionType
                    }
                    catch {
                        Write-Host "Error occurred while updating Configuration. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                        break
                    }                                                                       
                }
                                          
            }
            elseif ($FeatureActionType -ieq "Disable") {         
                if (($feature.DependentFeaturesForDisabling -ne $null) -and ($feature.DependentFeaturesForDisabling -ne "")) {                
                    $DependentFeaturesForDisabling = @()
                    foreach ($resource in $feature.DependentFeaturesForDisabling) { 
                        $DependentFeaturesForDisabling += $resource 
                    }

                    Write-Host "By disbaling feature $FeatureName following feature may get impacketed $DependentFeaturesForDisabling." -ForegroundColor $([Constants]::MessageType.Info)
                    Write-Host "Do you want to Continue? " -ForegroundColor $([Constants]::MessageType.Warning)
                     
                    $userInput = Read-Host -Prompt "(Y|N)"

                    if ($userInput -ne "Y") {
                        Write-Host  "Azts Feature $FeatureName will not be enabled in the Subscription. Exiting..." -ForegroundColor $([Constants]::MessageType.Warning)
                        break
                    }
                }
                    

                #Need to add check for dependant feature
                foreach ($resource in $feature.ConfigurationDependenciesForDisabling) {
                    $ConfigurationHashtable = [hashtable]@{};
                    $featureName = $resource.ComponentName + $ResourceHash;
                    foreach ($Configuration in $resource.Configuration) {
                        $ConfigurationHashtable[$Configuration.ConfigurationName] = $Configuration.ConfigurationValue
                    }

                    try {

                        # calling function to update the values
                        Configure-ModifyAppSetting -SubscriptionId $SubscriptionId -ScanHostRGName $ScanHostRGName -WebAppName $featureName -AppSettings $ConfigurationHashtable -FeatureActionType $FeatureActionType       
                    }
                    catch {
                        Write-Host "Error occurred while updating Configuration. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                        break
                    }                                                        
                }                         
            }
        }
    }

    Write-Host "Configuration completed." -ForegroundColor $([Constants]::MessageType.Update)
}


function Configure-ModifyAppSetting {
    Param(

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to be Enabled/Disabled.")]
        $WebAppName,       

        [hashtable]
        [Parameter(Mandatory = $true, HelpMessage = "App Settings Keys which needs to be modified.")]
        $AppSettings,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on Azts Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType

    )

    Write-Host "Configuring $WebAppName for new control addition." -ForegroundColor $([Constants]::MessageType.Info)
    
    $AzTSAppSettings = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $WebAppName -ErrorAction Stop

    if ($null -ne $AzTSAppSettings) {
        # Existing app settings
        $ExistingAppSettings = $AzTSAppSettings.SiteConfig.AppSettings

        # Moving existing app settings in new app settings list to avoid being overridden
        $NewAppSettings = @{}
        $NewAppSettingsKeyOnly = @()       

        if ($FeatureActionType -ieq "Enable") {
            ForEach ($appSetting in $ExistingAppSettings) {
                $NewAppSettings[$appSetting.Name] = $appSetting.Value
            }

            
        }
        elseif ($FeatureActionType -ieq "Disable") {
            ForEach ($appSetting in $ExistingAppSettings) {                
                $NewAppSettings[$appSetting.Name] = $appSetting.Value               
            }
        }

        # Adding new settings to new app settings list
        $AppSettings.GetEnumerator() | ForEach-Object {           
            $NewAppSettings[$_.Key] = $_.Value
            $NewAppSettingsKeyOnly += $_.Value
        }

       
        # Configuring new app settings
        $AzTSAppSettings = Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $WebAppName -AppSettings $NewAppSettings -ErrorAction Stop

        Write-Host "Configured $WebAppName for new control addition." -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)

    }
}


function Validate-AppSetting {
    Param(
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to be Enabled/Disabled.")]
        $WebAppName,
        
        [hashtable]
        [Parameter(Mandatory = $true, HelpMessage = "App Settings Keys which needs to be modified.")]
        $AppSettings,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on Azts Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType
    )

    

    Write-Host "Configuring AzTS $WebAppName for new control addition." -ForegroundColor $([Constants]::MessageType.Info)
    
    $IsFeatureEnabled = $false

    $AzTSAppSettings = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $WebAppName -ErrorAction Stop

    if ($null -ne $AzTSAppSettings) {
        # Existing app settings
        $ExistingAppSettings = $AzTSAppSettings.SiteConfig.AppSettings

        # Moving existing app settings in new app settings list to avoid being overridden
        $NewAppSettings = @{}
        $NewAppSettingsKeyOnly = @()
        $ConfigurationFoundCount = 0
        $ConfigurationNotFoundCount = 0

        # Adding new settings to new app settings list
        $AppSettings.GetEnumerator() | ForEach-Object {
           
            $NewAppSettings[$_.Key] = $_.Value
            $configurationName = $_.Key
            $configurationValue = $_.Value

            $SettingFound = $ExistingAppSettings | Where-Object { ($_.Name -ieq $configurationName) -and ($_.Value -ieq $configurationValue) }

            if ( $SettingFound -eq $null) {
                $ConfigurationNotFoundCount++
            }
            else {
                $ConfigurationFoundCount++
            }

           
        }

        if ($ConfigurationNotFoundCount -ieq 0) {
            $IsFeatureEnabled = $true
        }

        return $IsFeatureEnabled;

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