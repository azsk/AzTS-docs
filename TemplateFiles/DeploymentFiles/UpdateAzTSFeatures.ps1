<###
# Overview:
    This script is used to enable/disable features of AzTS in a Subscription. 

# Instructions to execute the script:
        1. Download the script and AztsControlConfigurationForFeatureExtension.json file..
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to enable/disable features of AzTS in the Subscription. Refer `Examples`, below.

# Examples:
    To Enable features of AzTS:
           Configure-AzTSFeature -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForFeatureExtension.json" -FeatureName "CMET"  -FeatureActionType "Enable"

    To Disable features of AzTS:
           Configure-AzTSFeature -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForFeatureExtension.json" -FeatureName "CMET"  -FeatureActionType "Disable"

###>

function Configure-AzTSFeature {
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which AzTS is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where AzTS is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "File path for AzTS Control Configuration JSON file AztsControlConfigurationForFeatureExtension.json.")]
        $FilePath = ".\ConfigureAzTSFeatureTemplate.json",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "AzTS Feature Name to be Enabled/Disabled. Values for this parameter are 'CMET', 'CMET Bulk Edit', 'MG Processor', 'PIM API','MG Compliance Initiate Editor'")]
        [ValidateSet("CMET", "CMET Bulk Edit", "MG Processor", "PIM API", "MG Compliance Initiate Editor")]
        $FeatureName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on AzTS Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        [ValidateSet("Enable", "Disable")]
        $FeatureActionType
    )

    $inputParams = $PSBoundParameters
    $FeatureName = $FeatureName.Trim()

    $logger = [Logger]::new($SubscriptionId)     
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Configure-AzTSFeature `r`nInput Parameters: $(($inputParams | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage("Starting process to $($FeatureActionType.ToLower()) $FeatureName feature. This may take 2-3 mins...", $([Constants]::MessageType.Info))


    $webAppConfigurationList = [hashtable]@{}
    $dependentFeaturesForEnabling = @{}
    $dependentFeaturesForDisabling = @{}

    # Set the context to host subscription
    Set-AzContext -SubscriptionId  $SubscriptionId | Out-null
    
    #To set context for default subs
    #Update-AzConfig -DefaultSubscriptionForLogin $SubscriptionId | Out-null
    
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
    
        #Checking if feature needs to be enabled
        if ($FeatureActionType -ieq "Enable") {   
            if (($null -ne $FilteredfeatureSetting.DependentFeaturesForEnabling) -and ($FilteredfeatureSetting.DependentFeaturesForEnabling -ne "")) {
                #Getting the list of dependent features
                $dependentFeaturesForEnabling = Get-DependentFeature -FeatureName $FeatureName -JsonContent $JsonContent -DepandentFeatureName $FeatureName -FeatureActionType $FeatureActionType
                
                #Getting Unique Values
                $dependentFeaturesForEnabling = $dependentFeaturesForEnabling | Sort-Object | Get-Unique 
                $dependentFeaturesForEnablingText = $dependentFeaturesForEnabling -join ", "

                #Enable below line for comma seperated dependent feature
                #$logger.PublishCustomMessage("For enabling $FeatureName following dependent feature needs to be enabled: $dependentFeaturesForEnablingText" , $([Constants]::MessageType.Warning))
                
                $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
                $logger.PublishCustomMessage("Enabling [$FeatureName] will also enable dependent feature(s): " , $([Constants]::MessageType.Warning))
                $logger.PublishCustomMessage( $(( $dependentFeaturesForEnabling | Out-String).TrimEnd()) , $([Constants]::MessageType.Warning))
                $logger.PublishCustomMessage("`r`nDo you want to Continue? ", $([Constants]::MessageType.Warning))
                     
                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -ne "Y") {
                    $logger.PublishCustomMessage( "Azts Feature $FeatureName will not be enabled in the Subscription. Exiting..." , $([Constants]::MessageType.Error))
                    break
                }

                #Adding configuration for dependent features
                foreach ($dependentFeature in $dependentFeaturesForEnabling) {               
                    $webAppConfigurationList = Get-Configuration -FeatureName $dependentFeature -JsonContent $JsonContent -ResourceHash $ResourceHash -FeatureActionType $FeatureActionType

                }
            }

            #Adding Configuration for Feature
            $webAppConfigurationList = Get-Configuration -FeatureName $FeatureName -JsonContent $JsonContent -ResourceHash $ResourceHash  -FeatureActionType $FeatureActionType
                     
                                                                  
        }
        elseif ($FeatureActionType -ieq "Disable") {    
            
            if (($null -ne $FilteredfeatureSetting.DependentFeaturesForDisabling) -and ($FilteredfeatureSetting.DependentFeaturesForDisabling -ne "")) {
                #Getting the list of dependent features
                $dependentFeaturesForDisabling = Get-DependentFeature -FeatureName $FeatureName -JsonContent $JsonContent -DepandentFeatureName $FeatureName -FeatureActionType $FeatureActionType
                
                #Getting Unique Values
                $dependentFeaturesForDisabling = $dependentFeaturesForDisabling | Sort-Object | Get-Unique
                $dependentFeaturesForDisablingText = $dependentFeaturesForDisabling -join ", " 

                $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
                $logger.PublishCustomMessage("Disabling [$FeatureName] will also disable dependent feature(s): " , $([Constants]::MessageType.Warning))
                $logger.PublishCustomMessage( $(( $dependentFeaturesForDisabling | Out-String).TrimEnd()) , $([Constants]::MessageType.Warning)) 
                $logger.PublishCustomMessage("`r`nDo you want to Continue? " , $([Constants]::MessageType.Warning))
                     
                $userInput = Read-Host -Prompt "(Y|N)"

                if ($userInput -ne "Y") {
                    $logger.PublishCustomMessage( "Azts Feature $FeatureName will not be disabled in the Subscription. Exiting..." , $([Constants]::MessageType.Error))
                    break
                }

                #Adding configuration for dependent features
                foreach ($dependentFeature in $dependentFeaturesForDisabling) {               
                    $webAppConfigurationList = Get-Configuration -FeatureName $dependentFeature -JsonContent $JsonContent -ResourceHash $ResourceHash -FeatureActionType $FeatureActionType
                }
            }

            #Adding Configuration for Feature
            $webAppConfigurationList = Get-Configuration -FeatureName $FeatureName -JsonContent $JsonContent -ResourceHash $ResourceHash -FeatureActionType $FeatureActionType                        
        }

        #Enabling/Disabling the feature
        $webAppConfigurationList.GetEnumerator() | ForEach-Object {
            try {         
           
                # calling function to update the values
                Configure-ModifyAppSetting -SubscriptionId $SubscriptionId -ScanHostRGName $ScanHostRGName -WebAppName $_.Name -AppSettings $_.Value -FeatureActionType $FeatureActionType
            }
            catch {
                $logger.PublishCustomMessage("Error occurred while updating Configuration. Error: $($_)" , $([Constants]::MessageType.Error))
                $logger.PublishLogFilePath()
                break
            }      
        }       
    }
    else {
        $availableFeatureName = $JsonContent.FeatureName -join ","
        $logger.PublishCustomMessage("The value entered for FeatureName: $FeatureName is invalid. Valid values are [$availableFeatureName]. Exiting..." , $([Constants]::MessageType.Error))
        $logger.PublishLogFilePath()
        break
    }
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
   

    $dependentFeatures = $dependentFeaturesForDisabling
    if (!$dependentFeaturesForEnabling.Count -eq 0) {
        $dependentFeatures = $dependentFeaturesForEnabling
    }   

    if ($dependentFeatures.Count -eq 0 ) {   
        $logger.PublishCustomMessage( "Successfully $($FeatureActionType.ToLower()+"d") [$FeatureName] feature.", $([Constants]::MessageType.Info))
    }
    else {   
        $logger.PublishCustomMessage( "The following feature(s) are $($FeatureActionType.ToLower()+"d") successfully:`r`n$FeatureName`r`n" + $(( $dependentFeatures | Out-String).TrimEnd()) , $([Constants]::MessageType.Info))    
    }

    $logger.PublishLogMessage($([Constants]::DoubleDashLine))
    $logger.PublishLogFilePath()
}


function Configure-ModifyAppSetting {
    Param(

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which AzTS is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where AzTS is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "AzTS Feature Name to be Enabled/Disabled.")]
        $WebAppName,       

        [hashtable]
        [Parameter(Mandatory = $true, HelpMessage = "App Settings Keys which needs to be modified.")]
        $AppSettings,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on AzTS Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType

    )   
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage("Updating configuration for: [$($WebAppName)]...", $([Constants]::MessageType.Info))

    #Enable below line to see the config values in console output window
    #$logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Configure-AzTSTenantSecurityAdditionalFeature `r`nInput Parameters: $(( $_.Value | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
    $logger.PublishLogMessage($_.Value )

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
        $logger.PublishCustomMessage("Updated configuration for: [$($WebAppName)]." , $([Constants]::MessageType.Update))
    }
}

function Get-DependentFeature {
    Param(
         
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "AzTS Feature Name to be Enabled/Disabled.")]
        $FeatureName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "AzTS Feature Name to be Enabled/Disabled.")]
        $DepandentFeatureName,
        
        [System.Object]
        [Parameter(Mandatory = $true)]
        $JsonContent,

        [System.Array]
        [Parameter(Mandatory = $false)]
        $DependentFeatures,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on AzTS Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType
        
    )

    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $DepandentFeatureName) }

    $DependentFeatures = @()
    if ($FeatureActionType -ieq "Enable") {
        $DependentFeatures = $FilteredfeatureSetting.DependentFeaturesForEnabling
    }
    else { $DependentFeatures = $FilteredfeatureSetting.DependentFeaturesForDisabling }

    if (($null -ne $DependentFeatures) -and ($DependentFeatures -ne "")) {                  
        foreach ($DependentFeature in $DependentFeatures) {
            if ( $FeatureName -ine $DependentFeature) {
                 
                if ($null -eq $DependentFeatures) {
                    $DependentFeatures += $DependentFeature                    
                    $IsDependentFeature = Validate-DependentFeature -FeatureName $DependentFeature -JsonContent $JsonContent -FeatureActionType $FeatureActionType 
                    if ($IsDependentFeature) {
                        Get-DependentFeature -FeatureName $FeatureName -JsonContent $JsonContent -DependentFeatures $DependentFeatures -DepandentFeatureName $DependentFeature -FeatureActionType $FeatureActionType
                    }
                }

                if (!$DependentFeatures.Contains($DependentFeature)) {
                    $DependentFeatures += $DependentFeature
                    $IsDependentFeature = Validate-DependentFeature -FeatureName $DependentFeature -JsonContent $JsonContent -FeatureActionType $FeatureActionType
                    if ($IsDependentFeature) {
                        Get-DependentFeature -FeatureName $FeatureName -JsonContent $JsonContent -DependentFeatures $DependentFeatures -DepandentFeatureName $DependentFeature -FeatureActionType $FeatureActionType
                    }
                }
            }
        }
    } 
    return $DependentFeatures
}

function Validate-DependentFeature {
    Param(
         
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "AzTS Feature Name to be Enabled/Disabled.")]
        $FeatureName,

        [System.Object]
        [Parameter(Mandatory = $true)]
        $JsonContent,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on AzTS Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType
    )

    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $FeatureName) }

    $DependentFeatures = @()
    if ($FeatureActionType -ieq "Enable") {
        $DependentFeatures = $FilteredfeatureSetting.DependentFeaturesForEnabling
    }
    else { $DependentFeatures = $FilteredfeatureSetting.DependentFeaturesForDisabling }

    if (($null -ne $DependentFeatures) -and ($DependentFeatures -ne "")) {  
        return $true
    }
    else {
        return $false
    }
}


function Get-Configuration {
    Param(
         
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "AzTS Feature Name to be Enabled/Disabled.")]
        $FeatureName,

        [System.Object]
        [Parameter(Mandatory = $true)]
        $JsonContent,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Hash value of resource.")]
        $ResourceHash,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Action to be taken on AzTS Feature, Pass Enabled for enabling the feature and Disable for disabling the feature.")]
        $FeatureActionType
    )
   
    #Filtering Dependent feature configuration
    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $FeatureName) }

    $ConfigurationDependencies = @()
    if ($FeatureActionType -ieq "Enable") {
        $ConfigurationDependencies = $FilteredfeatureSetting.ConfigurationDependenciesForEnabling
    }
    else { $ConfigurationDependencies = $FilteredfeatureSetting.ConfigurationDependenciesForDisabling }


    foreach ($ConfigurationDependency in $ConfigurationDependencies) {

        #Creating a hashtable for storing the configuration
        $ConfigurationHashtable = [hashtable]@{};
        $featureName = $ConfigurationDependency.ComponentName + $ResourceHash;
        foreach ($Configuration in $ConfigurationDependency.Configuration) {
                                        
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
        #null check
        if ($null -ne $webAppConfigurationList) {
            #if key contains
            if (!$webAppConfigurationList.ContainsKey($featureName)) {
                $webAppConfigurationList[$featureName] = $ConfigurationHashtable;
            }
            else {
                #key found
                $TempConfiguration = $webAppConfigurationList[$featureName]
                $MergedConfiguration = $TempConfiguration + $ConfigurationHashtable
                $webAppConfigurationList[$featureName] = $MergedConfiguration;
            }
        }
        else
        { $webAppConfigurationList[$featureName] = $ConfigurationHashtable; }
    }
    return $webAppConfigurationList;
}

<###
# Overview:
    This script is used to add feature configuration value for AzTS in a Subscription. 

# Instructions to execute the script:
        1. Download the script.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to add feature configuration value for AzTS in a Subscription. Refer `Examples`, below.

# Examples:
    To add user's object id into configuration of AzTS:
        Add-AztsFeatureConfigurationValues -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FeatureName "CMET"  -FeatureConfigValues "00000000-xxxx-0000-xxxx-000000000001,00000000-xxxx-0000-xxxx-000000000002,00000000-xxxx-0000-xxxx-000000000003"

###>

function Add-AztsFeatureConfigurationValues {
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName,

        [string]
        [Parameter(Mandatory = $false, HelpMessage = "File path for Azts Control Configuration file AztsControlConfiguration.json.")]
        $FilePath = "./AddAzTSFeatureConfigurationValuesTemplate.json",

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to add Configuration values. Values for this parameter are 'CMET', 'MG Compliance Initiate Editor'")]
        [ValidateSet("CMET", "MG Compliance Initiate Editor")]
        $FeatureName,        

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "Pass multiple Configuration Value as comma seperated")]
        $FeatureConfigValues
    )

    $inputParams = $PSBoundParameters
    $logger = [Logger]::new($SubscriptionId)     
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine + "`r`nMethod Name: Add-AztsFeatureConfigurationValues `r`nInput Parameters: $(($inputParams | Out-String).TrimEnd()) `r`n"), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
    $logger.PublishCustomMessage("Starting process to add Configuration Values for $FeatureName feature. This may take 2-3 mins...", $([Constants]::MessageType.Info))
   
     
    #checking if ConfigurationValues enetered is having single or multiple values
    if ( !$FeatureConfigValues.Contains(",")) {
        $FeatureConfigValues += ","; 
    }

    #Splitting the UserObjectIds from (,)
    [System.Collections.ArrayList] $FeatureConfigValueArray = $FeatureConfigValues.Split(',').Trim();

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
            $ExistingConfigurationList = @{}

            $ComponentName = $dependentConfiguration.ComponentName + $ResourceHash;
            
            #Getting Existing configuration value
            $AzTSAppConfigurationSettings = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $ComponentName -ErrorAction Stop
        
            foreach ($Configuration in $dependentConfiguration.Configuration) {
                if ($null -ne $AzTSAppConfigurationSettings) {

                    if ($FeatureName -ieq "CMET" -or $FeatureName -ieq "MG Compliance Initiate Editor") {

                        #Splitting the UserObjectIds from (,)
                        [System.Collections.ArrayList] $FeatureConfigValueArray = $FeatureConfigValues.Split(',').Trim();
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
                                if ($FeatureConfigValueArray.Contains($appSetting.Value)) {
                                    $ExistingConfigurationList["$($appSetting.Name)"] =$appSetting.Value
                                    $FeatureConfigValueArray.Remove($appSetting.Value);
                                }            
                            }
                        }
                    
                        #If exisitng configuration values does not exist, then setting it to 0
                        if ($IntPrivilegedEditorIds.Count -eq 0) {
                            $IntPrivilegedEditorIds = 0
                        }
                    
                        #Fetching max value
                        $IntPrivilegedEditorIdsMaxValue = ($IntPrivilegedEditorIds | Measure-Object -Maximum).Maximum
                    
                        #Adding configuration
                        foreach ($FeatureConfig in $FeatureConfigValueArray) { 
                            if ($FeatureConfig -ne "") {                       
                                $NewAppSettings["$Configuration$IntPrivilegedEditorIdsMaxValue"] = $FeatureConfig
                                $NewConfigurationList["$Configuration$IntPrivilegedEditorIdsMaxValue"] = $FeatureConfig
                                $IntPrivilegedEditorIdsMaxValue++
                            }
                        }
                    
                    }
                }
            }

            try {
                if ($FeatureConfigValueArray.Count -gt 0) {
                    $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
                    $logger.PublishCustomMessage("Updating configuration for [$($ComponentName)]...", $([Constants]::MessageType.Info))
                    $logger.PublishLogMessage($NewConfigurationList)
                   
                    #uncomment below line to see data in output console window
                    #$(( $NewConfigurationList | Out-String).TrimEnd()) | Write-Host -ForegroundColor $([Constants]::MessageType.Info) 
                  
                    #Updating the new configuration values
                    $AzTSAppConfigurationSettings = Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $ComponentName -AppSettings $NewAppSettings -ErrorAction Stop

                    $logger.PublishCustomMessage("Updated configuration for [$($ComponentName)]." , $([Constants]::MessageType.Update))
                    
                    if ($ExistingConfigurationList.Count -gt 0)
                    {
                        $logger.PublishLogMessage($([Constants]::SingleDashLine))
                        $logger.PublishLogMessage("Existing Configuration found:")
                        $logger.PublishLogMessage($ExistingConfigurationList)
                        $logger.PublishLogMessage($([Constants]::SingleDashLine))
                    }
                }
                else {
                    $logger.PublishCustomMessage("Entered configuration values are already present in $ComponentName.", $([Constants]::MessageType.Error))
                    $logger.PublishLogMessage("Existing Configuration found:")
                    $logger.PublishLogMessage($([Constants]::SingleDashLine))
                    $logger.PublishLogMessage($ExistingConfigurationList)
                    $logger.PublishLogMessage($([Constants]::SingleDashLine))
                    break
                }
            }
            catch {
                $logger.PublishCustomMessage("Error occurred while updating Configuration. Error: $($_)", $([Constants]::MessageType.Error))
                break
            }         
        }        
        if ($FeatureConfigValueArray.Count -gt 0) {
            $logger.PublishCustomMessage($([Constants]::DoubleDashLine), $([Constants]::MessageType.Info)) 
            $logger.PublishCustomMessage("Successfully added configuration(s) for [$FeatureName] feature." , $([Constants]::MessageType.Update))
        }
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
        $logFileName = "\$('FeatureUpdateLogs_' + $(Get-Date).ToString('yyyyMMddhhmm') + '.txt')";
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