<###
# Overview:
    This script is used to add user's object id into configuration for enable/disable features of AzTS in a Subscription. 

# Instructions to execute the script:
        1. Download the script and AztsControlConfigurationForUserObjectAddition json file.
        2. Load the script in a PowerShell session. Refer https://aka.ms/AzTS-docs/RemediationscriptExcSteps to know more about loading the script.
        3. Execute the script to add user's object id into configuration for enable/disable features of AzTS in a Subscription. Refer `Examples`, below.

# Examples:
    To add user's object id into configuration of AzTS:
        Configure-AddUserObjctIds -SubscriptionId 00000000-xxxx-0000-xxxx-000000000000 -ScanHostRGName AzTS-Solution-RG -FilePath "D:\Working\AztsScript\AztsControlConfigurationForUserObjectAddition.json" -FeatureName "CMET"  -UserObjectIds "00000000-xxxx-0000-xxxx-000000000001,00000000-xxxx-0000-xxxx-000000000002,00000000-xxxx-0000-xxxx-000000000003"

###>

function Configure-AddUserObjctIds {
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
        [Parameter(Mandatory = $true, HelpMessage = "Azts Feature Name to be Enabled/Disabled. Values for this parameter are 'CMET', 'MG_Compliance_Initiate_Editor'")]
        $FeatureName,

        [string]
        [Parameter(Mandatory = $true, HelpMessage = "user's object id can be referenced from Azure AD. Pass multiple user object id with comma seperated value")]
        $UserObjectIds
    )

    #Splitting the UserObjectIds from (,)
    $UserObjectIdsArray = $UserObjectIds.Split(',');

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
    $FilteredfeatureSetting = $JsonContent | Where-Object { ($_.FeatureName -ieq $FeatureName) }
    if ($null -ne $FilteredfeatureSetting) {
     

        #Checking if any Dependent Features needs to be enabled
        foreach ($resource in $FilteredfeatureSetting.ConfigurationDependencies) {
            $IntPrivilegedEditorIds = @()
            $NewAppSettings = @{}
            $featureName = $resource.ComponentName + $ResourceHash;

            Write-Host $([Constants]::SingleDashLine)
            Write-Host "Loading Existing configuration for: [$($featureName)]..." -ForegroundColor $([Constants]::MessageType.Info)
            Write-Host $([Constants]::SingleDashLine)
            #Getting Existing configuration value
            $AzTSAppConfigurationSettings = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $featureName -ErrorAction Stop
        
            foreach ($Configuration in $resource.Configuration) {
                if ($null -ne $AzTSAppConfigurationSettings) {
                    # Existing app settings
                    $AppSettings = $AzTSAppConfigurationSettings.SiteConfig.AppSettings

                    # Moving existing app settings in new app settings list to avoid being overridden                
                    ForEach ($appSetting in $AppSettings) {
                        $NewAppSettings[$appSetting.Name] = $appSetting.Value

                        #Checking if Configuration values exist to get the exisiting array value
                        if ($appSetting.Name.Contains($Configuration)) {
                            $appSettingNameArray = $appSetting.Name.Split('_');
                            $IntPrivilegedEditorIds += $appSettingNameArray[6];               
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
                        $NewAppSettings["$Configuration$IntPrivilegedEditorIdsMaxValue"] = $UserObjectId
                        $IntPrivilegedEditorIdsMaxValue++
                    }
                }
            }

            try {

                Write-Host $([Constants]::SingleDashLine)
                Write-Host "Updating new configuration values for: [$($featureName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                #Updating the new configuration values
                $AzTSAppConfigurationSettings = Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $FeatureName -AppSettings $NewAppSettings -ErrorAction Stop

                Write-Host "Updated new configuration values for: [$($featureName)]..." -ForegroundColor $([Constants]::MessageType.Info)
                Write-Host $([Constants]::SingleDashLine)
            }
            catch {
                Write-Host "Error occurred while updating Configuration. Error: $($_)" -ForegroundColor $([Constants]::MessageType.Error)
                break
            }         
        }        

        Write-Host "Configuration completed...." -ForegroundColor $([Constants]::MessageType.Update)
    }
    else {
        Write-Host "FeatureName does not match. Expected values are 'CMET', 'MG_Compliance_Initiate_Editor'...." -ForegroundColor $([Constants]::MessageType.Error)
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