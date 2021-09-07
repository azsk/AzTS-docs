function Configure-CustomControlAdditionPrerequisites
{
    Param(
        [string]
        [Parameter(Mandatory = $true, HelpMessage="Subscription id in which Azure Tenant Security Solution is installed.")]
        $SubscriptionId,

        [string]
		[Parameter(Mandatory = $true, HelpMessage="Name of ResourceGroup where Azure Tenant Security Solution is installed.")]
        $ScanHostRGName
    )

    # Set the context to host subscription
        Set-AzContext -SubscriptionId  $SubscriptionId
    
    # AzTS resources name preparation
    $ResourceId='/subscriptions/{0}/resourceGroups/{1}' -f $SubscriptionId,$ScanHostRGName;
    $ResourceIdHash = get-hash($ResourceId)
    $ResourceHash = $ResourceIdHash.Substring(0,5).ToString().ToLower()

    $APIName = "AzSK-AzTS-WebApi-" + $ResourceHash
    $MetaDataAggregatorName = "AzSK-AzTS-MetadataAggregator-" + $ResourceHash
    $WorkItemProcessorName = "AzSK-AzTS-WorkItemProcessor-" + $ResourceHash

    Write-Host "Configuring AzTS API : $APIName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Info)
    
    $AzTSAPI = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $APIName -ErrorAction Stop

    if($null -ne $AzTSAPI)
    {
        # Existing app settings
        $APIAppSettings = $AzTSAPI.SiteConfig.AppSettings

        # Moving existing app settings in new app settings list to avoid being overridden
        $NewAPIAppSettings = @{}
        ForEach ($appSetting in $APIAppSettings) {
            $NewAPIAppSettings[$appSetting.Name] = $appSetting.Value
        }

        # Adding new settings to new app settings list
        $NewAPIAppSettings['FeatureManagement__OrgPolicy'] = "true"
        $NewAPIAppSettings['FeatureManagement__AddNewControl'] = "true"
        $NewAPIAppSettings['FeatureManagement__PolicyStates'] = "true"
        $NewAPIAppSettings['UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled'] = "true"
        $NewAPIAppSettings['UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled'] = "true"
        $NewAPIAppSettings['WorkItemProcessorSettings__AppName'] = $WorkItemProcessorName
        $NewAPIAppSettings['WorkItemProcessorSettings__HostResourceGroupName'] = $ScanHostRGName
        $NewAPIAppSettings['WorkItemProcessorSettings__HostSubscriptionId'] = $SubscriptionId

        # Configuring new app settings
        Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $APIName -AppSettings $NewAPIAppSettings -ErrorAction Stop

        Write-Host "Configured AzTS API : $APIName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)

    }

    Write-Host "Configuring AzTS MetaDataAggregator : $MetaDataAggregatorName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Info)
    
    $AzTSMDA = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $MetaDataAggregatorName -ErrorAction Stop

    if($null -ne $AzTSMDA)
    {
        # Existing app settings
        $MDAAppSettings = $AzTSMDA.SiteConfig.AppSettings

        # Moving existing app settings in new app settings list to avoid being overridden
        $NewMDAAppSettings = @{}
        ForEach ($appSetting in $MDAAppSettings) {
            $NewMDAAppSettings[$appSetting.Name] = $appSetting.Value
        }

        # Adding new settings to new app settings list
        $NewMDAAppSettings['FeatureManagement__OrgPolicy'] = "true"
        $NewMDAAppSettings['FeatureManagement__PolicyStates'] = "true"

        # Configuring new app settings
        Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $MetaDataAggregatorName -AppSettings $NewMDAAppSettings -ErrorAction Stop

        Write-Host "Configured AzTS MetaDataAggregator : $MetaDataAggregatorName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)

    }

    Write-Host "Configuring AzTS WorkItemProcessor : $WorkItemProcessorName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Info)
    
    $AzTSWIP = Get-AzWebApp -ResourceGroupName $ScanHostRGName -Name $WorkItemProcessorName -ErrorAction Stop

    if($null -ne $AzTSWIP)
    {
        # Existing app settings
        $WIPAppSettings = $AzTSWIP.SiteConfig.AppSettings

        # Moving existing app settings in new app settings list to avoid being overridden
        $NewWIPAppSettings = @{}
        ForEach ($appSetting in $WIPAppSettings) {
            $NewWIPAppSettings[$appSetting.Name] = $appSetting.Value
        }

        # Adding new settings to new app settings list
        $NewWIPAppSettings['FeatureManagement__OrgPolicy'] = "true"
        $NewWIPAppSettings['FeatureManagement__PolicyStates'] = "true"

        # Configuring new app settings
        Set-AzWebApp -ResourceGroupName $ScanHostRGName -Name $WorkItemProcessorName -AppSettings $NewWIPAppSettings -ErrorAction Stop

        Write-Host "Configured AzTS WorkItemProcessor : $WorkItemProcessorName for Custom policy based control addition and evaluation" -ForegroundColor $([Constants]::MessageType.Update)
        Write-Host $([Constants]::DoubleDashLine)

    }

    Write-Host "Configuration completed. Ready to add policy based control now..." -ForegroundColor $([Constants]::MessageType.Update)
}

function get-hash([string]$textToHash) 
{
    $hasher = new-object System.Security.Cryptography.MD5CryptoServiceProvider
    $toHash = [System.Text.Encoding]::UTF8.GetBytes($textToHash)
    $hashByteArray = $hasher.ComputeHash($toHash)
    $result = [string]::Empty;
    foreach($byte in $hashByteArray)
    {
      $result += "{0:X2}" -f $byte
    }
    return $result;
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