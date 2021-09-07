## Prerequisite AzTS configurations to add new control
Below mentioned configurations are required before adding new controls:

### AzTS API

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__AddNewControl -> true
- FeatureManagement__PolicyStates -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled -> true
- WorkItemProcessorSettings__AppName -> work item processor web app name
- WorkItemProcessorSettings__HostResourceGroupName -> AzTS solution host resource group name
- WorkItemProcessorSettings__HostSubscriptionId -> AzTS solution host subscription id

### AzTS MetaDataAggregator

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

### AzTS WorkItemProcessor

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

Above mentioned settings can be configured either from Azure portal or using the helper script provided with AzTS solution.

- Azure Portal
  - Open the [Azure portal](https://portal.azure.com/).
  - Navigate to AzTS host subscription -> AzTS host resource group.
  - Go to required app service(API/MetaDataAggreagator/workItemProcessor) -> Configuration -> Click on "New application setting" to add required app settings.

- Using helper script
  - Download the script from [here]()(Script can be downloaded by clicking Alt+Raw button).
  - Open powershell session.
  - Navigate to the download location of the script in powershell session.
    - cd "Download location"
  - Load script in session.
    - . ".\ConfigureCustomPolicyControlEval.ps1"
    - Note : Do not miss the '.' at beginning of the above command
  - Invoke the configuration cmdlet
    - Configure-CustomControlAdditionPrerequisites -SubscriptionId "AzTS solution host subscription id" -ScanHostRGName "AzTS solution host resource group name"
