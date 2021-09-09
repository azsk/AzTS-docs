## Prerequisite AzTS configurations to add new control
Below mentioned appsettings are required before adding new controls:

### AzTS API

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__AddNewControl -> true
- FeatureManagement__PolicyStates -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled -> true
- WorkItemProcessorSettings__AppName -> AzTS work item processor web app name
- WorkItemProcessorSettings__HostResourceGroupName -> AzTS solution host resource group name
- WorkItemProcessorSettings__HostSubscriptionId -> AzTS solution host subscription id

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy based control evaluation.

### AzTS MetaDataAggregator

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy based control evaluation.

### AzTS WorkItemProcessor

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy based control evaluation.
-----
Above mentioned appsettings can be configured either from Azure portal or using the helper script provided with AzTS solution.

- Azure Portal
  - Open the [Azure portal](https://portal.azure.com/).
  - Navigate to AzTS host subscription -> AzTS host resource group.
  - Go to required app service(AzSK-AzTS-WebApi-xxxxx/AzSK-AzTS-MetadataAggregator-xxxxx/AzSK-AzTS-WorkItemProcessor-xxxxx).
  - Go to Configuration under Settings.
  - Click on "New application setting" to add required appsettings.

- Using helper script
  - Download the script from [here](./Scripts/ConfigureCustomControlAdditionPrerequisites.ps1)(Script can be downloaded by clicking Alt+Raw button).
  - Open a powershell session.
  - Navigate to the download location of the script in powershell session.
    - cd "Script download location"
  - Load the script in current powershell session.
    - . ".\ConfigureCustomControlAdditionPrerequisites.ps1"
    > **Note:** Do not miss the '.' at beginning of the above command.
  - Connect to AzAccount
    - Connect-AzAccount -Tenant "AzTSHostingTenantId"
  - Invoke the configuration cmdlet
    - Configure-CustomControlAdditionPrerequisites -SubscriptionId "AzTSHostingSubscriptionId" -ScanHostRGName "AzTSHostingRGName"
