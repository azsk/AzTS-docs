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
  - Download the script from [here](./Scripts/ConfigureCustomControlAdditionPrerequisites.ps1)
  > **Note:** Script can be downloaded by clicking Alt+Raw button.
  - Open a powershell session.
  - Navigate to the download location of the script in powershell session.
    - cd "Script download location"
  - Unblock the downloaded script.
    - Unblock-File -Path ".\ConfigureCustomControlAdditionPrerequisites.ps1"
  - Load the script in current powershell session.
    - . ".\ConfigureCustomControlAdditionPrerequisites.ps1"
    > **Note:** Do not miss the '.' at beginning of the above command.
  - Connect to AzAccount
    - Connect-AzAccount -Tenant "AzTSHostingTenantId"
  - Invoke the configuration cmdlet
    - Configure-CustomControlAdditionPrerequisites -SubscriptionId "AzTSHostingSubscriptionId" -ScanHostRGName "AzTSHostingRGName"

-----
## Access to CMET (Control metadata editor tool)

Any user can add new controls using the CMET (Control metadata editor tool) from the AzTS UI. Only the privileged users can access CMET. To elevate any user to privileged role kindly follow the steps mentioned below:

- Open the [Azure portal](https://portal.azure.com/).
- Navigate to AzTS host subscription -> AzTS host resource group.
- Go to required AzTS API app service(AzSK-AzTS-WebApi-xxxxx).
- Go to Configuration under Settings.
- Click on "New application setting" to add required appsettings.
- Add **ControlActionItem__0__PrivilegedEditorIds__[index]** as the Name of the appsetting.
> **Note:** For first user being added **index** value should be 0, eg. **ControlActionItem__0__PrivilegedEditorIds__0** and incremented sequentially for further users being added.
- Add the user's object id as the value of the appsetting.
> **Note:** user's object id can be referenced from Azure AD.
