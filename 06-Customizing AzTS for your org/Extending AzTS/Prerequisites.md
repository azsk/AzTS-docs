## Prerequisite AzTS configurations to enable Control Metadata Editor tool(CMET)


To enable the Control Metadata Editor tool (CMET), you need to configure a few application settings in for AzTS Function Apps/WebApps. This can be done either through the Azure portal or by using the helper script. Once these application settings are configured, please follow the steps mentioned [here](#access-to-cmet-control-metadata-editor-tool) to add users to Privileged editor roles.

- Using Azure Portal
  1. Open the [Azure portal](https://portal.azure.com/).
  2. Navigate to AzTS host subscription -> AzTS host resource group.
  3. Go to required app service(AzSK-AzTS-WebApi-xxxxx/AzSK-AzTS-MetadataAggregator-xxxxx/AzSK-AzTS-WorkItemProcessor-xxxxx).
  4. Go to Configuration under Settings.
  5. Click on 'New application setting' to add required application setting and its value.
  6. Repeat step 5 for all settings required for Function App/Web App. Then click 'Save'.


Below mentioned appsettings are required for enabling CMET:


### AzTS API(AzSK-AzTS-WebApi-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__AddNewControl -> true
- FeatureManagement__PolicyStates -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled -> true
- WorkItemProcessorSettings__AppName -> AzTS work item processor web app name
- WorkItemProcessorSettings__HostResourceGroupName -> AzTS solution host resource group name
- WorkItemProcessorSettings__HostSubscriptionId -> AzTS solution host subscription id

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.

### AzTS MetaDataAggregator(AzSK-AzTS-MetadataAggregator-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.

### AzTS WorkItemProcessor(AzSK-AzTS-WorkItemProcessor-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.
-----


- Using helper script
  - Download the script from [here](../../TemplateFiles/DeploymentFiles.zip), skip this step if you have already downloaded the deployment package zip
  > **Note:** Script can be downloaded by clicking Alt+Raw button.
  - Open a PowerShell session.
  - Navigate to the download location of the script in PowerShell session.
    - cd "Script download location"
  - Unblock the downloaded script.
    - Unblock-File -Path ".\ConfigureAzTSFeature.ps1"
  - Load the script in current PowerShell session.
    - . ".\ConfigureAzTSFeature.ps1"
    > **Note:** Do not miss the '.' at beginning of the above command.
  - Connect to AzAccount
    - Connect-AzAccount -Tenant "AzTSHostingTenantId"
  - Invoke the configuration cmdlet
    - Configure-AzTSFeature -SubscriptionId "AzTSHostingSubscriptionId" -ScanHostRGName "AzTSHostingRGName" -FeatureName "CMET"  -FeatureActionType "Enable"


## Access to CMET (Control metadata editor tool)

Only privileged users have access to CMET for updating control metadata or adding new controls. To elevate a user to a privileged role, please follow the steps outlined below:

- Open the [Azure portal](https://portal.azure.com/).
- Navigate to AzTS host subscription -> AzTS host resource group.
- Go to required AzTS API app service(AzSK-AzTS-WebApi-xxxxx).
- Go to Configuration under Settings.
- Click on "New application setting" to add required appsettings.
- Add **ControlActionItem__0__PrivilegedEditorIds__[index]** as the Name of the appsetting.
> **Note:** For first user being added **index** value should be 0, eg. **ControlActionItem__0__PrivilegedEditorIds__0** and incremented sequentially for further users being added.
- Add the user's object id as the value of the appsetting.
> **Note:** user's object id can be referenced from Azure AD.
-----

- Using helper script
  - Download the script from [here](../../TemplateFiles/DeploymentFiles.zip), skip this step if you have already downloaded the deployment package zip
  > **Note:** Script can be downloaded by clicking Alt+Raw button.
  - Open a PowerShell session.
  - Navigate to the download location of the script in PowerShell session.
    - cd "Script download location"
  - Unblock the downloaded script.
    - Unblock-File -Path ".\Add-AztsFeatureConfigurationValues.ps1"
  - Load the script in current PowerShell session.
    - . ".\Add-AztsFeatureConfigurationValues.ps1"
    > **Note:** Do not miss the '.' at beginning of the above command.
  - Connect to AzAccount
    - Connect-AzAccount -Tenant "AzTSHostingTenantId"
  - Invoke the configuration cmdlet
    - Add-AztsFeatureConfigurationValues -SubscriptionId "AzTSHostingSubscriptionId" -ScanHostRGName "AzTSHostingRGName" -FeatureName "CMET"  -FeatureConfigValues "user's object id"
    > **Note:** user's object id can be referenced from Azure AD.<br />
    For adding multiple user, pass the user's object id value seperated by comma(',').<br />
    For example:  Add-AztsFeatureConfigurationValues -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" -ScanHostRGName "AzTS-Solution-XX" -FeatureName "CMET"  -FeatureConfigValues "00000000-xxxx-0000-xxxx-000000000001,00000000-xxxx-0000-xxxx-000000000002,00000000-xxxx-0000-xxxx-000000000003"
