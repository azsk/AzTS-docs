## Prerequisite AzTS configurations to enable Control Metadata Editor tool(CMET)


To enable the Control Metadata Editor tool (CMET), you need to configure a few application settings in for AzTS Function Apps/WebApps. This can be done either through the Azure portal or by using the helper script. Once these application settings are configured, please follow the steps mentioned [here](#access-to-cmet-control-metadata-editor-tool) to add users to Privileged editor roles.

### Option 1: Using Azure Portal
  1. Open the [Azure portal](https://portal.azure.com/).
  2. Navigate to AzTS host subscription -> AzTS host resource group.
  3. Go to required app service(AzSK-AzTS-WebApi-xxxxx/AzSK-AzTS-MetadataAggregator-xxxxx/AzSK-AzTS-WorkItemProcessor-xxxxx).
  4. Go to Configuration under Settings.
  5. Click on 'New application setting' to add required application setting and its value.
  6. Repeat step 5 for all settings required for Function App/Web App. Then click 'Save'.


Below mentioned appsettings are required for enabling CMET:


#### AzTS API(AzSK-AzTS-WebApi-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__AddNewControl -> true
- FeatureManagement__PolicyStates -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsAddNewControlEnabled -> true
- UIConfigurations__ControlEditorFeatureConfiguration__IsEnabled -> true
- WorkItemProcessorSettings__AppName -> AzTS work item processor web app name
- WorkItemProcessorSettings__HostResourceGroupName -> AzTS solution host resource group name
- WorkItemProcessorSettings__HostSubscriptionId -> AzTS solution host subscription id

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.

#### AzTS MetadataAggregator(AzSK-AzTS-MetadataAggregator-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.

### AzTS WorkItemProcessor(AzSK-AzTS-WorkItemProcessor-xxxxx)

- FeatureManagement__OrgPolicy -> true
- FeatureManagement__PolicyStates -> true

> **Note:** **FeatureManagement__PolicyStates** appsettings is required only for Azure custom policy-based control evaluation.
-----
### Option 2: Using Powershell
If you have already downloaded the deployment package zip, directly go to step (4).<br/>
- Download deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/DeploymentFiles.zip) to your local machine. </br>

- Extract zip to local folder location. <br/>

-  Unblock the content. The below command will help to unblock files. <br/>

    ``` PowerShell
    Get-ChildItem -Path "<Extracted folder path>" -Recurse |    Unblock-File 
    ```

-  Point current path to deployment folder and load AzTS setup script. <br/>


    ``` PowerShell
    # Point current path to extracted folder location and load setup script from the deployment folder 

    CD "<LocalExtractedFolderPath>\DeploymentFiles"

    # Load AzTS Setup script in session
    . ".\UpdateAzTSFeatures.ps1"

    # Note: Make sure you copy  '.' present at the start of the line.  
   ```

-  Connect to AzAccount.
    ``` PowerShell
      Connect-AzAccount -Tenant <TenantId>
    ```
-  Invoke the configuration cmdlet.
     ``` PowerShell
      Configure-AzTSFeature 
      -SubscriptionId <AzTSHostingSubscriptionId> `
      -ScanHostRGName <AzTSHostingRGName> `
      -FeatureName "CMET" `
      -FeatureActionType "Enable"
     ```



## Access to CMET (Control metadata editor tool)

Only privileged users have access to CMET for updating control metadata or adding new controls. This can be done either through the Azure portal or by using the helper script. To elevate a user to a privileged role, please follow the steps outlined below:
### Option 1: Using Azure Portal
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

### Option 2: Using Powershell
  If you have already downloaded the deployment package zip, directly go to step (4).<br/>
- Download deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/DeploymentFiles.zip) to your local machine. </br>

- Extract zip to local folder location. <br/>

-  Unblock the content. The below command will help to unblock files. <br/>

    ``` PowerShell
    Get-ChildItem -Path "<Extracted folder path>" -Recurse |    Unblock-File 
    ```

-  Point current path to deployment folder and load AzTS setup script. <br/>


    ``` PowerShell
    # Point current path to extracted folder location and load setup script from the deployment folder 

    CD "<LocalExtractedFolderPath>\DeploymentFiles"

    # Load AzTS Setup script in session
    . ".\UpdateAzTSFeatures.ps1"

    # Note: Make sure you copy  '.' present at the start of the line.  
   ```

-  Connect to AzAccount.
    ``` PowerShell
      Connect-AzAccount -Tenant <TenantId>
    ```
-  Invoke the configuration cmdlet.
     ``` PowerShell
      Add-AztsFeatureConfigurationValues 
      -SubscriptionId <AzTSHostingSubscriptionId> `
      -ScanHostRGName <AzTSHostingRGName> `
      -FeatureName "CMET" ` 
      -FeatureConfigValues <User`s object id>

      <# Note: 1) User's object id can be referenced from Azure AD.
      2) For adding multiple user, pass the user's object id value seperated by comma(',').
      For example:  
        Add-AztsFeatureConfigurationValues 
        -SubscriptionId "00000000-xxxx-0000-xxxx-000000000000" `
        -ScanHostRGName "AzTS-Solution-XX" `
        -FeatureName "MG `Compliance Initiate Editor" `
        -FeatureConfigValues "00000000-xxxx-0000-xxxx-000000000001,00000000-xxxx-0000-xxxx-000000000002,00000000-xxxx-0000-xxxx-000000000003"
     ```
