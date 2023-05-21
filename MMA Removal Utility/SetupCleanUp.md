# **Steps to clean up AzTS MMA Removal Utility**

In this section, we will walk you through the steps of cleaning up or deleting resources associated with AzTS MMA Removal Utility.

Before initiating the deletion please validate the prerequisites, download and extract deployment package using [Prerequisites](./Prerequisites.md).

As part of cleanup execute the following steps:

1. [Load deletion script](#step-1-of-2-load-deletion-script)
3. [Execute deletion command](#step-2-of-2-execute-deletion-command)

Let's start!

> _**Note:** Please validate the prerequisites [here](./Prerequisites.md). You can download the deployment package zip from [here](https://github.com/azsk/AzTS-docs/raw/main/TemplateFiles/AzTSMMARemovalUtilityDeploymentFiles.zip) and before extracting the zip file, right click on the zip file --> click on 'Properties' --> Under the General tab in the dialog box, select the 'Unblock' checkbox --> Click on 'OK' button. Extract the zip file and use **MMARemovalUtilityDeletionScript.ps1** present in this package to run the commands mentioned in below steps_

<br/>

### **Step 1 of 2. Load deletion script**
 
 1. Point current path to deployment folder and load AzTS MMA Removal Utility deletion script <br/>

  ``` PowerShell
  # Point current path to extracted folder location and load deletion script from the deployment folder 
  CD "<LocalExtractedFolderPath>\AzTSMMARemovalUtilityDeploymentFiles"
  # Load AzTS MMA Removal Utility delete script in session
  . ".\MMARemovalUtilityDeletionScript.ps1"
  # Note: Make sure you copy  '.' present at the start of the line.
  ```
[Back to top…](#steps-to-clean-up-azts-mma-removal-utility)

<br/>

### **Step 2 of 2. Execute deletion command**  
MMA Utility setup can be cleaned up using Remove-AzTSMMARemovalUtilitySolutionResources

``` PowerShell
# -----------------------------------------------------------------#
# Clean up AzTS MMA Removal Utility Solution Resources
# -----------------------------------------------------------------#

Remove-AzTSMMARemovalUtilitySolutionResources ` 
    -SubscriptionId <HostingSubId> `
    -ResourceGroupName <HostingRGName> `
    -DeleteResourceGroup `
    -KeepInventoryAndProcessLogs

```

**Parameter details:**
|Param Name|Description|Required?
|----|----|----|
|SubscriptionId| Subscription id from which AzTS MMA Removal Utility solution resoure group will be deleted.| Yes|
|ResourceGroupName| Name of ResourceGroup which will be deleted.| Yes|
|DeleteResourceGroup| Boolean flag to delete entire resource group of AzTS MMA Removal Utility solution resources.| Yes|
|KeepInventoryAndProcessLogs| Boolean flag to exclude log analytics workspace and application insights while deletion of AzTS MMA Removal Utility solution resources. This switch cannot be used with DeleteResourceGroup.| No|

[Back to top…](#steps-to-clean-up-azts-mma-removal-utility)

<br/>