# **Steps to clean up AzTS MMA Removal Utility**

In this section, we will walk you through the steps of cleaning up or deleting resources associated with AzTS MMA Removal Utility.

Before initiating the cleanup please validate the prerequisites, download and extract deployment package using the link [here](./Prerequisites.md).

As part of cleanup execute the following steps:

1. [Load cleanup script](#step-1-of-2-load-cleanup-script)
3. [Execute cleanup command](#step-2-of-2-execute-cleanup-command)

Let's start!

> _**Note: ** Please validate the prerequisites [here](./Prerequisites.md) and then proceed with the below steps_

<br/>

### **Step 1 of 2. Load cleanup script**
 
 1. Point the current path to the folder containing the extracted deployment package and load the cleanup script for AzTS MMA Removal Utility <br/>

  ``` PowerShell
  # Point current path to extracted folder location and load cleanup script from the deployment folder 
  CD "<LocalExtractedFolderPath>\AzTSMMARemovalUtilityDeploymentFiles"
  # Load AzTS MMA Removal Utility delete script in session
  . ".\MMARemovalUtilityCleanUpScript.ps1"
  # Note: Make sure you copy '.' present at the start of the line.
  ```
[Back to top…](#steps-to-clean-up-azts-mma-removal-utility)

<br/>

### **Step 2 of 2. Execute cleanup command**  
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
|KeepInventoryAndProcessLogs| Boolean flag to exclude log analytics workspace and application insights while cleanup of AzTS MMA Removal Utility solution resources. This switch cannot be used with DeleteResourceGroup.| No|

[Back to top…](#steps-to-clean-up-azts-mma-removal-utility)

<br/>