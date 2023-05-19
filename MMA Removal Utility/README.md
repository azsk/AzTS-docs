----------------------------------------------

> The Azure Tenant Security Solution (AzTS) was created by the Core Services Engineering & Operations (CSEO) division at Microsoft, to help accelerate Microsoft IT's adoption of Azure. We have shared AzTS and its documentation with the community to provide guidance for rapidly scanning, deploying and operationalizing cloud resources, across the different stages of DevOps, while maintaining controls on security and governance.
<br>AzTS is not an official Microsoft product – rather an attempt to share Microsoft CSEO's best practices with the community.

# AzTS MMA Removal Utility

-----------------------------------------------------------------
## Overview 

AzTS MMA Removal utility can be used to remove MMA extension/agent from Azure Virtual Machine (VMs) across subscriptions. Microsoft Monitoring Agent (MMA) will be retired on 31 August 2024 and users need to migarte to Azure Monitor agent (AMA). If you have already migrated all of your Virtual Machines (VMs) to start using AMA for monitoring, it is recommened to remove MMA agent to avoide dupliaction of logs.

AzTS MMA Removal utility can help to remove MMA extension from VMs which already have AMA extension present at tenant scale in centralized manner instead of doing it per VM manullay.

## How it works?

AzTS MMA Removal utility works in two phases:
1. Discovery Phase
2. Removal Phase

**1- Discovery Phase**

In this phase, it will collect all Virtual Machines and their extensions inventory to identify, which VMs have both MMA and AMA agent. Users can validate such VMs, VMs having both MMA and AMA agent will be processed further to remova MMA extension in next 'Removal Phase'.

It is recommened to avoid creating new VMs with MMA extension or installing MMA extension on existing VMs after AzTS MMA Removal utility starts processing. For this you can assign Azure policy with 'Deny' effect on your subscriptions before running this utility. Guidance for same is available [here] (link).

**2- Removal Phase**

VMs having both MMA and AMA agent will be applicable for this phase. In this phase actual removal of MMA extension from VM will be done. If needed users can disbale this phase, and enable it after validating the such VMs list post Discovery phase.

## Installation

Please follow steps provider here, to install and configure AzTS MMA Removal utility.

## FAQs

### **1. At what scope(s) AzTS MMA Removal utility can run?** 
Scopes in AzTS MMA Removal utility is configurable, you can configure to run it at selected subscriptions socpe, selected management groups scope, entire tenant or for multiple tenants as well.

### **2. What permissons AzTS MMA Removal utility needs?** 
AzTS MMA Removal utility will create one remediation identity (User assigned managed identity in case of single tenant and AAD App/SPN in case of multi-tenant scopes), this identity requires 'Reader' and 'Virtual Machine Contributor' role at configured scopes. 

### **3. After MMA agents has been removed from all VMs, should I clean-up setup?**
Once MMA agents has been removed from all VMs, you can delete all setup resources using clean-up steps available here. You may want to keep inventory/process logs for future reference, steps to keep same will be available in clean-up guidance itself.

### **4. What's the cost of running AzTS MMA Removal utility?**
TBD. If you choose to keep inventory/process logs, cost will increase as per the period you choose.

### **5. How much AzTS MMA Removal utility will take to remove MMA agnets?**
TBD

### **6. How I can get list of all the VMs available in configured scope(s)?**
TBD, Reach LA + Query

``` KQL
Inventory_CL
| where TimeGenerated > ago(3d)
| where ResourceType =~ "VirtualMachine"
| summarize arg_max(TimeGenerated,*) by ResourceId = tolower(ResourceId)
| extend OSType = tostring(parse_json(Metadata_s).OSType)
```

### **7. How I can get list of all the VMs which have both MMA & AMA agent present and are eligible for removal phase?**
TBD, Reach LA + Query

``` KQL
let timeago = timespan(4d);
let virtualMachines = Inventory_CL
| where TimeGenerated > ago(timeago)
| where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
| where ResourceType =~ "VirtualMachine"
| summarize arg_max(TimeGenerated,*) by ResourceId = tolower(ResourceId)
| extend  OSType = tostring(parse_json(Metadata_s).OSType)
| project VMResourceID = ResourceId, OSType;
let virtualMachinesExtensions = Inventory_CL
| where TimeGenerated > ago(timeago)
| where JobId_d == toint(format_datetime(now(), 'yyyyMMdd'))
| where ResourceType =~ "VMExtension" and Source_s =~ "AzTS_05_VMExtensionInventoryProcessor"
| summarize arg_max(TimeGenerated,*) by ResourceId = tolower(ResourceId)
| extend VMResourceID = tolower(substring(ResourceId,0,indexof(ResourceId, '/', 0, -1, 9 )))
| extend ExtensionType = tostring(parse_json(Metadata_s).ExtensionType)
| project ResourceId, VMResourceID, ExtensionType;
let virtualMachinesWithBothExtensions = virtualMachines
| join kind=leftouter (virtualMachinesExtensions) on VMResourceID
| summarize Extensions = make_list(ExtensionType) by VMResourceID, OSType
|where (Extensions contains "MicrosoftMonitoringAgent" or Extensions contains "OmsAgentForLinux") and (Extensions contains "AzureMonitorWindowsAgent" or Extensions contains "AzureMonitorLinuxAgent");
virtualMachinesWithBothExtensions
```



