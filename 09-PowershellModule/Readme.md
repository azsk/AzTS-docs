
## Installation Guide

>**Pre-requisites**:
> - PowerShell 7.0 or higher. 
> - Windows OS
	
1. First verify that prerequisites are already installed:  
    Ensure that you are using Windows OS and have PowerShell version 7.0 or higher by typing **$PSVersionTable** in the PS/ISE console window and looking at the PSVersion in the output as shown below.) 
 If the PSVersion is older than 7.0, update PowerShell using command 
 ```Powershell
    iex "& { $(irm aka.ms/install-powershell.ps1) } -UseMSI"
``` 
   ![PowerShell Version](../Images/09_PS_VERSION.PNG)   

2. Install the Tenant Security Solution for Azure (AzTS) PS module:  
	  
```PowerShell
  Install-Module AzTS -Scope CurrentUser
```


## AzTS command

> **Note**: AzTS cmdlet support 3 letter acronyms (e.g.: IAS). You can invoke cmdlet using these *after* AzTS has been imported in the session. So, to use this alias, make sure you run 'ipmo AzTS' as the first thing in a new PS/ISE console window ('ipmo' itself is an alias for 'import-module'). Apart from cmdlet, parameters also have associated aliases.

| Command (alias) | What it does |	Required Permission |
|----|----|-----|
|Invoke-AzureScan (IAS)|Scans an Azure subscription for security best practices and configuration baselines for things such as alerts, ARM policy, RBAC, MDC, etc.|Reader on subscription|


## List of commonly used parameters

| Parameter (alias) |
|-------------------|
|SubscriptionId (sid)|
|TenantId (tid)|
|FilterTags (ftg)|
|ResourceTypeNames (rtn)|
|ExcludeResourceTypeNames (ertn)|
|ControlIds (cids)|
|ExcludeControlIds (ecids)|

----------------------------------------------------------
## AzTS: Subscription Health Scan

### Overview
 
The subscription health check script runs a set of automated scans to examine a subscription and flags 
off conditions that are indications that your subscription may be at a higher risk due to various security 
issues, misconfigurations or obsolete artifacts/settings. 

The following aspects of security are checked:
1. 	 Access control configuration - identity and access management related issues in the subscription
2. 	 Alert configuration - configuration of activity alerts for sensitive actions for the subscription and various cloud resources
3. 	 Microsoft Defender for Cloud configuration - configuration of MDC (security point of contact, various MDC policy settings, etc.)
4. 	 ARM Policy and Resource Locks configuration - presence of desired set of ARM policy rules and resource locks. 

### Scan the security health of your subscription 

The subscription health check script can be run using the command below after replacing `<SubscriptionId`> 
 with your subscriptionId and  `<TenantId`> with your tenantId of subscription.
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId> -TenantId <TenantId>
```
The parameters used are:
- SubscriptionId – Subscription ID is the identifier of your Azure subscription
- TenantId - Tenant ID is the identifier for your Azure tenant 

You need to have at least **Reader** role at the subscription scope to run this command. 

### Subscription Health Scan - How to fix findings?

AzTS cmdlet generate outputs which are organized as under: 
- summary information of the control evaluation (pass/fail) status in a CSV file

To address findings, you should do the following:
1. See the summary of control evaluation first in the CSV file. (Open the CSV in XLS. Use "Format as Table", "Hide Columns", "Filter", etc.)
2. Review controls that are marked as "Failed" or "Verify"
3. The 'Remediation Steps' column for each control in the XLS will tell you the command/steps needed to resolve the issue.


### Target specific controls during a subscription health scan

The subscription health check supports multiple parameters as specified below:
- SubscriptionId – Subscription ID is the identifier of your Azure subscription 
- TenantId - Tenant ID is the identifier of your Azure subscription
- FilterTags  - Comma separated tags to filter the security controls. e.g.: RBAC, Automated, etc.
- ControlIds  - Comma separated control ids to filter the security controls. e.g.:Azure_Storage_AuthN_Dont_Allow_Anonymous,"Azure_APIManagement_DP_Use_HTTPS_URL_Scheme, etc.
- ResourceTypeNames - Comma separated resource type to filter the security controls. e.g.:Storage,SubsciptionCore, etc.
- ExcludeControlIds - Comma separated control ids to exclude the security controls. e.g.:Azure_Storage_AuthN_Dont_Allow_Anonymous,Azure_APIManagement_DP_Use_HTTPS_URL_Scheme, etc.
- ExcludeResourceTypeNames - Comma separated resource type to exclude the security controls. e.g.:Storage,SubsciptionCore, etc.
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId> -TenantId <TenantId> [-ControlIds <ControlIds>] [-FilterTags <FilterTags>] [-ResourceTypeNames <ResourceTypeNames>] [-ExcludeControlIds <ExcludeControlIds>] [-ExcludeResourceTypeNames <ExcludeResourceTypeNames>] 
```
These different parameters would enable you to execute different 'flavors' of subscription health scan.  
Here are some examples:

1. Execute only RBAC related controls.
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId> -TenantId <TenantId> -FilterTags "RBAC"
``` 
2. Execute all the controls related to storage resource type.
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId>  -TenantId <TenantId> ResourceTypeNames "Storage"
``` 
3. Execute specific control related to storage resource type. 
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId> -TenantId <TenantId> -ControlIds Azure_Storage_AuthN_Dont_Allow_Anonymous
``` 
4. Exclude specific control related to storage resource type. 
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId> -TenantId <TenantId> -ControlIds Azure_Storage_AuthN_Dont_Allow_Anonymous
``` 
5. Exclude all the controls related to storage resource type.
```PowerShell
Invoke-AzureScan -SubscriptionId <SubscriptionId>  -TenantId <TenantId> ResourceTypeNames "Storage"
``` 
