# AVDApplicationGroups

**Resource Type:** Microsoft.DesktopVirtualization/ApplicationGroups

<!-- TOC -->

- [Azure_AVD_Audit_Enable_ApplicationGroup_Diagnostics](#Azure_AVD_Audit_Enable_ApplicationGroup_Diagnostics)

<!-- /TOC -->
<br/>

___ 

## Azure_AVD_Audit_Enable_ApplicationGroup_Diagnostics

### Display Name 
Diagnostic settings must be enabled for AVD Application Groups.

### Rationale 
Diagnostic logs are needed for creating activity trail while investigating an incident or a compromise.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
		"Checkpoint",
		"Management",
		"Error"
    ],
    "DiagnosticMinRetentionPeriod":
	"365"
}
 ``` 
### Control Spec 

> **Passed:** 
> 1. Required diagnostic logs are enabled.
> 2. At least one of the below setting configured:
> a. Log Analytics.
> b. Storage account (with min Retention period of 365 or forever(Retention period 0).
> c. Event Hub.
> 
> **Failed:** 
> 1. Diagnostics setting is disabled for resource.
> 
>       or
>
> 2. Diagnostic settings meet the following conditions:
> a. All diagnostic logs are not enabled.
> b. None of the below setting is configured:
> i. Log Analytics.
> ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
> iii. Event Hub.
> 
> **Error:** 
> Required logs are not configured in control settings.
> 

### Recommendation 

- **Azure Portal** 

	 You can create or update the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings?tabs=portal#create-diagnostic-settings.

- **PowerShell** 

	 ```powershell 

	# Below commands will be useful to Configure diagnostic settings on AVDApplicationGroups

    Connect-AzAccount
	Set-AzContext -SubscriptionId "<sub id>"`
	
	#Add diagnostic settings to an existing AVDApplicationGroups
	$log = @()
	$log += New-AzDiagnosticSettingLogSettingsObject -Enabled $true -CategoryGroup allLogs

	New-AzDiagnosticSetting -Name <DiagnosticSettingName> -ResourceId <AVDApplicationGroupsResourceId> -WorkspaceId <LogAnalyticsWorkspaceID> -Log $log -StorageAccountId <StorageAccountResourceId> -EventHubName <EventHubName>-EventHubAuthorizationRuleId <EventHubAuthorizationRuleId>

	
	Note: If Storage Accounts are used to store diagnostic logs, minimum retention period must be set to '365' or '0' (forever). 
 	```  
### Azure Policy or ARM API used for evaluation 

- ARM API to list diagnostic setting details of AVDApplicationGroups resources: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DesktopVirtualization/applicationgroups/{AVDApplicationGroupsName}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
<br/>
**Properties:**<br/> 
name<br />
properties.logs.category<br />
properties.logs.enabled<br />
properties.logs.retentionPolicy.enabled<br />
properties.logs.retentionPolicy.days<br />
properties.workspaceId<br />
properties.storageAccountId<br />
properties.eventHubName<br />
<br />

<br />
