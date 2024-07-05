# Data Share
**Resource Type:** Microsoft.DataShare/accounts


<!-- TOC -->

- [Azure_DataShare_Audit_Enable_Diagnostic_Settings](#azure_datashare_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_DataShare_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure Data Share

### Rationale 
Auditing logs must be enabled as they provide details for investigation in case of a security breach for threats.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "Shares",
        "ShareSubscriptions",
        "SentShareSnapshots",
        "ReceivedShareSnapshots"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Diagnostic settings should meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below setting configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 90 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1. Diagnostic settings should meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. No logs destination is configured:
>          i. Log Analytics.
>          ii. Storage account with min Retention period of 90 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - To configure diagnostic settings: Go to the Azure portal --> Data Share --> Monitoring --> select Diagnostic settings --> Add diagnostic settings --> Select the required diagnostic setting from categories --> Select one or more destination targets, such as a Log Analytics workspace, a storage account, or an event hub --> Select Save.

      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostic settings and its related properties at Resource level:
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
**Properties:**
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName
 <br />

- REST API used to list diagnostic category group mapping and its related properties at Resource level:
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview <br />
**Properties:**
properties.categoryGroups, name
<br />
___ 


