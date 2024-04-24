# Stream Analytics Jobs
**Resource Type:** Microsoft.StreamAnalytics/streamingJobs

<!-- TOC -->

- [Azure_StreamAnalytics_Audit_Enable_Diagnostic_Settings](#azure_streamanalytics_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_StreamAnalytics_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure Stream Analytics

### Rationale 
Diagnostic logs must be enabled as they provide details for investigation in case of a security breach for threats.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "Execution",
        "Authoring"
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
    - "To Configure 'Diagnostic settings' for Stream Analytics, go to Azure Portal --> Your Stream Analytics Resource --> Diagnostic settings --> Enable Execution and Authoring Logs with a minimum retention period of 90 days.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostic settings and its related properties at Resource level:
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
**Properties:**
properties.metrics.category,properties.metrics.enabled,properties.metrics.retentionPolicy.enabled, properties.metrics.retentionPolicy.days
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled,properties.metrics.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName
 <br />

- REST API used to list diagnostic category group mapping and its related properties at Resource level:
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview <br />
**Properties:**
properties.categoryGroups, name
<br />
___ 


