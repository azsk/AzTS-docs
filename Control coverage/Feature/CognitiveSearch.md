# Cognitive Search
**Resource Type:** Microsoft.Search/searchServices

<!-- TOC -->

- [Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only](#azure_aisearch_authz_enable_role_based_api_access_only)
- [Azure_IoTHubs_Audit_Enable_Diagnostic_Settings](#azure_iothubs_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_AISearch_AuthZ_Enable_Role_Based_API_Access_Only
 

### Display Name 
Protect Azure AI Search Instances by only allowing RBAC API Access

### Rationale 
Disabling key-based API access control mitigates the risk of unauthorized access, ensuring that only authenticated users with appropriate credentials can interact with the service. This security measure aligns with best practices, protecting sensitive data and system integrity.

### Control Spec 

> **Passed:** 
> Role based API access is enabled on Azure AI search (disableLocalAuth property is true).
> 
> **Failed:** 
> Role based API access is disabled on Azure AI search (disableLocalAuth property is false).

 
### Recommendation 

- **Azure Portal** 
    Remediation Steps for failed Configurations: 
    >   1. In the Azure portal, navigate to your search service. 
    >   2. In the left-navigation pane, select Keys. 
    >   3. Select Role-based access control. 
    
    For more information, please refer: https://learn.microsoft.com/en-us/azure/search/search-security-rbac?tabs=config-svc-portal%2Croles-portal%2Ctest-portal%2Ccustom-role-portal%2Cdisable-keys-portal.

### Azure Policies or REST APIs used for evaluation 

- REST API used to list Azure AI search and its related properties at Subscription level:
/subscriptions/{0}/providers/Microsoft.Search/searchServices?api-version=2023-11-01<br />
**Properties:**
properties.disableLocalAuth

<br />

___



## Azure_AISearch_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure AI Search

### Rationale 
Auditing logs and metrics must be enabled as they provide details for investigation in case of a security breach for threats

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "OperationLogs"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> Diagnostic settings meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below setting configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 90 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1. Diagnostic settings meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. No logs destination is configured:
>          i. Log Analytics.
>          ii. Storage account with min Retention period of 90 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/ai-services/openai/how-to/monitoring#configure-diagnostic-settings and while updating the diagnostic settings 'Operation Logs' category of logs and minimum required retention period is of 90 days.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list diagnostic settings and its related properties at Resource level:
/{ResourceId}/providers/microsoft.insights/diagnosticSettings?api-version=2021-05-01-preview<br />
**Properties:**
properties.metrics.category,properties.metrics.enabled,properties.metrics.retentionPolicy.enabled, properties.metrics.retentionPolicy.days
properties.logs.category, properties.logs.categorygroup,properties.logs.enabled,properties.metrics.logs.enabled, properties.logs.retentionPolicy.days, name, properties.workspaceId,properties.storageAccountId,properties.eventHubName

- REST API used to list diagnostic category group mapping and its related properties at Resource level:
/{ResourceId}/providers/Microsoft.Insights/diagnosticSettingsCategories?api-version=2021-05-01-preview <br />
**Properties:**
properties.categoryGroups, name
<br />
<br />
___ 


