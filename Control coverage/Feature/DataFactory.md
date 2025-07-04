# Data Factory

**Resource Type:** Microsoft.DataFactory/factories


<!-- TOC -->

- [Azure_DataFactory_Audit_Enable_Diagnostic_Settings](#azure_datafactory_audit_enable_diagnostic_settings)
- [Azure_DataFactory_DP_Avoid_Plaintext_Secrets](#azure_datafactory_dp_avoid_plaintext_secrets)

<!-- /TOC -->
<br/>

___ 

## Azure_DataFactory_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in Azure Data Factories

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "ActivityRuns",
        "PipelineRuns",
        "TriggerRuns",
        "SandboxPipelineRuns",
        "SandboxActivityRuns",
        "SSISPackageEventMessages",
        "SSISPackageExecutableStatistics",
        "SSISPackageEventMessageContext",
        "SSISPackageExecutionComponentPhases",
        "SSISPackageExecutionDataStatistics",
        "SSISIntegrationRuntimeLogs",
        "AirflowTaskLogs",
        "AirflowWorkerLogs",
        "AirflowDagProcessingLogs",
        "AirflowSchedulerLogs",
        "AirflowWebLogs"
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
>          ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics setting is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings.
      

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
___ 


## Azure_DataFactory_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure Data Factory

### Rationale
Storing secrets such as passwords, keys, or connection strings in plaintext within Azure Data Factory pipelines, datasets, or linked services exposes sensitive information to potential compromise. Using secure methods for secret management, such as Azure Key Vault, helps protect credentials from unauthorized access, supports regulatory compliance (e.g., ISO 27001, SOC 2, PCI DSS), and reduces the risk of data breaches.

### Control Spec

> **Passed:**
> - All secrets (e.g., passwords, keys, connection strings) referenced in Azure Data Factory pipelines, datasets, and linked services are stored securely using Azure Key Vault or other secure references.
> - No plaintext secrets are present in pipeline definitions, parameters, or JSON ARM templates.
>
> **Failed:**
> - Any secret value is found in plaintext within pipeline, dataset, or linked service definitions.
> - Secrets are hardcoded in ARM templates, parameters, or directly in the Data Factory UI.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Data Factory instance.
    2. Review all linked services, datasets, and pipeline parameters.
    3. Ensure that any sensitive fields (e.g., passwords, keys, connection strings) use the "Secure String" type and reference Azure Key Vault secrets.
    4. For existing plaintext secrets, update the configuration to reference a Key Vault secret instead.
    5. Publish the changes.

- **PowerShell**
    ```powershell
    # Example: Update a linked service to use Azure Key Vault for a SQL password
    $linkedService = Get-AzDataFactoryV2LinkedService -ResourceGroupName "<ResourceGroup>" -DataFactoryName "<DataFactoryName>" -Name "<LinkedServiceName>"
    $linkedService.Properties.TypeProperties.ConnectionString = "@Microsoft.KeyVault(SecretName='SqlPassword', SecretVersion='', VaultName='<KeyVaultName>')"
    Set-AzDataFactoryV2LinkedService -ResourceGroupName "<ResourceGroup>" -DataFactoryName "<DataFactoryName>" -Name "<LinkedServiceName>" -DefinitionFile "<PathToUpdatedJson>"
    ```

- **Azure CLI**
    ```bash
    # Example: Update a linked service definition to use Key Vault reference
    az datafactory linked-service update \
      --resource-group <ResourceGroup> \
      --factory-name <DataFactoryName> \
      --name <LinkedServiceName> \
      --properties @updated-linkedservice.json
    ```

- **Automation/Remediation**
    - Use Azure Policy to deny creation of Data Factory resources with plaintext secrets:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.DataFactory/factories/linkedservices"
              },
              {
                "not": {
                  "field": "Microsoft.DataFactory/factories/linkedservices/typeProperties.connectionString",
                  "contains": "@Microsoft.KeyVault"
                }
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - Regularly scan ARM templates and Data Factory definitions for hardcoded secrets using tools such as Microsoft Security DevOps or AzTS (Azure Tenant Security) scripts.
    - For bulk remediation, export all linked services, search for plaintext secrets, and update them to use Key Vault references.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataFactory/factories/{factoryName}/linkedservices?api-version=2018-06-01`
  <br />
  **Properties:** `typeProperties.connectionString`, `typeProperties.password`, `typeProperties.secret`
- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DataFactory/factories/{factoryName}/pipelines?api-version=2018-06-01`
  <br />
  **Properties:** Pipeline parameters, activity settings referencing secrets

<br/>

___
