# Databricks

**Resource Type:** Microsoft.Databricks/workspaces

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_Databricks_Audit_Enable_Diagnostic_Settings](#azure_databricks_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___

## Azure_Databricks_Audit_Enable_Diagnostic_Settings

### Display Name
Databricks workspaces must have diagnostic settings enabled

### Rationale
Enabling diagnostic settings for Databricks provides visibility into workspace activities, job executions, and security events. This is essential for monitoring, compliance, and security incident response in data analytics environments.

### Control Settings 
```json
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticLogs": [
        "workspace",
        "clusters", 
        "accounts",
        "jobs",
        "notebook"
    ],
    "DiagnosticMinRetentionPeriod": "365"
}
```

### Control Spec

> **Passed:**
> Required diagnostic logs are enabled with appropriate retention configuration.
>
> **Failed:**
> Diagnostic logs are not enabled or retention period is insufficient.
>

### Recommendation

- **Azure Portal**

    Go to Databricks workspace ? Monitoring ? Diagnostic settings ? Add diagnostic setting ? Select required log categories (workspace, clusters, accounts, jobs, notebook) ? Configure destination (Log Analytics, Storage Account, or Event Hub) ? Set retention period to 365 days or more.

### Azure Policies or REST APIs used for evaluation

- REST API to list diagnostic setting details: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Databricks/workspaces/{workspaceName}/providers/microsoft.insights/diagnosticSettings?api-version=2017-05-01-preview<br />
**Properties:** properties.logs.category, properties.logs.enabled, properties.logs.retentionPolicy<br />

<br />

___