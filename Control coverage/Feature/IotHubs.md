# Iot Hubs
**Resource Type:** Microsoft.Devices/IotHubs

<!-- TOC -->

- [Azure_IoTHubs_Audit_Enable_Diagnostic_Settings](#azure_iothubs_audit_enable_diagnostic_settings)
- [Azure_IoTHub_DP_Use_Secure_TLS_Version](#azure_iothub_dp_use_secure_tls_version)


<!-- /TOC -->
<br/>

___ 

## Azure_IoTHubs_Audit_Enable_Diagnostic_Settings
 

### Display Name 
Enable Security Logging in IoT Hubs

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.

### Control Settings 
```json 
{
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "90",
    "DiagnosticLogs": [
        "Connections"
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
    You can change the diagnostic settings from the Azure Portal by following the steps given here: https://learn.microsoft.com/en-us/azure/app-service/troubleshoot-diagnostic-logs.
      

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


## Azure_IoTHub_DP_Use_Secure_TLS_Version

### Display Name
IoT Hub should use a secure TLS version

### Rationale
Transport Layer Security (TLS) is a cryptographic protocol that ensures secure communication over a network. Using outdated or insecure versions of TLS can expose IoT Hubs to vulnerabilities such as man-in-the-middle attacks, data interception, and unauthorized access. Enforcing the use of a secure TLS version (such as TLS 1.2 or above) helps to maintain the confidentiality and integrity of data transmitted between IoT devices and the Azure IoT Hub, and supports compliance with industry security standards.

### Control Spec

> **Passed:**  
> The IoT Hub is configured to require a secure TLS version (TLS 1.2 or higher) for all device and service connections.
>
> **Failed:**  
> The IoT Hub allows connections using insecure or deprecated TLS versions (such as TLS 1.0 or 1.1).

### Recommendation

- **Azure Portal**
    1. Navigate to your IoT Hub in the Azure Portal.
    2. Under **Settings**, select **TLS/SSL settings** or **Properties** (depending on the portal version).
    3. Ensure that the **Minimum TLS Version** is set to **1.2** or higher.
    4. Save your changes.

- **PowerShell**
    ```powershell
    # Set the minimum TLS version to 1.2 for an IoT Hub
    Set-AzIotHub -ResourceGroupName "<ResourceGroupName>" -Name "<IoTHubName>" -MinimumTlsVersion "1.2"
    ```

- **Azure CLI**
    ```bash
    # Set the minimum TLS version to 1.2 for an IoT Hub
    az iot hub update --name <IoTHubName> --resource-group <ResourceGroupName> --set properties.minimumTlsVersion="1.2"
    ```

- **Automation/Remediation**
    - Use Azure Policy to enforce TLS version requirements across all IoT Hubs:
        ```json
        {
          "if": {
            "allOf": [
              {
                "field": "type",
                "equals": "Microsoft.Devices/IotHubs"
              },
              {
                "field": "Microsoft.Devices/IotHubs/properties.minimumTlsVersion",
                "notEquals": "1.2"
              }
            ]
          },
          "then": {
            "effect": "deny"
          }
        }
        ```
    - For bulk remediation, use AzTS or custom scripts to iterate through all IoT Hubs and set the minimum TLS version to 1.2.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `PATCH https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Devices/IotHubs/{resourceName}?api-version=2021-07-02`  
  **Properties:** `properties.minimumTlsVersion`

<br/>

___
