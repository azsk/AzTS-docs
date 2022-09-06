## **List of controls supported for remediation through AzTS UI**
***

1. [Azure_Storage_AuthN_Dont_Allow_Anonymous](ControlsEligibleForRemediationThroughUI.md#1-Azure_Storage_AuthN_Dont_Allow_Anonymous)

2. [Azure_AppService_Config_Disable_Remote_Debugging](ControlsEligibleForRemediationThroughUI.md#2-Azure_AppService_Config_Disable_Remote_Debugging)

3. [Azure_AppService_DP_Dont_Allow_HTTP_Access](ControlsEligibleForRemediationThroughUI.md#3-Azure_AppService_DP_Dont_Allow_HTTP_Access)

4. [Azure_AppService_DP_Use_Secure_TLS_Version](ControlsEligibleForRemediationThroughUI.md#4-Azure_AppService_DP_Use_Secure_TLS_Version)

5. [Azure_ContainerRegistry_Config_Enable_Security_Scanning](ControlsEligibleForRemediationThroughUI.md#5-Azure_ContainerRegistry_Config_Enable_Security_Scanning)

6. [Azure_KubernetesService_AuthN_Enabled_AAD](ControlsEligibleForRemediationThroughUI.md#6-Azure_KubernetesService_AuthN_Enabled_AAD)

<br />

___

## 1. Azure_Storage_AuthN_Dont_Allow_Anonymous

### Display Name
Ensure secure access to Storage account containers

### Link to Bulk Remediation Script (BRS)
[Remediate-AnonymousAccessOnContainers](Remediate-AnonymousAccessOnContainers.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 2. Azure_AppService_Config_Disable_Remote_Debugging

### Display Name
Remote debugging should be turned off for Web Applications

### Link to Bulk Remediation Script (BRS)
[Remediate-DisableRemoteDebuggingForAppServices](Remediate-DisableRemoteDebuggingForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 3. Azure_AppService_DP_Dont_Allow_HTTP_Access

### Display Name
Use HTTPS for App Services

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableHTTPSForAppServices](Remediate-EnableHTTPSForAppServices.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 4. Azure_AppService_DP_Use_Secure_TLS_Version

### Display Name
Use Approved TLS Version in App Service

### Link to Bulk Remediation Script (BRS)
[Remediate-SetAppServiceMinReqTLSVersion](Remediate-SetAppServiceMinReqTLSVersion.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___

## 5. Azure_ContainerRegistry_Config_Enable_Security_Scanning

### Display Name
Security scanner identity must be granted access to Container Registry for image scans

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableSecurityScanningForContainerRegistry](Remediate-EnableSecurityScanningForContainerRegistry.ps1)

### Minimum permissions required to run the script
Reader role at subscription level and Contributor role at resource level

___

## 6. Azure_KubernetesService_AuthN_Enabled_AAD

### Display Name
AAD should be enabled in Kubernetes Service

### Link to Bulk Remediation Script (BRS)
[Remediate-EnableAADForKubernetesService](Remediate-EnableAADForKubernetesService.ps1)

### Minimum permissions required to run the script
Contributor role at resource level

___