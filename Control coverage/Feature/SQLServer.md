# SQLServer

**Resource Type:** Microsoft.Sql/servers

<!-- TOC -->

- [Azure_SQLDatabase_AuthZ_Use_AAD_Admin](#azure_sqldatabase_authz_use_aad_admin)
- [Azure_SQLDatabase_AuthZ_Use_Microsoft_Entra_ID_Only](#azure_sqldatabase_authz_use_microsoft_entra_id_only)
- [Azure_SQLDatabase_DP_Enable_TDE](#azure_sqldatabase_dp_enable_tde)
- [Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server](#azure_sqldatabase_audit_enable_threat_detection_server)
- [Azure_SQLDatabase_Audit_Enable_Vuln_Assessment](#azure_sqldatabase_audit_enable_vuln_assessment)
- [Azure_SQLDatabase_NetSec_Dont_Allow_Universal_IP_Range](#azure_sqldatabase_netsec_dont_allow_universal_ip_range)
- [Azure_SQLDatabase_Audit_Enable_Logging_and_Monitoring_Server](#azure_sqldatabase_audit_enable_logging_and_monitoring_server)
- [Azure_SQLDatabase_AuthZ_Firewall_Deny_Access_AzureServices](#azure_sqldatabase_authz_firewall_deny_access_azureservices)
- [Azure_SQLDatabase_SI_Remediate_Security_Vulnerabilities](#azure_sqldatabase_si_remediate_security_vulnerabilities)
- [Azure_SQLDatabase_DP_Use_Secure_TLS_Version](#azure_sqldatabase_dp_use_secure_tls_version)

- [_Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access](#azure_sqlserver_authn_dont_allow_public_network_access)


<!-- /TOC -->
<br/>

___

## Azure_SQLDatabase_AuthZ_Use_AAD_Admin

### Display Name
Use AAD Authentication for SQL Database

### Rationale
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions.

### Control Spec

> **Passed:**
> Azure Active Directory (AAD) administrators are assigned on the SQL server.
>
> **Failed:**
> No Azure Active Directory (AAD) administrators are assigned on the SQL server.
><!--
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>-->
### Recommendation


- **Azure Portal**

  * **For standard SQL servers:**
  
    ```azure portal
    Search for and select 'SQL server' --> Under 'Settings' section select 'Azure Active Directory'--> Select 'Set admin'. --> Search and select the 'user' or 'group' to be an administrator --> Select 'Select' button --> select 'Save'.
    ```

  * **For Synapse Analytics Workspaces:**

    ```azure portal
    Search for and select 'Azure Synapse Analytics'. --> Under Settings section select 'SQL Active Directory admin' --> Select 'Set admin'. -->  Search and select the 'user' or 'group' to be an administrator --> Select 'Select' button --> select 'Save'.
    ```


- **PowerShell**

  * **For standard SQL servers:**

    ```powershell
	  Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -DisplayName '{AzureAdAdmin Display Name}'
	  ```

    Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveractivedirectoryadministrator to configure an Azure Active Directory (AAD) administrator on a SQL server.

  * **For Synapse Analytics Workspaces:**

    ```powershell
    Set-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName '{ResourceGroupName}' -WorkspaceName '{Workspace Name}' -DisplayName '{AzureAdAdmin Display Name}'
    ```

    Refer https://docs.microsoft.com/en-us/powershell/module/az.synapse/set-azsynapsesqlactivedirectoryadministrator to configure an Azure Active Directory (AAD) administrator on a Synapse Analytics Workspace.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get the list of Azure Active Directory administrators in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/administrators?api-version=2014-04-01
  <br />
  **Properties:** [*]
  
- REST API to list all security assessments in a Subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** 
[\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData<br />
 **Assessments:** 
 f0553104-cfdb-65e6-759c-002812e38500 - SQL servers should have an Azure Active Directory administrator provisioned.
  <br />
  <br />

___

## Azure_SQLDatabase_AuthZ_Use_Microsoft_Entra_ID_Only

### Display Name
Enable Entra ID (formerly AAD) as only Authentication for the SQL Server

### Rationale
Entra ID (formerly AAD) authentication is used to centrally manage identities of database users. Enforcing Entra ID (formerly AAD) Only Authentication prevents the proliferation of user identities across servers.

### Control Spec

> **Passed:**
> Entra ID (formerly AAD) Only Authentication is enabled the SQL server.
>
> **Failed:**
> Entra ID (formerly AAD) Only Authentication is disabled on the SQL server.
><!--
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>-->
### Recommendation


- **Azure Portal**

  * **For standard SQL servers:**
  
    ```azure portal
    Search for and select 'SQL server' --> Under 'Settings' section select 'Azure Active Directory'--> In 'Azure Active Directory authentication only' section, Enable 'Support only Azure Active Directory authentication for this serve' --> Select 'Save'.
    ```

  * **For Synapse Analytics Workspaces:**

    ```azure portal
    Search for and select 'Azure Synapse Analytics'. --> Under Settings section select 'Azure Active Directory' --> Select 'Manage Azure AD identity and access for {Server Name}' -->  In 'Azure Active Directory authentication only' section, Enable 'Support only Azure Active Directory authentication for this serve' --> Select 'Save'.
    ```


- **PowerShell**

	To enable Entra ID (formerly AAD) Only Authentication enable Azure AD Admin for SQL server and turn on the Support for Entra ID (formerly AAD) Only Authentication.


  * **For standard SQL servers:**

	To enable Entra ID (formerly AAD) Admin,

    ```powershell
	  Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -DisplayName '{AzureAdAdmin EmailId}'
	  ```

    Refer: https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveractivedirectoryadministrator

	To enable Entra ID (formerly AAD) Only Authentication,

	```powershell
	Enable-AzSqlServerActiveDirectoryOnlyAuthentication -ServerName '{ServerName}' -ResourceGroupName '{ResourceGroupName}'
	```
	
	Refer https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication?view=azuresql&tabs=azure-powershell

  * **For Synapse Analytics Workspaces:**

	To enable Entra ID (formerly AAD) Admin,

    ```powershell
    Set-AzSynapseSqlActiveDirectoryAdministrator -ResourceGroupName '{ResourceGroupName}' -WorkspaceName '{Workspace Name}' -DisplayName '{AzureAdAdmin EmailId}'
    ```
    
	Refer https://docs.microsoft.com/en-us/powershell/module/az.synapse/set-azsynapsesqlactivedirectoryadministrator


	To enable Entra ID (formerly AAD) Only Authentication,

	```powershell
	Enable-AzSynapseActiveDirectoryOnlyAuthentication  -ResourceGroupName '{ResourceGroupName}' -WorkspaceName '{Workspace Name}'
	```
	
	Refer https://learn.microsoft.com/en-us/azure/azure-sql/database/authentication-azure-ad-only-authentication?view=azuresql&tabs=azure-powershell

### ARM API used for evaluation

- REST API to get if Entra ID (formerly AAD) Only Authentication is enabled on a SQL server:
  /{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/administrators?api-version=2021-11-01
  <br />
  **Properties:** "azureADOnlyAuthentication"
  <br />
  <br />

___

## Azure_SQLDatabase_DP_Enable_TDE

### Display Name
Enable Transparent Data Encryption on SQL databases

### Rationale
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements.

### Control Spec

> **Passed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as `Healthy`.
> (or)
> Transparent Data Encryption is enabled on all databases in the SQL server.
>
> **Failed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`.
> (or)
> Transparent Data Encryption is not enabled on all databases in the SQL server.
>
> **Verify:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as `Not Applicable` with `cause` other than `OffByPolicy` and `Exempt`.
>
> **NotApplicable:**
> Not Applicable.
>
> **Note:** If no Microsoft Defender for Cloud (MDC) assessment is found for the SQL server, response from the ARM API is considered for the evaluation.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

  * **For standard SQL servers:**

    ```powershell
	  Set-AzSqlDatabaseTransparentDataEncryption -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -DatabaseName '{DatabaseName}' -State 'Enabled'
	  ```

	  Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqldatabasetransparentdataencryption to enable Transparent Data Encryption on a SQL database in a SQL server.
	
  * **For Synapse workspaces:**

	  ```powershell
	  Set-AzSynapseSqlPoolTransparentDataEncryption -ResourceId '{ Resource ID of the SQL pool }' -State 'Enabled'
	  ```

	 Refer https://docs.microsoft.com/en-us/powershell/module/az.synapse/set-azsynapsesqlpooltransparentdataencryption to enable Transparent Data Encryption on a SQL pool.

  **Note:** If **Blob Auditing** or **Threat Detection** is enabled on the server, they will always apply to the database, regardless of the database level settings.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- Azure Policy (built-in):
  [Transparent Data Encryption on SQL databases should be enabled](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F17k78e20-9358-41c9-923c-fb736d382a12)
  <br />

- REST API to get the list of databases in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases?api-version=2019-06-01-preview
  <br />
  **Properties:** [*].id
  <br />

- REST API to get a logical database's transparent data encryption status:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/transparentDataEncryption/current?api-version=2014-04-01
  <br />
  **Properties:** properties.state
  <br />
  <br />

___

## Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

### Display Name
Enable advanced data security on your SQL servers

### Rationale
Enabling threat detection helps generate alerts about suspicious activity that might indicate attacks such as SQL Injection, login from a new location, unusual usage patterns and related attacks in a timely manner.

### Control Settings

```json
{
    "SecurityContacts": {
        "NotificationsRecipientsRoleName": [
            "Owner",
            "ServiceAdmin"
        ]
    }
}
```

### Control Spec

> **Passed:**
> All the following conditions are met:
> * Auditing is enabled on the SQL server.
> * Advanced Threat Protection (ATP) is enabled on all databases in the SQL server.
> * Advanced Threat Protection is enabled for all types.
> * Email notification on alerts is enabled, either to administrators and subscription owners, or to specific email addresses.
>
> **Failed:**
> One or more of the following conditions are not met:
> * Auditing is enabled on the SQL server.
> * Advanced Threat Protection (ATP) is enabled on all databases in the SQL server.
> * Advanced Threat Protection is enabled for all types.
> * Email notification on alerts is enabled, either to administrators and subscription owners, or to specific email addresses.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

  * **For standard SQL servers:**

	```powershell
	Set-AzSqlServerAudit -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -StorageAccountResourceId '{StorageAccountResourceId}' -BlobStorageTargetState 'Enabled' -RetentionInDays 365
	Update-AzSqlServerAdvancedThreatProtectionSetting -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -StorageAccountName '{StorageAccountName}' -EmailAdmins $true -ExcludedDetectionType 'None'
	```

	Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit to enable auditing on a SQL server.

  * **For Synapse workspaces:**

	```powershell
	Set-AzSynapseSqlAuditSetting -WorkspaceName {workspacename} -BlobStorageTargetState Enabled -RetentionInDays 365 -StorageAccountResourceId { StorageAccountResourceId }
	Update-AzSynapseSqlAdvancedThreatProtectionSetting -WorkspaceName {workspacename} -EmailAdmin $true -ExcludedDetectionType None -ResourceGroupName {ResourceGroupName} -StorageAccountName {StorageAccountName}
	```
	
	Refer https://docs.microsoft.com/en-us/powershell/module/az.synapse/update-azsynapsesqladvancedthreatprotectionsetting to enable auditing on a Synapse workspace.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get a SQL server's blob auditing policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/auditingSettings/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state
  <br />

- REST API to get a SQL server's security alert policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/securityAlertPolicies/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state, properties.emailAccountAdmins, properties.emailAddresses, properties.disabledAlerts
  <br />
	<br />

___

## Azure_SQLDatabase_Audit_Enable_Vuln_Assessment

### Display Name
Enable Vulnerability assessment on your SQL servers

### Rationale
Known database vulnerabilities in a system can be easy targets for attackers. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner.

### Control Spec

> **Passed:**
> All the following conditions are met:
> * Vulnerability assessment is enabled on the SQL server.
> * Email notification on alerts is enabled, either to administrators and subscription owners, or to specific email addresses.
> * Storage account is configured.
>
> **Failed:**
> One or more of the following conditions are not met:
> * Vulnerability assessment is enabled on the SQL server.
> * Email notification on alerts is enabled, either to administrators and subscription owners, or to specific email addresses.
> * Storage account is configured.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

	```powershell
	Enable-AzSqlServerAdvancedDataSecurity -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}'
	Update-AzSqlServerVulnerabilityAssessmentSetting -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -StorageAccountName '{StorageAccountName}' -ScanResultsContainerName 'vulnerability-assessment' -RecurringScansInterval Weekly -EmailAdmins $true -NotificationEmail  @('mail1@mail.com', 'mail2@mail.com')
	```

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get the vulnerability assessment of a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/vulnerabilityAssessments/default?api-version=2018-06-01-preview
  <br />
  **Properties:** properties.storageContainerPath, properties.recurringScans.isEnabled, properties.recurringScans.emails, properties.recurringScans.emailSubscriptionAdmins
  <br />
  <br />

___

## Azure_SQLDatabase_NetSec_Dont_Allow_Universal_IP_Range

### Display Name
Do not use Any-to-Any IP range for Azure SQL Database

### Rationale
Using the firewall feature ensures that access to the data or the service is restricted to a specific set/group of clients. NOTE: While this control does provide an extra layer of access control protection, it may not always be feasible to implement in all scenarios.

### Control Settings

```json
{
    "IPRangeStartIP": "0.0.0.0",
    "IPRangeEndIP": "255.255.255.255",
    "FirewallRuleName_AllowAzureIps": "AllowAllWindowsAzureIps"
}
```

### Control Spec

> **Passed:**
> No firewall rules found.
> (or)
> Firewall rule is configured only to allow access from Azure services.
> (or)
> No firewall rule found covering all IP addresses in the range denoted by `IPRangeStartIP` and `IPRangeEndIP`.
>
> **Failed:**
> Firewall rule(s) found covering all IP addresses in the range denoted by `IPRangeStartIP` and `IPRangeEndIP`.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

  Do not configure Any to Any firewall IP address.

	```powershell
	Remove-AzSqlServerFirewallRule -FirewallRuleName '{AnyToAny FirewallRule Name}' -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}'
	```

  Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/Remove-AzSqlServerFirewallRule to remove a firewall rule associated with a SQL server.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get the list of firewall rules in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/firewallRules?api-version=2014-04-01
  <br />
  **Properties:** [*]
  <br />
  <br />

___

## Azure_SQLDatabase_Audit_Enable_Logging_and_Monitoring_Server

### Display Name
Ensure Azure SQL Server auditing is configured correctly

### Rationale
Auditing enables log collection of important system events pertinent to security. Regular monitoring of audit logs can help to detect any suspicious and malicious activity early and respond in a timely manner.

### Control Settings

```json
{
    "SqlServer":
    {
        "AuditRetentionPeriod_Min": 365,
        "AuditRetentionPeriod_Forever": 0
    }
}
```

### Control Spec

> **Passed:**
> All the following conditions are met:
> * Auditing is enabled on the SQL server.
> * At least one audit log destination is chosen from among - `Storage`, `Log Analytics` and `EventHub`.
> * If `Storage` is chosen as a destination for the audit logs, a storage account is configured.
> * If `Storage` is chosen as a destination for the audit logs, retention period is set to a minimum of 365 days.
>
> **Failed:**
> One or more of the following conditions are not met:
> * Auditing is enabled on the SQL server.
> * At least one audit log destination is chosen from among - `Storage`, `Log Analytics` and `EventHub`.
> * If `Storage` is chosen as a destination for the audit logs, a storage account is configured.
> * If `Storage` is chosen as a destination for the audit logs, retention period is set to a minimum of 365 days.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

- **Azure Portal**

  After logging into subscription, go under Home -> Select Azure SQL server -> Under security section select auditing. Ensure auditing is turned ON. If selecting storage, ensure that the retention period is set to at least 365 days.

- **PowerShell**

	```powershell
	Set-AzSqlServerAudit -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -StorageAccountResourceId '{StorageAccountResourceId}' -BlobStorageTargetState 'Enabled' -RetentionInDays 365
	```

	Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveraudit to enable auditing in a SQL server.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get a SQL server's blob auditing policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/auditingSettings/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state, properties.storageAccountSubscriptionId, properties.storageEndpoint, properties.retentionDays, properties.isAzureMonitorTargetEnabled
  <br />
 <br />

___

## Azure_SQLDatabase_AuthZ_Firewall_Deny_Access_AzureServices

### Display Name
Use the 'Allow access to Azure services' flag only if required

### Rationale
The 'Allow access to Azure services' setting configures a very broad range of IP addresses from Azure as permitted to access the SQL Server. Please make sure your scenario really requires this setting before enabling it. Turning it ON exposes your SQL Server to risk of attacks from resources (IPs) owned by others in the Azure region.

### Control Settings

```json
{
    "FirewallRuleName_AllowAzureIps": "AllowAllWindowsAzureIps"
}
```

### Control Spec

> **Passed:**
> SQL server is configured to allow access from Azure services.
>
> **Failed:**
> SQL server is not configured to allow access from Azure services.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

<!--
- **Azure Portal**
-->

- **PowerShell**

	```powershell
	Remove-AzSqlServerFirewallRule -FirewallRuleName 'AllowAllWindowsAzureIps' -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}'
	```

	 Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/remove-azsqlserverfirewallrule to remove a firewall rule associated with a SQL server.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get the list of firewall rules in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/firewallRules?api-version=2014-04-01
  <br />
  **Properties:** [*]
  <br />
  <br />

___

## Azure_SQLDatabase_SI_Remediate_Security_Vulnerabilities

### Display Name
Vulnerabilities on your SQL databases must be remediated

### Rationale
Known database vulnerabilities in a system can be easy targets for attackers. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner.

### Control Spec

> **Passed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as `Healthy`.
>
> **Failed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy`, `Exempt`, `Exempt by Rule` or `Disabled parent assessment`.
>
> **Verify:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the SQL server as `Not Applicable` with `cause` other than `OffByPolicy`, `Exempt`, `Exempt by Rule` or `Disabled parent assessment`.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation

- **Azure Portal**

	Go to security center --> Data & storage --> SQL --> Click on SQL server name --> Click on Recommendation in Recommendation List --> Remediate list of vulnerabilities

<!--
- **PowerShell**

	 ```powershell
	 $variable = 'apple'
	 ```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- Azure Policy (built-in):
  [SQL databases should have vulnerability findings resolved](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2Ffeedbf84-6b99-488c-acc2-71c829aa5ffc)
  <br />
  <br />

___

## Azure_SQLDatabase_DP_Use_Secure_TLS_Version

### Display Name
Use approved version of TLS for SQL Server

### Rationale
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Settings 
```json 
{
    "MinReqTLSVersion": "1.2"
}
 ``` 

### Control Spec

> **Passed:**
> Current TLS version of SQL Server is set to either equal or greater than the required minimum TLS version.
>
> **Failed:**
> One or more of the following conditions are met:
> * Current TLS version of SQL Server is less than the required minimum TLS version.
> * TLS for SQL Server is not configured.
>
> **Error:**
> Required minimum TLS version is not set properly in control settings.
>

### Recommendation

- **Azure Portal**

	To Configure 'Minimum TLS Version' setting for SQL Server, go to Azure Portal --> Your Resource --> Firewalls and virtual networks --> Set the Minimum TLS Version to latest version.

<!--
- **PowerShell**

	 ```powershell
	 $variable = 'apple'
	 ```
-->

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to check a SQL server's TLS version:
  /subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers?api-version=2019-06-01-preview
  <br />
  **Properties:** properties.minimalTlsVersion
  <br />
 <br />

___

## Azure_SQLServer_AuthN_Dont_Allow_Public_Network_Access

### Display Name
Public network access on Azure SQL Database should be disabled

### Rationale
Configuring public access on your SQL server allows the server access through a public endpoint which is not recommended.

### Control Spec

> **Passed:**
> Public Network Access is configured as Disabled.
>
> **Failed:**
Public Network Access is configured as Enabled.
>

### Recommendation

- **Azure Portal**

	To remediate, disable public network access on your SQL server or refer link https://learn.microsoft.com/en-us/azure/azure-sql/database/connectivity-settings?view=azuresql&tabs=azure-portal

### Azure Policies or REST APIs used for evaluation

- REST API to check a SQL server's public network access:
subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers?api-version=2021-11-01
  <br />
  **Properties:** properties.publicNetworkAccess
  <br />
 <br />
___