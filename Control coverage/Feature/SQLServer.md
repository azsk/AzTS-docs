# SQLServer

**Resource Type:** Microsoft.Sql/servers

<!-- TOC -->

- [Azure_SQLDatabase_AuthZ_Use_AAD_Admin](#azure_sqldatabase_authz_use_aad_admin)
- [Azure_SQLDatabase_DP_Enable_TDE](#azure_sqldatabase_dp_enable_tde)
- [Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server](#azure_sqldatabase_audit_enable_threat_detection_server)
- [Azure_SQLDatabase_Audit_Enable_Vuln_Assessment](#azure_sqldatabase_audit_enable_vuln_assessment)
- [Azure_SQLDatabase_NetSec_Dont_Allow_Universal_IP_Range](#azure_sqldatabase_netsec_dont_allow_universal_ip_range)
- [Azure_SQLDatabase_Audit_Enable_Logging_and_Monitoring_Server](#azure_sqldatabase_audit_enable_logging_and_monitoring_server)
- [Azure_SQLDatabase_AuthZ_Firewall_Deny_Access_AzureServices](#azure_sqldatabase_authz_firewall_deny_access_azureservices)
- [Azure_SQLDatabase_SI_Remediate_Security_Vulnerabilities](#azure_sqldatabase_si_remediate_security_vulnerabilities)
- [Azure_SQLDatabase_DP_Use_Secure_TLS_Version](#azure_sqldatabase_dp_use_secure_tls_version)

<!-- /TOC -->
<br/>

___

## Azure_SQLDatabase_AuthZ_Use_AAD_Admin

### DisplayName
Use AAD Authentication for SQL Database

### Rationale
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions.

### Control Spec

> **Passed:**
> Azure Active Directory (AAD) administrators are assigned on the SQL server.
>
> **Failed:**
> No Azure Active Directory (AAD) administrators are assigned on the SQL server.
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
	Set-AzSqlServerActiveDirectoryAdministrator -ResourceGroupName '{ResourceGroupName}' -ServerName '{ServerName}' -DisplayName '{AzureAdAdmin Display Name}'
	```

	Refer https://docs.microsoft.com/en-us/powershell/module/az.sql/set-azsqlserveractivedirectoryadministrator to configure an Azure Active Directory (AAD) administrator on a SQL server.

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policy or ARM API used for evaluation

- ARM API to get the list of Azure Active Directory administrators in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/administrators?api-version=2014-04-01
  <br />
  **Properties:** [*]
  <br />
  <br />

___

## Azure_SQLDatabase_DP_Enable_TDE

### DisplayName
Enable Transparent Data Encryption on SQL databases

### Rationale
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements.

### Control Spec

> **Passed:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as `Healthy`.
> (or)
> Transparent Data Encryption is enabled on all databases in the SQL server.
>
> **Failed:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`.
> (or)
> Transparent Data Encryption is not enabled on all databases in the SQL server.
>
> **Verify:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as `Not Applicable` with `cause` other than `OffByPolicy` and `Exempt`.
>
> **NotApplicable:**
> Not Applicable.
>
> **Note:** If no Azure Security Center (ASC) assessment is found for the SQL server, response from the ARM API is considered for the evaluation.
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

### Azure Policy or ARM API used for evaluation

- Azure Policy (built-in):
  [Transparent Data Encryption on SQL databases should be enabled](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F17k78e20-9358-41c9-923c-fb736d382a12)
  <br />

- ARM API to get the list of databases in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases?api-version=2019-06-01-preview
  <br />
  **Properties:** [*].id
  <br />

- ARM API to get a logical database's transparent data encryption status:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/databases/{databaseName}/transparentDataEncryption/current?api-version=2014-04-01
  <br />
  **Properties:** properties.state
  <br />
  <br />

___

## Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get a SQL server's blob auditing policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/auditingSettings/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state
  <br />

- ARM API to get a SQL server's security alert policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/securityAlertPolicies/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state, properties.emailAccountAdmins, properties.emailAddresses, properties.disabledAlerts
  <br />
	<br />

___

## Azure_SQLDatabase_Audit_Enable_Vuln_Assessment

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get the vulnerability assessment of a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/vulnerabilityAssessments/default?api-version=2018-06-01-preview
  <br />
  **Properties:** properties.storageContainerPath, properties.recurringScans.isEnabled, properties.recurringScans.emails, properties.recurringScans.emailSubscriptionAdmins
  <br />
  <br />

___

## Azure_SQLDatabase_NetSec_Dont_Allow_Universal_IP_Range

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get the list of firewall rules in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/firewallRules?api-version=2014-04-01
  <br />
  **Properties:** [*]
  <br />
  <br />

___

## Azure_SQLDatabase_Audit_Enable_Logging_and_Monitoring_Server

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get a SQL server's blob auditing policy:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/auditingSettings/default?api-version=2017-03-01-preview
  <br />
  **Properties:** properties.state, properties.storageAccountSubscriptionId, properties.storageEndpoint, properties.retentionDays, properties.isAzureMonitorTargetEnabled
  <br />
 <br />

___

## Azure_SQLDatabase_AuthZ_Firewall_Deny_Access_AzureServices

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get the list of firewall rules in a SQL server:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/servers/{serverName}/firewallRules?api-version=2014-04-01
  <br />
  **Properties:** [*]
  <br />
  <br />

___

## Azure_SQLDatabase_SI_Remediate_Security_Vulnerabilities

### DisplayName
Vulnerabilities on your SQL databases must be remediated

### Rationale
Known database vulnerabilities in a system can be easy targets for attackers. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner.

### Control Spec

> **Passed:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as `Healthy`.
>
> **Failed:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy`, `Exempt`, `Exempt by Rule` or `Disabled parent assessment`.
>
> **Verify:**
> Azure Security Center (ASC) reports the assessment status for the SQL server as `Not Applicable` with `cause` other than `OffByPolicy`, `Exempt`, `Exempt by Rule` or `Disabled parent assessment`.
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

### Azure Policy or ARM API used for evaluation

- Azure Policy (built-in):
  [SQL databases should have vulnerability findings resolved](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2Ffeedbf84-6b99-488c-acc2-71c829aa5ffc)
  <br />
  <br />

___

## Azure_SQLDatabase_DP_Use_Secure_TLS_Version

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to check a SQL server's TLS version:
  /subscriptions/{subscriptionId}/providers/Microsoft.Sql/servers?api-version=2019-06-01-preview
  <br />
  **Properties:** properties.minimalTlsVersion
  <br />
 <br />

___
