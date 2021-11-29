# SQLManagedInstance

**Resource Type:** Microsoft.Sql/managedInstances

<!-- TOC -->

- [Azure_SQLManagedInstance_Audit_Enable_Vuln_Assessment](#azure_sqlmanagedinstance_audit_enable_vuln_assessment)

<!-- /TOC -->
<br/>

___ 

## Azure_SQLManagedInstance_Audit_Enable_Vuln_Assessment 

### DisplayName 
Vulnerability assessment must be enabled on your SQL managed instances 

### Rationale 
Known database vulnerabilities in a system can be easy targets for attackers. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Spec 

> **Passed:** 
> All the following conditions are true -
> a. Vulnerability assessment setting is enabled
> b. At least one option to send email notification on alert is selected
> c. Storage account container path is selected.
> 
> **Failed:** 
> Any one of the four conditions is false -
> a. Vulnerability assessment setting is enabled
> b. At least one option to send email notification on alert is selected
> c. Storage account container path is selected.
> 
### Recommendation 
 
- **PowerShell** 

	 First run command 
	 ```powershell
	 Enable-AzSqlInstanceAdvancedDataSecurity -ResourceGroupName '{ResourceGroupName}' -InstanceName '{InstanceName}'
	 ```
	 Then run command 
	 ```powershell
	 Update-AzSqlInstanceVulnerabilityAssessmentSetting -ResourceGroupName '{ResourceGroupName}' -InstanceName '{InstanceName}' -StorageAccountName '{StorageAccountName}' -ScanResultsContainerName 'vulnerability-assessment' -RecurringScansInterval Weekly -EmailAdmins $true -NotificationEmail @('mail1@mail.com' , 'mail2@mail.com')
	 ``` 

<!-- - **Azure Portal** 

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

-->
### Azure Policy or ARM API used for evaluation 

- ARM API to get Vulnerability Assessment of a SQLManagedInstance: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Sql/managedInstances/{resourceName}/vulnerabilityAssessments/default?api-version=2018-06-01-preview <br />
**Properties:** properties.VulnerabilityAssessmentSetting.IsEnabled, properties.EmailSubscriptionAdmins, properties.StorageContainerPath, properties.Emails
 <br />

<br />

___ 
<!-- 
## Azure_SQLManagedInstance_SI_Remediate_Security_Vulnerabilities 

### DisplayName 
Vulnerabilities on your SQL databases should be remediated 

### Rationale 
Known database vulnerabilities in a system can be easy targets for attackers. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Spec 

> **Passed:** 
> Passed condition
> 
> **Failed:** 
> Failed condition
> 
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
> 
### Recommendation 


- **Azure Portal** 

	 Go to security center -> Data & storage -> SQL -> Click on SQL DB Managed instance -> Click on Recommendation in Recommendation List -> Remediate list of vulnerabilities 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_SQLManagedInstance_DP_Use_Secure_TLS_Version 

### DisplayName 
Use approved version of TLS for Azure SQL Managed Instance 

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions. 

### Control Settings 
```json 
{
    "MinReqTLSVersion": "1.2",
    "MinTLSVersionNotSet": "None"
}
 ```  

### Control Spec 

> **Passed:** 
> Passed condition
> 
> **Failed:** 
> Failed condition
> 
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
> 
### Recommendation 

- **Azure Portal** 

	 Configure 'Minimal TLS Version' setting for Azure SQL Managed Instance. Refer: https://docs.microsoft.com/en-us/azure/azure-sql/managed-instance/minimal-tls-version-configure 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 
 -->
