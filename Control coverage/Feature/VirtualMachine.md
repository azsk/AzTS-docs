<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_VirtualMachine_SI_Enable_Antimalware](#azure_virtualmachine_si_enable_antimalware)
- [Azure_VirtualMachine_Config_Enable_NSG](#azure_virtualmachine_config_enable_nsg)
- [Azure_VirtualMachine_NetSec_Justify_PublicIPs](#azure_virtualmachine_netsec_justify_publicips)
- [Azure_VirtualMachine_DP_Enable_Disk_Encryption](#azure_virtualmachine_dp_enable_disk_encryption)
- [Azure_VirtualMachine_SI_MDC_OS_Vulnerabilities](#azure_virtualmachine_si_MDC_os_vulnerabilities)
- [Azure_VirtualMachine_SI_MDC_Recommendations](#azure_virtualmachine_si_mdc_recommendations)
- [Azure_VirtualMachine_Audit_Enable_Diagnostics](#azure_virtualmachine_audit_enable_diagnostics)
- [Azure_VirtualMachine_SI_Enable_Vuln_Solution](#azure_virtualmachine_si_enable_vuln_solution)
- [Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension](#azure_virtualmachine_si_deploy_guestconfig_extension)
- [Azure_VirtualMachine_SI_Enable_Monitoring_Agent](#azure_virtualmachine_si_enable_monitoring_agent)
- [Azure_VirtualMachine_NetSec_Dont_Open_Restricted_Ports](#azure_virtualmachine_netsec_dont_open_restricted_ports)
- [Azure_VirtualMachine_SI_Deploy_Data_Collection_Extension](#azure_virtualmachine_si_deploy_data_collection_extension)
- [Azure_VirtualMachine_NetSec_Apply_MDC_Network_Recommendations](#azure_virtualmachine_netsec_apply_mdc_network_recommendations)
- [Azure_VirtualMachine_SI_Remediate_Security_Vulnerabilities](#azure_virtualmachine_si_remediate_security_vulnerabilities)
- [Azure_VirtualMachine_SI_Remediate_Container_Security_Vulnerabilities](#azure_virtualmachine_si_remediate_container_security_vulnerabilities)
- [Azure_VirtualMachine_Just_In_Time_Network_Access_Control](#azure_virtualmachine_just_in_time_network_access_control)
- [Azure_VirtualMachine_SI_Remediate_Assessment_Soln_Vulnerabilities](#azure_virtualmachine_si_remediate_assessment_soln_vulnerabilities)
- [Azure_VirtualMachine_NetSec_Open_Allowed_Ports_Only](#azure_virtualmachine_netsec_open_allowed_ports_only)
- [Azure_VirtualMachine_DP_Use_Secure_TLS_Version_Trial](#azure_virtualmachine_dp_use_secure_tls_version_trial)
- [Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_Id_Auth_Linux](#azure_virtualmachine_authN_enable_microsoft_entra_id_auth_linux)
- [Azure_VirtualMachine_Audit_Enable_Diagnostic_Settings](#azure_virtualmachine_audit_enable_diagnostic_settings)

<!-- /TOC -->
<br/>

___ 

## Azure_VirtualMachine_SI_Enable_Antimalware 

### Display Name 
Ensure all devices have anti-malware protection installed and enabled 

### Rationale 
Enabling antimalware protection minimizes the risks from existing and new attacks from various types of malware. Microsoft Antimalware provide real-time protection, scheduled scanning, malware remediation, signature updates, engine updates, samples reporting, exclusion event collection etc. 


### Control Settings 
```jsonP
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ],
    "ReqExtensionPublisher": "Microsoft.Azure.Security",
    "ReqExtensionType": "IaaSAntimalware"
} 
```
### Control Spec 

> **Passed:** 
> If evaluated by reader permissions Required Antimalware extension is present in VM, and Auto upgrade to minor version is configured as true for extension and Real time protection is enabled for extension.
> 
> **Failed:** 
> If evaluated by reader permissions Required Antimalware extension is missing for VM, or Auto upgrade to minor version is configured as false for extension or Real time protection is disabled for extension.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> Control not applicable for Linux OS machine.
> 
> **NotScanned:**
> VM OS kind is null or empty.

### Recommendation 

- **Azure Portal** 

	 To install antimalware, Go to Azure Portal --> VM Properties --> Extensions --> Add 'Microsoft Antimalware' --> Enable Real-Time Protection and Scheduled Scan --> Click Ok. If antimalware is already present on VM, validate and resolve endpoint protection recommendations in MDC. Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection, https://docs.microsoft.com/en-us/azure/security/azure-security-antimalware 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link)
	 "/providers/Microsoft.Authorization/policyDefinitions/af6cd1bd-1635-48cb-bde7-5b15693900b9"

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list virtual machine extensions at specific level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{virtualMachineName}/extensions?api-version=2019-07-01<br />
**Properties:** [\*].properties.type, [\*].properties.publisher
 <br />

- REST API to list Virtual Machines at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** [\*].properties.storageProfile.osDisk.osType
 <br />

<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

## Azure_VirtualMachine_Config_Enable_NSG 

### Display Name 
Internet-facing virtual machines must be protected with Network Security Groups 

### Rationale 
Restricting inbound and outbound traffic via NSGs limits the network exposure of a VM by reducing the attack surface. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
>NSG is configured for the VM or VM does not have any public IP configured.
>
> **Failed:** 
> No NSG found on the VM.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> VM instance is part of ADB cluster.
> 
### Recommendation

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/endpoints-in-resource-manager, https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-create-nsg-arm-ps 
<!--
- **PowerShell**

	 ```powershell 
	 $variable = 'apple' 
	 ```

- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
	 "/providers/Microsoft.Authorization/policyDefinitions/af6cd1bd-1635-48cb-bde7-5b15693900b9"


	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list networkInterfaces at subscription level: 
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** publicIPAddress.id, networkSecurityGroup.id<br />

- REST API to list Virtual Networks at
subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01<br />
**Properties:** networkSecurityGroup.id
<br />
<br />

___

## Azure_VirtualMachine_NetSec_Justify_PublicIPs 

### Display Name 
Public IPs on a Virtual Machine should be carefully reviewed 

### Rationale 
Public IPs provide direct access over the internet exposing the VM to attacks over the public network. Hence each public IP on a VM must be reviewed carefully. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
No Public IP address is associated with VM. 
><!--
> **Failed:** 
> Failed condition
> -->
> **Verify:** 
> One or more Public IP address is associated with VM.
> 
> **NotApplicable:** 
> VM is part of Azure Databricks cluster.
> 
### Recommendation 

- **Azure Portal** 

	Go to Azure Portal --> VM Settings --> Networking --> Network Interfaces --> Select NIC --> IP Configurations --> Select IP Configs with Public IP --> Click 'Disabled' --> Save. Refer: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-public-ip-address  
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure olicy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machines at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** 
properties.networkProfile.networkInterfaces[\*].id<br />

- REST API to list Network Interfaces at
subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01<br />
**Properties:**  publicIPAddress.id	
 <br />
<br />

___ 

## Azure_VirtualMachine_DP_Enable_Disk_Encryption 

### Display Name 
Disk encryption should be applied on virtual machines 

### Rationale 
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements. In the case of VMs, both OS and data disks may contain sensitive information that needs to be protected at rest. Hence disk encryption must be enabled for both. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
>MDC assessment found with Healthy status code.
> 
> **Failed:** 
> MDC assessment found with Unhealthy status code.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> VM is part of Azure Databricks cluster or using ephemeral OS disks.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json. Note: After enabling disk encryption, it takes some time for changes to reflect in Microsoft Defender for Cloud (MDC). Thus, if you scan immediately, the control may still fail even though the VM itself shows as encrypted. Please wait a few hours to ascertain the fix. 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list security assessments at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01<br />
 **Properties:** [\*].id, [\*].name, [\*].resourceDetails.Id, [\*].displayName, [\*].status.code, [\*].status, [\*].additionalData <br />

- REST API to list Virtual Machines at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01<br>
**Properties:** [\*].properties.storageProfile.osDisk.caching, [\*].properties.storageProfile.diffDiskSettings.option
 <br />
<br />

___ 

## Azure_VirtualMachine_SI_MDC_OS_Vulnerabilities 

### Display Name 
Virtual Machine must be in a healthy state in Microsoft Defender for Cloud 

### Rationale 
Microsoft Defender for Cloud raises alerts (which are typically indicative of resources that are not compliant with some baseline security protection). It is important that these alerts/actions are resolved promptly in order to eliminate the exposure to attacks. 

### Control Settings 
```json
{
    "MDCApprovedBaselineStatuses": {
        "Linux": [
            "Healthy"
        ],
        "Windows": [
            "Healthy"
        ]
    }
} 
```

### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is in the approved status(es) list.
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is not in the approved status(es) list.
> 
<!--
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
> 
-->

### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-remediate-os-vulnerabilities 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** 
[\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData<br />
 **Assessments:** 
 181ac480-f7c4-544b-9865-11b8ffe87f47 - Vulnerabilities in security configuration on your machines should be remediated.
<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

## Azure_VirtualMachine_SI_Missing_OS_Patches 

### Display Name 
Patch virtual machine to protect against vulnerabilities 

### Rationale 
Un-patched VMs are easy targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
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

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-system-updates. It takes 24 hours to reflect the latest status at MDC. 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policies or REST APIs used for evaluation 

- Example ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 
## Azure_VirtualMachine_SI_MDC_Recommendations 

### Display Name 
Virtual Machine must implement all the flagged MDC recommendations 

### Rationale 
Microsoft Defender for Cloud provide various security recommendations for resources that are not compliant with some baseline security protection. It is important that these recommendations are resolved promptly in order to eliminate the exposure to attacks. 

### Control Spec 

> **Passed:** 
> No Microsoft Defender for Cloud Assessment for the Virtual Machine is "Unhealthy".
> 
> **Failed:** 
>One or more Microsoft Defender for Cloud Assessments for the Virtual Machine are "Unhealthy".
<!--
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
-->
### Recommendation 

- **Azure Portal** 

	 First, examine the detailed AzSK log file for this VM to find out the specific recommendations this control is currently failing for. Review the MDC documentation for those recommendations and implement the suggested fixes. (Note: Not all MDC recommendations are flagged by AzSK. So the first step is critical.). <br>1.For Disk encryption should be applied on virtual machines Refer:https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview <br> 2.For Adaptive application controls for defining safe applications should be enabled on your machines Refer:https://docs.microsoft.com/en-us/azure/defender-for-cloud/adaptive-network-hardening <br> 3.For A vulnerability assessment solution should be enabled on your virtual machines Refer:https://docs.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm#deploy-the-integrated-scanner-to-your-azure-and-hybrid-machines.
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription:
/subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01<br>
 **Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData<br>
 **Assessments:**  
  d57a4221-a804-52ca-3dea-768284f06bb7 - Disk encryption should be applied on virtual machines.<br>
  35f45c95-27cf-4e52-891f-8390d1de5828 - Adaptive application controls for defining safe applications should be enabled on your machines.<br>
  ffff0522-1e88-47fc-8382-2a80ba848f5d - A vulnerability assessment solution should be enabled on your virtual machines.
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** 
-->
 <br />

___ 

## Azure_VirtualMachine_Audit_Enable_Diagnostics 

### Display Name 
Diagnostics must be enabled on the Virtual Machine 

### Rationale 
Diagnostics logs are needed for creating activity trail while investigating an incident or a compromise. 

### Control Settings 
```json
{
    "RequiredDiagnosticsExtensions": {
        "Linux": [
            {
                "ExtensionType": "LinuxDiagnostic",
                "Publisher": "Microsoft.Azure.Diagnostics"
            }
        ],
        "Windows": [
            {
                "ExtensionType": "IaaSDiagnostics",
                "Publisher": "Microsoft.Azure.Diagnostics"
            }
        ]
    }
}
```

### Control Spec 

> **Passed:** 
> 1. All required diagnostic extension(s) are configured.
> 2. No mandatory diagnostic extension(s) have been specified for the Operating System.
> 
> **Failed:** 
> One or more diagnostic extension(s) are not configured on the Virtual Machine.
<!--
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
> 
-->
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> VM Properties --> Diagnostics settings --> Enable guest-level-monitoring. Refer: https://docs.microsoft.com/en-us/azure/monitoring-and-diagnostics/azure-diagnostics 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  


- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list all extensions in a Virtual Machine:
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupId}/providers/Microsoft.Compute/virtualMachines/{virtualMachineName}/extensions?api-version=2019-07-01<br />
**Properties:** properties.type, properties.publisher	
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
-->
 <br />

___ 

## Azure_VirtualMachine_SI_Enable_Vuln_Solution 

### Display Name 
Install DSRE Qualys Cloud Agent on assets 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising a VM/container with such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        },
        {
            "Description": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        }
    ],
    "Linux": {
        "ExtensionPublisher": "Qualys",
        "ExtensionType": "QualysAgentLinux"
    },
    "Windows": {
        "ExtensionPublisher": "Qualys",
        "ExtensionType": "QualysAgent"
    }
} 
```

### Control Spec 

> **Passed:** 
> Required vulnerability assessment solution is present in VM.
> 
> **Failed:** 
> Required vulnerability assessment solution is not present in VM.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> VM instance is part of AKS or ADB cluster.
> 
### Recommendation 

- **Azure Portal** 

	 To install vulnerability assessment solution, please refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-vulnerability-assessment-recommendations 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machine Extensions at resource level:
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions?api-version=2019-07-01<br />
**Properties:** [\*].properties.type, [\*].properties.publisher
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
-->
 <br />


___

## Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension 

### Display Name 
Guest Configuration extension must be deployed to the VM using Azure Policy assignment 

### Rationale 
Installing Guest configuration extension on VM allows you to run In-Guest Policy on the VM, making it possible to monitor system and security policies for compliance checks in the VM. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        },
        {
            "Desciption": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        }
    ],
    "Linux": {
        "ExtensionPublisher": "Microsoft.GuestConfiguration",
        "ExtensionType": "ConfigurationForLinux",
        "RequiredVersion": "1.9.0"
    },
    "Windows": {
        "ExtensionPublisher": "Microsoft.GuestConfiguration",
        "ExtensionType": "ConfigurationForWindows",
        "RequiredVersion": "1.11.0"
    }
} 
```

### Control Spec 

> **Passed:** 
> Guest config extension is present, and System assigned MI is enabled for VM.
> 
> **Failed:** 
> Guest config extension is not present in VM, or System assigned MI is disabled for VM.
> 
> **NotApplicable:** 
> VM is part of ADB/AKS cluster.
> 
> **Not Scanned:** 
> VM OS type is null or empty.
> 
### Recommendation 

- **Azure Portal** 

	This control checks that the VM meets the following criteria: [a] Guest Configuration Extension is installed and provisioned successfully, [b] 'SystemAssigned' managed identity (MSI) is enabled for the VM. Both, the required Guest Configuration extension and a system-assigned MSI, will be automatically deployed and configured when the machine is in scope for an Azure Policy assignment that includes definitions in the Guest Configuration category. 
    Refer: https://docs.microsoft.com/en-us/azure/virtual-machines/extensions/guest-configuration

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machines at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** [*].identity.type
 <br />

- REST API to list Virtual Machine Extensions at resource level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions?api-version=2019-07-01<br />
**Properties:** [\*].properties.type, [\*].properties.publisher
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Enable_Monitoring_Agent 

### Display Name 
Ensure MMA or AMA is running on your VM

### Rationale 
One or more extensions may be required for maintaining data plane security hygiene and visibility for all Azure VMs in use at an Org. It is important to ensure all required extensions are installed and in healthy provisioning state. 

### Control Settings 
```json
{
    "ExtensionsForWindows": [
        {
            "ExtensionType": "MicrosoftMonitoringAgent",
            "Publisher": "Microsoft.EnterpriseCloud.Monitoring"
        },
        {
            "ExtensionType": "AzureMonitorWindowsAgent",
            "Publisher": "Microsoft.Azure.Monitor"
        }
    ],
    "ExtensionsForLinux": [
        {
            "ExtensionType": "OmsAgentForLinux",
            "Publisher": "Microsoft.EnterpriseCloud.Monitoring"
        },
        {
            "ExtensionType": "AzureMonitorLinuxAgent",
            "Publisher": "Microsoft.Azure.Monitor"
        }
    ],
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
> All required extensions are present in VM.
> 
> **Failed:** 
> One or more required extensions are missing in VM.
> 
> **Not Scanned:** 
> VM OS type is null or empty.
> 
> **NotApplicable:** 
> VM is part of ADB cluster.
> 
### Recommendation 

- **Azure Portal** 

	 Please refer: https://docs.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-install?context=/azure/virtual-machines/context/context 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machine Extensions at resource level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions?api-version=2019-07-01 <br />
**Properties:** [\*].properties.type, [\*].properties.publisher
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Dont_Open_Restricted_Ports 

### Display Name 
Management ports must not be open on machines 

### Rationale 
Open remote management ports expose a VM/compute node to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ],
    "PrivateIpAddressPrefixesToExclude": [
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16"
    ],
    "RestrictedPortsForLinux": "445,3389,22",
    "RestrictedPortsForWindows": "445,3389,5985,5986"
} 
```

### Control Spec 

> **Passed:** 
> NSG is configured and no inbound port is open, or NSG is configured and no restricted ports are open. Restricted ports, if open, are only via JIT (with Source not as "Any"), or are from a private source IP address.
> 
> **Failed:** 
> No NSG is configured on VM, or NSG is configured but restricted ports are open. Restricted ports are open via JIT, but with Source as "Any".
> 
> **NotApplicable:** 
> VM instance is part of ADB cluster.
> 
> **Error:** 
> RestrictedPorts list is not properly configured in control settings.
> ### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal -> VM Settings -> Networking -> Inbound security rules -> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22, SMB-445) -> Click 'Deny' under Action -> Click Save. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Network Interfaces at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** [\*].properties.networkSecurityGroup.Id, [\*].properties.ipConfigurations
<br />

- REST API to list Virtual Networks and route table associated with each subnet of VNet at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
**Properties:** [\*].properties.subnets
<br />

- REST API to list open ports in the NSG at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:** [\*].properties.securityRules.destinationPortRanges
<br />

- **Assessments:** 
805651bc-6ecd-4c73-9b55-97a19d0582d0 - Management ports of virtual machines should be protected with just-in-time network access control
<br />

<br />

___ 

## Azure_VirtualMachine_SI_Deploy_Data_Collection_Extension 

### Display Name 
[Preview]: Install Network data collection agents 

### Rationale 
Security Center uses the Microsoft Monitoring Dependency Agent to collect network traffic data from your Azure virtual machines to enable advanced network protection features such as traffic visualization on the network map, network hardening recommendations and specific network threats. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ],
    "Linux": {
        "ExtensionPublisher": "Microsoft.Azure.Monitoring.DependencyAgent",
        "ExtensionType": "DependencyAgentLinux"
    },
    "Windows": {
        "ExtensionPublisher": "Microsoft.Azure.Monitoring.DependencyAgent",
        "ExtensionType": "DependencyAgentWindows"
    }
} 
```

### Control Spec 

> **Passed:** 
> Required vulnerability assessment solution is present in VM
> 
> **Failed:** 
> Required vulnerability assessment solution is not present in VM
> 
> **NotApplicable:** 
> VM instance is part of AKS or ADB cluster
> 
> **Not Scanned:** 
> VM OS type is null or empty
> 
### Recommendation 

- **Azure Portal** 

	 Please refer: https://docs.microsoft.com/en-us/azure/azure-monitor/agents/diagnostics-extension-overview 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machine Extensions at resource level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions?api-version=2019-07-01 <br />
**Properties:** [\*].properties.type, [\*].properties.publisher
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Apply_MDC_Network_Recommendations 

### Display Name 
Apply Adaptive Network Hardening to Internet facing virtual machines 

### Rationale 
Adaptive Network Hardening uses a machine learning algorithm that factors in actual traffic, known trusted configuration, threat intelligence, and other indicators of compromise, and then provides recommendations to further restrict NSGs rules for an improved security posture. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        },
        {
            "Desciption": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        }
    ]
} 
```
### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Healthy".
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Unhealthy".
> 
### Recommendation 

- **Azure Portal** 

	 Please refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening#what-is-adaptive-network-hardening 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData
 <br />

- **Assessments:** 
f9f0eed0-f143-47bf-b856-671ea2eeed62 - Adaptive network hardening recommendations should be applied on internet facing virtual machines. <br />
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Security_Vulnerabilities 

### Display Name 
Vulnerabilities in security configuration on your machines must be remediated. 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Healthy".
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Unhealthy".
> 
### Recommendation 

- **Azure Portal** 

	 Go to security center -> Compute & apps -> VMs and Servers-> Click on VM name -> Click on VM Vulnerability remediation recommendation -> Click on Take Action -> Remediate list of vulnerabilities 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData
 <br />

- **Assessments:**
181ac480-f7c4-544b-9865-11b8ffe87f47 - Machines should be configured securely.
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Container_Security_Vulnerabilities 

### Display Name 
Vulnerabilities in container security configurations must be remediated 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising a VM/container with such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. Unpatched VMs are easy targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Healthy".
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Unhealthy".
> 
### Recommendation 

- **Azure Portal** 

	 Go to security center -> Compute & apps -> Containers -> Click on VM name -> Click on VM Container Vulnerability remediation recommendation -> Click on Take Action -> Remediate list of vulnerabilities 
<!-- 
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData
 <br />

- **Assessments:**
0677209d-e675-2c6f-e91a-54cef2878663 - Container hosts should be configured securely
 <br />

<br />

___ 

## Azure_VirtualMachine_Just_In_Time_Network_Access_Control 

### Display Name 
Just-In-Time network access control must be applied on virtual machines 

### Rationale 
For new deployments, require Just-In-Time network access control on virtual machines. (Effect type "Deny") *For existing VMs, force the deployment of require Just-In-Time network access on virtual machines. (Effect type "DeployIfNotExists") 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        },
        {
            "Desciption": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Healthy".
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Unhealthy".
>  
> **NotApplicable:** 
> VM is part of either Azure Databricks cluster or Azure Kubernetes service cluster.
> 
### Recommendation 

- **Azure Portal** 

	 Go to Security Center -> Just in time VM access -> Go to Not Configured -> Select your VM -> Click on Enable JIT on 1 VMs 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData
 <br />

- **Assessments:**
 805651bc-6ecd-4c73-9b55-97a19d0582d0 - Management ports of virtual machines should be protected with just-in-time network access control.
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Assessment_Soln_Vulnerabilities 

### Display Name 
Vulnerabilities must be remediated by a Vulnerability Assessment solution 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        },
        {
            "Desciption": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        }
    ]
} 
```
### Control Spec 

> **Passed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Healthy".
> 
> **Failed:** 
> Microsoft Defender for Cloud (MDC) Assessment status is "Unhealthy".
>
### Recommendation 

- **Azure Portal** 

	 Go to security center -> Compute & apps -> VMs and Servers -> Click on VM name -> Click on VM Vulnerability remediation recommendation by Assessment solution -> Click on Take Action -> Remediate list of vulnerabilities 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list all security assessments in a Subscription: /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** [\*].id, [\*].name, [\*].properties.resourceDetails.id, [\*].properties.displayName, [\*].properties.status, [\*].properties.additionalData
 <br />

- **Assessments:** 
71992a2a-d168-42e0-b10e-6b45fa2ecddb - Management ports of virtual machines should be protected with just-in-time network access control.
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Open_Allowed_Ports_Only 

### Display Name 
Only allowed ports must be opened on Virtual Machines 

### Rationale 
Open remote management ports expose a VM/compute node to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine. 

### Control Settings 
```json
{
    "AllowedPortsForLinux": "443,80",
    "AllowedPortsForWindows": "443,80",
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ]
} 
```

### Control Spec 

> **Passed:** 
> NSG is configured and no inbound port is open or NSG is configured and only allowed ports are open.
> 
> **Failed:** 
> No NSG is configured on VM or NSG is configured but other than allowed ports are open.
> 
> **NotApplicable:** 
> VM instance is part of Azure Databricks cluster or connected to ERvNET.
> 
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal -> VM Settings -> Networking -> Inbound security rules -> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22) -> Click 'Deny' under Action -> Click Save. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machines at subscription level: /subscriptions/{0}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** [\*].properties.networkProfile.networkInterfaces[\*].id
 <br />

- REST API to list Network Interfaces at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01 <br />
**Properties:** [\*].properties.networkSecurityGroup.id
 <br />

- REST API to list Virtual Networks (and associated subnets) at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
**Properties:**  [\*].properties.subnets[\*].networkSecurityGroup.id
 <br />

- REST API to list Network Security Groups at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01 <br />
**Properties:** [\*].properties.securityRules.destinationPortRange, [\*].properties.securityRules.destinationPortRanges

 <br />

<br />

___ 

## Azure_VirtualMachine_DP_Use_Secure_TLS_Version_Trial 

### Display Name 
[Trial] Use approved version of TLS for Windows Servers

### Rationale 
TLS provides privacy and data integrity between client and server. Using approved TLS version significantly reduces risks from security design issues and security bugs that may be present in older versions.

### Control Settings 
```json
{
     "ApplicableOsTypes": [
          "Windows"
      ]
} 
```

### Control Spec 

> **Passed:** 
> Azure Policy "Configure secure communication protocols (TLS 1.1 or TLS 1.2)" is set compliant state to "Compliant".
>
> **Failed:** 
> Azure Policy "Configure secure communication protocols (TLS 1.1 or TLS 1.2)" is set compliant state to "Non-Compliant"".
> 
> **Verify:** 
> Policy state not available for evaluation.
>
> **NotApplicable:** 
> VM OS type is other then 'Windows'.
>

### Recommendation
<!-- 
- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/endpoints-in-resource-manager, https://docs.microsoft.com/en-us/azure/virtual-network/virtual-networks-create-nsg-arm-ps 
-->

-
	Install the guest configuration extention.
	 
	```powershell 
	Set-AzVMExtension -Publisher 'Microsoft.GuestConfiguration' -Type 'ConfigurationforWindows' -Name 'AzurePolicyforWindows' -TypeHandlerVersion 1.0 -ResourceGroupName 'myResourceGroup' -Location 'myLocation' -VMName 'myVM' -EnableAutomaticUpgrade $true 
	 ```

- Assign Policy (Configure secure communication protocols (TLS 1.1 or TLS 1.2) on windows servers. Refer: https://learn.microsoft.com/en-us/azure/governance/policy/assign-policy-portal
<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri//providers/Microsoft.Authorization/policyDefinitions/828ba269-bf7f-4082-83dd-633417bc391d) 
	 "/providers/Microsoft.Authorization/policyDefinitions/af6cd1bd-1635-48cb-bde7-5b15693900b9"


	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policies or REST APIs used for evaluation 


- REST API to list Virtual Machine at
subscription level:
[/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list-all?tabs=HTTP)<br />
**Properties:** properties.storageProfile.osDisk.osType


- Azure Policy used for evaluation: [/providers/Microsoft.Authorization/policyDefinitions/828ba269-bf7f-4082-83dd-633417bc391d](https://portal.azure.com/#view/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F828ba269-bf7f-4082-83dd-633417bc391d)
<br />
<br />

___
## Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

### Display Name 
Entra ID (formerly AAD) extension must be deployed to the Linux VM

### Rationale 
Installing Entra ID (formerly AAD) extension on VM allows you to login into VM using Azure AD, making it possible to login user without password and improves authentication security.

### Control Settings 
```json
{
    "ExclusionTags": [
        {
            "Description": "VM is part of ADB cluster.",
            "TagName": "vendor",
            "TagValue": "Databricks"
        }
    ],
     "Linux": {
            "ExtensionType" : "AADSSHLoginForLinux",
            "ExtensionPublisher" : "Microsoft.Azure.ActiveDirectory",
            "ProvisioningState" : "Succeeded"
     }
} 
```

### Control Spec 

> **Passed:** 
> AAD extension present and provisioning state is succeeded.
>
> **Failed:** 
>  AAD extension is not present or provisioning state is not succeeded.
>
> **NotApplicable:** 
> Operating System (OS) Windows type is not supported for the evaluation.
> VM is part of Azure Databricks cluster.
>

### Recommendation

- **Azure Portal** 

	 To install AAD Extension in VM, Go to Azure Portal --> VM --> Settings --> Extensions+Applications --> Click Add --> Select AADSSHForLinuxVM --> Click Next --> Click Review+Create. 

-
	Install the AAD Auth extension.
	 
	```powershell 
	Set-AzVMExtension -Publisher 'Microsoft.Azure.ActiveDirectory' -Type 'AADSSHLoginForLinux' -Name 'AADSSHLoginForLinux' -TypeHandlerVersion 1.0 -ResourceGroupName 'myResourceGroup' -Location 'myLocation' -VMName 'myVM'
	 ```

### Azure Policies or REST APIs used for evaluation 

- REST API to list Virtual Machine at
subscription level:
[/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machines/list?tabs=HTTP)<br />
**Properties:** [\*].properties.storageProfile.osDisk.osType,</br>
                [\*].properties.orchestrationMode


- REST API to list extensions at Virtual Machine level: [/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupsName}/providers/Microsoft.Compute/virtualMachines/{VMName}/extensions?api-version=2019-07-01](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-extensions/list?tabs=HTTP)</br>
**Properties:** [\*].properties.publisher,</br>
                [\*].properties.type,</br>
                [\*].properties.provisioningState,

<br />

___

## Azure_VirtualMachine_Audit_Enable_Diagnostic_Settings 

### Display Name 
Enable Security Logging in Azure Virtual Machines

### Rationale 
Auditing logs must be enabled as they provide details for investigation in case of a security breach for threats 


### Control Settings 
```json
{
    "ExcludeBasedOnExtension": {
        "Windows": {
            "AllMandatory": false,
            "Extensions": [
            {
                "Type": "Compute.AKS.Windows.Billing",
                "Publisher": "Microsoft.AKS",
                "ExclusionMessage": "VMSS is part of AKS cluster."
            }
            ]
        }
    },
    "Windows": {
        "ExtensionType": "IaaSDiagnostics",
        "Publisher": "Microsoft.Azure.Diagnostics",
        "ProvisioningState": "Succeeded",
        "RequiredDiagnosticLogs": [ "Audit Failure", "Audit Success" ],
        "RequiredAuditLogsValue": "13510798882111488",
        "AuditLogsConfig": [
            {
            "Name": "Audit Failure",
            "Value": "4503599627370496"
            },
            {
            "Name": "Audit Success",
            "Value": "9007199254740992"
            }
        ]
    }
} 
```

### Control Spec 

> **Passed:** 
> Diagnostic extension present and 'Audit Success', 'Audit Failure' logs are enabled.
> 
> **Failed:** 
>  If any of the below condition is not satisfied:
> - Diagnostic extension is present
> - Audit Success', 'Audit Failure' logs are enabled.
>
> **NotScanned:**
> VM OS kind is null or empty.

### Recommendation 

- **Azure Portal** 
    - To change the diagnostic settings from the Azure Portaly follow the steps given here: https://learn.microsoft.com/en-us/azure/azure-monitor/agents/diagnostics-extension-windows-install#install-with-azure-portal and while configuring or updating the diagnostic settings ['audit success','audit failure'] logs should be enabled.

### Azure Policies or REST APIs used for evaluation 

- REST API to list virtual machine extensions at specific level: /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachines/{2}/extensions?api-version=2019-07-01<br />
**Properties:** properties.type, properties.publisher, name, properties.provisioningState, properties.settings.storageAccount, properties.settings.WadCfg.DiagnosticMonitorConfiguration.WindowsEventLog.DataSource
 <br />

- REST API to list Virtual Machines at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** properties.storageProfile.osDisk.osType
 <br />

<br />

___ 

## Azure_VirtualMachineScaleSet_Audit_Enable_Data_Collection_Rule

### Display Name
Audit enabling of Data Collection Rule on Virtual Machine Scale Sets

### Rationale
Enabling Data Collection Rules (DCR) on Azure Virtual Machine Scale Sets ensures that diagnostic data, such as performance metrics and security logs, is collected and sent to a central location for monitoring and analysis. This is critical for maintaining visibility into the health, performance, and security posture of your scale sets. Enabling DCR supports compliance with regulatory requirements and organizational security standards by ensuring that audit and diagnostic logs are retained and available for investigation.

### Control Spec

> **Passed:**
> - The Virtual Machine Scale Set has an associated Data Collection Rule (DCR) configured and enabled.
>
> **Failed:**
> - The Virtual Machine Scale Set does not have any Data Collection Rule (DCR) configured or enabled.

### Recommendation

- **Azure Portal**
    1. Navigate to **Virtual Machine Scale Sets** in the Azure Portal.
    2. Select the target scale set.
    3. Under **Monitoring**, select **Diagnostic settings**.
    4. Click **+ Add diagnostic setting**.
    5. Choose or create a Data Collection Rule (DCR) and associate it with the scale set.
    6. Save the configuration.

- **PowerShell**
    ```powershell
    # Example: Associate a DCR with a VMSS using PowerShell
    $resourceGroup = "<ResourceGroupName>"
    $vmssName = "<VMSSName>"
    $dcrId = "<DCRResourceId>"

    Set-AzVmssExtension -ResourceGroupName $resourceGroup `
        -VMScaleSetName $vmssName `
        -Name "AzureMonitorWindowsAgent" `
        -Publisher "Microsoft.Azure.Monitor" `
        -Type "AzureMonitorWindowsAgent" `
        -TypeHandlerVersion "1.10" `
        -Settings @{ "dataCollectionRuleId" = $dcrId }
    ```

- **Azure CLI**
    ```bash
    # Example: Associate a DCR with a VMSS using Azure CLI
    az vmss extension set \
      --resource-group <ResourceGroupName> \
      --vmss-name <VMSSName> \
      --name AzureMonitorWindowsAgent \
      --publisher Microsoft.Azure.Monitor \
      --version 1.10 \
      --settings '{"dataCollectionRuleId":"<DCRResourceId>"}'
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      Deploy the built-in Azure Policy `Configure Azure Monitor agent to be enabled on virtual machine scale sets` to automatically audit and enforce DCR association.
    - **ARM Template:**  
      Use an ARM template to deploy the Azure Monitor agent extension with the required DCR on all VMSS instances.
    - **Bulk Remediation:**  
      Use Azure Policy Remediation Tasks to apply the policy to existing resources at scale.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/extensions?api-version=2022-03-01`
  <br />
  **Properties:**  
  - `settings.dataCollectionRuleId` (must be present and reference a valid DCR)
  - Extension type: `AzureMonitorWindowsAgent` or `AzureMonitorLinuxAgent`

<br/>

___


## Azure_VirtualMachineScaleSet_AuthN_Enable_AADAuth_Windows

### Display Name
Azure Virtual Machine Scale Sets running Windows should have Azure Active Directory authentication enabled

### Rationale
Enabling Azure Active Directory (AAD) authentication for Windows Virtual Machine Scale Sets (VMSS) enhances security by allowing centralized identity management and conditional access policies. This reduces the risk of credential compromise, supports multi-factor authentication, and simplifies user lifecycle management, thereby aligning with compliance requirements such as ISO 27001, NIST SP 800-53, and PCI DSS.

### Control Spec

> **Passed:**
> - Azure Active Directory login is enabled for all Windows VMSS instances.
>
> **Failed:**
> - Azure Active Directory login is not enabled for one or more Windows VMSS instances.

### Recommendation

- **Azure Portal**
    1. Navigate to **Virtual Machine Scale Sets** in the Azure Portal.
    2. Select the target VMSS.
    3. Under **Settings**, select **Configuration**.
    4. In the **Azure Active Directory** section, set **Login with Azure Active Directory** to **On**.
    5. Save the configuration.

- **PowerShell**
    ```powershell
    # Enable AAD login extension for a Windows VMSS
    $resourceGroup = "<ResourceGroupName>"
    $vmssName = "<VMSSName>"
    Set-AzVmssExtension -ResourceGroupName $resourceGroup `
        -VMScaleSetName $vmssName `
        -Name "AADLoginForWindows" `
        -Publisher "Microsoft.Azure.ActiveDirectory" `
        -Type "AADLoginForWindows" `
        -TypeHandlerVersion "1.0"
    ```

- **Azure CLI**
    ```bash
    # Enable AAD login extension for a Windows VMSS
    az vmss extension set \
      --resource-group <ResourceGroupName> \
      --vmss-name <VMSSName> \
      --name AADLoginForWindows \
      --publisher Microsoft.Azure.ActiveDirectory \
      --version 1.0
    ```

- **Automation/Remediation**
    - Use Azure Policy definition:  
      Assign the built-in policy **[Audit Windows virtual machine scale sets without Azure Active Directory authentication enabled](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDefinitionBlade/definitionId/5e5e0c8e-8c0d-4b5a-8d8a-9b3c7b7c8e6e)** to audit and enforce this control.
    - For bulk remediation, use an Azure Policy assignment with a deployIfNotExists effect to automatically enable AAD authentication on non-compliant VMSS resources.
    - ARM Template snippet:
      ```json
      {
        "type": "Microsoft.Compute/virtualMachineScaleSets/extensions",
        "name": "[concat(parameters('vmssName'), '/AADLoginForWindows')]",
        "apiVersion": "2021-07-01",
        "properties": {
          "publisher": "Microsoft.Azure.ActiveDirectory",
          "type": "AADLoginForWindows",
          "typeHandlerVersion": "1.0",
          "autoUpgradeMinorVersion": true,
          "settings": {}
        }
      }
      ```

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/extensions?api-version=2021-07-01`  
**Properties:**  
- Checks for the presence of the `AADLoginForWindows` extension with `publisher` set to `Microsoft.Azure.ActiveDirectory` and `type` set to `AADLoginForWindows`.

<br/>

___


## Azure_VirtualMachineScaleSet_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Virtual Machine Scale Set data properties

### Rationale
Storing sensitive information such as passwords, connection strings, or API keys in plaintext within Virtual Machine Scale Set (VMSS) data properties exposes your environment to significant security risks. Attackers who gain access to these properties could compromise your applications and data. Using secure mechanisms such as Azure Key Vault or managed identities reduces the risk of accidental exposure and helps meet compliance requirements for data protection and confidentiality.

### Control Spec

> **Passed:**
> No plaintext secrets (e.g., passwords, connection strings, API keys) are found in VMSS custom data, tags, or other properties. All sensitive data is referenced securely (e.g., via Key Vault references or managed identities).
>
> **Failed:**
> Plaintext secrets are detected in VMSS custom data, tags, or other properties. Sensitive information is directly embedded in the resource configuration.

### Recommendation

- **Azure Portal**
    1. Navigate to **Virtual Machine Scale Sets** in the Azure Portal.
    2. Select the VMSS instance.
    3. Review the **Custom data** and **Tags** sections for any embedded secrets.
    4. Remove any plaintext secrets and replace them with secure references (e.g., Key Vault URIs or managed identities).
    5. Save your changes.

- **PowerShell**
    ```powershell
    # Get VMSS custom data and tags
    $vmss = Get-AzVmss -ResourceGroupName "<ResourceGroup>" -VMScaleSetName "<VMSSName>"
    $customData = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($vmss.VirtualMachineProfile.OsProfile.CustomData))
    $tags = $vmss.Tags

    # Review and update as needed
    # To update custom data (ensure secrets are removed)
    $vmss.VirtualMachineProfile.OsProfile.CustomData = [Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes("<secure custom data>"))
    Update-AzVmss -ResourceGroupName "<ResourceGroup>" -Name "<VMSSName>" -VirtualMachineScaleSet $vmss
    ```

- **Azure CLI**
    ```bash
    # View custom data (decode from base64)
    az vmss show --resource-group <ResourceGroup> --name <VMSSName> --query "virtualMachineProfile.osProfile.customData" -o tsv | base64 --decode

    # Update custom data (ensure secrets are removed)
    az vmss update --resource-group <ResourceGroup> --name <VMSSName> --set virtualMachineProfile.osProfile.customData="<base64-encoded-secure-data>"
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit and deny VMSS resources with plaintext secrets in custom data or tags.
    - Implement CI/CD pipeline checks to scan for secrets before deployment.
    - Use Azure Key Vault references in VMSS configurations for sensitive data.
    - For bulk remediation, script enumeration of all VMSS instances and automate the removal or replacement of detected secrets.

    **Example Azure Policy Definition:**
    ```json
    {
      "if": {
        "allOf": [
          {
            "field": "type",
            "equals": "Microsoft.Compute/virtualMachineScaleSets"
          },
          {
            "anyOf": [
              {
                "field": "Microsoft.Compute/virtualMachineScaleSets/virtualMachineProfile.osProfile.customData",
                "contains": "password"
              },
              {
                "field": "tags",
                "contains": "key"
              }
            ]
          }
        ]
      },
      "then": {
        "effect": "deny"
      }
    }
    ```

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}?api-version=2022-08-01`<br />
**Properties:** `virtualMachineProfile.osProfile.customData`, `tags`

<br/>

___


## Azure_VirtualMachine_Audit_Enable_DataCollectionRule

### Display Name
Audit - Enable Data Collection Rule for Virtual Machines

### Rationale
Enabling a Data Collection Rule (DCR) on Azure Virtual Machines ensures that security-relevant telemetry, such as performance metrics, event logs, and security logs, is collected and sent to a central Log Analytics workspace. This supports monitoring, threat detection, and compliance with regulatory requirements such as ISO 27001, NIST, and PCI DSS. Without a DCR, critical security and operational data may not be available for analysis, increasing the risk of undetected threats and non-compliance.

### Control Spec

> **Passed:**
> - The Azure Virtual Machine has an associated Data Collection Rule (DCR) that is configured and enabled for the resource.
>
> **Failed:**
> - The Azure Virtual Machine does not have any Data Collection Rule (DCR) associated, or the DCR is not enabled.

### Recommendation

- **Azure Portal**
    1. Navigate to **Azure Monitor** in the Azure Portal.
    2. Select **Data Collection Rules** under the "Settings" section.
    3. Click **+ Create** to define a new Data Collection Rule, specifying the required data sources (e.g., Windows Event Logs, performance counters).
    4. Under **Resources**, add the target Virtual Machine(s).
    5. Review and create the rule.
    6. Ensure the rule is enabled and associated with the intended Virtual Machine(s).

- **PowerShell**
    ```powershell
    # Install the Az.Monitor module if not already present
    Install-Module -Name Az.Monitor

    # Create a new Data Collection Rule
    $dcr = New-AzDataCollectionRule `
        -ResourceGroupName "<ResourceGroup>" `
        -RuleName "<DCR-Name>" `
        -Location "<Region>" `
        -DataSources @(@{Kind="WindowsEventLog"; Streams=@("Microsoft-Windows-Security-Auditing")}) `
        -Destinations @(@{Kind="LogAnalytics"; WorkspaceResourceId="/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"})

    # Associate the DCR with a Virtual Machine
    New-AzDataCollectionRuleAssociation `
        -ResourceId "/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vmName>" `
        -RuleId $dcr.Id `
        -AssociationName "<AssociationName>"
    ```

- **Azure CLI**
    ```bash
    # Create a Data Collection Rule (DCR)
    az monitor data-collection rule create \
      --resource-group <ResourceGroup> \
      --name <DCR-Name> \
      --location <Region> \
      --data-flows '[{"streams":["Microsoft-Windows-Security-Auditing"],"destinations":["<workspace>"]}]' \
      --data-sources '[{"kind":"WindowsEventLog","streams":["Microsoft-Windows-Security-Auditing"]}]' \
      --destinations '[{"kind":"LogAnalytics","workspaceResourceId":"/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.OperationalInsights/workspaces/<workspace>"}]'

    # Associate the DCR with a VM
    az monitor data-collection rule association create \
      --resource "/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Compute/virtualMachines/<vmName>" \
      --rule "/subscriptions/<subId>/resourceGroups/<rg>/providers/Microsoft.Insights/dataCollectionRules/<DCR-Name>" \
      --name <AssociationName>
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:** Deploy the built-in policy **[Deploy Data Collection Rule to enable VM insights monitoring](https://portal.azure.com/#blade/Microsoft_Azure_Policy/EditAssignmentBlade/id/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2Ff2e7b6b1-8e8d-4c3e-b6e6-1c2f4b4d5a3d)** to automatically audit and deploy DCRs to all virtual machines.
    - **ARM Template:** Use the [Data Collection Rule ARM template](https://learn.microsoft.com/azure/azure-monitor/essentials/data-collection-rule-templates) to automate deployment at scale.
    - **Bulk Remediation:** Use Azure Policyâ€™s "Remediate" feature to assign the policy to a management group or subscription for tenant-wide enforcement.
    - **AzTS Bulk Remediation:** If using Azure Tenant Security (AzTS), leverage the bulk remediation script provided in the AzTS toolkit to associate DCRs with all VMs in the tenant.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/providers/Microsoft.Insights/dataCollectionRuleAssociations?api-version=2021-09-01-preview`  
  **Properties:**  
  - `dataCollectionRuleId`  
  - `associationState` (should be `Enabled`)

<br/>

___


## Azure_VirtualMachine_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

### Display Name
Enable Microsoft Entra ID Authentication for Linux Virtual Machines

### Rationale
Enabling Microsoft Entra ID (formerly Azure Active Directory) authentication for Linux virtual machines enhances security by allowing centralized identity management and eliminating the need for local credentials. This control ensures that only users with appropriate Microsoft Entra ID permissions can access Linux VMs, supporting compliance with standards such as ISO 27001, NIST SP 800-53, and CIS Controls. It also enables conditional access policies, multi-factor authentication, and improved auditability.

### Control Spec

> **Passed:**
> - The Linux virtual machine is configured to allow login using Microsoft Entra ID authentication.
> - The VM has the required extensions installed and the system-assigned managed identity enabled.
>
> **Failed:**
> - The Linux virtual machine does not have Microsoft Entra ID authentication enabled.
> - The required extensions or managed identity are missing or misconfigured.

### Recommendation

- **Azure Portal**
    1. Navigate to **Virtual Machines** in the Azure Portal.
    2. Select the target Linux VM.
    3. Under **Settings**, select **Configuration**.
    4. In the **Identity** section, enable the **System-assigned managed identity**.
    5. Go to **Login with Microsoft Entra ID** and enable the option.
    6. Save the configuration.
    7. Ensure the **AADLoginForLinux** extension is installed.

- **PowerShell**
    ```powershell
    # Enable system-assigned managed identity
    az vm identity assign --name <vm-name> --resource-group <resource-group>

    # Install the AADLoginForLinux extension
    az vm extension set \
      --publisher Microsoft.Azure.ActiveDirectory.LinuxSSH \
      --name AADLoginForLinux \
      --resource-group <resource-group> \
      --vm-name <vm-name>
    ```

- **Azure CLI**
    ```bash
    # Enable system-assigned managed identity
    az vm identity assign --name <vm-name> --resource-group <resource-group>

    # Install the AADLoginForLinux extension
    az vm extension set \
      --publisher Microsoft.Azure.ActiveDirectory.LinuxSSH \
      --name AADLoginForLinux \
      --resource-group <resource-group> \
      --vm-name <vm-name>
    ```

- **Automation/Remediation**
    - Use Azure Policy definition: `Audit Linux virtual machines without Microsoft Entra ID login enabled`
    - Assign the policy at the subscription or management group level for bulk enforcement.
    - Use Azure Blueprints or ARM templates to automate VM deployment with Entra ID authentication enabled.
    - For tenant-wide remediation, leverage Azure Policy remediation tasks to deploy the extension and enable managed identity on all non-compliant VMs.

### Azure Policies or REST APIs used for evaluation

- REST API: `https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2023-03-01`
  <br />
  **Properties:** 
    - `identity.type` (should be `SystemAssigned` or `UserAssigned`)
    - `resources[*].type` (should include `Microsoft.Azure.ActiveDirectory.LinuxSSH/AADLoginForLinux`)
    - `osProfile.linuxConfiguration.ssh` (should be configured for Entra ID login)

<br/>

___

## Azure_VirtualMachine_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext on Azure Virtual Machines

### Rationale
Storing secrets such as passwords, connection strings, or API keys in plaintext on virtual machines exposes them to unauthorized access and increases the risk of data breaches. Adhering to this control helps organizations meet compliance requirements (such as ISO 27001, PCI DSS, and NIST SP 800-53) and strengthens the overall security posture by ensuring sensitive information is protected using secure mechanisms like Azure Key Vault or managed identities.

### Control Spec

> **Passed:**
> - No plaintext secrets (e.g., passwords, API keys, connection strings) are found in configuration files, environment variables, or scripts on the virtual machine.
> - Secrets are retrieved securely at runtime using Azure Key Vault, managed identities, or other secure secret management solutions.
>
> **Failed:**
> - Plaintext secrets are detected in files, environment variables, or scripts on the virtual machine.
> - No secure secret management solution is used for sensitive data.

### Recommendation

- **Azure Portal**
    1. Review your VM configuration files, environment variables, and scripts for any hardcoded secrets.
    2. Remove any plaintext secrets and replace them with secure references (e.g., environment variables that use Azure Key Vault).
    3. Configure your applications to retrieve secrets at runtime from Azure Key Vault or use managed identities for authentication.

- **PowerShell**
    ```powershell
    # Example: Assign a managed identity to the VM
    $vm = Get-AzVM -ResourceGroupName "<ResourceGroupName>" -Name "<VMName>"
    $vm.Identity.Type = "SystemAssigned"
    Update-AzVM -ResourceGroupName "<ResourceGroupName>" -VM $vm

    # Example: Grant the VM access to Key Vault
    Set-AzKeyVaultAccessPolicy -VaultName "<KeyVaultName>" -ObjectId $vm.Identity.PrincipalId -PermissionsToSecrets get
    ```

- **Azure CLI**
    ```bash
    # Assign a system-assigned managed identity to the VM
    az vm identity assign --resource-group <ResourceGroupName> --name <VMName>

    # Grant the VM access to Key Vault secrets
    az keyvault set-policy --name <KeyVaultName> --object-id <PrincipalId> --secret-permissions get
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit and deny deployments that include plaintext secrets in VM extensions or custom scripts.
    - Implement Azure Blueprints to enforce secure secret management practices across your environment.
    - Use Azure Security Center recommendations to identify VMs with insecure secret storage.
    - For bulk remediation, use scripts to scan VMs for plaintext secrets and automate the migration of secrets to Azure Key Vault.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2022-08-01`<br />
**Properties:** `osProfile`, `customData`, VM extensions, environment variables, and configuration files scanned for plaintext secrets

<br/>

___


## Azure_VirtualMachine_DP_Enable_Encryption_At_Host

### Display Name
Enable Encryption at Host for Azure Virtual Machines

### Rationale
Enabling Encryption at Host ensures that all data stored on the VM host is encrypted at rest using platform-managed keys. This provides an additional layer of security beyond disk encryption, protecting against unauthorized access to data at the infrastructure level. This control helps organizations meet compliance requirements for data protection and confidentiality, such as those found in ISO 27001, PCI DSS, and other regulatory frameworks.

### Control Spec

> **Passed:**
> - The Azure Virtual Machine has the "Encryption at host" feature enabled.
>
> **Failed:**
> - The Azure Virtual Machine does not have "Encryption at host" enabled.

### Recommendation

- **Azure Portal**
    1. Navigate to **Virtual Machines** in the Azure Portal.
    2. Select the VM you want to configure.
    3. Under **Settings**, select **Disks**.
    4. Click on **Encryption**.
    5. Set **Encryption at host** to **Enabled**.
    6. Save the changes and restart the VM if required.

- **PowerShell**
    ```powershell
    # Enable Encryption at Host for an existing VM
    $vm = Get-AzVM -ResourceGroupName "<ResourceGroupName>" -Name "<VMName>"
    $vm.SecurityProfile = @{ EncryptionAtHost = $true }
    Update-AzVM -ResourceGroupName "<ResourceGroupName>" -VM $vm
    ```

- **Azure CLI**
    ```bash
    # Enable Encryption at Host for an existing VM
    az vm update \
      --resource-group <ResourceGroupName> \
      --name <VMName> \
      --set securityProfile.encryptionAtHost=true
    ```

- **Automation/Remediation**
    - **Azure Policy Definition:**  
      You can assign the built-in Azure Policy:  
      `Audit VMs without encryption at host enabled`  
      or create a custom policy to enforce encryption at host.
    - **ARM Template Example:**
      ```json
      {
        "type": "Microsoft.Compute/virtualMachines",
        "apiVersion": "2021-07-01",
        "name": "[parameters('vmName')]",
        "properties": {
          "securityProfile": {
            "encryptionAtHost": true
          }
        }
      }
      ```
    - **Bulk Remediation:**  
      Use Azure Policy's "DeployIfNotExists" effect to automatically enable encryption at host on non-compliant VMs.

### Azure Policies or REST APIs used for evaluation

- **REST API:**  
  `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}?api-version=2021-07-01`  
  **Properties:**  
  `securityProfile.encryptionAtHost`

<br/>

___


## Azure_VirtualMachine_SI_Enable_Sense_Agent

### Display Name
Microsoft Defender for Endpoint (Sense Agent) should be enabled on Virtual Machines

### Rationale
Enabling the Microsoft Defender for Endpoint (Sense Agent) on Azure Virtual Machines provides advanced threat protection, endpoint detection and response, and vulnerability management. This control helps organizations detect, investigate, and respond to advanced threats on their virtual machines, supporting compliance with security frameworks such as CIS, NIST, and ISO 27001. Ensuring the Sense Agent is enabled reduces the attack surface and improves the security posture of your cloud workloads.

### Control Spec

> **Passed:**
> - The Microsoft Defender for Endpoint (Sense Agent) is installed and running on the Azure Virtual Machine.
>
> **Failed:**
> - The Sense Agent is not installed, not running, or not reporting on the Azure Virtual Machine.

### Recommendation

- **Azure Portal**
    1. Navigate to **Microsoft Defender for Cloud** in the Azure Portal.
    2. Select **Environment settings** and choose the relevant subscription.
    3. Under **Defender plans**, ensure **Microsoft Defender for Servers** is enabled.
    4. This will automatically deploy the Microsoft Defender for Endpoint (Sense Agent) via the Log Analytics agent or Azure Monitor agent, depending on your configuration.
    5. For individual VMs, you can check the **Extensions + applications** blade to verify the presence of the 'MDE.Windows' extension.

- **PowerShell**
    ```powershell
    # Install the Microsoft Defender for Endpoint agent on a Windows VM
    Set-AzVMExtension -ResourceGroupName "<ResourceGroupName>" `
      -VMName "<VMName>" `
      -Name "MDE.Windows" `
      -Publisher "Microsoft.Azure.AzureDefender" `
      -ExtensionType "MDE.Windows" `
      -TypeHandlerVersion "1.0"
    ```

- **Azure CLI**
    ```bash
    # Install the Microsoft Defender for Endpoint agent on a Windows VM
    az vm extension set \
      --resource-group <ResourceGroupName> \
      --vm-name <VMName> \
      --name MDE.Windows \
      --publisher Microsoft.Azure.AzureDefender \
      --version 1.0
    ```

- **Automation/Remediation**
    - **Azure Policy**: Assign the built-in policy definition `Deploy Microsoft Defender for Endpoint sensor on Windows virtual machines` to automatically deploy the Sense Agent on all new and existing VMs.
    - **Bulk Remediation**: Use Azure Policy's 'Remediate' feature to deploy the extension to all non-compliant VMs at scale.
    - **ARM Template**: Add the following extension resource to your VM ARM template:
        ```json
        {
          "type": "Microsoft.Compute/virtualMachines/extensions",
          "name": "[concat(parameters('vmName'), '/MDE.Windows')]",
          "apiVersion": "2021-07-01",
          "location": "[parameters('location')]",
          "properties": {
            "publisher": "Microsoft.Azure.AzureDefender",
            "type": "MDE.Windows",
            "typeHandlerVersion": "1.0",
            "autoUpgradeMinorVersion": true
          }
        }
        ```
    - **AzTS Remediation**: If using Azure Tenant Security (AzTS), leverage the provided bulk remediation scripts to deploy the Sense Agent across all VMs in the tenant.

### Azure Policies or REST APIs used for evaluation

- **REST API:** `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{vmName}/extensions?api-version=2021-07-01`  
  **Properties:** Checks for the presence and provisioning state of the `MDE.Windows` extension.

<br/>

___
