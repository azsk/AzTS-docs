# VirtualMachine

**Resource Type:** Microsoft.Compute/virtualMachines

___ 

## Azure_VirtualMachine_SI_Enable_Antimalware 

### DisplayName 
Ensure all devices have anti-malware protection installed and enabled 

### Rationale 
Enabling antimalware protection minimizes the risks from existing and new attacks from various types of malware. Microsoft Antimalware provide real-time protection, scheduled scanning, malware remediation, signature updates, engine updates, samples reporting, exclusion event collection etc. 


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
    "ReqExtensionPublisher": "Microsoft.Azure.Security",
    "ReqExtensionType": "IaaSAntimalware"
}
 ```  

### Control Spec 

> **Passed:** 
> If evaluated by reader permissions Required Antimalware extension is present in VM,and Auto upgrade to minor version is configured as true for extension and Real time protection is enabled for extension.
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

	 To install antimalware, Go to Azure Portal --> VM Properties --> Extensions --> Add 'Microsoft Antimalware' --> Enable Real-Time Protection and Scheduled Scan --> Click Ok. If antimalware is already present on VM, validate and resolve endpoint protection recommendations in ASC. Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection, https://docs.microsoft.com/en-us/azure/security/azure-security-antimalware 
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
### Azure Policy or ARM API used for evaluation 

- ARM API to list virtual machine extensions at specific level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{virtualMachineName}/extensions?api-version=2019-07-01<br />
**Properties:** Properties.StorageProfile.osDisk.osType ,properties.Type ,properties.Publisher
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

## Azure_VirtualMachine_SI_Enable_Antimalware_Trial 

### DisplayName 
[Trial] Ensure all devices have anti-malware protection installed and enabled 

### Rationale 
Enabling antimalware protection minimizes the risks from existing and new attacks from various types of malware. Microsoft Antimalware provide real-time protection, scheduled scanning, malware remediation, signature updates, engine updates, samples reporting, exclusion event collection etc. 


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
    "ReqExtensionPublisher": "Microsoft.Azure.Security",
    "ReqExtensionType": "IaaSAntimalware"
}
 ```  


### Control Spec 
<!--
> **Passed:** 
> Passed condition
> 
> **Failed:** 
> Failed condition
> -->
> **Verify:** 
> Virtual Machine's Operating System (OS) type is considered for evaluation.
> <!--
> **NotApplicable:** 
> NotApplicable condition if applicable
> -->
> **Error:** Virtual Machine's Operating System (OS) type cannot be determined. 
### Recommendation 

- **Azure Portal** 

	 To install antimalware, Go to Azure Portal --> VM Properties --> Extensions --> Add 'Microsoft Antimalware' --> Enable Real-Time Protection and Scheduled Scan --> Click Ok. If antimalware is already present on VM, validate and resolve endpoint protection recommendations in ASC. Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-install-endpoint-protection, https://docs.microsoft.com/en-us/azure/security/azure-security-antimalware 
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
### Azure Policy or ARM API used for evaluation 

- ARM API to list virtual machine extensions at resource group level: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachines/{virtualMachineName}/extensions?api-version=2019-07-01<br />
**Properties:** Properties.StorageProfile.osDisk.osType, properties.Type ,properties.Publisher
 <br />
<!--
- Example-2 ARM API to list service and its related property at resource group level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

## Azure_VirtualMachine_Config_Enable_NSG 

### DisplayName 
Internet-facing virtual machines must be protected with Network Security Groups 

### Rationale 
Restricting inbound and outbound traffic via NSGs limits the network exposure of a VM by reducing the attack surface. 

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
### Azure Policy or ARM API used for evaluation 

- ARM API to list networkInterfaces at subscription level: 
/subscriptions/{subscriptionId}/providers
/Microsoft.Network/networkInterfaces
?api-version=2019-04-01 <br />
**Properties:** publicIPAddress.id, networkSecurityGroup.id<br />

- ARM API to list Virtual Networks at
subscription level:
/subscriptions/{subscriptionId}/providers
/Microsoft.Network/virtualNetworks
?api-version=2019-11-01<br />
**Properties:** networkSecurityGroup.id
 <br />
<br />

___ 

## Azure_VirtualMachine_NetSec_Justify_PublicIPs 

### DisplayName 
Public IPs on a Virtual Machine should be carefully reviewed 

### Rationale 
Public IPs provide direct access over the internet exposing the VM to attacks over the public network. Hence each public IP on a VM must be reviewed carefully. 

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
### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Machines at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01 <br />
**Properties:** 
properties.networkProfile.networkInterfaces[*].id<br />

- ARM API to list Network Interfaces at
subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces
?api-version=2019-04-01<br />
**Properties:**  publicIPAddress.id	
 <br />
<br />

___ 

## Azure_VirtualMachine_DP_Enable_Disk_Encryption 

### DisplayName 
Disk encryption should be applied on virtual machines 

### Rationale 
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements. In the case of VMs, both OS and data disks may contain sensitive information that needs to be protected at rest. Hence disk encryption must be enabled for both. 

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
>ASC assessment found with Healthy status code.
> 
> **Failed:** 
> ASC assessment found with Unhealthy status code.
> <!--
> **Verify:** 
> Verify condition
> -->
> **NotApplicable:** 
> VM is part of Azure Databricks cluster or using ephemeral OS disks.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-disk-encryption?toc=%2fazure%2fsecurity%2ftoc.json. Note: After enabling disk encryption, it takes some time for changes to reflect in Azure Security Center (ASC). Thus, if you scan immediately, the control may still fail even though the VM itself shows as encrypted. Please wait a few hours to ascertain the fix. 
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policy or ARM API used for evaluation 

- ARM API to list security assessments at
subscription level:
/subscriptions/{subscriptionId}/providers
/Microsoft.Security/assessments?
api-version=2020-01-01<br />
 **Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData <br />

- ARM API to list Virtual Machines at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2019-07-01<br>
**Properties:** properties.storageProfile.osDisk.caching, properties.storageProfile.diffDiskSettings.option
 <br />
<br />

___ 

## Azure_VirtualMachine_SI_ASC_OS_Vulnerabilities 

### DisplayName 
Virtual Machine must be in a healthy state in Azure Security Center 

### Rationale 
Azure Security Center raises alerts (which are typically indicative of resources that are not compliant with some baseline security protection). It is important that these alerts/actions are resolved promptly in order to eliminate the exposure to attacks. 

### Control Settings 
```json 
{
    "ASCApprovedBaselineStatuses": {
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
> Azure Security Center (ASC) Assessment status is in the approved status(es) list.
> 
> **Failed:** 
> Azure Security Center (ASC) Assessment status is not in the approved status(es) list.
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

### Azure Policy or ARM API used for evaluation 

- ARM API to list all security assessments in a Subscription:
/subscriptions/{subscriptionId}/
providers/Microsoft.Security/assessments?api-version=2020-01-01 <br />
**Properties:** 
id, name, properties.resourceDetails.id,
properties.displayName, properties.status, properties.additionalData<br />
 **Assessments:** 
 181ac480-f7c4-544b-9865-11b8ffe87f47 - Vulnerabilities in security
configuration on your machines should be remediated.
<!--
- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />
-->
<br />

___ 

<!--
## Azure_VirtualMachine_SI_Missing_OS_Patches 

### DisplayName 
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

	 Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-system-updates . It takes 24 hours to reflect the latest status at ASC. 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 
-->
## Azure_VirtualMachine_SI_ASC_Recommendations 

### DisplayName 
Virtual Machine must implement all the flagged ASC recommendations 

### Rationale 
Azure Security Center provide various security recommendations for resources that are not compliant with some baseline security protection. It is important that these recommendations are resolved promptly in order to eliminate the exposure to attacks. 

### Control Spec 

> **Passed:** 
> No Azure Security Center Assessment for the Virtual Machine is "Unhealthy".
> 
> **Failed:** 
>One or more Azure Security Center Assessments for the Virtual Machine are "Unhealthy".
<!--
> **Verify:** 
> Verify condition
> 
> **NotApplicable:** 
> NotApplicable condition if applicable
-->
### Recommendation 

- **Azure Portal** 

	 First, examine the detailed AzSK log file for this VM to find out the specific recommendations this control is currently failing for. Review the ASC documentation for those recommendations and implement the suggested fixes. (Note: Not all ASC recommendations are flagged by AzSK. So the first step is critical.). <br>1.For Disk encryption should be applied on virtual machines Refer:https://docs.microsoft.com/en-us/azure/virtual-machines/windows/disk-encryption-overview <br> 2.For Adaptive application controls for defining safe applications should be enabled on your machines Refer:https://docs.microsoft.com/en-us/azure/defender-for-cloud/adaptive-network-hardening <br> 3.For A vulnerability assessment solution should be enabled on your virtual machines Refer:https://docs.microsoft.com/en-us/azure/defender-for-cloud/deploy-vulnerability-assessment-vm#deploy-the-integrated-scanner-to-your-azure-and-hybrid-machines.
<!--
- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->
### Azure Policy or ARM API used for evaluation 

- ARM API to list all security assessments in a Subscription:
/subscriptions/{subscriptionId}/
providers/Microsoft.Security/assessments?api-version=2020-01-01<br>
 **Properties:** id, name, properties.resourceDetails.id,
properties.displayName, properties.status, properties.additionalData<br>
 **Assessments:**  
  d57a4221-a804-52ca-3dea-768284f06bb7 - Disk encryption should be applied on virtual machines.<br>
  35f45c95-27cf-4e52-891f-8390d1de5828 - Adaptive application controls for defining safe applications should be enabled on your machines.<br>
  ffff0522-1e88-47fc-8382-2a80ba848f5d  - A vulnerability assessmentsolution should be enabled on your virtual machines.
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** 
-->
 <br />

___ 

## Azure_VirtualMachine_Audit_Enable_Diagnostics 

### DisplayName 
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
> 1. All required diagnostics extension(s) are configured.
>2. No mandatory diagnostics extension(s) have been specified for the Operating System.
> 
> **Failed:** 
>  One or more diagnostics extension(s) are not configured on the Virtual Machine.
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
### Azure Policy or ARM API used for evaluation 

- ARM API to list all extensions in a Virtual Machine:
/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupId}/
providers/Microsoft.Compute/virtualMachines/{virtualMachineName}/
extensions?api-version=2019-07-01<br />
**Properties:** properties.type, properties.publisher	
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
-->
 <br />

___ 

## Azure_VirtualMachine_SI_Enable_Vuln_Solution 

### DisplayName 
Install DSRE Qualys Cloud Agent on assets 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising a VM/container with such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

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
### Azure Policy or ARM API used for evaluation 

- ARM API to list Virtual Machine Extensions at
resource level:
/subscriptions/{subscriptionId}/resourceGroups/
{resourceGroupName}/providers/Microsoft.
Compute/virtualMachines/{vmName}
/extensions?api-version=2019-07-01<br />
**Properties:** properties.type, properties.publisher
 <br />
<!--
- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
-->
 <br />


___
<!--
## Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension 

### DisplayName 
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

	 This control checks that the VM meets the following criteria: [a] Guest Configuration Extension is installed and provisioned successfully, [b] 'SystemAssigned' managed identity (MSI) is enabled for the VM. Both, the required Guest Configuration extension and a system-assigned MSI, will be automatically deployed and configured when the machine is in scope for an Azure Policy assignment that includes definitions in the Guest Configuration category. 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Enable_Monitoring_Agent 

### DisplayName 
Ensure the MMA on your VM is healthy (running successfully) 

### Rationale 
One or more extensions may be required for maintaining data plane security hygiene and visibility for all Azure VMs in use at an Org. It is important to ensure all required extensions are installed and in healthy provisioning state. 

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
    "ExtensionsForLinux": [
        {
            "ExtensionType": "OmsAgentForLinux",
            "Publisher": "Microsoft.EnterpriseCloud.Monitoring"
        }
    ],
    "ExtensionsForWindows": [
        {
            "ExtensionType": "MicrosoftMonitoringAgent",
            "Publisher": "Microsoft.EnterpriseCloud.Monitoring"
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

	 Please refer: https://docs.microsoft.com/en-us/azure/azure-monitor/agents/azure-monitor-agent-install?context=/azure/virtual-machines/context/context 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Dont_Open_Restricted_Ports 

### DisplayName 
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
    "RestrictedPortsForLinux": "445,3389,22",
    "RestrictedPortsForWindows": "445,3389,5985"
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

	 Go to Azure Portal -> VM Settings -> Networking -> Inbound security rules -> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22, SMB-445) -> Click 'Deny' under Action -> Click Save. 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Deploy_Data_Collection_Extension 

### DisplayName 
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

	 Please refer: https://docs.microsoft.com/en-us/azure/azure-monitor/agents/diagnostics-extension-overview 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Apply_ASC_Network_Recommendations 

### DisplayName 
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

	 Please refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-adaptive-network-hardening#what-is-adaptive-network-hardening 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Security_Vulnerabilities 

### DisplayName 
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

	 Go to security center -> Compute & apps -> VMs and Servers-> Click on VM name -> Click on VM Vulnerability remediation recommendation -> Click on Take Action -> Remediate list of vulnerabilities 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Container_Security_Vulnerabilities 

### DisplayName 
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

	 Go to security center -> Compute & apps -> Containers -> Click on VM name -> Click on VM Container Vulnerability remediation recommendation -> Click on Take Action -> Remediate list of vulnerabilities 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_Just_In_Time_Network_Access_Control 

### DisplayName 
Just-In-Time network access control must be applied on virtual machines 

### Rationale 
For new deployments, require Just-In-Time network access control on virtual machines.(Effect type "Deny") *For existing VMs, force the deployment of require Just-In-Time network access on virtual machines. (Effect type "DeployIfNotExists") 

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

	 Go To Security Center -> Just in time VM access -> Go To Not Configured -> Select your VM -> Click on Enable JIT on 1 VMs 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Remediate_Assessment_Soln_Vulnerabilities 

### DisplayName 
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

	 Go to security center -> Compute & apps -> VMs and Servers -> Click on VM name -> Click on VM Vulnerability remediation recommendation by Assessment solution -> Click on Take Action -> Remediate list of vulnerabilities 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_NetSec_Open_Allowed_Ports_Only 

### DisplayName 
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

	 Go to Azure Portal -> VM Settings -> Networking -> Inbound security rules -> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22) -> Click 'Deny' under Action -> Click Save. 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 

## Azure_VirtualMachine_SI_Enable_Sense_Agent 

### DisplayName 
Ensure Sense Agent is installed and healthy 

### Rationale 
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising a VM/container with such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner. 

### Control Settings 
```json 
{
    "ApplicableOsTypes": [
        "Windows"
    ],
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

	 NA 

- **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

### Azure Policy or ARM API used for evaluation 

- Example ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

- Example-2 ARM API to list service and its related property at specified level: - /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceName/service/{serviceName}/tenant/access? 
 <br />
**Properties:** example-property
 <br />

<br />

___ 
-->
