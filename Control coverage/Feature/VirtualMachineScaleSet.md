# VirtualMachineScaleSet

**Resource Type:** Microsoft.Compute/virtualMachineScaleSets
<!-- TOC -->

- [Azure_VirtualMachineScaleSet_Audit_Enable_Diagnostics](#azure_virtualmachinescaleset_audit_enable_diagnostics)
- [Azure_VirtualMachineScaleSet_Config_Enable_NSG](#azure_virtualmachinescaleset_config_enable_nsg)
- [Azure_VirtualMachineScaleSet_Deploy_Monitoring_Agent](#azure_virtualmachinescaleset_deploy_monitoring_agent)
- [Azure_VirtualMachineScaleSet_NetSec_Dont_Open_Management_Ports](#azure_virtualmachinescaleset_netsec_dont_open_management_ports)
- [Azure_VirtualMachineScaleSet_NetSec_Justify_PublicIPs](#azure_virtualmachinescaleset_netsec_justify_publicips)
- [Azure_VirtualMachineScaleSet_SI_Enable_Antimalware](#azure_virtualmachinescaleset_si_enable_antimalware)
- [Azure_VirtualMachineScaleSet_SI_Enable_Auto_OS_Upgrade](#azure_virtualmachinescaleset_si_enable_auto_os_upgrade)
- [Azure_VirtualMachineScaleSet_SI_Latest_Model_Applied](#azure_virtualmachinescaleset_si_latest_model_applied)
- [Azure_VirtualMachineScaleSet_SI_Missing_OS_Patches](#azure_virtualmachinescaleset_si_missing_os_patches)
- [Azure_VirtualMachineScaleSet_SI_Remediate_Security_Vulnerabilities](#azure_virtualmachinescaleset_si_remediate_security_vulnerabilities)
- [Azure_VirtualMachineScaleSet_DP_Enable_Disk_Encryption](#azure_virtualmachinescaleset_dp_enable_disk_encryption)
- [Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux](#Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux)
- [Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy](#azure_virtualmachinescaleset_si_enforce_automatic_upgrade_policy)
- [Azure_VirtualMachineScaleSet_Audit_Enable_Diagnostic_Settings](#azure_virtualmachinescaleset_audit_enable_diagnostic_settings)
- [Azure_VirtualMachineScaleSet_AuthN_Enable_AAD_Auth_Windows](#azure_virtualmachinescaleset_authn_enable_aad_auth_windows)
- [Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host](#azure_virtualmachinescaleset_dp_enable_encryption_at_host)
- [Azure_VirtualMachineScaleSet_Audit_Enable_Data_Collection_Rule](#azure_virtualmachinescaleset_audit_enable_data_collection_rule)
- [Azure_VirtualMachineScaleSet_AuthN_Enable_AADAuth_Windows](#azure_virtualmachinescaleset_authn_enable_aadauth_windows)
- [Azure_VirtualMachineScaleSet_DP_Avoid_Plaintext_Secrets](#azure_virtualmachinescaleset_dp_avoid_plaintext_secrets)

<!-- /TOC -->
<br/>



___

## Azure_VirtualMachineScaleSet_Audit_Enable_Diagnostics

### Display Name
Diagnostics (IaaSDiagnostics extension on Windows; LinuxDiagnostic extension on Linux) must be enabled on Virtual Machine Scale Set.

### Rationale
Diagnostics logs are needed for creating activity trail while investigating an incident or a compromise.

### Control Settings
```json
{
    "LinuxExtensionType": "LinuxDiagnostic",
    "LinuxExtensionPublisher": "Microsoft.OSTCExtensions",
    "WindowsExtensionType": "IaaSDiagnostics",
    "WindowsExtensionPublisher": "Microsoft.Azure.Diagnostics"
}
```
### Control Spec

> **Passed:**
> Required diagnostics extension is present in VM Scale Set.
>
> **Failed:**
> Required diagnostics extension is missing in VM Scale Set.
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

- Refer: https://docs.microsoft.com/en-us/cli/azure/vmss/diagnostics?view=azure-cli-latest

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extensions
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_Config_Enable_NSG

### Display Name
NSG must be configured for Virtual Machine Scale Set.

### Rationale
Restricting inbound and outbound traffic via NSGs limits the network exposure of a VM Scale Set by reducing the attack surface.

### Control Spec

> **Passed:**
> VMSS does not have any associated public IP or NSG is configured for the VMSS.
>
> **Failed:**
> VMSS have associated public IP and no NSG is configured for it.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation


- To apply NSG at scale set, refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-networking#nsg--asgs-per-scale-set
, or 

- To apply NSG at subnet level, refer: https://docs.microsoft.com/en-us/azure/virtual-network/tutorial-filter-network-traffic#associate-network-security-group-to-subnet


<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to get all the public IPs for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/publicipaddresses?api-version=2019-07-01
  <br />

  **Properties:** properties.ipAddress
  <br />
  <br />

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.networkSecurityGroup, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_Deploy_Monitoring_Agent

### Display Name
Log analytics agent should be installed on Virtual Machine Scale Set.

### Rationale
Installing the Log Analytics extension for Windows and Linux allows Azure Monitor to collect data from your Azure VM Scale Sets which can be used for detailed analysis and correlation of events.

### Control Settings
```json
{
    "LinuxExtensionType": "OmsAgentForLinux",
    "LinuxExtensionPublisher": "Microsoft.EnterpriseCloud.Monitoring",
    "WindowsExtensionType": "MicrosoftMonitoringAgent",
    "WindowsExtensionPublisher": "Microsoft.EnterpriseCloud.Monitoring"
}
```
### Control Spec

> **Passed:**
> Required monitoring agent is present in VM Scale Set.
>
> **Failed:**
> Required monitoring agent is missing in VM Scale Set.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>
### Recommendation


<!-- Run following commands: 1- `$allVersions= (Get-AzVMExtensionImage -Location 'eastus' -PublisherName 'Microsoft.EnterpriseCloud.Monitoring' -Type 'MicrosoftMonitoringAgent or OmsAgentForLinux').Version 2- `$versionString = `$allVersions[(`$allVersions.count)-1].Split('.')[0] + '.' + `$allVersions[(`$allVersions.count)-1].Split('.')[1] 3- `$VMSS = Get-AzVmss -ResourceGroupName <VMSS RG Name> -VMScaleSetName <VMSS Name> 4- Add-AzVmssExtension -VirtualMachineScaleSet `$VMSS -Name 'MicrosoftMonitoringAgent' -Publisher 'Microsoft.EnterpriseCloud.Monitoring' -Type 'MicrosoftMonitoringAgent or OmsAgentForLinux' -TypeHandlerVersion `$versionString -Setting '{'workspaceId': '<your workspace ID here>'}' -ProtectedSetting '{'workspaceKey': '<your workspace key here>'}' 5- Update-AzVmss -ResourceGroupName <VMSS RG Name> -Name <VMSS Name> -VirtualMachineScaleSet `$VMSS ", -->


- **Powershell**
```powershell
    `$allVersions= (Get-AzVMExtensionImage -Location 'eastus' -PublisherName 'Microsoft.EnterpriseCloud.Monitoring' -Type 'MicrosoftMonitoringAgent or OmsAgentForLinux').Version
    `$versionString = `$allVersions[(`$allVersions.count)-1].Split('.')[0] + '.' + `$allVersions[(`$allVersions.count)-1].Split('.')[1]
    $VMSS = Get-AzVmss -ResourceGroupName '{ResourceGroupName}' -VMScaleSetName '{ResourceName}'
    Add-AzVmssExtension -VirtualMachineScaleSet `$VMSS -Name 'MicrosoftMonitoringAgent' -Publisher 'Microsoft.EnterpriseCloud.Monitoring' -Type 'MicrosoftMonitoringAgent or OmsAgentForLinux' -TypeHandlerVersion `$versionString -Setting '{'workspaceId': '{Your workplace Id}'}' -ProtectedSetting '{'workspaceKey': '{Your workplace Key}'}' 
        Update-AzVmss -ResourceGroupName '{ResourceGroupName}' -Name '{ResourceName}' -VirtualMachineScaleSet `$VMSS
```

<!--
- **Enforcement Policy**

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)
-->

### Azure Policies or REST APIs used for evaluation

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extensions
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_NetSec_Dont_Open_Management_Ports

### Display Name
Management ports must not be open on Virtual Machine Scale Sets.

### Rationale
Open remote management ports expose a VMSS instance/compute node to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine.

### Control Settings 
```json
{
    "RestrictedPortsForWindows": "445,3389,5985",
    "RestrictedPortsForLinux": "445,3389,22"
}
```

### Control Spec

> **Passed:**
> No inbound port is open in attached NSG or No restricted port is open in attached NSG.
>
> **Failed:**
> No NSG found on the VMSS or One or more restricted ports are open in NSG.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- **Azure Portal**

	Go to Azure Portal --> VM Scale Set --> Settings --> Networking --> Inbound security rules --> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22, SMB-445) --> Click 'Delete' under Action --> Click Save.

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

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.networkSecurityGroup, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
 <br />
 
- REST API to list all the NSG configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01
  <br />

  **Properties:** properties.securityRules.properties.destinationPortRange
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_NetSec_Justify_PublicIPs

### Display Name
Public IPs on a Virtual Machine Scale Set instances should be carefully reviewed.

### Rationale
Public IPs provide direct access over the internet exposing the VMSS instance to attacks over the public network. Hence each public IP on a VMSS instance must be reviewed carefully.

### Control Spec

> **Passed:**
> No Public IP is associated with VMSS or VMSS has Public IP associated with it but it is not part of ExpressRoute connected virtual network.
>
> **Failed:**
> VMSS is part of an ExpressRoute connected virtual network and has Public IP associated with it.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- Refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-networking#public-ipv4-per-virtual-machine

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

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
 <br />

- REST API to get all the public IPs for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/publicipaddresses?api-version=2019-07-01
  <br />

  **Properties:** properties.ipAddress
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Enable_Antimalware

### Display Name
Antimalware must be enabled with real time protection on Virtual Machine Scale Set.

### Rationale
Enabling antimalware protection minimizes the risks from existing and new attacks from various types of malware. Microsoft Antimalware provide real-time protection, scheduled scanning, malware remediation, signature updates, engine updates, samples reporting, exclusion event collection etc.

### Control Settings 
```json
{
    "ExtensionType": "IaaSAntimalware",
    "Publisher": "Microsoft.Azure.Security",
    "ExclusionTags": [
        {
            "Description": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        },
        {
            "Description": "VM is part of Service Fabric.",
            "TagName": "resourcetype",
            "TagValue": "service fabric"
        }
    ]
}
```

### Control Spec

> **Passed:**
> Antimalware Malware extension is deployed at VMSS model and all its VM instances with Auto Upgrade to minor version enabled and Realtime protection enabled
>
> **Failed:**
> AntiMalware extension is not deployed at VMSS model or at one or more VM instances or AntiMalware extension is present, but Auto Upgrade to minor version is disabled, or AntiMalware extension is present but Auto Realtime protection is disabled.
>
> **Error:**
>Required Extension details is not properly defined in control settings.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> VMSS is running on Linux OS
>

### Recommendation

- **Azure Portal**

	To install antimalware, Go to Azure Portal --> VMSS --> Settings --> Extensions --> Add 'Microsoft Antimalware' --> Enable Real-Time Protection and Scheduled Scan --> Click Ok. To turn on antimalware using powershell.
  
  Refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-faq#how-do-i-turn-on-antimalware-in-my-virtual-machine-scale-set

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

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br/>
  
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extension
  <br />
 <br />
 
- REST API to get all the VM instances for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/virtualMachines?api-version=2019-07-01
  <br />

  **Properties:** instance.resources (Microsoft.Compute/virtualMachines/extensions)
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Enable_Auto_OS_Upgrade

### Display Name
Enable automatic OS image upgrade on Virtual Machine Scale Set.

### Rationale
Being on the latest OS version significantly reduces risks from security design issues and security bugs that may be present in previous versions.

### Control Spec

> **Passed:**
> Automatic OS image upgrade is configured for VM Scale Set.
>
> **Failed:**
> Automatic OS image upgrade is not configured for VM Scale Set.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- To configure auto OS image upgrade on VM Scale Set, refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-automatic-upgrade

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

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade
  <br />
 <br />
 
___

## Azure_VirtualMachineScaleSet_SI_Latest_Model_Applied

### Display Name
All VMs in VM Scale Set must be up-to-date with the latest scale set model.

### Rationale
All the security configurations applied on VM Scale Set will be effective only if all the individual VM instances in Scale Set is up-to-date with the latest overall Scale Set model.

### Control Spec

> **Passed:**
> VMSS upgrade policy is not manual or VMSS upgrade policy is manual but all the VM instances are running on latest VM Scale Set model.
>
> **Failed:**
> VMSS upgrade policy is manual and any of the VM instance is not running on latest VM Scale Set model.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

-	Refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-upgrade-scale-set#how-to-bring-vms-up-to-date-with-the-latest-scale-set-model

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

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.upgradePolicy.mode
  <br />
 <br />
 
- REST API to get all the VM instances for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/virtualMachines?api-version=2019-07-01
  <br />

  **Properties:** instance.properties.latestModelApplied
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Missing_OS_Patches

### Display Name
System updates on virtual machine scale sets must be installed.

### Rationale
Un-patched VMSSs are easy targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software.

### Control Spec

> **Passed:**
> MDC assessment found with Healthy status code.
>
> **Failed:**
> MDC assessment found with Unhealthy status code.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-system-updates. It takes 24 hours to reflect the latest status at MDC.

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

- REST API to fetch all the security assessment for the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
  <br />

  **Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Remediate_Security_Vulnerabilities

### Display Name
Vulnerabilities in security configuration on your virtual machine scale sets must be remediated.

### Rationale
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner.

### Control Spec

> **Passed:**
> MDC assessment found with Healthy status code.
>
> **Failed:**
> MDC assessment found with Unhealthy status code.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- **Azure Portal**

	Go to security center --> Compute & apps --> VM scale sets --> Click on VMSS name --> Click on VMSS Vulnerability remediation recommendation --> Click on Take Action --> Remediate list of vulnerabilities.

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

- REST API to fetch all the security assessment for the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
  <br />

  **Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_DP_Enable_Disk_Encryption

### Display Name
Disk encryption should be applied on virtual machine scale sets.

### Rationale
Using this feature ensures that sensitive data is stored encrypted at rest. This minimizes the risk of data loss from physical theft and also helps meet regulatory compliance requirements. In the case of VM Scale Set, both OS and data disks may contain sensitive information that needs to be protected at rest. Hence disk encryption must be enabled for both.

### Control Settings 
```json
{
    "AzureDiskEncryptionExtension": {
        "ExtensionDefaultName": "AzureDiskEncryption",
        "LinuxExtensionDefaultName": "AzureDiskEncryptionForLinux"
    }
}
```

### Control Spec

> **Passed:**
> Azure disk encryption extension is installed, and existing disks (OS and Data) are encrypted.
>
> **Failed:**
> Azure disk encryption extension is not installed One or more existing disks (OS or Data) are in a non-compliant state
> (Any other state other than Encrypted is a non-compliant state.
> Possible states: Encrypted/NotEncrypted/NotMounted/DecryptionInProgress
> /EncryptionInProgress/VMRestartPending/Unknown/NoDiskFound)
>
> **Verify:**
> Storage profile for VM Scale Set unavailable or number of Virtual Machine instances in VM Scale Set exceeded scan limit.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- Refer: https://docs.microsoft.com/en-in/azure/virtual-machine-scale-sets/disk-encryption-powershell

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

- REST API to get configuration of a Virtual Machine Scale Set:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />

  **Properties:** properties.virtualMachineProfile.extensionProfile.extensions[\*].type, properties.virtualMachineProfile.extensionProfile.extensions.[\*].provisioningState
  <br />
 <br />
 
- REST API to get instance view of Virtual Machines in a Virtual Machine Scale Set:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/virtualmachines/{instanceId}/instanceView?api-version=2021-03-01
  <br />

  **Properties:** disks.statuses[*].code
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_AuthN_Enable_Microsoft_Entra_ID_Auth_Linux

### Display Name
Entra ID (formerly AAD) extension must be deployed to the Linux VMSS

### Rationale
Installing Entra ID (formerly AAD) extension on VMSS allows you to login into VMSS instances using Azure AD, making it possible to login user without password and improves authentication security.

### Control Settings 
```json
{
    "Linux": {
          "ExtensionType": "AADSSHLoginForLinux",
          "ExtensionPublisher": "Microsoft.Azure.ActiveDirectory",
          "ProvisioningState": "Succeeded"
        }
}
```
### Note:
This control only covers Virtual Machine Scale Sets with 'Uniform' Orchestration mode and following Linux distributions are currently supported for deployments in a supported region.

> 1. Common Base Linux Mariner (CBL-Mariner) - CBL-Mariner 1, CBL-Mariner 2
> 2. CentOS - CentOS 7, CentOS 8
>3. Debian - Debian 9, Debian 10, Debian 11
>4. openSUSE - openSUSE Leap 42.3, openSUSE Leap 15.1+
>5. RedHat Enterprise Linux (RHEL) - RHEL 7.4 to RHEL 7.10, RHEL 8.3+
>6. SUSE Linux Enterprise Server (SLES) - SLES 12, SLES 15.1+
>7. Ubuntu Server - Ubuntu Server 16.04 to Ubuntu Server 22.04


### Control Spec

> **Passed:**
> Entra ID (formerly AAD) Extension is present for Linux Virtual Machine Scale Set with provisioning state as succeeded.
>
> **Failed:**
> Entra ID (formerly AAD) Extension is missing or provisioning state is not succeeded.
>
> **Error:**
> If Orchestration mode or OS is null or empty.
> Required Extension details is not properly defined in control settings.
>
> **NotApplicable:**
> If Orchestration mode is not uniform/ Operating System (OS) Windows type is not supported for the evaluation.
>

### Recommendation
Using Azure Portal :
- To install Entra ID (formerly AAD) Extension in VMSS, Go to Azure Portal --> VMSS --> Settings --> Extensions+Applications --> Click Add --> Select AADSSHForLinuxVM --> Click Next --> Click Review+Create.


### Azure Policies or REST APIs used for evaluation

- REST API to list Virtual Machine Scale Set at subscription level:
[/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-scale-sets/list-all?tabs=HTTP)<br/>
  **Properties:** properties.storageProfile.osDisk.osType
                  properties.orchestrationMode
  <br />
  <br />

- REST API to list Virtual Machine Scale Set Extensions at resource level:
[/subscriptions/{subscriptionId}/resourceGroups/{ResourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{VMScaleSetName}/extensions?api-version=2022-03-01](https://learn.microsoft.com/en-us/rest/api/compute/virtual-machine-scale-set-extensions/list?tabs=HTTP)
</br>**Properties:** properties.virtualMachineProfile.extensionProfile.extensions.publisher
                  properties.virtualMachineProfile.extensionProfile.extensions.type
                  properties.virtualMachineProfile.extensionProfile.extensions.provisioningState

 <br />
<br />
___

## Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy

### Display Name
Enforce Automatic Upgrade policy in VMSS

### Rationale
All the security configurations applied on VM Scale Set will be effective only if all the individual VM instances in Scale Set are up-to-date with the latest overall Scale Set model. Automatic upgrade policy mode ensures individual VM instances are up-to-date with the latest overall Scale Set model.

### Control Settings 
```json
{
    "AllowedUpgradePolicyModes": [
      "Automatic"
    ],
    "ApplicableOrchestrationModes": [
      "Uniform"
    ]
}
```
### Note:
This control only covers Virtual Machine Scale Sets with 'Uniform' Orchestration mode.

### Control Spec

> **Passed:**
>  VMSS upgrade policy is set as one of the allowed upgrade policy mode.
>
> **Failed:**
> VMSS upgrade policy is not set as one of the allowed upgrade policy mode.
>
> **NotApplicable:**
> Orchestration mode is not in applicable orchestration modes.
>

### Recommendation
To set upgrade policy for VMSS, please refer: https://learn.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-upgrade-policy


### Azure Policies or REST APIs used for evaluation

- REST API to list Virtual Machine Scale Set at subscription level:
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01<br/>
  **Properties:** properties.orchestrationMode
  properties.upgradePolicy.mode
  <br />
  <br />
___


## Azure_VirtualMachineScaleSet_Audit_Enable_Diagnostic_Settings

### Display Name
Enable Security Logging in Azure Virtual Machine Scale Sets

### Rationale
Auditing logs must be enabled as they provide details for investigation in case of a security breach for threats.

### Control Settings
```json
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
"RequiredOsType": [ "Windows"],
"Windows": {
  "ExtensionType": "IaaSDiagnostics",
  "Publisher": "Microsoft.Azure.Diagnostics",
  "ProvisioningState": "Succeeded",
  "PerformanceCounters": [
    {
      "displayName": "CPU utilization",
      "counterSpecifier": "\\Processor(_Total)\\% Processor Time"
    },
    {
      "displayName": "CPU privileged time",
      "counterSpecifier": "\\Processor(_Total)\\% Privileged Time"
    },
    {
      "displayName": "CPU user time",
      "counterSpecifier": "\\Processor(_Total)\\% User Time"

    },
    {
      "displayName": "CPU frequency",
      "counterSpecifier": "\\Processor Information(_Total)\\Processor Frequency"
    },
    {
      "displayName": "Processes",
      "counterSpecifier": "\\System\\Processes"
    },
    {
      "displayName": "Threads",
      "counterSpecifier": "\\Process(_Total)\\Thread Count"
    },
    {
      "displayName": "Handles",
      "counterSpecifier": "\\Process(_Total)\\Handle Count"
    },
    {

      "displayName": "Memory usage",
      "counterSpecifier": "\\Memory\\% Committed Bytes In Use"
    },
    {
      "displayName": "Memory available",
      "counterSpecifier": "\\Memory\\Available Bytes"
    },
    {
      "displayName": "Memory committed",
      "counterSpecifier": "\\Memory\\Committed Bytes"
    },
    {
      "displayName": "Memory commit limit",
      "counterSpecifier": "\\Memory\\Commit Limit"
    },
    {
      "displayName": "Disk active time",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\% Disk Time"
    },
    {
      "displayName": "Disk active read time",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\% Disk Read Time"
    },
    {
      "displayName": "Disk active write time",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\% Disk Write Time"
    },
    {
      "displayName": "Disk operations",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Transfers/sec"
    },
    {
      "displayName": "Disk read operations",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Reads/sec"
    },
    {
      "displayName": "Disk write operations",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Writes/sec"
    },
    {
      "displayName": "Disk speed",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Bytes/sec"
    },
    {
      "displayName": "Disk read speed",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Read Bytes/sec"
    },
    {
      "displayName": "Disk write speed",
      "counterSpecifier": "\\PhysicalDisk(_Total)\\Disk Write Bytes/sec"
    },
    {
      "displayName": "Disk free space (percentage)",
      "counterSpecifier": "\\LogicalDisk(_Total)\\% Free Space"
    }
  ],
  "WindowsEventLog": [
    {
      "LogName": "Application",
      "LogLevel": "Application!*[System[(Level=1 or Level=2)]]"
    },
    {
      "LogName": "System",
      "LogLevel": "System!*[System[(Level=1 or Level=2)]]"
    }
  ]
} 
```

### Control Spec

> **Passed:**
> Diagnostic extension, default Performance counters should be present and event logs should be enabled.
>
> **Failed:**
> If any of the below condition is not satisfied:
> - Diagnostic extension should be present
> - Default Performance counters should be present
> - Event logs should be enabled.

### Recommendation

- Refer: https://learn.microsoft.com/en-us/cli/azure/vmss/diagnostics?view=azure-cli-latest&WT.mc_id=Portal-Microsoft_Azure_Security and while configuring or updating the diagnostic extention, default Performance counters and event logs should be configured."

### Azure Policies or REST APIs used for evaluation

- REST API to get all the extension related details:
  /subscriptions/{0}/resourceGroups/{1}/providers/Microsoft.Compute/virtualMachineScaleSets/{2}/extensions?api-version=2022-03-01 <br />
  **Properties:** properties.type, properties.provisioningState, name, properties.publisher,
  <br />

- REST API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01 <br />
  **Properties:** properties.storageProfile.osDisk.osType
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_AuthN_Enable_AAD_Auth_Windows

### Display Name
Azure AD extension must be deployed to Windows VMSS

### Rationale
Installing Azure AD extension on VMSS allows you to login into VMSS instances using Azure AD, making it possible to login user without password and improves authentication security.

### Control Settings {
    "Windows": {
        "ExtensionType": "AADLoginForWindows",
        "ExtensionPublisher": "Microsoft.Azure.ActiveDirectory",
        "ProvisioningState": "Succeeded"
    }
}
### Control Spec

> **Passed:**
> AAD extension present for Windows Virtual Machine Scale Set with provisioning state as succeeded.
>
> **Failed:**
> AAD extension is missing or provisioning state is not succeeded.
>
> **NotApplicable:**
> Operating System (OS) Linux type is not supported for the evaluation or Orchestration mode is not uniform.
>

### Recommendation

- **Azure Portal**

    To install AAD Extension in VMSS, Go to Azure Portal ? VMSS ? Settings ? Extensions+Applications ? Click Add ? Select AADLoginForWindows ? Click Next ? Click Review+Create.

### Azure Policies or REST APIs used for evaluation

- REST API to list VMSS extensions: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmssName}/extensions?api-version=2022-03-01<br />
**Properties:** properties.publisher, properties.type, properties.provisioningState<br />

<br />

___

## Azure_VirtualMachineScaleSet_DP_Enable_Encryption_At_Host

### Display Name
Virtual Machine Scale Set must enable encryption at host

### Rationale
Encryption at host provides an additional layer of encryption for VM disks, including temporary disks and ephemeral OS disks, enhancing data protection.

### Control Spec

> **Passed:**
> Encryption at host is enabled for VMSS.
>
> **Failed:**
> Encryption at host is not enabled for VMSS.
>

### Recommendation

- **Azure Portal**

    Enable encryption at host during VMSS creation or update existing VMSS through Azure Portal ? VMSS ? Disks ? Encryption at host ? Enable.

### Azure Policies or REST APIs used for evaluation

- REST API to get VMSS configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmssName}<br />
**Properties:** properties.virtualMachineProfile.securityProfile.encryptionAtHost<br />

<br />

___

## Azure_VirtualMachineScaleSet_Audit_Enable_DataCollectionRule

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

## Azure_VirtualMachineScaleSet_AuthN_Enable_AAD_Auth_Windows

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
