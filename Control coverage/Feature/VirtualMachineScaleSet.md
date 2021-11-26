# VirtualMachineScaleSet

**Resource Type:** Microsoft.Compute/virtualMachineScaleSets

___

## Azure_VirtualMachineScaleSet_Audit_Enable_Diagnostics

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extensions
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_Config_Enable_NSG

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to get all the public IPs for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/publicipaddresses?api-version=2019-07-01
  <br />
  **Properties:** properties.ipAddress
  <br />
  <br />

- ARM API to list all the VMSS configurations under the specified subscription::
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.networkSecurityGroup, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_Deploy_Monitoring_Agent

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extensions
  <br />
  <br />

___

## Azure_VirtualMachineScaleSet_NetSec_Dont_Open_Management_Ports

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.networkSecurityGroup, properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
 <br />
 
- ARM API to list all the NSG configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01
  <br />
  **Properties:** properties.securityRules.properties.destinationPortRange
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_NetSec_Justify_PublicIPs

### DisplayName
Public IPs on a Virtual Machine Scale Set instances should be carefully reviewed.

### Rationale
Public IPs provide direct access over the internet exposing the VMSS instance to attacks over the public network. Hence each public IP on a VMSS instance must be reviewed carefully.

### Control Spec

> **Passed:**
> No Public IP is associated with VMSS or VMSS has Public IP is associated with it but its not part of ExpressRoute connected virtual network.
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.virtualMachineProfile.networkProfile.networkInterfaceConfigurations.properties.ipConfigurations.properties.subnet
  <br />
 <br />

 - ARM API to get all the public IPs for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/publicipaddresses?api-version=2019-07-01
  <br />
  **Properties:** properties.ipAddress
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Enable_Antimalware

### DisplayName
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
            "Desciption": "VM is part of AKS cluster.",
            "TagName": "orchestrator",
            "TagValue": "kubernetes"
        },
        {
            "Desciption": "VM is part of Service Fabric.",
            "TagName": "resourcetype",
            "TagValue": "service fabric"
        }
    ]
}
 ``` 

### Control Spec

> **Passed:**
> Antimalware Malware extension is deployed at VMSS model and all it's VM instances with Auto Upgrade to minor version enabled and Realtime protection enabled
>
> **Failed:**
> AntiMalware extension is not deployed at VMSS model or at one or more VM instances or AntiMalware extension is present but Auto Upgrade to minor version is disabled or AntiMalware extension is present but Auto Realtime protection is disabled.
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
  
  Please refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-faq#how-do-i-turn-on-antimalware-in-my-virtual-machine-scale-set

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

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.storageProfile.osDisk.osType, properties.virtualMachineProfile.extensionProfile.extension
  <br />
 <br />
 
- ARM API to get all the VM instances for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/virtualMachines?api-version=2019-07-01
  <br />
  **Properties:** instance.resources (Microsoft.Compute/virtualMachines/extensions)
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Enable_Auto_OS_Upgrade

### DisplayName
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

- To configure auto OS image upgarde on VM Scale Set, refer: https://docs.microsoft.com/en-us/azure/virtual-machine-scale-sets/virtual-machine-scale-sets-automatic-upgrade

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

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.upgradePolicy.automaticOSUpgradePolicy.enableAutomaticOSUpgrade
  <br />
 <br />
 
___

## Azure_VirtualMachineScaleSet_SI_Latest_Model_Applied

### DisplayName
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

### Azure Policy or ARM API used for evaluation

- ARM API to list all the VMSS configurations under the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.upgradePolicy.mode
  <br />
 <br />
 
- ARM API to get all the VM instances for the specified VMSS:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{resourceName}/virtualMachines?api-version=2019-07-01
  <br />
  **Properties:** instance.properties.latestModelApplied
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Missing_OS_Patches

### DisplayName
System updates on virtual machine scale sets must be installed.

### Rationale
Un-patched VMSSs are easy targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in operating systems and related software.

### Control Spec

> **Passed:**
> ASC assessment found with Healthy status code.
>
> **Failed:**
> ASC assessment found with Unhealthy status code.
>
> **Verify:**
> Not Applicable.
>
> **NotApplicable:**
> Not Applicable.
>

### Recommendation

- Refer: https://docs.microsoft.com/en-us/azure/security-center/security-center-apply-system-updates. It takes 24 hours to reflect the latest status at ASC.

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

- ARM API to fetch all the security assessment for the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
  <br />
  **Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_SI_Remediate_Security_Vulnerabilities

### DisplayName
Vulnerabilities in security configuration on your virtual machine scale sets must be remediated.

### Rationale
Known OS/framework vulnerabilities in a system can be easy targets for attackers. An attacker can start by compromising such a vulnerability and can eventually compromise the security of the entire network. A vulnerability assessment solution can help to detect/warn about vulnerabilities in the system and facilitate addressing them in a timely manner.

### Control Spec

> **Passed:**
> ASC assessment found with Healthy status code.
>
> **Failed:**
> ASC assessment found with Unhealthy status code.
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

### Azure Policy or ARM API used for evaluation

- ARM API to fetch all the security assessment for the specified subscription:
  /subscriptions/{subscriptionId}/providers/Microsoft.Security/assessments?api-version=2020-01-01
  <br />
  **Properties:** id, name, resourceDetails.Id, displayName, status.code, status, additionalData
  <br />
 <br />

___

## Azure_VirtualMachineScaleSet_DP_Enable_Disk_Encryption

### DisplayName
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
> Azure disk encryption extension is installed and existing disks (OS and Data) are encrypted.
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

### Azure Policy or ARM API used for evaluation

- ARM API to get configuration of a Virtual Machine Scale Set:
  /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01
  <br />
  **Properties:** properties.virtualMachineProfile.extensionProfile.extensions[\*].type, properties.virtualMachineProfile.extensionProfile.extensions.[\*].provisioningState
  <br />
 <br />
 
- ARM API to get instance view of Virtual Machines in a Virtual Machine Scale Set:
  /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.Compute/virtualMachineScaleSets/{vmScaleSetName}/virtualmachines/{instanceId}/instanceView?api-version=2021-03-01
  <br />
  **Properties:** disks.statuses[*].code
  <br />
 <br />

___