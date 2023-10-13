# AVD Host Pool

**Resource Type:** Microsoft.DesktopVirtualization/hostpools


<!-- TOC -->

- [Azure_AVD_Audit_Enable_HostPool_BootDiagnostics
](#azure_avd_audit_enable_hostpool_bootdiagnostics)
- [Azure_AVD_SI_Configure_HostPool_SecureBoot](#azure_avd_si_configure_hostpool_secureboot)
- [Azure_AVD_NetSec_Restrict_Public_InboundPort](#azure_avd_netsec_restrict_public_inboundport)

<!-- /TOC -->
<br/>

___ 

## Azure_AVD_Audit_Enable_HostPool_BootDiagnostics
 

### Display Name 
Boot Diagnostic must be enabled with Managed Storage Account on Azure AVD Host pool VMs.

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.


### Control Spec 

> **Passed:** 
>  Boot Diagnostic is enabled with Managed Storage Account on Azure AVD host pool VM.
> 
> **Failed:** 
> One of the following conditions is met:
>  - Boot Diagnostic is disabled on Azure AVD host pool VM.
>  - Boot Diagnostic is enabled with non-managed storage account on Azure AVD >host pool VM.

 
### Recommendation 

- **Azure Portal** 
    - To remediate: Go to Azure Portal --> Search Virtual Machine --> 'Help'  --> 'Boot diagnostics' settings --> 'Settings' --> Select 'Enable with managed storage account (recommended)' --> Click 'Save'.
      

### Azure Policies or REST APIs used for evaluation 

- ARM API used to list virtual machine and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01<br />
**Properties:**
properties.diagnosticsProfile.bootDiagnostics.enabled,<br />
properties.diagnosticsProfile.bootDiagnostics.storageUri
 <br />

___ 


## Azure_AVD_SI_Configure_HostPool_SecureBoot
 

### Display Name 
Azure AVD Host pool VMs should be of security type Trusted launch with Secure boot and vTPM enabled.

### Rationale 
Trusted launch protects against advanced and persistent attack techniques. It is composed of Secure boot, VTPM, Integrity monitoring technologies that can be enabled to Securely deploy virtual machines with verified boot loaders, OS kernels, and drivers and it helps to protect keys, certificates, and secrets in the virtual machine.

### Control Settings 
```json 
{
    "AllowedSecurityType": 
    [
        "TrustedLaunch"
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> All of the following conditions is met:
> - Security type is of type "TrustedLaunch" for Azure AVD host pool VM.
> - Secure boot is enabled for Azure AVD host pool VM.
> - vTPM is enabled for Azure AVD host pool VM.
> 
> **Failed:** 
> One of the following conditions is not met:
> - Security type is of type "TrustedLaunch" for Azure AVD host pool VM.
> - Secure boot is enabled for Azure AVD host pool VM.
> - vTPM is enabled for Azure AVD host pool VM.
 
### Recommendation 

- **Azure Portal** 
     - To remediate: Go to Azure Portal --> Search Virtual Machine --> 'settings'  --> 'Configuration' -->  Go to Security Type --> Mark the checkbox for 'Enable Secure boot'  and 'Enable vTPM'. --> select 'Save'. **NOTE**: Remediation is only possible if service type is 'Trusted Launch' otherwise create a new VM.
      

### Azure Policies or REST APIs used for evaluation 

- ARM API used to list virtual machine and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01<br />
**Properties:**
properties.securityProfile.securityType,<br />
properties.securityProfile.uefiSettings.secureBootEnabled, <br />
properties.securityProfile.uefiSettings.vTpmEnabled 
 <br />

___ 



## Azure_AVD_NetSec_Restrict_Public_InboundPort
 

### Display Name 
Public Inbound ports must be disabled on Azure AVD Host pool VMs.

### Rationale 
By default, access to the virtual machine is restricted to sources in the same virtual network, and traffic from Azure load balancing solutions.Open restricted ports expose a VM to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine.


### Control Spec 

> **Passed:** 
>   Public Inbound ports are disabled on Azure AVD host pool VMs.
> 
> **Failed:** 
> One of the following conditions is met:
>  - Public Inbound ports are enabled on Azure AVD host pool VMs.
>  - No NSG is configured on the Azure AVD host pool VMs.

 
### Recommendation 

- **Azure Portal** 
    - To delete the inbound rules: Go to Azure Portal --> Search Virtual Machine --> 'Networking'  --> 'Network settings'  --> 'Network security group'--> 'Inbound port rules' --> Delete all the rules except the default rules. List of Default Inbound rules: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#inbound.  If no NSG is configured follow: To add a new NSG: a.) Create a new NSG with only default inbound rules or use an exisiting NSG with only default. https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal#create-a-network-security-group b.) To add the NSG: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal#change-a-network-security-group
     
      

### Azure Policies or REST APIs used for evaluation 

- ARM API used to list virtual machine and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01<br />
**Properties:**
properties.networkProfile.networkInterfaces[\*].id<br />

- ARM API used to list NIC and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01<br />
**Properties:**
properties.ipConfigurations[\*].id<br />

- ARM API used to list NSG and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:**
id ,<br />
properties.securityRules<br />


___ 

