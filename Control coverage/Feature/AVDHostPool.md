# AVD Host Pool

**Resource Type:** Microsoft.DesktopVirtualization/hostpools


<!-- TOC -->

- [Azure_AVD_Audit_Enable_HostPool_BootDiagnostics
](#azure_avd_audit_enable_hostpool_bootdiagnostics)
- [Azure_AVD_SI_Configure_HostPool_SecureBoot](#azure_avd_si_configure_hostpool_secureboot)
- [Azure_AVD_NetSec_Restrict_Public_InboundPort](#azure_avd_netsec_restrict_public_inboundport)
- [Azure_AVD_Audit_Enable_HostPool_Diagnostic_Settings](#azure_avd_audit_enable_hostpool_diagnostic_settings)
- [Azure_AVD_NetSec_Restrict_Public_IPs](#azure_avd_netsec_restrict_public_ips)
- [Azure_AVD_NetSec_Dont_Allow_Public_Network_Access](#azure_avd_netsec_dont_allow_public_network_access)

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
    - To remediate: Go to Azure Portal --> Search Virtual Machine --> 'Help'  --> 'Boot diagnostic' settings --> 'Settings' --> Select 'Enable with managed storage account (recommended)' --> Click 'Save'.
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list virtual machine and its related properties at Subscription level: <br />
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

### Control Settings {
    "AllowedSecurityType": 
    [
        "TrustedLaunch"
    ]
} 

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

- REST API used to list virtual machine and its related properties at Subscription level: <br />
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
> Public Inbound ports are disabled on Azure AVD host pool VMs.
> 
> **Failed:** 
> One of the following conditions is met:
>  - Public Inbound ports are enabled on Azure AVD host pool VMs.
>  - No NSG is configured on the Azure AVD host pool VMs.

 
### Recommendation 

- **Azure Portal** 
    - To delete the inbound rules: Go to Azure Portal --> Search Virtual Machine --> 'Networking'  --> 'Network settings'  --> 'Network security group'--> 'Inbound port rules' --> Delete all the rules except the default rules. List of Default Inbound rules: https://learn.microsoft.com/en-us/azure/virtual-network/network-security-groups-overview#inbound.  If no NSG is configured follow: To add a new NSG: a.) Create a new NSG with only default inbound rules or use an exisiting NSG with only default. https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal#create-a-network-security-group b.) To add the NSG: https://learn.microsoft.com/en-us/azure/virtual-network/manage-network-security-group?tabs=network-security-group-portal#change-a-network-security-group
     
      

### Azure Policies or REST APIs used for evaluation 

- REST API used to list virtual machine and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachines?api-version=2023-03-01<br />
**Properties:**
properties.networkProfile.networkInterfaces[\*].id<br />

- REST API used to list NIC and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkInterfaces?api-version=2019-04-01<br />
**Properties:**
properties.ipConfigurations[\*].id<br />

- REST API used to list NSG and its related properties at Subscription level: <br />
/subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:**
id ,<br />
properties.securityRules<br />


___ 

## Azure_AVD_Audit_Enable_HostPool_Diagnostic_Settings
 

### Display Name 
Diagnostic logs must be enabled for AVD Host pool VMs.

### Rationale 
Logs should be retained for a long enough period so that activity trail can be recreated when investigations are required in the event of an incident or a compromise. A period of 1 year is typical for several compliance requirements as well.


### Control Settings {
    "DiagnosticForeverRetentionValue": "0",
    "DiagnosticMinRetentionPeriod": "365",
    "DiagnosticLogs": [
        "Checkpoint",
        "Error",
        "Management"
    ]
} 

### Control Spec 

> **Passed:** 
> Diagnostic settings should meet the following conditions:
>   1. Diagnostic logs are enabled.
>   2. At least one of the below logs destination is configured:
>       a. Log Analytics.
>       b. Storage account with min Retention period of 365 or forever(Retention period 0).
>       c. Event Hub.
> 
> **Failed:** 
> If any of the below conditions are meet:
>   1. Diagnostic settings should meet the following conditions:
>       a. All diagnostic logs are not enabled.
>       b. No logs destination is configured:
>          i. Log Analytics.
>          ii. Storage account (with min Retention period of 365 or forever(Retention period 0).
>          iii. Event Hub.
>   2. Diagnostics settings is disabled for resource.

 
### Recommendation 

- **Azure Portal** 
    - You can change the diagnostic settings from the Azure Portal by following the steps given here: https://docs.microsoft.com/en-us/azure/azure-monitor/essentials/diagnostic-settings
      

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




## Azure_AVD_NetSec_Restrict_Public_IPs
 

### Display Name 
Public IPs must not be open on AVD Host pool VMs.

### Rationale 
Public IPs provide direct access over the internet exposing the VM to attacks over the public network. Hence AVD Host pool VMs must not be accessible to any public IPs.


### Control Spec 

> **Passed:** 
> Public IPs are disabled on Azure AVD host pool VMs.
> 
> **Failed:** 
> Public IPs are enabled on Azure AVD host pool VMs.

 
### Recommendation 

- **Azure Portal** 
    - To delete the Public IPs: Go to Azure Portal --> VM --> VM Settings --> Networking --> Network Interfaces --> <Select NIC> --> IP Configurations --> <Select IP Configs with Public IP> --> Click 'Disabled' --> Save. Refer: https://docs.microsoft.com/en-us/azure/virtual-network/virtual-network-public-ip-address
     
      

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

## Azure_AVD_NetSec_Dont_Allow_Public_Network_Access

### Display Name
Azure Virtual Desktop must not allow public network access

### Rationale
Restricting public network access to Azure Virtual Desktop resources reduces the attack surface and ensures that access is only allowed from authorized networks through private connectivity.

### Control Spec

> **Passed:**
> Public network access is disabled for AVD resources.
>
> **Failed:**
> Public network access is enabled for AVD resources.
>

### Recommendation

- **Azure Portal**

    Go to Azure Virtual Desktop ? Networking ? Public network access ? Select "Disabled" ? Configure private endpoints and virtual network integration for secure access.

### Azure Policies or REST APIs used for evaluation

- REST API to check AVD configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.DesktopVirtualization/hostpools/{hostPoolName}<br />
**Properties:** properties.publicNetworkAccess<br />

<br />

___