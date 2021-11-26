# NSG

**Resource Type:** Microsoft.Network/networkSecurityGroups 

___ 

## Azure_NSG_NetSec_Dont_Open_Restricted_Ports 

### DisplayName 
Do not use risky ports on firewall and NSGs 

### Rationale 
Open restricted ports expose a NSG to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine. 

### Control Settings 
```json 
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "databricks-environment",
            "TagValue": "true"
        },
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "application",
            "TagValue": "databricks"
        }
    ],
    "RestrictedPorts": "445,3389,5985,22"
}
 ```  

### Control Spec 

> **Passed:** 
> 1. If no restricted port [445,3389,5985,22] found.
> 2. If Any-Any inbound rule not found.
> 
> **Failed:** 
> 1. If restricted port found.
> 2. If Any-Any inbound rule found.
> 
> **NotApplicable:** 
> This Control does not apply to NSGs associated with VMs in a ADB cluster.
> 
> **Error:**
> Restricted ports list in control settings not configured properly
>
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> NSG Settings --> Inbound security rules --> Select security rule which allows management ports (e.g. RDP-3389, WINRM-5985, SSH-22, SMB-445) --> Click 'Deny' under Action --> Click Save. 

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

- ARM API to list open ports in the NSG at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:** properties.direction, properties.access, properties.destinationPortRange<br />

<br />

___ 

## Azure_NSG_NetSec_Dont_Open_InBound_Any_Any 

### DisplayName 
Firewall/NSG rules must not allow unrestricted traffic (any-any rule) 

### Rationale 
Open restricted ports expose a NSG to a high level of risk from internet-based attacks that attempt to brute force credentials to gain admin access to the machine. 

### Control Settings 
```json 
{
    "ExclusionTags": [
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "databricks-environment",
            "TagValue": "true"
        },
        {
            "Desciption": "VM is part of ADB cluster.",
            "TagName": "application",
            "TagValue": "databricks"
        }
    ],
    "UniversalPortRange": [
        "*",
        "0-65535"
    ],
    "ValidRules": [
        {
            "NonCompliantSourceAddressPrefixes": [
                "*",
                "Internet"
            ],
            "Protocol": "ICMP"
        }
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> If Any-Any inbound port not found
> 
> **Failed:** 
> If Any-Any inbound port found
> 
> **NotApplicable:** 
> This Control does not apply to NSGs associated with VMs in a ADB cluster.
>
### Recommendation 

- **Azure Portal** 

	 Go to Azure Portal --> NSG Settings --> Inbound security rules --> Select security rule which allows Any-Any inbound port --> Click 'Deny' under Action --> Click Save. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
-->

### Azure Policy or ARM API used for evaluation 

- ARM API to list all the inbound rules in Network Security Groups at subscription level: - /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01<br />
**Properties:** properties.direction, properties.access <br />

<br />

___ 

