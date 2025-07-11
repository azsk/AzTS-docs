# ServiceFabric

**Resource Type:** Microsoft.ServiceFabric/clusters

<!-- TOC -->

- [Azure_ServiceFabric_AuthZ_Security_Mode_Enabled](#azure_servicefabric_authz_security_mode_enabled)
- [Azure_ServiceFabric_AuthN_Client_AuthN_Microsoft_Entra_ID_Only](#azure_servicefabric_authn_client_microsoft_entra_id_aad_only)
- [Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel](#azure_servicefabric_dp_set_property_clusterprotectionlevel)
- [Azure_ServiceFabric_AuthN_NSG_Enabled](#azure_servicefabric_authn_nsg_enabled)
- [Azure_ServiceFabric_Audit_Publicly_Exposed_Load_Balancer_Ports](#azure_servicefabric_audit_publicly_exposed_load_balancer_ports)
- [Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port](#azure_servicefabric_dp_dont_expose_reverse_proxy_port)
- [Azure_ServiceFabric_SI_Set_Auto_Update_Cluster](#azure_servicefabric_si_set_auto_update_cluster)
- [Azure_ServiceFabric_D_P_Dont_Have_Plaintext_Secrets](#azure_servicefabric_d_p_dont_have_plaintext_secrets)

<!-- /TOC -->
<br/>

___ 

## Azure_ServiceFabric_AuthZ_Security_Mode_Enabled 

### Display Name
Service Fabric cluster security must be enabled using security mode option 

### Rationale 
A secure cluster prevents unauthorized access to management operations, which includes deployment, upgrade, and deletion of microservices. Also provides encryption for node-to-node communication, client-to-node communication etc. In oppose to unsecured cluster which can be connected by any anonymous user. 

### Control Spec 

> **Passed:** 
> Service Fabric cluster is secured with certificate.
> 
> **Failed:** 
> Service Fabric cluster is not secured with certificate.
> 

### Recommendation 

- **Azure Portal** 

	 A secure cluster must be created to prevent unauthorized access to management operations (e.g., deployment, upgrade or deletion of microservices). A secure cluster also provides encryption for node-to-node communication, client-to-node communication, etc. An insecure cluster is open to be connected by any anonymous user. An insecure cluster cannot be secured at a later time. For creating a secure cluster using (1) Azure Portal, refer: https://azure.microsoft.com/en-in/documentation/articles/service-fabric-cluster-creation-via-portal/#_3-security or using (2) ARM template refer:https://azure.microsoft.com/en-in/documentation/articles/service-fabric-cluster-creation-via-arm/ 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

-->

### Azure Policies or REST APIs used for evaluation 

- REST API to get certificate details of Service Fabric resource: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** properties.certificate
 <br />

<br />

___ 

## Azure_ServiceFabric_AuthN_Client_AuthN_Microsoft_Entra_ID_Only 

### Display Name 
Use Microsoft Entra ID (formerly AAD) for client authentication on Service Fabric clusters 

### Rationale 
Using the native enterprise directory for authentication ensures that there is a built-in high level of assurance in the user identity established for subsequent access control. All Enterprise subscriptions are automatically associated with their enterprise directory (xxx.onmicrosoft.com) and users in the native directory are trusted for authentication to enterprise subscriptions. 

### Control Spec 

> **Passed:** 
> Entra ID (formerly AAD) authentication is enabled.
> 
> **Failed:** 
> Entra ID (formerly AAD) authentication is not enabled.
> 

### Recommendation 

- **Azure Portal** 

	 A Service Fabric cluster offers several entry points to its management functionality, including the web-based Service Fabric Explorer, Visual Studio and PowerShell. Access to the cluster must be controlled using Microsoft Entra ID (formerly AAD). Refer: https://docs.microsoft.com/en-in/azure/service-fabric/service-fabric-cluster-creation-setup-aad 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

-->

### Azure Policies or REST APIs used for evaluation 

- REST API to get Azure Active Directory details and its related property: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** property.azureActiveDirectory.tenantId
 <br />

<br />

___ 

## Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel 

### Display Name 
The ClusterProtectionLevel property must be set to EncryptAndSign for Service Fabric clusters

### Rationale 
With cluster protection level set to 'EncryptAndSign', all the node-to-node messages are encrypted and digitally signed. This protects the intra-cluster communication from eavesdropping/tampering/man-in-the-middle attacks on the network. 

### Control Spec

> **Passed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the Service Fabric cluster as `Healthy`. (or) Cluster protection level is set to "EncryptAndSign"
>
> **Failed:**
> Microsoft Defender for Cloud (MDC) reports the assessment status for the Service Fabric cluster as either `Unhealthy`, or `NotApplicable` with `cause` - `OffByPolicy` or `Exempt`. (or) Cluster protection level is not set to "EncryptAndSign"
>
> **Note:** If no Microsoft Defender for Cloud (MDC) assessment is found for the Service Fabric cluster, response from the ARM API is considered for the evaluation.


### Recommendation

- **Azure Portal** 

    Go to the Service Fabric Cluster resource > Settings > Custom fabric settings > Edit the parameter - 'ClusterProtectionLevel' (add, if absent). Set its value to 'EncryptAndSign'. > Save.

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

-->

### Azure Policies or REST APIs used for evaluation

- Azure Policy (built-in): [Service Fabric clusters should have the ClusterProtectionLevel property set to EncryptAndSign](https://portal.azure.com/#blade/Microsoft_Azure_Policy/PolicyDetailBlade/definitionId/%2Fproviders%2FMicrosoft.Authorization%2FpolicyDefinitions%2F617c02be-7f02-4efd-8836-3180d47b6c68)

- REST API to get cluster protection level: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** property.fabricSettings.ClusterProtectionLevel.value
 <br />

<br />

___ 

## Azure_ServiceFabric_AuthN_NSG_Enabled 

### Display Name 
Enable Firewall/NSGs on subnet of Service Fabric cluster 

### Rationale 
Use of appropriate NSG rules can limit exposure of Service Fabric cluster in multiple scenarios. For example, RDP connections can be restricted only for specific admin machines. Incoming requests to microservices may be restricted to specific clients. Also, deployments can be restricted to happen only from an allowed range of IP addresses. 

### Control Settings 
```json 
{
    "RestrictedPorts": "445,3389,5985,22"
}
 ```  

### Control Spec 

> **Passed:** 
> NSG is configured with no restricted ports (e.g. RDP 3389, SMB 445 etc.) open using NSG rules.
> 
> **Failed:** 
> NSG is not configured or any restricted ports (e.g. RDP 3389, SMB 445 etc.) are open using NSG rules.
> 
> **Verify:** 
> No linked Virtual machine scale set (VMSS) node found.
> 
### Recommendation 

- **Azure Portal** 

	 NSG contains a list of Access Control List (ACL) rules that allow or deny network traffic to Service Fabric node instances in a Virtual Network. NSGs can be associated with either subnets or individual node/VM instances within a subnet. NSG must be used in following scenarios: (1) Restrict RDP connection only from admin machine IP, (2) Restrict microservice incoming request from trusted source IP, (3) Lock down the remote address ranges allowed for microservice deployments. Refer: https://azure.microsoft.com/en-in/documentation/articles/virtual-networks-create-nsg-arm-pportal/ 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

--> 

### Azure Policies or REST APIs used for evaluation 

- REST API to list Service Fabric cluster resources at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** properties.nodeTypes[*].name
 <br />

- REST API to list Virtual Machine scale sets at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Compute/virtualMachineScaleSets?api-version=2019-07-01 <br />
**Properties:** properties.virtualMachineProfile.networkProfile.
networkInterfaceConfigurations[*].properties.ipConfigurations[*]
.properties.subnet.id, tags
 <br />

- REST API to list Virtual Networks at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/virtualNetworks?api-version=2019-11-01 <br />
**Properties:** properties.networkSecurityGroup.id
 <br />

- REST API to list Network Security Groups at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/networkSecurityGroups?api-version=2019-04-01 <br />
**Properties:** properties.destinationPortRange, properties.destinationPortRanges

 <br/>

 <br />


___ 

## Azure_ServiceFabric_Audit_Publicly_Exposed_Load_Balancer_Ports 

### Display Name 
Monitor publicly exposed ports on load balancers used by Service Fabric cluster 

### Rationale 
Publicly exposed ports must be monitored to detect suspicious and malicious activities early and respond in a timely manner. 

### Control Settings 
```json 
{
    "RestrictedPorts": [
        19000,
        19080,
        445,
        3389,
        5985,
        22
    ]
}
 ```  

### Control Spec 

> **Passed:** 
> NSG is configured with no restricted ports (e.g. RDP 3389, SMB 445 etc.) open using NSG rules.
> 
> **Failed:** 
> NSG is not configured or any restricted ports (e.g. RDP 3389, SMB 445 etc.) are open using NSG rules.
> 
> **Error:** 
> Restricted port list not defined against control settings.
> 
> **Verify**
> No load balancer rules found on service fabric
> 
### Recommendation 

- **Azure Portal** 

	 Azure load balancer maps the public IP address and port number of incoming traffic to the private IP address and port number of the Service Fabric nodes (ports number opened by microservices). Intranet microservice ports must not be exposed to the internet. Moreover, publicly exposed IP address/port numbers must be monitored using Azure load balancer rules as follows: Azure Portal --> Load Balancers --> <Load Balancer Name> --> Load Balancing Rules --> Validate mapping of public end port with backend port. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

-->

### Azure Policies or REST APIs used for evaluation 

- REST API to list Load Balancer Rules at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01 <br />
**Properties:** properties.loadBalancingRules.BackendPort
 <br />

<br />

___ 

## Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port

### Display Name
Reverse proxy port must not be exposed publicly for Service Fabric clusters

### Rationale
Configuring the reverse proxy's port in Load Balancer with public IP will expose all microservices with HTTP endpoint. Microservices meant to be internal may be discoverable by a determined malicious user.

### Control Spec

> **Passed:**
>   <br>
>   One of the following conditions are true:
>   - No reverse proxy found.
>   - No load balancer found on the Service Fabric cluster.
>   - No load balancer rules found on the Service Fabric cluster.
>   - Reverse proxy is not exposed using load balancer.
>
> **Failed:**
>   <br>
>   Reverse proxy on one or more nodes is exposed using a public load balancer on the Service Fabric cluster.
>
### Recommendation

- **Azure Portal**

    Check that reverse proxy port is not exposed through Azure Load Balancer rules as follows: Azure Portal --> Load Balancers --> \<Load Balancer Name\> --> Load Balancing Rules (Under 'Settings') --> Validate reverse proxy port is not exposed.

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

- REST API to get reverse proxy details at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** properties.nodeTypes.reverseProxyEndpointPort
 <br />

- REST API to list Load Balancer Rules at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.Network/loadBalancers?api-version=2019-12-01<br />
**Properties:** properties.loadBalancingRules.BackendPort
 <br />

<br />

___ 

## Azure_ServiceFabric_SI_Set_Auto_Update_Cluster 

### Display Name 
Upgrade mode should be set to automatic for cluster 

### Rationale 
Clusters with unsupported fabric version can become targets for compromise from various malware/trojan attacks that exploit known vulnerabilities in software. 

### Control Spec 

> **Passed:** 
> Upgrade mode for cluster is set to automatic
> 
> **Failed:** 
> Upgrade mode for cluster is set to manual
> 
### Recommendation 

- **Azure Portal** 

	 You can set your cluster to receive automatic fabric upgrades as they are released by Microsoft, for details please refer: https://docs.microsoft.com/en-us/azure/service-fabric/service-fabric-cluster-upgrade 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 
--> 

### Azure Policies or REST APIs used for evaluation 

- REST API to get status of upgrade mode at subscription level: /subscriptions/{subscriptionId}/providers/Microsoft.ServiceFabric/clusters?api-version=2018-02-01 <br />
**Properties:** properties.UpgradeMode
 <br />

<br />

___ 


## Azure_ServiceFabric_DP_Dont_Have_Plaintext_Secrets

### Display Name
Service Fabric cluster configuration should not contain plaintext secrets

### Rationale
Storing secrets such as passwords, connection strings, or keys in plaintext within Service Fabric cluster configurations exposes sensitive data to potential compromise. Attackers or unauthorized users with access to configuration files or parameters could retrieve these secrets, leading to data breaches or unauthorized access to resources. Using secure mechanisms like Azure Key Vault or encrypted parameters helps ensure that secrets are protected at rest and in transit, supporting compliance with industry standards and regulatory frameworks (such as ISO 27001, SOC 2, and PCI DSS).

### Control Spec

> **Passed:**
> - No plaintext secrets (such as passwords, connection strings, or keys) are present in Service Fabric cluster configuration settings.
> - All sensitive values are referenced securely, e.g., via Azure Key Vault references or encrypted parameters.
>
> **Failed:**
> - Any plaintext secret is found in the Service Fabric cluster configuration, including in application parameters, diagnostics settings, or custom configuration sections.

### Recommendation

- **Azure Portal**
    1. Navigate to your Service Fabric cluster in the Azure Portal.
    2. Under **Settings**, select **Configuration**.
    3. Review all configuration sections (including diagnostics, application parameters, and custom settings) for any plaintext secrets.
    4. Replace any plaintext secrets with references to Azure Key Vault secrets or use encrypted parameters.
    5. Save and apply the updated configuration.

- **PowerShell**
    ```powershell
    # Example: Update a Service Fabric cluster configuration to use a Key Vault reference
    $clusterName = "<your-cluster-name>"
    $resourceGroup = "<your-resource-group>"
    $configFile = "<path-to-updated-config.json>"

    # Update the cluster configuration with secure references
    Set-AzServiceFabricCluster -ResourceGroupName $resourceGroup -Name $clusterName -ClusterConfigPath $configFile
    ```

- **Azure CLI**
    ```bash
    # Example: Update Service Fabric cluster configuration using Azure CLI
    az sf cluster upgrade-type set \
      --resource-group <your-resource-group> \
      --cluster-name <your-cluster-name> \
      --upgrade-mode Automatic

    # Use az keyvault secret set to store secrets securely and reference them in your configuration
    az keyvault secret set --vault-name <your-keyvault-name> --name <secret-name> --value <secret-value>
    ```

- **Automation/Remediation**
    - Use Azure Policy to audit and deny deployments that include plaintext secrets in Service Fabric cluster configurations.
    - Implement CI/CD pipeline checks to scan configuration files for plaintext secrets before deployment.
    - Use Azure Key Vault integration with Service Fabric to securely reference secrets in configuration files.
    - For bulk remediation, script scanning of all Service Fabric cluster configurations in your subscription for plaintext secrets and automate replacement with Key Vault references.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ServiceFabric/clusters/{clusterName}?api-version=2021-06-01`
  <br />
  **Properties:** `properties.fabricSettings`, `properties.diagnostics`, `properties.applicationParameters`
- Azure Policy: Custom policy definitions can be used to audit for plaintext secrets in configuration fields.

<br/>

___
