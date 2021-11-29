# HDInsight

**Resource Type:** Microsoft.HDInsight/clusters

<!-- TOC -->

- [Azure_HDInsight_Deploy_Supported_Cluster_Version](#azure_hdinsight_deploy_supported_cluster_version)
- [Azure_HDInsight_NetSec_Restrict_Cluster_Network_Access](#azure_hdinsight_netsec_restrict_cluster_network_access)
- [Azure_HDInsight_DP_Use_Secure_TLS_Version](#azure_hdinsight_dp_use_secure_tls_version)

<!-- /TOC -->
<br/>

___ 

## Azure_HDInsight_Deploy_Supported_Cluster_Version 

### DisplayName 
HDInsight must have supported HDI cluster version 

### Rationale 
Being on the latest/supported HDInsight version significantly reduces risks from security bugs or updates that may be present in older or retired cluster versions. 

### Control Settings 
```json 
{
    "MinRequiredClusterVersion": "3.6.0"
}
 ```  

### Control Spec 

> **Passed:** 
> Cluster version is greater or equal to minimum required version.
> 
> **Failed:** 
> Cluster version is less than minimum required version.
> 
> **Error:** 
> Minimum required version is not defined in control settings.
> 
### Recommendation 

- **Azure Portal** 

	 Refer: https://docs.microsoft.com/en-us/azure/hdinsight/hdinsight-component-versioning?#supported-hdinsight-versions https://docs.microsoft.com/en-us/azure/hdinsight/hdinsight-upgrade-cluster 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to lists all the HDInsight clusters under the subscription: /subscriptions/{subscriptionId}/providers/Microsoft.HDInsight/clusters?api-version=2018-06-01-preview <br />
**Properties:** properties.clusterVersion
 <br />

<br />

___ 

## Azure_HDInsight_NetSec_Restrict_Cluster_Network_Access 

### DisplayName 
HDInsight cluster access must be restricted using virtual network or Azure VPN gateway service with NSG traffic rules 

### Rationale 
Restricting cluster access with inbound and outbound traffic via NSGs limits the network exposure for cluster and reduces the attack surface. 

### Control Spec 

> **Passed:** 
> All roles contain a VirtualNetworkProfile.
> 
> **Failed:** 
> One or more roles does not contain VirtualNetworkProfile.
> 
> **Error:** 
> HD Insight cluster roles were not found.
> 
### Recommendation 

- **Azure Portal** 

	 You should restrict IP range and port as per application needs. Refer: https://docs.microsoft.com/en-us/azure/hdinsight/hdinsight-extend-hadoop-virtual-network. Note: In case the IP range is indeterminate (for instance, if the client is a PaaS endpoint), you may need to attest this control. 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```  

- **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to lists all the HDInsight clusters under the subscription: /subscriptions/{subscriptionId}/providers/Microsoft.HDInsight/clusters?api-version=2018-06-01-preview <br />
**Properties:** properties.computeProfile
 <br />

<br />

___ 

## Azure_HDInsight_DP_Use_Secure_TLS_Version 

### DisplayName 
Use approved version of TLS for HDInsight cluster 

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
> Current TLS version of HDInsight cluster is set to either equal or greater than the required minimum TLS version.
> 
> **Failed:** 
> Current TLS version of HDInsight cluster is less than the required minimum TLS version.
> 
> **Error:** 
> Required minimum TLS version is not set properly in control settings.
> 

### Recommendation 

- **Azure Portal** 

	 The TLS setting can only be configured during cluster creation using either the Azure portal, or a Resource Manager template. Refer : https://docs.microsoft.com/en-us/azure/hdinsight/transport-layer-security 

<!-- - **PowerShell** 

	 ```powershell 
	 $variable = 'apple' 
	 ```   -->

<!-- - **Enforcement Policy** 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/View_Definition.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>) 

	 [![Link to Azure Policy](https://raw.githubusercontent.com/MSFT-Chirag/AzTS-docs/main/Assets/Deploy_To_Azure.jpg)](https://portal.azure.com/#blade/Microsoft_Azure_Policy/CreatePolicyDefinitionBlade/uri/<policy-raw-link>)  -->

### Azure Policy or ARM API used for evaluation 

- ARM API to lists all the HDInsight clusters under the subscription: /subscriptions/{subscriptionId}/providers/Microsoft.HDInsight/clusters?api-version=2018-06-01-preview <br />
**Properties:** properties.minSupportedTlsVersion
 <br />

<br />

___ 

