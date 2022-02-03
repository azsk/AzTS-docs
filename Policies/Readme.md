# Azure Policy for Azure Tenant Security Solution controls

Azure Policy helps to enforce organizational standards. It also helps to bring your resources to compliance through bulk remediation for existing resources and automatic remediation for new resources. Azure Policy can also be used to keep resources compliant as per Azure Tenant Security Solution controls requirements. It can be used to: 
1. Disallow creation of new non-compliant resources or auto remediation of new resources 
2. Remediate existing non-compliant resources

## AzTS controls with available Azure Policy definition

The following are the AzTS controls for which Azure policy definitions are available to keep resources compliant as per controls requirements:

1. [Azure_APIManagement_DP_Use_HTTPS_URL_Scheme](APIManagement/Azure_APIManagement_DP_Use_HTTPS_URL_Scheme/Readme.md)
2. [Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server](SQLServer/Azure_SQLDatabase_Audit_Enable_Threat_Detection_Server/Readme.md)
3. [Azure_SQLDatabase_DP_Enable_TDE](SQLServer/Azure_SQLDatabase_DP_Enable_TDE/Readme.md)
4. [Azure_Storage_DP_Encrypt_In_Transit](Storage/Azure_Storage_DP_Encrypt_In_Transit/Readme.md)
5. [Azure_Subscription_SI_Classic_Resources](Subscription/Azure_Subscription_SI_Classic_Resources/Readme.md)
6. [Azure_ContainerRegistry_Congif_Security_Scanning](ContainerRegistry/Azure_ContainerRegistry_Congif_Security_Scanning/Readme.md)

## Using Azure policy to bring your resources to compliance

In this section, we will walk you through the steps to use Azure Policy to keep your resources compliant:

**Step 1:** Access the Azure Policy rule for the AzTS controls from the links mentioned in the section [above](#azts-controls-with-available-azure-policy-definition).

**Step 2:** Create new custom policy definition. To create the new custom policy, please follow the steps mentioned [here](https://docs.microsoft.com/en-us/azure/governance/policy/tutorials/create-and-manage#implement-a-new-custom-policy). In the policy rule section, provide the content obtained from step #1.

**Step 3:** Assign a policy. Once the policy definition is created, next step is to assign the policy definition. Please follow the steps mentioned [here](https://docs.microsoft.com/en-us/azure/governance/policy/tutorials/create-and-manage#assign-a-policy) to assign a policy definition. In the 'Policy definition' selection step, search and select the custom policy definition created in step #2. 
