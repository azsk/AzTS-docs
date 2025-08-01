# ContainerInstance

**Resource Type:** Microsoft.ContainerInstance/containerGroups

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ContainerInstance_DP_Avoid_Plaintext_Secrets](#azure_containerinstance_dp_avoid_plaintext_secrets)

<!-- /TOC -->
<br/>

___

## Azure_ContainerInstance_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure Container Instance environment variables

### Rationale
Storing sensitive information such as passwords, connection strings, or API keys in plaintext within environment variables exposes them to potential compromise. Anyone with access to the container definition or runtime environment can retrieve these secrets. Using secure mechanisms like Azure Key Vault or Kubernetes secrets ensures that sensitive data is encrypted at rest and only accessible by authorized workloads, reducing the risk of data leakage and supporting compliance with standards such as ISO 27001, PCI DSS, and SOC 2.

### Control Spec

> **Passed:**  
> No sensitive information (e.g., passwords, keys, connection strings) is stored in plaintext within environment variables in Azure Container Instance definitions. Secrets are referenced securely using Azure Key Vault or other secret management solutions.
>
> **Failed:**  
> Sensitive information is found in plaintext within environment variables in Azure Container Instance definitions.

### Recommendation

- **Azure Portal**
    1. Navigate to **Container Instances** in the Azure Portal.
    2. Select the relevant container group.
    3. Under **Settings**, select **Containers** and review the **Environment variables** section.
    4. Remove any sensitive information (such as passwords, keys, or connection strings) from environment variables.
    5. Store secrets in [Azure Key Vault](https://learn.microsoft.com/azure/key-vault/general/basic-concepts) and reference them securely in your application code.

- **PowerShell**
    ```powershell
    # Example: Remove sensitive environment variable from a container group
    $resourceGroup = "<ResourceGroupName>"
    $containerGroup = "<ContainerGroupName>"
    $containerGroupObj = Get-AzContainerGroup -ResourceGroupName $resourceGroup -Name $containerGroup

    # Remove or update environment variables containing secrets
    $containerGroupObj.Containers[0].EnvironmentVariables = $containerGroupObj.Containers[0].EnvironmentVariables | Where-Object { $_.Name -notin @('SECRET_PASSWORD', 'API_KEY') }

    # Update the container group
    Set-AzContainerGroup -ResourceGroupName $resourceGroup -Name $containerGroup -Container $containerGroupObj.Containers
    ```

- **Azure CLI**
    ```bash
    # Remove sensitive environment variable by updating the container group definition
    az container create \
      --resource-group <ResourceGroupName> \
      --name <ContainerGroupName> \
      --image <ImageName> \
      --environment-variables # Only include non-sensitive variables here
    ```

- **Automation/Remediation**
    - Use [Azure Policy](https://learn.microsoft.com/azure/governance/policy/samples/deny-plaintext-secrets-in-container-instances) to audit or deny deployments of container groups that include environment variables with sensitive key names (e.g., containing "password", "secret", "key", "token").
    - Implement CI/CD pipeline checks to scan for sensitive values in environment variables before deployment.
    - Reference secrets from Azure Key Vault using managed identities in your containerized application code.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.ContainerInstance/containerGroups/{containerGroupName}?api-version=2023-05-01`
  <br />
  **Properties:**  
  - `properties.containers[*].environmentVariables[*].value`  
  - `properties.containers[*].environmentVariables[*].secureValue`

<br/>

___
