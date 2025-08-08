# ContainerApps

**Resource Type:** Microsoft.App/containerApps

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ContainerApps_DP_Dont_Allow_HTTP_Access](#azure_containerapps_dp_dont_allow_http_access)
- [Azure_ContainerApps_DP_Enable_mTLS_Encryption](#azure_containerapps_dp_enable_mtls_encryption)
- [Azure_ContainerApps_DP_Avoid_Plaintext_Secrets](#azure_containerapps_dp_avoid_plaintext_secrets)


<!-- /TOC -->
<br/>

___

## Azure_ContainerApps_DP_Dont_Allow_HTTP_Access

### Display Name
Container Apps must not allow HTTP access and require HTTPS

### Rationale
Enforcing HTTPS-only access ensures that all communication with Container Apps is encrypted in transit, protecting against man-in-the-middle attacks and data interception.

### Control Settings 
```json
{
  "RequireHTTPS": true,
  "AllowInsecureConnections": false,
  "MinimumTLSVersion": "1.2",
  "RedirectHTTPToHTTPS": true
}
```

### Control Spec

> **Passed:**
> HTTPS is enforced and HTTP access is disabled.
>
> **Failed:**
> HTTP access is allowed or HTTPS is not enforced.
>

### Recommendation

- **Azure Portal**

    Go to Container App ? Ingress ? Set "Allow insecure connections" to disabled ? Ensure transport is set to "HTTP/2" or "Auto" for HTTPS enforcement.

- **ARM Template**

    ```json
    {
      "type": "Microsoft.App/containerApps",
      "properties": {
        "configuration": {
          "ingress": {
            "external": true,
            "targetPort": 80,
            "allowInsecure": false,
            "transport": "http2"
          }
        }
      }
    }
    ```

### Azure Policies or REST APIs used for evaluation

- REST API to get Container App configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.App/containerApps/{containerAppName}<br />
**Properties:** properties.configuration.ingress.allowInsecure<br />

<br />

___

## Azure_ContainerApps_DP_Enable_mTLS_Encryption

### Display Name
Container Apps must enable mutual TLS (mTLS) encryption

### Rationale
Mutual TLS provides enhanced security by ensuring both client and server authentication, providing better protection for service-to-service communication.

### Control Spec

> **Passed:**
> Mutual TLS encryption is enabled and properly configured.
>
> **Failed:**
> Mutual TLS encryption is not enabled or is misconfigured.
>

### Recommendation

- **Azure Portal**

    Go to Container App ? Ingress ? Configure client certificate mode ? Enable mutual TLS for enhanced security ? Configure certificate validation.

- **Configuration Example**

    ```yaml
    properties:
      configuration:
        ingress:
          external: true
          targetPort: 443
          clientCertificateMode: "require"
          transport: "http2"
    ```

### Azure Policies or REST APIs used for evaluation

- REST API to get Container App configuration: /subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.App/containerApps/{containerAppName}<br />
**Properties:** properties.configuration.ingress.clientCertificateMode<br />

<br />

___

## Azure_ContainerApps_DP_Avoid_Plaintext_Secrets

### Display Name
Avoid storing secrets in plaintext in Azure Container Apps

### Rationale
Storing secrets such as passwords, connection strings, or API keys in plaintext within Azure Container Apps environment variables or configuration files exposes sensitive information to potential attackers. Utilizing secure secret storage mechanisms, such as Azure Key Vault, ensures that secrets are encrypted at rest and only accessible by authorized services. This control helps organizations meet compliance requirements (such as ISO 27001, SOC 2, and PCI DSS) and reduces the risk of credential leakage.

### Control Spec

> **Passed:**  
> No secrets (such as passwords, connection strings, or API keys) are stored in plaintext within environment variables or configuration files of Azure Container Apps. All sensitive information is referenced securely, for example, via Azure Key Vault integration or other supported secret management solutions.
>
> **Failed:**  
> One or more secrets are detected in plaintext within environment variables or configuration files of Azure Container Apps. Sensitive information is not protected by secure secret management mechanisms.

### Recommendation

- **Azure Portal**
    1. Navigate to your Azure Container App in the Azure Portal.
    2. Under **Settings**, select **Secrets**.
    3. Remove any plaintext secrets from environment variables or configuration files.
    4. Add secrets to Azure Key Vault or the Container App's Secrets section.
    5. Reference secrets in your application code or configuration using secure references (e.g., environment variable referencing a Key Vault secret).

- **PowerShell**
    ```powershell
    # Example: Remove a plaintext secret from a Container App and reference Azure Key Vault
    $resourceGroup = "<resource-group-name>"
    $containerAppName = "<container-app-name>"
    $secretName = "<secret-name>"
    $keyVaultSecretUri = "<key-vault-secret-uri>"

    # Remove existing secret (if applicable)
    az containerapp secret remove `
        --name $containerAppName `
        --resource-group $resourceGroup `
        --secret-name $secretName

    # Add secret from Azure Key Vault
    az containerapp secret set `
        --name $containerAppName `
        --resource-group $resourceGroup `
        --secrets name=$secretName,value=$keyVaultSecretUri
    ```

- **Azure CLI**
    ```bash
    # Remove a plaintext secret
    az containerapp secret remove \
      --name <container-app-name> \
      --resource-group <resource-group-name> \
      --secret-name <secret-name>

    # Add a secret from Azure Key Vault
    az containerapp secret set \
      --name <container-app-name> \
      --resource-group <resource-group-name> \
      --secrets name=<secret-name>,value=<key-vault-secret-uri>
    ```

- **Automation/Remediation**
    - Use Azure Policy to deny or audit the use of plaintext secrets in Container Apps configurations.
    - Implement CI/CD pipeline checks to scan for plaintext secrets before deployment.
    - Use Azure Key Vault references in Container Apps for all sensitive configuration values.
    - For bulk remediation, develop scripts to scan all Container Apps for plaintext secrets and migrate them to Azure Key Vault.

### Azure Policies or REST APIs used for evaluation

- REST API: `GET https://management.azure.com/subscriptions/{subscriptionId}/resourceGroups/{resourceGroupName}/providers/Microsoft.App/containerApps/{containerAppName}?api-version=2022-03-01`
  <br />
  **Properties:**  
  - `properties.template.containers.env` (checks for plaintext values)
  - `properties.configuration.secrets` (checks for secure references)

<br/>

___
