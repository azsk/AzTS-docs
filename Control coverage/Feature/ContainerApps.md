# ContainerApps

**Resource Type:** Microsoft.App/containerApps

<!-- TOC depthfrom:2 depthto:2 -->

- [Azure_ContainerApps_DP_Dont_Allow_HTTP_Access](#azure_containerapps_dp_dont_allow_http_access)
- [Azure_ContainerApps_DP_Enable_mTLS_Encryption](#azure_containerapps_dp_enable_mtls_encryption)

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