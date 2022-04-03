@description('Specify a name for the API Management service. Use only alphanumerics and hyphens. The name must start with a letter and end with an alphanumeric. The name must be unique across Azure.')
@minLength(1)
@maxLength(50)
param apiManagementServiceName string

@description('Specify the Azure region the API Management service is to be hosted in. Not every resource is available in every region. The default location is same as the enclosing Resource Group\'s location.')
param apiManagementServiceRegion string = resourceGroup().location

@description('Specify the name of your organization for use in the developer portal and e-mail notifications.')
param publisherName string

@description('Specify the e-mail address to receive all system notifications sent from API Management.')
param publisherEmail string

@allowed([
    'Basic'
    'Consumption'
    'Developer'
    'Isolated'
    'Premium'
    'Standard'
])
@description('Specify the name of the SKU to be used for the API Management service. The default SKU type is \'Developer\'.')
param skuName string = 'Developer'

@description('Specify the capacity of the SKU to be used for the API Management service. The capacity for \'Consumption\' SKU is 0. The capacity for \'Developer\' SKU is 1.')
@minValue(0)
param skuCapacity int = 1

// The list of protocols and ciphers that are to be enabled/disabled on the API Management service.
// This contains protocols and ciphers common to all pricing tiers.
var protocolAndCipherSettingsDefault = { 
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls11': false
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Tls10': false
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls11': false
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Tls10': false
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Backend.Protocols.Ssl30': false
    // "Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2" is not seen as insecure by AzTS, but Azure disables this by default when the API Management service is being created.
    // Retaining the same behaviour to be in line with standard product recommendations.
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Protocols.Server.Http2': false
}

// This contains protocols and ciphers that apply to specific pricing tiers.
var protocolAndCipherSettingsExtended = { 
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Ciphers.TripleDes168': false
    'Microsoft.WindowsAzure.ApiManagement.Gateway.Security.Protocols.Ssl30': false
}

// Flag indicating if the API Management service is being hosted in a 'Consumption' tier.
var isConsumptionTier = skuName == 'Consumption' ? true : false

// The capacity of the SKU to be used for the API Management service. The capacity for 'Consumption' SKU is 0.
var skuCapacityFinal = isConsumptionTier ? 0 : skuCapacity

// Create an API Management service.
resource apiManagementService 'Microsoft.ApiManagement/service@2021-08-01' = {
    name: apiManagementServiceName
    location: apiManagementServiceRegion
    sku: {
        capacity: skuCapacityFinal
        name: skuName
    }
    properties: {
        publisherEmail: publisherEmail
        publisherName: publisherName
        customProperties: isConsumptionTier ? protocolAndCipherSettingsDefault : union(protocolAndCipherSettingsDefault, protocolAndCipherSettingsExtended) // Azure_APIManagement_DP_Use_Secure_TLS_Version - Disable insecure protocols and ciphers.
    }

    // To disable Management REST API.
    resource tenantAccessInformation 'tenant@2021-08-01' = if (!isConsumptionTier) {
        name: 'access'
        properties: {
            enabled: false // Azure_APIManagement_AuthN_Disable_Management_API - Disable Management REST API.
        }
    }

    // To disable basic authentication, i.e. username + password.
    resource portalSettings 'portalsettings@2021-08-01' = if (!isConsumptionTier) {
        name: 'signup'
        properties: {
            enabled: false // Azure_APIManagement_AuthN_Use_AAD_for_Client_AuthN - Disable basic authentication.
        }
    }
}
