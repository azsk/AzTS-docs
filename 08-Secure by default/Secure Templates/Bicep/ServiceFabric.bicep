@description('Specify the name of the new Service Fabric cluster to create. Use only lowercase letters, numbers and hyphens. Start with a lowercase letter and end with a lowercase letter or number. The name must be 4 - 24 characters in length.')
@minLength(4)
@maxLength(24)
param serviceFabricClusterName string = 'sf-${utcNow()}'

@description('Specify the Azure region where the Service Fabric cluster is to be created. The default location is same as the enclosing Resource Group\'s location.')
param serviceFabricClusterLocation string = resourceGroup().location

@description('Specify the username of the Service Fabric cluster administrator.')
param adminUsername string

@description('Specify the password of the Service Fabric cluster administrator.')
@secure()
param adminPassword string

// Certificate related configurations
@description('Specify the name of the certificate store in the virtual machine the certificate will be deployed to.')
param certificateStoreName string = 'My'

@description('Specify the thumbprint of the certificate being uploaded to the Service Fabric cluster.')
@secure()
param certificateThumbprint string

@description('''
Specify the identifier of the key vault containing the certificate.
The key vault should be in the same Subscription and location as the Service Fabric cluster.
This should be in the format: /subscriptions/<subID>/resourceGroups/<resourceGroupName>/providers/Microsoft.KeyVault/vaults/<vaultName>.
''')
param sourceKeyVaultResourceId string

@description('Specify the URL of the certificate in the key vault.')
@secure()
param certificateUrl string

// Azure Active Directory (AAD) related configurations
@description('Specify the ID of the client application in Azure Active Directory (AAD).')
param clientApplicationId string

@description('Specify the ID of the cluster application in Azure Active Directory (AAD).')
param clusterApplicationId string

// Service Fabric cluster node / virtual machine related parameters
@description('Specify the size of the virtual machine to use for the cluster nodes. The default value is \'Standard_D2_v3\'.')
param nodeTypeSize string = 'Standard_D2_v3'

@description('Specify the publisher of the Azure Virtual Machines Marketplace image. For example, \'Canonical\' or \'MicrosoftWindowsServer\'. The default value is \'MicrosoftWindowsServer\'.')
param vmImagePublisher string = 'MicrosoftWindowsServer'

@description('Specify the offer type of the Azure Virtual Machines Marketplace image. For example, \'UbuntuServer\' or \'WindowsServer\'. The default value is \'WindowsServer\'.')
param vmImageOffer string = 'WindowsServer'

@description('Specify the SKU of the Azure Virtual Machines Marketplace image. For example, \'14.04.0-LTS\' or \'2012-R2-Datacenter\'. The default value is \'2019-Datacenter\'.')
param vmImageSku string = '2019-Datacenter'

@description('Specify the version of the Azure Virtual Machines Marketplace image. A value of \'latest\' can be specified to select the latest version of an image. If omitted, the default is \'latest\'.')
param vmImageVersion string = 'latest'

@description('Specify the total nodes to be deployed in the Service Fabric cluster. The default value is 5.')
@minValue(0)
param nodeType0VmInstanceCount int = 5

@description('Specify the SKU type of the node to be deployed in the Service Fabric cluster. The default type is \'Standard\'.')
param nodeSkuTier string = 'Standard'

@description('Specify the desired durability level for the node type. The default level is \'Silver\'.')
param nodeType0DurabilityLevel string = 'Silver'

@description('[1 / 2] Primary input endpoint for the application to use.')
@minValue(0)
@maxValue(65535)
param loadBalancedAppPort1 int = 80

@description('[2 / 2] Secondary input endpoint for the application to use.')
@minValue(0)
@maxValue(65535)
param loadBalancedAppPort2 int = 8081

// Service Fabric cluster configurations
// Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel - The ClusterProtectionLevel property must be set to "EncryptAndSign".
var clusterProtectionLevel = 'EncryptAndSign'

// Node type configurations
// Prefix of the node type.
var nodeType0VmName = 'vm0'

// Size of the node type.
var nodeType0VmSize = nodeTypeSize

// Client connection endpoint port
var nodeType0FabricTcpGatewayPort = 19000

// HTTP Gateway endpoint port
var nodeType0FabricHttpGatewayPort = 19080

// Virtual network configurations
// Name of the virtual network.
var virtualNetworkName = 'virtual-network'

// Address prefix of the virtual network .
var virtualNetworkAddressPrefix0 = '10.0.0.0/16'

// Subnet configurations
// Name of the subnet.
var subnet0Name = 'subnet-0'

// Address prefix of the subnet.
var subnet0AddressPrefix0 = '10.0.0.0/24'

// Reference to the subnet being created.
var subnet0Ref = resourceId('Microsoft.Network/virtualNetworks/subnets/', virtualNetworkName, subnet0Name)

// Prefix for the Network Interface Controller names (NICs).
var nicNamePrefix = 'nic'

// Load balancer configurations
// Name of the load balancer.
var loadBalancerName = 'lb-${serviceFabricClusterName}-${nodeType0VmName}'

// Name of the public IP address for the load balancer.
var loadBalancerIpAddressName = 'public-ip-lb-front-end'

// Load balancer IP configuration.
var loadBalancerFrontendIPConfigurations0 = resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations/', loadBalancerName, 'LoadBalancerFrontendIPConfigurations0')

// Load balancer backend address pool configuration.
var loadBalancerBackendAddressPoolId = resourceId('Microsoft.Network/loadBalancers/backendAddressPools', loadBalancerName, 'LoadBalancerBackendAddressPool')

// Load balancer Gateway probe configuration.
var loadBalancerFabricGatewayProbeId = resourceId('Microsoft.Network/loadBalancers/probes', loadBalancerName, 'LoadBalancerFabricGatewayProbe')

// Load balancer HTTP Gateway probe configuration.
var loadBalancerFabricHttpGatewayProbeId = resourceId('Microsoft.Network/loadBalancers/probes', loadBalancerName, 'LoadBalancerFabricHttpGatewayProbe')

// Load balancer backend address NAT pool configuration.
var loadBalancerFabricBackendAddressNatPoolId = resourceId('Microsoft.Network/loadBalancers/inboundNatPools', loadBalancerName, 'LoadBalancerBackendAddressNatPool')

// Name of the DNS to be used for the cluster.
var domainNameLabel = toLower(serviceFabricClusterName)

// Create a virtual network.
resource virtualNetwork 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: virtualNetworkName
  location: serviceFabricClusterLocation
  properties: {
    addressSpace: {
      addressPrefixes: [
        virtualNetworkAddressPrefix0
      ]
    }
    subnets: [
      {
        name: subnet0Name
        properties: {
          addressPrefix: subnet0AddressPrefix0
        }
      }
    ]
  }
}

// Create a public IP address for the load balancer.
resource loadBalancerPublicIpAddress 'Microsoft.Network/publicIPAddresses@2021-05-01' = {
  name: loadBalancerIpAddressName
  location: serviceFabricClusterLocation
  properties: {
    dnsSettings: {
      domainNameLabel: domainNameLabel
    }
  }
}

// Create a load balancer.
resource loadBalancer 'Microsoft.Network/loadBalancers@2021-05-01' = {
  name: loadBalancerName
  location: serviceFabricClusterLocation
  properties: {
    frontendIPConfigurations: [
      {
        name: 'LoadBalancerFrontendIPConfigurations0'
        properties: {
          publicIPAddress: {
            id: loadBalancerPublicIpAddress.id
          }
        }
      }
    ]
    backendAddressPools: [
      {
        name: 'LoadBalancerBackendAddressPool'
        properties: {}
      }
    ]
    loadBalancingRules: [
      {
        name: 'LoadBalancerRule0'
        properties: {
          backendAddressPool: {
            id: loadBalancerBackendAddressPoolId
          }
          backendPort: nodeType0FabricTcpGatewayPort
          frontendIPConfiguration: {
            id: loadBalancerFrontendIPConfigurations0
          }
          frontendPort: nodeType0FabricTcpGatewayPort
          idleTimeoutInMinutes: 5
          probe: {
            id: loadBalancerFabricGatewayProbeId
          }
          protocol: 'Tcp'
        }
      }
      {
        name: 'LoadBalancerHttpRule0'
        properties: {
          backendAddressPool: {
            id: loadBalancerBackendAddressPoolId
          }
          backendPort: nodeType0FabricHttpGatewayPort
          enableFloatingIP: false
          frontendIPConfiguration: {
            id: loadBalancerFrontendIPConfigurations0
          }
          frontendPort: nodeType0FabricHttpGatewayPort
          idleTimeoutInMinutes: 5
          probe: {
            id: loadBalancerFabricHttpGatewayProbeId
          }
          protocol: 'Tcp'
        }
      }
      {
        name: 'AppPortLoadBalancerRule1'
        properties: {
          backendAddressPool: {
            id: loadBalancerBackendAddressPoolId
          }
          backendPort: loadBalancedAppPort1
          enableFloatingIP: false
          frontendIPConfiguration: {
            id: loadBalancerFrontendIPConfigurations0
          }
          frontendPort: loadBalancedAppPort1
          idleTimeoutInMinutes: 5
          probe: {
            id: resourceId('Microsoft.Network/loadBalancers/probes', loadBalancerName, 'LoadBalancerAppPort1Probe')
          }
          protocol: 'Tcp'
        }
      }
      {
        name: 'AppPortLoadBalancerRule2'
        properties: {
          backendAddressPool: {
            id: loadBalancerBackendAddressPoolId
          }
          backendPort: loadBalancedAppPort2
          enableFloatingIP: false
          frontendIPConfiguration: {
            id: loadBalancerFrontendIPConfigurations0
          }
          frontendPort: loadBalancedAppPort2
          idleTimeoutInMinutes: 5
          probe: {
            id: resourceId('Microsoft.Network/loadBalancers/probes', loadBalancerName, 'LoadBalancerAppPort2Probe')
          }
          protocol: 'Tcp'
        }
      }
    ]
    probes: [
      {
        name: 'LoadBalancerFabricGatewayProbe'
        properties: {
          intervalInSeconds: 5
          numberOfProbes: 2
          port: nodeType0FabricTcpGatewayPort
          protocol: 'Tcp'
        }
      }
      {
        name: 'LoadBalancerFabricHttpGatewayProbe'
        properties: {
          intervalInSeconds: 5
          numberOfProbes: 2
          port: nodeType0FabricHttpGatewayPort
          protocol: 'Tcp'
        }
      }
      {
        name: 'LoadBalancerAppPort1Probe'
        properties: {
          intervalInSeconds: 5
          numberOfProbes: 2
          port: loadBalancedAppPort1
          protocol: 'Tcp'
        }
      }
      {
        name: 'LoadBalancerAppPort2Probe'
        properties: {
          intervalInSeconds: 5
          numberOfProbes: 2
          port: loadBalancedAppPort2
          protocol: 'Tcp'
        }
      }
    ]
    inboundNatPools: [
      {
        name: 'LoadBalancerBackendAddressNatPool'
        properties: {
          backendPort: 3389
          frontendIPConfiguration: {
            id: loadBalancerFrontendIPConfigurations0
          }
          frontendPortRangeEnd: 4500
          frontendPortRangeStart: 3389
          protocol: 'Tcp'
        }
      }
    ]
  }
}

// Create a virtual machine scale set.
resource nodeType0Vm 'Microsoft.Compute/virtualMachineScaleSets@2021-11-01' = {
  name: nodeType0VmName
  location: serviceFabricClusterLocation
  sku: {
    name: nodeType0VmSize
    capacity: nodeType0VmInstanceCount
    tier: nodeSkuTier
  }
  properties: {
    overprovision: false
    upgradePolicy: {
      mode: 'Automatic'
    }
    virtualMachineProfile: {
      extensionProfile: {
        extensions: [
          {
            name: '${nodeType0VmName}_ServiceFabricNode'
            properties: {
              type: 'ServiceFabricNode'
              autoUpgradeMinorVersion: true
              publisher: 'Microsoft.Azure.ServiceFabric'
              settings: {
                clusterEndpoint: serviceFabricCluster.properties.clusterEndpoint
                nodeTypeRef: nodeType0VmName
                dataPath: 'D:\\\\SvcFab'
                durabilityLevel: nodeType0DurabilityLevel
                enableParallelJobs: true
                nicPrefixOverride: subnet0AddressPrefix0
                certificate: {
                  thumbprint: certificateThumbprint
                  x509StoreName: certificateStoreName
                }
              }
              typeHandlerVersion: '1.1'
            }
          }
        ]
      }
      networkProfile: {
        networkInterfaceConfigurations: [
          {
            name: '${nicNamePrefix}-0'
            properties: {
              ipConfigurations: [
                {
                  name: '${nicNamePrefix}-0'
                  properties: {
                    loadBalancerBackendAddressPools: [
                      {
                        id: loadBalancerBackendAddressPoolId
                      }
                    ]
                    loadBalancerInboundNatPools: [
                      {
                        id: loadBalancerFabricBackendAddressNatPoolId
                      }
                    ]
                    subnet: {
                      id: subnet0Ref
                    }
                  }
                }
              ]
              primary: true
            }
          }
        ]
      }
      osProfile: {
        adminPassword: adminPassword
        adminUsername: adminUsername
        computerNamePrefix: nodeType0VmName
        secrets: [
          {
            sourceVault: {
              id: sourceKeyVaultResourceId
            }
            vaultCertificates: [
              {
                certificateStore: certificateStoreName
                certificateUrl: certificateUrl
              }
            ]
          }
        ]
      }
      storageProfile: {
        imageReference: {
          publisher: vmImagePublisher
          offer: vmImageOffer
          sku: vmImageSku
          version: vmImageVersion
        }
      }
    }
  }
  dependsOn: [
    virtualNetwork
    loadBalancer
  ]
}

// Create a Service Fabric cluster.
resource serviceFabricCluster 'Microsoft.ServiceFabric/clusters@2021-06-01' = {
  name: serviceFabricClusterName
  location: serviceFabricClusterLocation
  properties: {
    azureActiveDirectory: { // Azure_ServiceFabric_AuthN_Client_AuthN_Microsoft_Entra_ID_Only - Enable Entra Id (formerly AAD) authentication on the Service Fabric cluster.
      clientApplication: clientApplicationId
      clusterApplication: clusterApplicationId
      tenantId: tenant().tenantId
    }
    certificate: {
      thumbprint: certificateThumbprint
      x509StoreName: certificateStoreName
    }
    fabricSettings: [
      {
        parameters: [
          {
            name: 'ClusterProtectionLevel'
            value: clusterProtectionLevel // Azure_ServiceFabric_DP_Set_Property_ClusterProtectionLevel - The ClusterProtectionLevel property must be set to "EncryptAndSign".
          }
        ]
        name: 'Security'
      }
    ]
    managementEndpoint: 'https://${loadBalancerPublicIpAddress.properties.dnsSettings.fqdn}:${nodeType0FabricHttpGatewayPort}'
    nodeTypes: [
      {
        name: nodeType0VmName
        clientConnectionEndpointPort: nodeType0FabricTcpGatewayPort
        httpGatewayEndpointPort: nodeType0FabricHttpGatewayPort
        isPrimary: true
        reverseProxyEndpointPort: null // Azure_ServiceFabric_DP_Dont_Expose_Reverse_Proxy_Port - Reverse proxy port must not be exposed publicly.
        vmInstanceCount: nodeType0VmInstanceCount
      }
    ]
  }
}
