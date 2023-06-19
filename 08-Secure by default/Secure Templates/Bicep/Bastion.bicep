@description('Name of the Resource Group')
param resourceGroupName string = resourceGroup().name

@description('Name of the Bastion Host')
param bastionHostName string

@description('SKU of the Bastion Host')
@allowed([
  'Basic'
  'Standard'
])
param bastionHostSku string = 'Standard'

@description('Name of the public IP Address')
param publicIpAddressName string = '${virtualNetworkName}-vnet-ip'

@description('Name of the Virtual Netwok')
param virtualNetworkName string

@description('Name of the SubNet')
param subnetName string = 'default'

@description('Address prefix in the format \'10.3.0.0/29\'')
param addressPrefix string = '10.0.0.0/16'

@description('Subnet prefix in the format \'10.3.0.0/29\'')
param subnetPrefix string = '10.0.0.0/24'

@description('Bastion Subnet prefix in the format \'10.3.0.0/29\'')
param BastionSubnetPrefix string = '10.0.1.0/26'

@description('Location for all resources.')
param location string = resourceGroup().location

resource publicIpAddress 'Microsoft.Network/publicIpAddresses@2020-08-01' = {
  name: publicIpAddressName
  location: location
  sku: {
    name: 'Standard'
  }
  properties: {
    publicIPAllocationMethod: 'Static'
  }
  tags: {}
}

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2021-05-01' = {
  name: virtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetPrefix
        }
      }
      {
        name: 'AzureBastionSubnet'
        properties: {
          addressPrefix: BastionSubnetPrefix
        }
      }
    ]
  }
}

resource bastionHost 'Microsoft.Network/bastionHosts@2022-09-01' = {
  name: bastionHostName
  sku: {
    name: bastionHostSku
  }
  location: location
  properties: {
    enableShareableLink: false // [Azure_Bastion_AuthZ_Disable_Shareable_Link]
    ipConfigurations: [
      {
        name: 'IpConf'
        properties: {
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, 'AzureBastionSubnet')
          }
          publicIPAddress: {
            id: resourceId(resourceGroupName, 'Microsoft.Network/publicIpAddresses', publicIpAddressName)
          }
        }
      }
    ]
    scaleUnits: 2
  }
  tags: {}
  dependsOn: [
    publicIpAddress
    virtualNetwork
  ]
}
