@description('Name of the Virtual Netwok')
param virtualNetworkName string

@description('Name of the SubNet')
param subnetName string = 'default'

@description('Address prefix in the format \'10.3.0.0/29\'')
param addressPrefix string = '10.0.0.0/16'

@description('Address prefix in the format \'10.3.0.0/29\'')
param subnetPrefix string = '10.0.0.0/24'

@description('Network security group name. This NSG will be associated with subnet.')
param networkSecurityGroupName string = '${subnetName}-subnet-nsg'

@description('Location for all resources.')
param location string = resourceGroup().location

resource nsg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: networkSecurityGroupName
  location: location
  properties: {
    securityRules: []
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2021-05-01' = {
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
          networkSecurityGroup: {
            id: nsg.id //[Azure_VNet_NetSec_Configure_NSG]
          }
        }
      }
    ]
  }
}
