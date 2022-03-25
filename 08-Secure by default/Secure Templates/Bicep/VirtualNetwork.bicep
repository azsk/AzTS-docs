@description('Name of the Virtual Netwok')
param virualNetworkName string

@description('Name of the Security Group')
param NSGname string

@description('Address prefix in the format \'10.3.0.0/29\'')
param addressPrefix string

@description('Name of the SubNet')
param subnetName string = 'default'

resource NSGname_resource 'Microsoft.Network/networkSecurityGroups@2017-06-01' = {
  name: NSGname
  location: 'centralus'
  properties: {
    securityRules: []
  }
  dependsOn: []
}

resource virualNetworkName_resource 'Microsoft.Network/virtualNetworks@2017-06-01' = {
  name: virualNetworkName
  location: 'centralus'
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: addressPrefix
          networkSecurityGroup: {
            id: NSGname_resource.id
          }
        }
      }
    ]
  }
}