@description('Scale Set name, also used in this template as a base for naming resources (hence limited to 9 characters or less).')
@maxLength(20)
param VMSSName string

@description('Number of VMSS instances')
@maxValue(100)
param instanceCount int

@description('Admin username on all VMs.')
param adminUsername string = 'vmssadmin'

@description('Admin password on all VMs.')
@secure()
param adminPassword string

@description('Location')
param location string 

var vmSize = 'Standard_D2s_v5'
var virtualNetworkName = '${VMSSName}vnet'
var subnetName = '${VMSSName}subnet'
var nicName = '${VMSSName}nic'
var ipConfigName = '${VMSSName}ipconfig'
var addressPrefix = '10.0.0.0/16'
var subnetPrefix = '10.0.0.0/24'
var osType = {
  publisher: 'MicrosoftWindowsServer'
  offer: 'WindowsServer'
  sku: '2022-datacenter-azure-edition'
  version: 'latest'
}
var imageReference = osType

resource virtualNetwork 'Microsoft.Network/virtualNetworks@2020-11-01' = {
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
    ]
  }
}

resource VMSS 'Microsoft.Compute/virtualMachineScaleSets@2021-03-01' = {
  name: VMSSName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  sku: {
    name: vmSize
    tier: 'Standard'
    capacity: instanceCount
  }
  properties: {
    upgradePolicy: {
      mode: 'Automatic' // Azure_VirtualMachineScaleSet_SI_Enforce_Automatic_Upgrade_Policy
    }
    orchestrationMode: 'Uniform'
    virtualMachineProfile: {
      storageProfile: {
        osDisk: {
          caching: 'ReadOnly'
          createOption: 'FromImage'
        }
        imageReference: imageReference
      }
      osProfile: {
        computerNamePrefix: VMSSName
        adminUsername: adminUsername
        adminPassword: adminPassword
      }
      networkProfile: {
        networkInterfaceConfigurations: [
          {
            name: nicName
            properties: {
              primary: true
              ipConfigurations: [
                {
                  name: ipConfigName
                  properties: {
                    subnet: {
                      id: '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.Network/virtualNetworks/${virtualNetworkName}/subnets/${subnetName}'
                    }
                  }
                }
              ]
            }
          }
        ]
      }
    }
    overprovision: true
  }
  dependsOn: [
    virtualNetwork
  ]
}
