@description('Scale Set name, also used in this template as a base for naming resources (hence limited to 9 characters or less).')
@maxLength(20)
param VMSSName string

@description('Number of VMSS instances')
@maxValue(100)
param instanceCount int

@description('Admin username on all VMSS Instances.')
param adminUsername string

@description('SSH rsa public key file as a string.')
param publicKey string

var vmSize = 'Standard_D1_v2'
var virtualNetworkName = '${VMSSName}vnet'
var subnetName = '${VMSSName}subnet'
var nicName = '${VMSSName}nic'
var ipConfigName = '${VMSSName}ipconfig'
var addressPrefix = '10.0.0.0/16'
var subnetPrefix = '10.0.0.0/24'
var storageAccountType = 'Standard_LRS'
var location = resourceGroup().location
var sshKeyPath = '/home/${adminUsername}/.ssh/authorized_keys'
var osType = {
  publisher: 'Canonical'
  offer: 'UbuntuServer'
  sku: '16.04-LTS'
  version: 'latest'
}
var imageReference = osType
var computeApiVersion = '2021-03-01'
var networkApiVersion = '2020-11-01'

resource virtualNetwork 'Microsoft.Network/virtualNetworks@[variables(\'networkApiVersion\')]' = {
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

resource VMSS 'Microsoft.Compute/virtualMachineScaleSets@[variables(\'computeApiVersion\')]' = {
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
      mode: 'Manual'
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
        linuxConfiguration: {
          disablePasswordAuthentication: 'true'
          ssh: {
            publicKeys: [
              {
                path: sshKeyPath
                keyData: publicKey
              }
            ]
          }
        }
      }
      extensionProfile: {
        extensions: [
          {
            name: 'AADSSHLoginForLinux'
            properties: {
              publisher: 'Microsoft.Azure.ActiveDirectory'
              type: 'AADSSHLoginForLinux'
              typeHandlerVersion: '1.0'
              settings: {}
            }
          }
        ]
      }
      networkProfile: {
        networkInterfaceConfigurations: [
          {
            name: nicName
            properties: {
              primary: 'true'
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
    overprovision: 'true'
  }
  dependsOn: [
    virtualNetwork
  ]
}
