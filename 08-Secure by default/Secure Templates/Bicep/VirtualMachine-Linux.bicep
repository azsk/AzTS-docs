@description('Name of the virtual machine.')
param vmName string = 'sampleLinux-vm'

@description('Username for the Virtual Machine.')
param adminUsername string

@description('Type of authentication to use on the Virtual Machine. SSH key is recommended.')
@allowed([
  'sshPublicKey'
  'password'
])
param authenticationType string = 'sshPublicKey'

@description('SSH Key or password for the Virtual Machine. SSH key is recommended. For information about SSH keys generation refer: https://docs.microsoft.com/en-us/azure/virtual-machines/linux/create-ssh-keys-detailed')
@secure()
param adminPasswordOrKey string

@description('Unique DNS Name for the Public IP used to access the Virtual Machine.')
param dnsLabelPrefix string = toLower('${vmName}-${uniqueString(resourceGroup().id, vmName)}')

@description('The Ubuntu version for the VM. This will pick a fully patched image of this given Ubuntu version. To get the list of all OS images refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/cli-ps-findimage.')
param ubuntuOSVersion string = '18_04-lts-gen2'

@description('Location for all resources.')
param location string = resourceGroup().location

@description('The size of the VM')
param vmSize string = 'Standard_D2s_v3'

@description('Name of the vNET to be created.')
param virtualNetworkName string = '${vmName}-vNet'

@description('Name of the subnet in the virtual network.')
param subnetName string = 'default'

@description('Name of the Network Security Group')
param networkSecurityGroupName string = '${vmName}-nsg'

@description('Name for the Public IP used to access the Virtual Machine.')
param publicIPAddressName string = toLower('${vmName}-publicIp')

@description('Allocation method for the Public IP used to access the Virtual Machine.')
@allowed([
  'Dynamic'
  'Static'
])
param publicIPAllocationMethod string = 'Dynamic'

@description('SKU for the Public IP used to access the Virtual Machine.')
@allowed([
  'Basic'
  'Standard'
])
param publicIpSku string = 'Basic'
param networkInterfaceName string = '${vmName}-nic'

@description('Resource Id of the LA Workspace to push logs from Microsoft Monitoring Agent.')
param laWorkSpaceResourceId string

@description('If “Auto-provisioning” for MMA is turned on in Azure Defender configuration, you can skip installation of MMA agent during VM creation as MDC will auto deploy MMA agent with desired configuations.')
param deployMicrosoftMonitoringAgent bool

var osDiskType = 'Standard_LRS'
var subnetAddressPrefix = '10.1.0.0/24'
var addressPrefix = '10.1.0.0/16'
var linuxConfiguration = {
  disablePasswordAuthentication: true
  ssh: {
    publicKeys: [
      {
        path: '/home/${adminUsername}/.ssh/authorized_keys'
        keyData: adminPasswordOrKey
      }
    ]
  }
}

resource networkInterfaceName_resource 'Microsoft.Network/networkInterfaces@2021-02-01' = {
  name: networkInterfaceName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: virtualNetworkName_subnetName.id
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIPAddressName_resource.id
          }
        }
      }
    ]
  }
}

resource networkSecurityGroupName_resource 'Microsoft.Network/networkSecurityGroups@2021-02-01' = {
  name: networkSecurityGroupName
  location: location
  properties: {
    securityRules: []
  }
}

resource virtualNetworkName_resource 'Microsoft.Network/virtualNetworks@2021-02-01' = {
  name: virtualNetworkName
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: [
        addressPrefix
      ]
    }
  }
}

resource virtualNetworkName_subnetName 'Microsoft.Network/virtualNetworks/subnets@2021-02-01' = {
  parent: virtualNetworkName_resource
  name: '${subnetName}'
  properties: {
    addressPrefix: subnetAddressPrefix
    privateEndpointNetworkPolicies: 'Enabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
    networkSecurityGroup: {
      id: networkSecurityGroupName_resource.id
    }
  }
}

resource publicIPAddressName_resource 'Microsoft.Network/publicIPAddresses@2021-02-01' = {
  name: publicIPAddressName
  location: location
  sku: {
    name: publicIpSku
  }
  properties: {
    publicIPAllocationMethod: publicIPAllocationMethod
    publicIPAddressVersion: 'IPv4'
    dnsSettings: {
      domainNameLabel: dnsLabelPrefix
    }
  }
}

resource vmName_resource 'Microsoft.Compute/virtualMachines@2021-11-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    storageProfile: {
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: osDiskType
        }
      }
      imageReference: {
        publisher: 'Canonical'
        offer: 'UbuntuServer'
        sku: ubuntuOSVersion
        version: 'latest'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: networkInterfaceName_resource.id
        }
      ]
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPasswordOrKey
      linuxConfiguration: ((authenticationType == 'password') ? null : linuxConfiguration)
    }
  }
}

resource vmName_AzurePolicyforLinux 'Microsoft.Compute/virtualMachines/extensions@2020-12-01' = {
  parent: vmName_resource
  name: 'AzurePolicyforLinux'
  location: location
  properties: {
    publisher: 'Microsoft.GuestConfiguration'
    type: 'ConfigurationforLinux'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {}
    protectedSettings: {}
  }
}

resource vmName_OmsAgentForLinux 'Microsoft.Compute/virtualMachines/extensions@2018-06-01' = if (deployMicrosoftMonitoringAgent) {
  parent: vmName_resource
  name: 'OmsAgentForLinux'
  location: location
  properties: {
    publisher: 'Microsoft.EnterpriseCloud.Monitoring'
    type: 'OmsAgentForLinux'
    typeHandlerVersion: '1.13'
    autoUpgradeMinorVersion: true
    settings: {
      workspaceId: (deployMicrosoftMonitoringAgent ? reference(laWorkSpaceResourceId, '2020-08-01').customerId : 'NotRequired')
    }
    protectedSettings: {
      workspaceKey: (deployMicrosoftMonitoringAgent ? listKeys(laWorkSpaceResourceId, '2020-08-01').primarySharedKey : 'NotRequired')
    }
  }
}

output adminUsername string = adminUsername
output hostname string = publicIPAddressName_resource.properties.dnsSettings.fqdn
output sshCommand string = 'ssh ${adminUsername}@${publicIPAddressName_resource.properties.dnsSettings.fqdn}'