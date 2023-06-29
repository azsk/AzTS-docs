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

@description('Network security group name. This NSG will be associated with subnet.')
param networkSecurityGroupName1 string = '${vmName}-subnet-nsg'

@description('Network security group name. This NSG will be associated with VM NIC.')
param networkSecurityGroupName2 string = '${vmName}-nic-nsg'

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

@description('If “Auto-provisioning” for AMA is turned on in Azure Defender configuration, you can skip installation of AMA agent during VM creation as MDC will auto deploy AMA agent with desired configuations.')
param deployAzureMonitoringAgent bool

@description('AAD SSH Extension would be required to login user with the help of Azure Active Directory.')
param deployAzureAADAuthExtension bool

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

resource nic 'Microsoft.Network/networkInterfaces@2021-05-01' = {
  name: networkInterfaceName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: {
            id: subnet.id
          }
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIP.id
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsg2.id //[Azure_VirtualMachine_Config_Enable_NSG]
    }
  }
}

resource nsg1 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: networkSecurityGroupName1
  location: location
  properties: {
    securityRules: []
  }
}

resource nsg2 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {
  name: networkSecurityGroupName2
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
  }
}

resource subnet 'Microsoft.Network/virtualNetworks/subnets@2021-05-01' = {
  parent: vnet
  name: '${subnetName}'
  properties: {
    addressPrefix: subnetAddressPrefix
    privateEndpointNetworkPolicies: 'Enabled'
    privateLinkServiceNetworkPolicies: 'Enabled'
    networkSecurityGroup: {
      id: nsg1.id //[Azure_VirtualMachine_Config_Enable_NSG]
    }
  }
}

resource publicIP 'Microsoft.Network/publicIPAddresses@2021-05-01' = {
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

resource vm 'Microsoft.Compute/virtualMachines@2021-11-01' = {
  name: vmName
  location: location
  identity: {
    type: 'SystemAssigned' //[Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension]
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
          id: nic.id
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

//[Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension]
resource vmExtension_AzurePolicyforLinux 'Microsoft.Compute/virtualMachines/extensions@2020-12-01' = {
  parent: vm
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

//[Azure_VirtualMachine_SI_Enable_Monitoring_Agent]
resource vmExtension_OmsAgentForLinux 'Microsoft.Compute/virtualMachines/extensions@2018-06-01' = if (deployMicrosoftMonitoringAgent) {
  parent: vm
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

//[//[Azure_VirtualMachine_SI_Enable_Monitoring_Agent_AMA_Trial]]
resource vmExtension_AzureMonitorLinuxAgent 'Microsoft.Compute/virtualMachines/extensions@2018-06-01' = if (deployAzureMonitoringAgent) {
  parent: vm
  name: 'AzureMonitorLinuxAgent'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.Monitor'
    type: 'AzureMonitorLinuxAgent'
    typeHandlerVersion: '1.22'
    enableAutomaticUpgrade: true
    autoUpgradeMinorVersion: true
    settings: {
      authentication : 'SystemAssigned'
      }
    }
  }
//[//[Azure_VirtualMachine_AuthN_Enable_AAD_Auth_Linux]]  
resource vmName_AADSSHLoginForLinux 'Microsoft.Compute/virtualMachines/extensions@2019-07-01' = if (deployAzureAADAuthExtension) {
  parent: vm
  name: 'AADSSHLoginForLinux'
  location: location
  properties: {
    publisher: 'Microsoft.Azure.ActiveDirectory'
    type: 'AADSSHLoginForLinux'
    typeHandlerVersion: '1.00'
    settings: {}
  }
}

output adminUsername string = adminUsername
output hostname string = publicIP.properties.dnsSettings.fqdn
output sshCommand string = 'ssh ${adminUsername}@${publicIP.properties.dnsSettings.fqdn}'
