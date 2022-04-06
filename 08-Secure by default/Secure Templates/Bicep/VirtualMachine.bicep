@description('Username for the Virtual Machine.')
param adminUsername string

@description('Password for the Virtual Machine.')
@minLength(12)
@secure()
param adminPassword string

@description('Unique DNS Name for the Public IP used to access the Virtual Machine.')
param dnsLabelPrefix string = toLower('${vmName}-${uniqueString(resourceGroup().id, vmName)}')

@description('Name for the Public IP used to access the Virtual Machine.')
param publicIpName string = toLower('${vmName}-publicIp')

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

@description('The Windows version for the VM. This will pick a fully patched Gen2 image of this given Windows version. To get the list of all OS images refer: https://docs.microsoft.com/en-us/azure/virtual-machines/windows/cli-ps-findimage.')
param OSVersion string = '2019-datacenter-gensecond'

@description('Size of the virtual machine.')
param vmSize string = 'Standard_D2s_v3'

@description('Location for all resources.')
param location string = resourceGroup().location
param virtualNetworkName string = '${vmName}-vNet'
param nicName string = '${vmName}-nic'

@description('Network security group name. This NSG will be associated with subnet.')
param networkSecurityGroupName1 string = '${vmName}-subnet-nsg'

@description('Network security group name. This NSG will be associated with VM NIC.')
param networkSecurityGroupName2 string = '${vmName}-nic-nsg'

param storageAccountName string = 'diagsforvm${uniqueString(resourceGroup().id)}'

@description('Resource Id of the LA Workspace to push logs from Microsoft Monitoring Agent.')
param laWorkSpaceResourceId string

@description('If “Auto-provisioning” for MMA is turned on in Azure Defender configuration, you can skip installation of MMA agent during VM creation as MDC will auto deploy MMA agent with desired configuations.')
param deployMicrosoftMonitoringAgent bool

@description('Name of the virtual machine.')
param vmName string = 'sample-VM'

var addressPrefix = '10.0.0.0/16'
var subnetName = 'Subnet'
var subnetPrefix = '10.0.0.0/24'

resource storageAccount 'Microsoft.Storage/storageAccounts@2021-08-01' = {
  name: storageAccountName
  location: location
  sku: {
    name: 'Standard_LRS'
  }
  properties: {
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
  }
  kind: 'Storage'
}

resource publicIP 'Microsoft.Network/publicIPAddresses@2021-05-01' = {
  name: publicIpName
  location: location
  sku: {
    name: publicIpSku
  }
  properties: {
    publicIPAllocationMethod: publicIPAllocationMethod
    dnsSettings: {
      domainNameLabel: dnsLabelPrefix
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
    subnets: [
      {
        name: subnetName
        properties: {
          addressPrefix: subnetPrefix
          networkSecurityGroup: {
            id: nsg1.id //[Azure_VirtualMachine_Config_Enable_NSG]
          }
        }
      }
    ]
  }
}

resource nic 'Microsoft.Network/networkInterfaces@2021-05-01' = {
  name: nicName
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIP.id
          }
          subnet: {
            id: resourceId('Microsoft.Network/virtualNetworks/subnets', virtualNetworkName, subnetName)
          }
        }
      }
    ]
    networkSecurityGroup: {
      id: nsg2.id //[Azure_VirtualMachine_Config_Enable_NSG]
    }
  }
  dependsOn: [
    vnet
  ]
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
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
      windowsConfiguration: {
        enableAutomaticUpdates: true
      }
    }
    storageProfile: {
      imageReference: {
        publisher: 'MicrosoftWindowsServer'
        offer: 'WindowsServer'
        sku: OSVersion
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: {
          storageAccountType: 'StandardSSD_LRS'
        }
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nic.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri: storageAccount.properties.primaryEndpoints.blob
      }
    }
  }
}

//[Azure_VirtualMachine_SI_Deploy_GuestConfig_Extension]
resource vmExtension_AzurePolicyforWindows 'Microsoft.Compute/virtualMachines/extensions@2020-12-01' = {
  parent: vm
  name: 'AzurePolicyforWindows'
  location: location
  properties: {
    publisher: 'Microsoft.GuestConfiguration'
    type: 'ConfigurationforWindows'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    enableAutomaticUpgrade: true
    settings: {}
    protectedSettings: {}
  }
}

//[Azure_VirtualMachine_SI_Enable_Monitoring_Agent]
resource vmExtension_MicrosoftMonitoringAgent 'Microsoft.Compute/virtualMachines/extensions@2020-12-01' = if (deployMicrosoftMonitoringAgent) {
  parent: vm
  name: 'MicrosoftMonitoringAgent'
  location: resourceGroup().location
  properties: {
    publisher: 'Microsoft.EnterpriseCloud.Monitoring'
    type: 'MicrosoftMonitoringAgent'
    typeHandlerVersion: '1.0'
    autoUpgradeMinorVersion: true
    settings: {
      workspaceId: (deployMicrosoftMonitoringAgent ? reference(laWorkSpaceResourceId, '2020-08-01').customerId : 'NotRequired')
    }
    protectedSettings: {
      workspaceKey: (deployMicrosoftMonitoringAgent ? listKeys(laWorkSpaceResourceId, '2020-08-01').primarySharedKey : 'NotRequired')
    }
  }
}

output hostname string = publicIP.properties.dnsSettings.fqdn