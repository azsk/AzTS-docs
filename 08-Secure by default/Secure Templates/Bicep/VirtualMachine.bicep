param vmName string

@description('Username for the Virtual Machine.')
param adminUsername string

@description('Password for the Virtual Machine.')
@secure()
param adminPassword string

@description('Unique DNS Name for the Storage Account where the Virtual Machine\'s disks will be placed.')
param newStorageAccountName string

@description('Unique DNS Name for the Public IP used to access the Virtual Machine.')
param dnsNameForPublicIP string

@description('The Windows version for the VM. This will pick a fully patched image of this given Windows version. Allowed values: 2008-R2-SP1, 2012-Datacenter, 2012-R2-Datacenter.')
@allowed([
  '2008-R2-SP1'
  '2012-Datacenter'
  '2012-R2-Datacenter'
])
param windowsOSVersion string = '2012-R2-Datacenter'
param newNsgName string
param nicName string = 'NicForVM'
param virtualNetworkName string = 'VirtualNetworkForVM'
param vmExtensionName string = 'AntiMalware'

@description('The name of an existing storage account to which diagnostics data will be transferred.')
param existingdiagnosticsStorageAccountName string

@description('The resource group for the storage account specified in existingdiagnosticsStorageAccountName')
param existingdiagnosticsStorageResourceGroup string

var apiVersion = '2015-06-15'
var imagePublisher = 'MicrosoftWindowsServer'
var imageOffer = 'WindowsServer'
var OSDiskName = 'osdiskforwindowssimple'
var addressPrefix = '10.0.0.0/16'
var subnetName = 'Subnet'
var subnetPrefix = '10.0.0.0/24'
var storageAccountType = 'Standard_LRS'
var publicIPAddressName_var = 'PublicIpAddressForVM'
var publicIPAddressType = 'Dynamic'
var vmStorageAccountContainerName = 'vhds'
var vmSize = 'Standard_A2'
var vnetID = virtualNetworkName_resource.id
var subnetRef = '${vnetID}/subnets/${subnetName}'
var accountid = '/subscriptions/${subscription().subscriptionId}/resourceGroups/${existingdiagnosticsStorageResourceGroup}/providers/Microsoft.Storage/storageAccounts/${existingdiagnosticsStorageAccountName}'
var wadlogs = '<WadCfg> <DiagnosticMonitorConfiguration overallQuotaInMB="4096" xmlns="http://schemas.microsoft.com/ServiceHosting/2010/10/DiagnosticsConfiguration"> <DiagnosticInfrastructureLogs scheduledTransferLogLevelFilter="Error"/> <WindowsEventLog scheduledTransferPeriod="PT1M" > <DataSource name="Application!*[System[(Level = 1 or Level = 2)]]" /> <DataSource name="Security!*[System[(Level = 1 or Level = 2)]]" /> <DataSource name="System!*[System[(Level = 1 or Level = 2)]]" /></WindowsEventLog>'
var wadperfcounters1 = '<PerformanceCounters scheduledTransferPeriod="PT1M"><PerformanceCounterConfiguration counterSpecifier="\\Processor(_Total)\\% Processor Time" sampleRate="PT15S" unit="Percent"><annotation displayName="CPU utilization" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Processor(_Total)\\% Privileged Time" sampleRate="PT15S" unit="Percent"><annotation displayName="CPU privileged time" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Processor(_Total)\\% User Time" sampleRate="PT15S" unit="Percent"><annotation displayName="CPU user time" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Processor Information(_Total)\\Processor Frequency" sampleRate="PT15S" unit="Count"><annotation displayName="CPU frequency" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\System\\Processes" sampleRate="PT15S" unit="Count"><annotation displayName="Processes" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Process(_Total)\\Thread Count" sampleRate="PT15S" unit="Count"><annotation displayName="Threads" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Process(_Total)\\Handle Count" sampleRate="PT15S" unit="Count"><annotation displayName="Handles" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Memory\\% Committed Bytes In Use" sampleRate="PT15S" unit="Percent"><annotation displayName="Memory usage" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Memory\\Available Bytes" sampleRate="PT15S" unit="Bytes"><annotation displayName="Memory available" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Memory\\Committed Bytes" sampleRate="PT15S" unit="Bytes"><annotation displayName="Memory committed" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\Memory\\Commit Limit" sampleRate="PT15S" unit="Bytes"><annotation displayName="Memory commit limit" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\% Disk Time" sampleRate="PT15S" unit="Percent"><annotation displayName="Disk active time" locale="en-us"/></PerformanceCounterConfiguration>'
var wadperfcounters2 = '<PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\% Disk Read Time" sampleRate="PT15S" unit="Percent"><annotation displayName="Disk active read time" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\% Disk Write Time" sampleRate="PT15S" unit="Percent"><annotation displayName="Disk active write time" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Transfers/sec" sampleRate="PT15S" unit="CountPerSecond"><annotation displayName="Disk operations" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Reads/sec" sampleRate="PT15S" unit="CountPerSecond"><annotation displayName="Disk read operations" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Writes/sec" sampleRate="PT15S" unit="CountPerSecond"><annotation displayName="Disk write operations" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Bytes/sec" sampleRate="PT15S" unit="BytesPerSecond"><annotation displayName="Disk speed" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Read Bytes/sec" sampleRate="PT15S" unit="BytesPerSecond"><annotation displayName="Disk read speed" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\PhysicalDisk(_Total)\\Disk Write Bytes/sec" sampleRate="PT15S" unit="BytesPerSecond"><annotation displayName="Disk write speed" locale="en-us"/></PerformanceCounterConfiguration><PerformanceCounterConfiguration counterSpecifier="\\LogicalDisk(_Total)\\% Free Space" sampleRate="PT15S" unit="Percent"><annotation displayName="Disk free space (percentage)" locale="en-us"/></PerformanceCounterConfiguration></PerformanceCounters>'
var wadcfgxstart = '${wadlogs}${wadperfcounters1}${wadperfcounters2}<Metrics resourceId="'
var wadmetricsresourceid = '/subscriptions/${subscription().subscriptionId}/resourceGroups/${resourceGroup().name}/providers/Microsoft.Compute/virtualMachines/'
var wadcfgxend = '"><MetricAggregation scheduledTransferPeriod="PT1H"/><MetricAggregation scheduledTransferPeriod="PT1M"/></Metrics></DiagnosticMonitorConfiguration></WadCfg>'

resource newNsgName_resource 'Microsoft.Network/networkSecurityGroups@2017-06-01' = {
  name: newNsgName
  location: resourceGroup().location
  properties: {
    securityRules: []
  }
  dependsOn: []
}

resource newStorageAccountName_resource 'Microsoft.Storage/storageAccounts@2015-06-15' = {
  name: newStorageAccountName
  location: resourceGroup().location
  properties: {
    accountType: storageAccountType
    supportsHttpsTrafficOnly: true
  }
}

resource publicIPAddressName 'Microsoft.Network/publicIPAddresses@2015-06-15' = {
  name: publicIPAddressName_var
  location: resourceGroup().location
  properties: {
    publicIPAllocationMethod: publicIPAddressType
    dnsSettings: {
      domainNameLabel: dnsNameForPublicIP
    }
  }
}

resource virtualNetworkName_resource 'Microsoft.Network/virtualNetworks@2015-06-15' = {
  name: virtualNetworkName
  location: resourceGroup().location
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
            id: newNsgName_resource.id
          }
        }
      }
    ]
  }
}

resource nicName_resource 'Microsoft.Network/networkInterfaces@2015-06-15' = {
  name: nicName
  location: resourceGroup().location
  properties: {
    enableIPForwarding: false
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: {
            id: publicIPAddressName.id
          }
          subnet: {
            id: subnetRef
          }
        }
      }
    ]
  }
}

resource vmName_resource 'Microsoft.Compute/virtualMachines@2015-06-15' = {
  name: vmName
  location: resourceGroup().location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    hardwareProfile: {
      vmSize: vmSize
    }
    osProfile: {
      computerName: vmName
      adminUsername: adminUsername
      adminPassword: adminPassword
    }
    storageProfile: {
      imageReference: {
        publisher: imagePublisher
        offer: imageOffer
        sku: windowsOSVersion
        version: 'latest'
      }
      osDisk: {
        name: 'osdisk'
        vhd: {
          uri: 'http://${newStorageAccountName}.blob.core.windows.net/${vmStorageAccountContainerName}/${OSDiskName}.vhd'
        }
        caching: 'ReadWrite'
        createOption: 'FromImage'
      }
    }
    networkProfile: {
      networkInterfaces: [
        {
          id: nicName_resource.id
        }
      ]
    }
    diagnosticsProfile: {
      bootDiagnostics: {
        enabled: true
        storageUri: 'http://${existingdiagnosticsStorageAccountName}.blob.core.windows.net'
      }
    }
  }
  dependsOn: [
    newStorageAccountName_resource
  ]
}

resource vmName_Microsoft_Insights_VMDiagnosticsSettings 'Microsoft.Compute/virtualMachines/extensions@[variables(\'apiVersion\')]' = {
  name: '${vmName}/Microsoft.Insights.VMDiagnosticsSettings'
  location: resourceGroup().location
  tags: {
    displayName: 'AzureDiagnostics'
  }
  properties: {
    publisher: 'Microsoft.Azure.Diagnostics'
    type: 'IaaSDiagnostics'
    typeHandlerVersion: '1.5'
    autoUpgradeMinorVersion: true
    settings: {
      xmlCfg: base64(concat(wadcfgxstart, wadmetricsresourceid, vmName, wadcfgxend))
      storageAccount: existingdiagnosticsStorageAccountName
    }
    protectedSettings: {
      storageAccountName: existingdiagnosticsStorageAccountName
      storageAccountKey: listkeys(accountid, apiVersion).key1
      storageAccountEndPoint: 'https://core.windows.net'
    }
  }
  dependsOn: [
    vmName_resource
  ]
}

resource vmName_vmExtensionName 'Microsoft.Compute/virtualMachines/extensions@2015-05-01-preview' = {
  parent: vmName_resource
  name: '${vmExtensionName}'
  location: resourceGroup().location
  properties: {
    publisher: 'Microsoft.Azure.Security'
    type: 'IaaSAntimalware'
    typeHandlerVersion: '1.1'
    settings: {
      AntimalwareEnabled: 'true'
      Exclusions: {
        Paths: 'C:\\Users'
        Extensions: '.txt'
        Processes: 'taskmgr.exe'
      }
      RealtimeProtectionEnabled: 'true'
      ScheduledScanSettings: {
        isEnabled: 'true'
        scanType: 'Quick'
        day: '7'
        time: '120'
      }
    }
    protectedSettings: null
  }
}

resource vmName_GuestConfigForWindows 'Microsoft.Compute/virtualMachines/extensions@2015-05-01-preview' = {
  parent: vmName_resource
  name: 'GuestConfigForWindows'
  location: resourceGroup().location
  properties: {
    publisher: 'Microsoft.GuestConfiguration'
    type: 'ConfigurationForWindows'
    typeHandlerVersion: '1.11'
    autoUpgradeMinorVersion: true
  }
}