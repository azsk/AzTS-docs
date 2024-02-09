@description('Describes plan\'s pricing tier and capacity. Check details at https://azure.microsoft.com/en-us/pricing/details/app-service/')
@allowed([
  'F1'
  'D1'
  'B1'
  'B2'
  'B3'
  'S1'
  'S2'
  'S3'
  'P1'
  'P2'
  'P3'
  'P3V2'
  'P2V2'
  'P4'
  'EP3'
  'EP1'
  'Y1'
])
param skuName string = 'Y1'

@description('Describes plan\'s pricing tier and capacity. Check details at https://azure.microsoft.com/en-us/pricing/details/app-service/')
@allowed([
  'Dynamic'
])
param skuTier string = 'Dynamic'

@description('Describes plan\'s instance count')
@minValue(1)
param skuCapacity int = 1

@allowed([
  'Standard_LRS'
  'Standard_ZRS'
  'Standard_GRS'
  'Standard_RAGRS'
  'Premium_LRS'
])
param storageSKU string = 'Standard_LRS'

@description('The language worker runtime to load in the function app.')
@allowed([
  'dotnet'
])
param runtime string = 'dotnet'
param applicationInsightsName string = '-AppInsights-'
param internalMIName string = '-InternalMI-'

@description('Pricing tier: PerGB2018 or legacy tiers (Free, Standalone, PerNode, Standard or Premium) which are not available to all customers.')
@allowed([
  'pergb2018'
  'Free'
  'Standalone'
  'PerNode'
  'Standard'
  'Premium'
])
param laSkuName string = 'pergb2018'
param MIResourceId string
param TenantId string
param ResourceHash string

@allowed([
  'AzureCloud'
  'AzureGovernmentCloud',
  'AzureChinaCloud'
])
param AzureEnvironmentName string = 'AzureCloud'
param IsClientSecretAuthMode bool = false

@description('Key Vault Secret Uri for Central scanning App\'s credential in multi-tenant setup')
param ClientSecretUri string = ''

@description('Application Id of central scanning identity in multi-tenant setup')
param ClientApplicationId string = ''

@description('Queue name for scope resolver processor.')
param ScopeResolverProcessorQueueName string = 'scoperesolverqueue'

@description('Queue name for extension inventory processor.')
param ExtensionInventoryProcessorQueueName string = 'vmextensionprocessor'

@description('Queue name for extension removal processor.')
param ExtensionRemovalProcessorQueueName string = 'extensionremovalqueue'

@description('Queue name for extension removal processor.')
param ExtensionRemovalStatucCheckProcessorQueueName string = 'extensionremovalstatuscheckqueue'

@description('Zip package url for Scope Resolver Trigger Processor.')
param ScopeResolverTriggerProcessorPackageUrl string = ''

@description('Zip package url for Scope Resolver Processor.')
param ScopeResolverProcessorPackageUrl string = ''

@description('Zip package url for Scope Resolver Processor.')
param ExtensionInventoryProcessorPackageUrl string = ''

@description('Zip package url for Scope Resolver Processor.')
param WorkItemSchedulerProcessorPackageUrl string = ''

@description('Zip package url for Extension Removal Processor.')
param ExtensionRemovalProcessorPackageUrl string = ''

@description('Zip package url for Extension Removal Processor.')
param ExtensionRemovalStatusCheckProcessorPackageUrl string = ''

@description('Anonymous usage telemetry level as per user\'s choice.')
param AnonymousUsageTelemetryLogLevel string = 'None'

@description('Organization name where setup being installed.')
param OrganizationName string = 'NA'

@description('Division name where setup being installed.')
param DivisionName string = 'NA'

@description('Contact email address.')
param ContactEmailAddressList string = 'NA'

@description('Hashed setup host tenant Id.')
param HashedTenantId string = ''

@description('Hashed setup host Resource Group Id.')
param HashedResourceGroupId string = 'NA'

@description('Host Resource Group Id.')
param location string = resourceGroup().location

var SolutionInitialName = 'MMARemovalUtility'
var ScopeResolverTriggerProcessorName = '${SolutionInitialName}-ScopeResolverTrigger-${ResourceHash}'
var ScopeResolverProcessorName = '${SolutionInitialName}-ScopeResolver-${ResourceHash}'
var WorkItemSchedulerProcessorName = '${SolutionInitialName}-WorkItemScheduler-${ResourceHash}'
var ExtensionInventoryProcessorName = '${SolutionInitialName}-ExtensionInventory-${ResourceHash}'
var ExtensionRemovalProcessorName = '${SolutionInitialName}-ExtensionRemoval-${ResourceHash}'
var ExtensionRemovalStatusCheckProcessorName = '${SolutionInitialName}-ExtensionRemovalStatusCheck-${ResourceHash}'
var WorkerHostingPlan1Name = '${SolutionInitialName}-AppServicePlan1-${ResourceHash}'
var WorkerHostingPlan2Name = '${SolutionInitialName}-AppServicePlan2-${ResourceHash}'
var WorkerHostingPlan3Name = '${SolutionInitialName}-AppServicePlan3-${ResourceHash}'
var WorkerHostingPlan4Name = '${SolutionInitialName}-AppServicePlan4-${ResourceHash}'
var WorkerHostingPlan5Name = '${SolutionInitialName}-AppServicePlan5-${ResourceHash}'
var SchedulerHostingPlanName = '${SolutionInitialName}-SchedulerHostingPlan-${ResourceHash}'
var LogicAppWorkflowName = '${SolutionInitialName}-Restart-LogicApp-${ResourceHash}'
var functionWorkerRuntime = runtime
var storageName = toLower('${SolutionInitialName}${ResourceHash}')
var workspaceName = '${SolutionInitialName}-LAWorkspace-${ResourceHash}'
var applicationInsightsNameVar = '${SolutionInitialName}${applicationInsightsName}${ResourceHash}'
var internalMINameVar = '${SolutionInitialName}${internalMIName}${ResourceHash}'
var rgRoleAssignmentGuid = guid(resourceGroup().id)
var contributorRoleId = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/b24988ac-6180-42a0-ab88-20f7382dd24c'
var rgRoleAssignmentName = rgRoleAssignmentGuid
var queueDataContributorRoleId = '${subscription().id}/providers/Microsoft.Authorization/roleDefinitions/974c5e8b-45b9-4653-ba55-5f855dd0fb88'
var userAssignedIdentities = {
  userAssignedManagedIdentity: {
    '${internalMI.id}': {}
    '${MIResourceId}': {}
  }
  clientSecret: {
    '${internalMI.id}': {}
  }
}
var ConnectionName = 'MMA-AgentRemoval-Restart-LogicApp-Connection-${ResourceHash}'
var ConnectionAPI = '/subscriptions/${subscription().subscriptionId}/providers/Microsoft.Web/locations/${location}/managedApis/azureappservice'
var ResourceGroupName = resourceGroup().name
var SubscriptionId = subscription().subscriptionId


resource storage 'Microsoft.Storage/storageAccounts@2022-05-01' = {
  name: storageName
  location: location
  sku: {
    name: storageSKU
  }
  properties: {
    supportsHttpsTrafficOnly: true
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    defaultToOAuthAuthentication: true
  }
  tags: {
    displayName: SolutionInitialName
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  kind: 'StorageV2'
  dependsOn: []
}

resource workspace 'Microsoft.OperationalInsights/workspaces@2021-12-01-preview' = {
  name: workspaceName
  location: location
  tags: {
    displayName: SolutionInitialName
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    sku: {
      name: laSkuName
    }
    retentionInDays: 30
    features: {
      searchVersion: 1
      legacy: 0
      enableLogAccessUsingOnlyResourcePermissions: true
    }
  }
}

resource internalMI 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: internalMINameVar
  location: location
  tags: {
    displayName: SolutionInitialName
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
}

resource WorkerHostingPlan1 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: WorkerHostingPlan1Name
  location: location
  tags: {
    displayName: 'WorkerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: WorkerHostingPlan1Name
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource WorkerHostingPlan2 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: WorkerHostingPlan2Name
  location: location
  tags: {
    displayName: 'WorkerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: WorkerHostingPlan2Name
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource WorkerHostingPlan3 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: WorkerHostingPlan3Name
  location: location
  tags: {
    displayName: 'WorkerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: WorkerHostingPlan3Name
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource WorkerHostingPlan4 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: WorkerHostingPlan4Name
  location: location
  tags: {
    displayName: 'WorkerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: WorkerHostingPlan4Name
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource WorkerHostingPlan5 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: WorkerHostingPlan5Name
  location: location
  tags: {
    displayName: 'WorkerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: WorkerHostingPlan5Name
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource SchedulerHostingPlan1 'Microsoft.Web/serverfarms@2021-03-01' = {
  name: SchedulerHostingPlanName
  location: location
  tags: {
    displayName: 'SchedulerHostingPlan'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  sku: {
    name: skuName
    capacity: skuCapacity
    tier: skuTier
  }
  kind: 'functionapp'
  properties: {
    #disable-next-line BCP037
    name: SchedulerHostingPlanName
    #disable-next-line BCP037
    computeMode: skuTier
  }
}

resource ScopeResolverTriggerProcessor 'Microsoft.Web/sites@2018-11-01' = {
  name: ScopeResolverTriggerProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${WorkerHostingPlan1Name}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: ScopeResolverTriggerProcessorName
    httpsOnly: true
    serverFarmId: WorkerHostingPlan1.id
    #disable-next-line BCP037
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'ScopeResolverTriggerTimer'
          value: '0 0 5 * * *'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'StorageQueueConfiguration__DefaultQueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ScopeResolverProcessorQueueName}'
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: ScopeResolverTriggerProcessorPackageUrl
        }
      ]
    }
  }
}

resource ScopeResolverTriggerProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: ScopeResolverTriggerProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: ScopeResolverTriggerProcessorPackageUrl
  }
}

resource ScopeResolverTriggerProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ScopeResolverTriggerProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ScopeResolverTriggerProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ScopeResolverTriggerProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ScopeResolverProcessor 'Microsoft.Web/sites@2021-03-01' = {
  name: ScopeResolverProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${WorkerHostingPlan2Name}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: ScopeResolverProcessorName
    httpsOnly: true
    serverFarmId: WorkerHostingPlan2.id
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'ScopeResolverProcessorConnectionString'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AzureQueueConnectionString'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'StorageQueueConfiguration__DefaultQueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ScopeResolverProcessorQueueName}'
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: ScopeResolverProcessorPackageUrl
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
      ]
    }
  }
}

resource ScopeResolverProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: ScopeResolverProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: ScopeResolverProcessorPackageUrl
  }
}

resource ScopeResolverProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ScopeResolverProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ScopeResolverProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ScopeResolverProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionInventoryProcessor 'Microsoft.Web/sites@2021-03-01' = {
  name: ExtensionInventoryProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${WorkerHostingPlan3Name}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: ExtensionInventoryProcessorName
    httpsOnly: true
    serverFarmId: WorkerHostingPlan3.id
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'VMExtensionProcessorConnectionString'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'StorageQueueConfiguration__DefaultQueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ExtensionInventoryProcessorQueueName}'
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: ExtensionInventoryProcessorPackageUrl
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
      ]
    }
  }
}

resource ExtensionInventoryProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: ExtensionInventoryProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: ExtensionInventoryProcessorPackageUrl
  }
}

resource ExtensionInventoryProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionInventoryProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionInventoryProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionInventoryProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource WorkItemSchedulerProcessor 'Microsoft.Web/sites@2021-03-01' = {
  name: WorkItemSchedulerProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${SchedulerHostingPlanName}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: WorkItemSchedulerProcessorName
    httpsOnly: true
    serverFarmId: SchedulerHostingPlan1.id
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'InventoryCollectionSchedulerProcessorTimer'
          value: '0 0 12 * * *'
        }
        {
          name: 'ExtensionRemovalSchedulerProcessorTimer'
          value: '0 0 15 * * *'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'StorageQueueConfiguration__DefaultQueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ExtensionInventoryProcessorQueueName}'
        }
        {
          name: 'StorageQueueConfiguration__AdditionalQueues__0__QueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ExtensionRemovalProcessorQueueName}'
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: WorkItemSchedulerProcessorPackageUrl
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
      ]
    }
  }
}

resource WorkItemSchedulerProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: WorkItemSchedulerProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: WorkItemSchedulerProcessorPackageUrl
  }
}

resource WorkItemSchedulerProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: WorkItemSchedulerProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource WorkItemSchedulerProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: WorkItemSchedulerProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionRemovalProcessor 'Microsoft.Web/sites@2021-03-01' = {
  name: ExtensionRemovalProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${WorkerHostingPlan4Name}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: ExtensionRemovalProcessorName
    httpsOnly: true
    serverFarmId: WorkerHostingPlan4.id
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'ExtensionRemovalProcessorConnectionString'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'StorageQueueConfiguration__DefaultQueueUri'
          value: 'https://${storageName}.queue.${environment().suffixes.storage}/${ExtensionRemovalStatucCheckProcessorQueueName}'
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: ExtensionRemovalProcessorPackageUrl
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
      ]
    }
  }
}

resource ExtensionRemovalProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: ExtensionRemovalProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: ExtensionRemovalProcessorPackageUrl
  }
}

resource ExtensionRemovalProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionRemovalProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionRemovalProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionRemovalProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionRemovalStatusCheckProcessor 'Microsoft.Web/sites@2021-03-01' = {
  name: ExtensionRemovalStatusCheckProcessorName
  location: location
  kind: 'functionapp'
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: (IsClientSecretAuthMode ? userAssignedIdentities.clientSecret : userAssignedIdentities.userAssignedManagedIdentity)
  }
  tags: {
    'hidden-related:${resourceGroup().id}/providers/Microsoft.Web/serverfarms/${WorkerHostingPlan5Name}': 'Resource'
    displayName: 'Website'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP037
    name: ExtensionRemovalStatusCheckProcessorName
    httpsOnly: true
    serverFarmId: WorkerHostingPlan5.id
    keyVaultReferenceIdentity: (IsClientSecretAuthMode ? internalMI.id : 'SystemAssigned')
    siteConfig: {
      remoteDebuggingEnabled: false
      webSocketsEnabled: false
      requestTracingEnabled: true
      httpLoggingEnabled: true
      detailedErrorLoggingEnabled: true
      minTlsVersion: '1.2'
      netFrameworkVersion: 'v6.0'
      ftpsState: 'Disabled'
      appSettings: [
        {
          name: 'AzureFunctionsJobHost__functionTimeout'
          value: '00:10:00'
        }
        {
          name: 'AzureWebJobsStorage'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'ExtensionRemovalStatusCheckQueueConnectionString'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__AuthenticationMode'
          value: 'UserAssignedManagedIdentity'
        }
        {
          name: 'AADAuthProviderConfiguration__InternalIdentityConfigurations__ClientId'
          value: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').clientId
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__AuthenticationMode'
          value: (IsClientSecretAuthMode ? 'ClientSecret' : 'UserAssignedManagedIdentity')
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientId'
          value: (IsClientSecretAuthMode ? ClientApplicationId : reference(MIResourceId, '2018-11-30').clientId)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__ClientSecret'
          value: (IsClientSecretAuthMode ? ClientSecretUri : null)
        }
        {
          name: 'AADAuthProviderConfiguration__ScannerIdentityConfigurations__HostTenantId'
          value: TenantId
        }
        {
          name: 'WEBSITE_CONTENTAZUREFILECONNECTIONSTRING'
          value: 'DefaultEndpointsProtocol=https;AccountName=${storageName};EndpointSuffix=${environment().suffixes.storage};AccountKey=${listKeys(storage.id, '2019-06-01').keys[0].value}'
        }
        {
          name: 'WEBSITE_CONTENTSHARE'
          value: toLower(ScopeResolverTriggerProcessorName)
        }
        {
          name: 'FUNCTIONS_EXTENSION_VERSION'
          value: '~4'
        }
        {
          name: 'WEBSITE_NODE_DEFAULT_VERSION'
          value: '~10'
        }
        {
          name: 'APPINSIGHTS_INSTRUMENTATIONKEY'
          value: reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
        }
        {
          name: 'AIConfigurationOptions__ConnectionString'
          value: reference(applicationInsights.id, '2020-02-02-preview').ConnectionString
        }
        {
          name: 'LAConfigurations__ResourceId'
          value: workspace.id
        }
        {
          name: 'LAConfigurations__WorkspaceId'
          value: reference(workspace.id, '2017-03-15-preview').customerId
        }
        {
          name: 'FUNCTIONS_WORKER_RUNTIME'
          value: functionWorkerRuntime
        }
        {
          name: 'ProcessConfigurations__CloudEnvironmentName'
          value: AzureEnvironmentName
        }
        {
          name: 'WEBSITE_RUN_FROM_PACKAGE'
          value: ExtensionRemovalStatusCheckProcessorPackageUrl
        }
        {
          name: 'UsageTelemetryConfigurations__LogLevel'
          value: AnonymousUsageTelemetryLogLevel
        }
        {
          name: 'UsageTelemetryConfigurations__HostTenantId'
          value: HashedTenantId
        }
        {
          name: 'UsageTelemetryConfigurations__HostResourceGroupId'
          value: HashedResourceGroupId
        }
        {
          name: 'UsageTelemetryConfigurations__Organization'
          value: OrganizationName
        }
        {
          name: 'UsageTelemetryConfigurations__Division'
          value: DivisionName
        }
        {
          name: 'UsageTelemetryConfigurations__ContactEmailAddressList'
          value: ContactEmailAddressList
        }
      ]
    }
  }
}

resource ExtensionRemovalStatusCheckProcessor_MSDeploy 'Microsoft.Web/sites/Extensions@2018-11-01' = {
  parent: ExtensionRemovalStatusCheckProcessor
  name: 'MSDeploy'
  properties: {
    packageUri: ExtensionRemovalStatusCheckProcessorPackageUrl
  }
}

resource ExtensionRemovalStatusCheckProcessor_ftp 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionRemovalStatusCheckProcessor
  name: 'ftp'
  #disable-next-line BCP187
  location: location
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource ExtensionRemovalStatusCheckProcessor_scm 'Microsoft.Web/sites/basicPublishingCredentialsPolicies@2022-03-01' = {
  parent: ExtensionRemovalStatusCheckProcessor
  #disable-next-line BCP187
  location: location
  name: 'scm'
  kind: 'basicPublishingCredentialsPolicies'
  properties: {
    allow: false
  }
}

resource rgRoleAssignment 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: rgRoleAssignmentName
  properties: {
    #disable-next-line use-resource-id-functions
    roleDefinitionId: contributorRoleId
    principalId: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').principalId
    #disable-next-line BCP073
    scope: resourceGroup().id
  }
  dependsOn: [
    internalMI
  ]
}

resource Microsoft_Storage_storageAccounts_storage 'Microsoft.Authorization/roleAssignments@2022-04-01' = {
  name: guid(storage.id)
  properties: {
    #disable-next-line use-resource-id-functions
    roleDefinitionId: queueDataContributorRoleId
    principalId: reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').principalId
    #disable-next-line BCP073
    scope: resourceGroup().id
  }
  dependsOn: [

    internalMI
  ]
}

resource applicationInsights 'microsoft.insights/components@2020-02-02' = {
  name: applicationInsightsNameVar
  kind: 'web'
  location: location
  tags: {
    'hidden-link:${resourceId('Microsoft.Web/sites', applicationInsightsNameVar)}': 'Resource'
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    #disable-next-line BCP073 use-resource-id-functions
    ApplicationId: applicationInsightsNameVar
    Application_Type: 'web'
    Request_Source: 'rest'
  }
}

resource Connection 'Microsoft.Web/connections@2016-06-01' = {
  name: ConnectionName
  location: location
  #disable-next-line BCP187
  kind: 'V1'
  tags: {
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  properties: {
    displayName: ConnectionName
    customParameterValues: {}
    api: {
      #disable-next-line use-resource-id-functions
      id: ConnectionAPI
    }
    #disable-next-line BCP037
    parameterValueType: 'Alternative'
  }
}

resource LogicAppWorkflow 'Microsoft.Logic/workflows@2019-05-01' = {
  name: LogicAppWorkflowName
  location: location
  tags: {
    AzTSMMARemovalUtilityIdentifier: HashedResourceGroupId
  }
  identity: {
    type: 'UserAssigned'
    userAssignedIdentities: {
      '${internalMI.id}': {}
    }
  }
  properties: {
    state: 'Enabled'
    definition: {
      '$schema': 'https://schema.management.azure.com/providers/Microsoft.Logic/schemas/2016-06-01/workflowdefinition.json#'
      contentVersion: '1.0.0.0'
      parameters: {
        '$connections': {
          defaultValue: {}
          type: 'Object'
        }
      }
      triggers: {
        Recurrence: {
          recurrence: {
            frequency: 'Day'
            interval: 1
            schedule: {
              hours: [
                '23'
              ]
            }
          }
          type: 'Recurrence'
        }
      }
      actions: {
        Restart_ScopeResolverTriggerProcessor: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${ScopeResolverTriggerProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
        Restart_ScopeResolverProcessor: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${ScopeResolverProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
        Restart_WorkItemScheduler: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${WorkItemSchedulerProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
        Restart_ExtensionInventoryProcessor: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${ExtensionInventoryProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
        Restart_ExtensionRemovalProcessor: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${ExtensionRemovalProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
        Restart_ExtensionRemovalStatusCheckProcessor: {
          runAfter: {}
          type: 'ApiConnection'
          inputs: {
            host: {
              connection: {
                name: '@parameters(\'$connections\')[\'azureappservice\'][\'connectionId\']'
              }
            }
            method: 'post'
            path: '/subscriptions/@{encodeURIComponent(\'${SubscriptionId}\')}/resourcegroups/@{encodeURIComponent(\'${ResourceGroupName}\')}/providers/Microsoft.Web/sites/@{encodeURIComponent(\'${ExtensionRemovalStatusCheckProcessorName}\')}/restart'
            queries: {
              'api-version': '2019-08-01'
            }
          }
        }
      }
      outputs: {}
    }
    parameters: {
      '$connections': {
        value: {
          azureappservice: {
            connectionId: Connection.id
            connectionProperties: {
              authentication: {
                type: 'ManagedServiceIdentity'
                identity: internalMI.id
              }
            }
            id: ConnectionAPI
          }
        }
      }
    }
  }
}

output storageId string = storage.id
output internalMIObjectId string = reference('Microsoft.ManagedIdentity/userAssignedIdentities/${internalMINameVar}', '2018-11-30').principalId
output applicationInsightsId string = applicationInsights.id
output logAnalyticsResourceId string = workspace.id
output applicationInsightsIKey string = reference(applicationInsights.id, '2020-02-02-preview').InstrumentationKey
