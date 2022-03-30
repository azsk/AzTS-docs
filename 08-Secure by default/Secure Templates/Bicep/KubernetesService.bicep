@description('The name of the Managed Cluster resource.')
param clusterName string

@description('The location of the Managed Cluster resource.')
param location string = resourceGroup().location

@description('Optional DNS prefix to use with hosted Kubernetes API server FQDN.')
param dnsPrefix string

@description('Disk size (in GB) to provision for each of the agent pool nodes. This value ranges from 0 to 1023. Specifying 0 will apply the default disk size for that agentVMSize.')
@minValue(0)
@maxValue(1023)
param osDiskSizeGB int = 0

@description('The number of nodes for the cluster.')
@minValue(1)
@maxValue(50)
param agentCount int = 3

@description('The size of the Virtual Machine.')
param agentVMSize string = 'Standard_D2s_v3'

@description('An array of AAD group object ids to give administrative access.')
param adminGroupObjectIDs array = []

resource clusterName_resource 'Microsoft.ContainerService/managedClusters@2021-07-01' = {
  name: clusterName
  location: location
  tags: {}
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    dnsPrefix: dnsPrefix
    enableRBAC: true //[Azure_KubernetesService_Deploy_Enable_Cluster_RBAC]
    aadProfile: {
      managed: true //[Azure_KubernetesService_AuthN_Enabled_AAD]
      adminGroupObjectIDs: adminGroupObjectIDs
      enableAzureRBAC: true
    }
    agentPoolProfiles: [
      {
        name: 'agentpool'
        osDiskSizeGB: osDiskSizeGB
        count: agentCount
        vmSize: agentVMSize
        osType: 'Linux'
        mode: 'System'
      }
    ]
  }
}

output controlPlaneFQDN string = clusterName_resource.properties.fqdn