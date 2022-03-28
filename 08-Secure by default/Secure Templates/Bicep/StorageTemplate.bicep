@description('The name of the new storage account to create.')
param storageaccount string

@description('The name of the alert for blob to create.')
param alertrule_blob string

@description('The name of the alert for file to create.')
param alertrule_file string

@description('The name of the alert for queue to create.')
param alertrule_queue string

@description('The name of the alert for table to create.')
param alertrule_table string

resource alertrule_blob_resource 'microsoft.insights/alertrules@2014-04-01' = {
  name: alertrule_blob
  location: 'southcentralus'
  properties: {
    name: alertrule_blob
    description: 'This metric alert rule was created from Powershell version: 3.1.0'
    isEnabled: true
    condition: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition'
      dataSource: {
        'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleMetricDataSource'
        resourceUri: '${storageaccount_resource.id}/services/blob'
        metricName: 'AnonymousSuccess'
      }
      operator: 'GreaterThan'
      threshold: 0
      windowSize: 'PT1H'
    }
    action: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleEmailAction'
      sendToServiceOwners: true
      customEmails: []
    }
  }
}

resource alertrule_file_resource 'microsoft.insights/alertrules@2014-04-01' = {
  name: alertrule_file
  location: 'southcentralus'
  properties: {
    name: alertrule_file
    description: 'This metric alert rule was created from Powershell version: 3.1.0'
    isEnabled: true
    condition: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition'
      dataSource: {
        'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleMetricDataSource'
        resourceUri: '${storageaccount_resource.id}/services/file'
        metricName: 'AnonymousSuccess'
      }
      operator: 'GreaterThan'
      threshold: 0
      windowSize: 'PT1H'
    }
    action: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleEmailAction'
      sendToServiceOwners: true
      customEmails: []
    }
  }
}

resource alertrule_queue_resource 'microsoft.insights/alertrules@2014-04-01' = {
  name: alertrule_queue
  location: 'southcentralus'
  scale: null
  properties: {
    name: alertrule_queue
    description: 'This metric alert rule was created from Powershell version: 3.1.0'
    isEnabled: true
    condition: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition'
      dataSource: {
        'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleMetricDataSource'
        resourceUri: '${storageaccount_resource.id}/services/queue'
        metricName: 'AnonymousSuccess'
      }
      operator: 'GreaterThan'
      threshold: 0
      windowSize: 'PT1H'
    }
    action: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleEmailAction'
      sendToServiceOwners: true
      customEmails: []
    }
  }
}

resource alertrule_table_resource 'microsoft.insights/alertrules@2014-04-01' = {
  name: alertrule_table
  location: 'southcentralus'
  scale: null
  properties: {
    name: alertrule_table
    description: 'This metric alert rule was created from Powershell version: 3.1.0'
    isEnabled: true
    condition: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.ThresholdRuleCondition'
      dataSource: {
        'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleMetricDataSource'
        resourceUri: '${storageaccount_resource.id}/services/table'
        metricNamespace: null
        metricName: 'AnonymousSuccess'
      }
      operator: 'GreaterThan'
      threshold: 0
      windowSize: 'PT1H'
    }
    action: {
      'odata.type': 'Microsoft.Azure.Management.Insights.Models.RuleEmailAction'
      sendToServiceOwners: true
      customEmails: []
    }
  }
}

resource storageaccount_resource 'Microsoft.Storage/storageAccounts@2017-10-01' = {
  sku: {
    name: 'Standard_GRS'
    tier: 'Standard'
  }
  kind: 'Storage'
  name: storageaccount
  location: 'southcentralus'
  tags: {}
  properties: {
    encryption: {
      keySource: 'Microsoft.Storage'
      services: {
        blob: {
          enabled: true
        }
        file: {
          enabled: true
        }
      }
    }
    supportsHttpsTrafficOnly: true
  }
  dependsOn: []
}