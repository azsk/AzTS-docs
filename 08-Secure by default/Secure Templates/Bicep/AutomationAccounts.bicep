@description('Specify the name of automation account to be created.\r\nUse only alphanumerics and hyphens.\r\nThe name must not start or end with alphanumeric and must be 6 - 50 characters in length.\r\n')
param automationAccountName string

@description('Enter location. If you leave this field blank resource group location would be used.')
param location string = resourceGroup().location

@description('Specify the name of automation account\'s variable')
param automationAccountVariableName string

@description('Specify the value of automation account\'s variable')
param automationAccountVariableValue string

@description('Specify the description of automation account\'s variable')
param automationAccountVariableDescription string

resource automationAccount 'Microsoft.Automation/automationAccounts@2020-01-13-preview' = {
  name: automationAccountName
  location: location
  identity: {
    type: 'SystemAssigned'
  }
  properties: {
    sku: {
      name: 'Basic'
    }
  }
}

resource automationAccountName_automationAccountVariable 'Microsoft.Automation/automationAccounts/variables@2022-08-08' = {
  parent: automationAccount
  name: automationAccountVariableName
  properties: {
    description: automationAccountVariableDescription
    isEncrypted: true
    value: '"${automationAccountVariableValue}"'
  }
}
