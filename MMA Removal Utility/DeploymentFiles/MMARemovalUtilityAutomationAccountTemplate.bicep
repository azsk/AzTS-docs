@description('Specify the name of automation account to be created.\r\nUse only alphanumerics and hyphens.\r\nThe name must not start or end with alphanumeric and must be 6 - 50 characters in length.\r\n')
param automationAccountName string

@description('Enter location. If you leave this field blank resource group location would be used.')
param location string = resourceGroup().location

resource automationAccount 'Microsoft.Automation/automationAccounts@2022-08-08' = {
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

resource microsoftGraphAuthentication 'Microsoft.Automation/automationAccounts/modules@2022-08-08' = {
  name: 'Microsoft.Graph.Authentication'
  location: location
  parent: automationAccount
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/Microsoft.Graph.Authentication/1.27.0'
    }
  }
}

resource msIdentityTools 'Microsoft.Automation/automationAccounts/modules@2022-08-08' = {
  name: 'MSIdentityTools'
  location: location
  parent: automationAccount
  properties: {
    contentLink: {
      uri: 'https://www.powershellgallery.com/api/v2/package/MSIdentityTools/2.0.42'
    }
  }
  dependsOn: [
    microsoftGraphAuthentication
  ]
}

output automationAccountManagedIdentity string = automationAccount.identity.principalId


