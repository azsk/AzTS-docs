@description('Name of the Traffic Manager')
param trafficManagerName string

resource trafficManagerName_resource 'Microsoft.Network/trafficManagerProfiles@2017-03-01' = {
  name: trafficManagerName
  location: 'global'
  properties: {
    profileStatus: 'Enabled'
    trafficRoutingMethod: 'Weighted'
    dnsConfig: {
      relativeName: trafficManagerName
      fqdn: '${trafficManagerName}.trafficmanager.net'
      ttl: 30
    }
    monitorConfig: {
      protocol: 'HTTPS'
      port: 80
      path: '/'
    }
    endpoints: [
      {
        name: 'External-endpoint'
        type: 'Microsoft.Network/trafficManagerProfiles/externalEndpoints'
        properties: {
          endpointStatus: 'Enabled'
          target: 'www.google.com'
          weight: 1
          priority: 1
        }
      }
    ]
  }
  dependsOn: []
}