@description('Specify the name of the Azure Redis Cache instance to create.')
param redisCacheName string = 'redis-cache-${uniqueString(resourceGroup().id, utcNow())}'

@description('Specify the Azure region of the Azure Redis Cache instance to create. The default location is same as the enclosing Resource Group\'s location.')
param redisCacheLocation string = resourceGroup().location

@allowed([
  'Basic'
  'Premium'
  'Standard'
])
@description('Specify the pricing tier of the new Azure Redis Cache instance. The default SKU is \'Standard\'.')
param redisCacheSku string = 'Standard'

@allowed([
  'C'
  'P'
])
@description('Specify the family for the SKU. \'C\' = Basic/Standard, \'P\' = Premium. The default SKU family is \'C\'.')
param redisCacheFamily string = 'C'

@allowed([
  0
  1
  2
  3
  4
  5
  6
])
@description('Specify the size of the new Azure Redis Cache instance. Valid values: for C (Basic/Standard) family (0, 1, 2, 3, 4, 5, 6), for P (Premium) family (1, 2, 3, 4).')
param redisCacheCapacity int = 1

resource redisCache 'Microsoft.Cache/Redis@2019-07-01' = {
  name: redisCacheName
  location: redisCacheLocation
  properties: {
    sku: {
      capacity: redisCacheCapacity
      family: redisCacheFamily
      name: redisCacheSku
    }
    enableNonSslPort: false // Azure_RedisCache_DP_Use_SSL_Port - Disable non-SSL port.
    minimumTlsVersion:'1.2' //Azure_RedisCache_DP_Use_Secure_TLS_Version - TLS version set to 1.2
  }
}
