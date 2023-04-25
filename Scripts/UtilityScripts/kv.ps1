function Get-PublicIpRanges()
{
  <#
    .SYNOPSIS
    This command retrieves the Service Tags from the current Microsoft public IPs file download.
    .DESCRIPTION
    This command retrieves the Service Tags from the current Microsoft public IPs file download.
    .INPUTS
    None
    .OUTPUTS
    Service Tags
    .EXAMPLE
    PS> Get-PublicIpRanges
    .LINK
    None
  #>

  [CmdletBinding()]
  param()

  $fileMatch = "ServiceTags_Public"
  $ipRanges = @()

  $uri = "https://www.microsoft.com/en-us/download/confirmation.aspx?id=56519"

  $response = Invoke-WebRequest -Uri $uri

  $links = $response.Links | Where-Object {$_.href -match $fileMatch}

  if ($links -and $links.Count -gt 0)
  {
    $link = $links[0]

    if ($link)
    {
      $jsonUri = $link.href

      $response = Invoke-WebRequest -Uri $jsonUri | ConvertFrom-Json

      if ($response -and $response.values)
      {
        $ipRanges = $response.values
      }
    }
  }

  return $ipRanges
}

function Get-PublicIpRangesForServiceTags()
{
  <#
    .SYNOPSIS
    This command retrieves the IPv4 CIDRs for the specified Service Tags from the current Microsoft public IPs file download.
    .DESCRIPTION
    This command retrieves the IPv4 CIDRs for the specified Service Tags from the current Microsoft public IPs file download.
    .PARAMETER ServiceTags
    An array of one or more Service Tags from the Microsoft Public IP file at https://www.microsoft.com/en-us/download/details.aspx?id=53602.
    .INPUTS
    None
    .OUTPUTS
    Array of IPv4 CIDRs for the specified Service tags
    .EXAMPLE
    PS> Get-PublicIpRangesForServiceTags -ServiceTags @("DataFactory.EastUS", "DataFactory.WestUS")
    .LINK
    None
  #>

  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string[]]
      $ServiceTags
  )

  $ips = @()

  $ipRanges = Get-PublicIpRanges

  if ($ipRanges)
  {
    foreach($serviceTag in $ServiceTags)
    {
      $ipsForServiceTag = ($ipRanges | Where-Object {$_.name -eq $serviceTag})

      #Filter out IPV4 Only
      $ips += $ipsForServiceTag.Properties.AddressPrefixes | Where-Object {$_ -like "*.*.*.*/*"}
    }
  }

  $ips = $ips | Sort-Object

  return $ips
}

function Get-ServiceTagsForIp()
{
  [CmdletBinding()]
  param
  (
      [Parameter(Mandatory=$true)]
      [string]
      $IpAddress
  )


}