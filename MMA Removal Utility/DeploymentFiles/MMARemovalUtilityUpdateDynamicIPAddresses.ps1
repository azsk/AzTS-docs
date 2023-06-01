function AddAzureFunctionAppRegionIPRangesOnKeyVault {
    param (
        $SubscriptionId,
        $KeyVaultResourceId,
        $FunctionAppUsageRegion,
        $RemoveExistingIPRanges = $false
    )
    Connect-AzAccount -Subscription $SubscriptionId -Identity
    Set-AzContext -SubscriptionId $SubscriptionId

    Write-Output "Downloading the Azure published IP ranges..."
    $location = Get-AzLocation | Where-Object { $_.Location -eq $FunctionAppUsageRegion -or $_.DisplayName -eq $FunctionAppUsageRegion} | Select-Object -First 1
    if ($null -ne $location)
    {
        $FunctionAppUsageRegion = $location.Location
    }
    else
    {
        Write-Output "Specified function app region $FunctionAppUsageRegion is invalid. Exiting..."
        return;
    }

    $IPRanges = Get-MsIdAzureIpRange -ServiceTag AppService -Region $FunctionAppUsageRegion

    Write-Output "Successfully downloaded the Azure published IP ranges..."
    Write-Output "Filtering the IP ranges for IPv4 addresses"
    $FilteredIPRanges = ($IPRanges | Where-Object {$_.Contains("::") -eq $false })

    # Remove existing IP Ranges if flag is set.
    if($RemoveExistingIPRanges -eq $true)
    {
        Write-Output "Overridding the IP Address ranges with the Azure IP ranges for specified function app region: $FunctionAppUsageRegion"
        Update-AzKeyVaultNetworkRuleSet -ResourceId $KeyVaultResourceId -IpAddressRange $FilteredIPRanges
        Write-Output "Successfully overridden the IP Address ranges with the Azure IP ranges for specified function app region: $FunctionAppUsageRegion"
    }
    else
    {
        Write-Output "Appending the IP Address ranges with the Azure IP ranges for specified function app region: $FunctionAppUsageRegion"
        Add-AzKeyVaultNetworkRule -ResourceId $KeyVaultResourceId -IpAddressRange $FilteredIPRanges
        Write-Output "Successfully appended the IP Address ranges with the Azure IP ranges for specified function app region: $FunctionAppUsageRegion"
    }
}

AddAzureFunctionAppRegionIPRangesOnKeyVault -SubscriptionId "<SubscriptionId>" -KeyVaultResourceId "<KeyVaultResourceId>" -FunctionAppUsageRegion "<FunctionAppUsageRegion>" -RemoveExistingIPRanges "<RemoveExistingIPRanges>"