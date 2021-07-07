Set-StrictMode -Version Latest

class ResourceResolver
{
	[string[]] $ExcludeResourceNames=@();
	[PSObject] $ExcludedResources=@();
	[string[]] $ExcludeResourceGroupNames=@();
	[string[]] $messageToPrint=@();
	
	ResourceResolver([string] $excludeResourceName , [string] $excludeResourceGroupName)
	{
		if(-not [string]::IsNullOrEmpty($excludeResourceName))
		{
			$this.ExcludeResourceNames += $this.ConvertToStringArray($excludeResourceName)
			if ($this.ExcludeResourceNames.Count -eq 0)
			{
				throw "The parameter 'ExcludeResourceNames' does not contain any valid value."
			}	
		}

		if(-not [string]::IsNullOrEmpty($excludeResourceGroupName))
		{
			$this.ExcludeResourceGroupNames += $this.ConvertToStringArray($excludeResourceGroupName)
			if ($this.ExcludeResourceGroupNames.Count -eq 0)
			{
				throw "The parameter 'ExcludeResourceGroupNames' does not contain any valid value."
			}	
		}
	}

	[string[]] ConvertToStringArray([string] $arrayString)
	{
		$result = @();
		if(-not [string]::IsNullOrWhiteSpace($arrayString))
		{
			$result += $arrayString.Split(',', [StringSplitOptions]::RemoveEmptyEntries) | 
							Where-Object { -not [string]::IsNullOrWhiteSpace($_) } |
							ForEach-Object { $_.Trim() } |
							Select-Object -Unique;
		}
		return $result;
	}

	#Method to filter resources based on exclude flags
	hidden [PSObject] ApplyResourceFilter([PSobject] $Resources)
	{	
		#First remove resource from the RGs specified in -ExcludeResourceGroupNames
		if(($this.ExcludeResourceGroupNames | Measure-Object).Count -gt 0)
		{
			$nonExistingRGS = @()
			$matchingRGs= $this.ExcludeResourceGroupNames | Where-Object{$_ -in $Resources.ResourceGroupName}
			$nonExistingRGS += $this.ExcludeResourceGroupNames | Where-Object{$_ -notin $matchingRGs}
			if(($nonExistingRGS| Measure-Object).Count -gt 0)
			{
				#print the message saying these RGS provided in excludeRGS are not found
				Write-Host "Warning: Following resource groups requested for exclusion not found in subscription:" -ForegroundColor Yellow
				Write-Host $nonExistingRGS
				Write-Host `n
			}

			if(($matchingRGs| Measure-Object).Count -gt 0 )
			{
				# Check if given exclude resource name belongs in one of the given resource group name
				if(($this.ExcludeResourceNames | Measure-Object).Count)
				{
					$coincidingResources = $Resources | Where-Object {$_.ResourceName -in $this.ExcludeResourceNames -and $_.ResourceGroupName -in $matchingRGs}
					if(($coincidingResources| Measure-Object).Count -gt 0)
					{
						# Updating ExcludeResourceNames with non-coinciding resources
						$this.ExcludeResourceNames = $this.ExcludeResourceNames | Where-Object {$_ -notin $coincidingResources.ResourceName}
						
						# Adding coinciding resources in ExcludedResources
						# ExcludedResources contain list of resources which are requested to exclude
						$this.ExcludedResources += $coincidingResources
						$this.messageToPrint += "Number of resources excluded due to excluding resource groups: $(($coincidingResources | Measure-Object).Count)"
						$this.messageToPrint += "$($coincidingResources | Select-Object -Property "ResourceGroupName", "ResourceName"| Sort-Object |Format-Table |Out-String)"
						
						# Updating matchingRGs with RGs of non-coinciding resources
						$matchingRGs = $matchingRGs | Where-Object { $_ -notin $coincidingResources.ResourceGroupName }
					}
				}

				# If no coinciding resource found then need to exclude given resource group name
				$this.ExcludedResources += $Resources| Where-Object{$_.ResourceGroupName -in $matchingRGs}
				$this.messageToPrint += "Number of resource group excluded explicitly: $(($matchingRGs | Measure-Object).Count)"
				$this.messageToPrint += "ResourceGroupName"
				$this.messageToPrint += "-----------------"				
				$this.messageToPrint += "$($matchingRGs | Sort-Object |Format-Table |Out-String)"
				$this.messageToPrint += "`n"
			}
		}
		
		$ExcludedRes = @();
		#Remove resources specified in -ExcludeResourceNames
		if(($this.ExcludeResourceNames | Measure-Object).Count -gt 0)
		{
			$NonExistingResource = @()
			$ResourcesToExclude =$this.ExcludeResourceNames
			
			# Checking ExcludeResourceNames are existing in subscription or not
			$NonExistingResource += $this.ExcludeResourceNames | Where-Object { $_ -notin $Resources.ResourceName}
			if(($NonExistingResource | Measure-Object).Count -gt 0 )
			{
				$ResourcesToExclude = $this.ExcludeResourceNames | Where-Object{ $_ -notin $NonExistingResource }
				Write-Host "Warning: Following resources requested for exclusion not found in subscription:" -ForegroundColor Yellow
				Write-Host $NonExistingResource
				Write-Host `n
			}	
			
			$ExcludedRes = $Resources | Where-Object{$_.ResourceName -in $ResourcesToExclude}
			$this.messageToPrint += "Number of resources excluded explicitly: $(($ExcludedRes | Measure-Object).Count)"
			$this.messageToPrint += "$($ExcludedRes | Select-Object -Property "ResourceGroupName", "ResourceName"| Sort-Object |Format-Table |Out-String)"
			$this.ExcludedResources += $ExcludedRes
		}
		$ResourcesToRemediate = $Resources | Where-Object {$_ -notin $this.ExcludedResources}
		return $ResourcesToRemediate
	}

    [void] static RemediationSummary([PSObject] $messageToPrint, [string] $path)
    {
        Write-Host "Remediation summary: $($path)" -ForegroundColor Cyan
        if(Test-Path $path)
        {
			$path = "$($path)\RemediationLog.txt"
            Add-Content -Value $messageToPrint -Path $path
        }
    }
}
