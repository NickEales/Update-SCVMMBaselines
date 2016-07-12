<# 
.Synopsis 
   Sample script to automatically keep SCVMM Baselines in sync with WSUS  
.DESCRIPTION 
   Script that synchronizes WSUS Updates with SCVMM, both adding new updates and removes old inactive updates.  
.EXAMPLE 
   .\Update-SCVMMBaseLines [-VMMServer VMMServerName] [-Verbose]

# Last updated 13 July 2016
 
# Author 
Current Author, Nick Eales, Microsoft

Based on script by Mikael Nyström @Truesec, available here:
https://gallery.technet.microsoft.com/scriptcenter/SCVMM-Automatic-Baseline-8779597b
#>

[CmdletBinding()]
Param([string]$VMMServer)
if($VMMServer -ne [string]::Empty){Get-SCVMMServer -ComputerName $VMMServer | out-null}

Function Update-SingleScvmmBaseline{ 
    [CmdletBinding()]
    Param ( 
    [Parameter(Mandatory=$false, 
    ValueFromPipeline=$true, 
    ValueFromPipelineByPropertyName=$true, 
    ValueFromRemainingArguments=$false, 
    Position=0)] 
    [String] 
    $BaseLineName
    ) 
  
    write-host "Starting Baseline '$BaselineName'" -foregroundcolor Green

    $baseline = Get-SCBaseline -Name $BaseLineName 
    if($Baseline -eq $NULL){
        Write-Host "Baseline '$BaselineName' not found - adding to VMM with all managed computers in scope"
        Add-Baseline -BaseLineName $BaseLineName
    }

    #directly connecting to WSUS for list of update - This gives far more reliable filtering than using SCVMM 
    write-host "$($baseline.UpdateCount) : Current updates in Baseline '$BaseLineName'"
    $SCUpdateServer = Get-SCUpdateServer
    $wsus = Get-WSUSServer -name $SCUpdateServer.Name -portnumber $SCUpdateServer.Port

    write-verbose "Get list of updates from WSUS for this classification"
    $AllUpdates=$Wsus.GetUpdates() | 
        where {
            $_.UpdateClassificationTitle -eq $baselineName -and 
            $_.IsSuperseded -eq $False -and 
            $_.IsApproved -eq $true -and 
            $_.isBeta -eq $false -and 
            $_.isdeclined -eq $false -and 
            $_.islatestrevision -eq $true -and 
            $_.publicationstate -ne "Expired" -and 
            $_.title -notmatch "itanium" 
        }
    write-verbose "$($AllUpdates.count) Updates found of classification '$baselineName' that are approved in WSUS and not superseded or expired"

    # Get list of operating systems in use on the computers managed by SCVMM
    # - will use WMI to query some managed computers for OS version. 
    $VMHostOSs=get-scvmhost | Where {$_.operatingSystem -match "(\S+\sServer\s\d+\s\S\d)|(\S+\sServer\s\d+)|(\S+\sServer)"} | %{$matches[0]}
    $VMMManagedComputerOSs = get-scvmmmanagedcomputer | where role -ne Host | select -unique FQDN | where {(Get-WmiObject -class Win32_OperatingSystem -ComputerName $_.FQDN -ErrorAction SilentlyContinue -WarningAction SilentlyContinue).caption -match "(\S+\sServer\s\d+\s\S\d)|(\S+\sServer\s\d+)|(\S+\sServer)"} | %{$matches[0]}
    $OperatingSystems = @($VMHostOSs) + @($VMMManagedComputerOSs) | select -Unique

    write-verbose "Filtering to operating systems: $($OperatingSystems -join ',')"
    $UpdatesToUse = @()
    foreach($os in $OperatingSystems){
        $UpdatesToUse += $allupdates | where {$_.ProductTitles -contains $OS -or $_.ProductTitles -notmatch "^Windows" -or $_.ProductTitles -match "$OS$"}
    }
    write-verbose "$($UpdatesToUse.count) Updates found for included operating systems."

    #Filter list of updates to those not currently in baseline
    $AddedUpdates = $UpdatesToUse | where {$baseline.Updates.updateid -notcontains $_.id.updateid.guid}
    #Convert list to type that we can use for Set-SCBaseline
    $addedUpdateList = get-scupdate | where {$AddedUpdates.id.updateid.guid -contains $_.updateid.GUID}

    write-host "$($addedUpdateList.Count) : New updates to add in to baseline '$BaseLineName'"
    if(($addedUpdateList| measure).count -gt 0){
        Set-SCBaseline -Baseline $baseline -Name $BaseLineName -Description $BaseLineName -AddUpdates $addedUpdateList  | ft ObjectType,name,updatecount -autosize
    }
     
    write-verbose "Scan WSUS for Updates that should not be Checked anymore"  
    $removeUpdateList = $baseline.Updates | Where {$UpdatesToUse.id.updateid.guid -notcontains $_.updateid}

    write-host "$($removeUpdateList.count) : Updates to remove from baseline '$BaseLineName'"
    if(($removeUpdateList | measure).count -gt 0){
        Set-SCBaseline -Baseline $baseline -Name $BaseLineName -Description $BaseLineName -RemoveUpdates $RemoveupdateList  | ft ObjectType,name,updatecount -autosize
    }
} 

Function Add-BaseLine{ 
  Param ( 
  [Parameter(Mandatory=$false, 
  ValueFromPipeline=$true, 
  ValueFromPipelineByPropertyName=$true, 
  ValueFromRemainingArguments=$false, 
  Position=0)] 
  [String] 
  $BaseLineName 
  ) 

  $baseline = New-SCBaseline -Name $BaseLineName -Description $BaseLineName 
  $scope = Get-SCVMHostGroup -Name "All Hosts" 
  Set-SCBaseline -Baseline $baseline -AddAssignmentScope $scope 
  $scope2 = Get-SCVMMManagedComputer  | where role -ne "Host"

  ForEach($Server in $scope2){ 
  Set-SCBaseline -Baseline $baseline -Name $baseLine -AddAssignmentScope $Server 
  } 
} 

Write-Host "Synchronizing WSUS Server with VMM"  
Get-SCUpdateServer | Start-SCUpdateServerSynchronization | FL ServerType,UpstreamServerName,Version,Name,SynchronizationType,SynchronizationTimeOfTheDay

. Update-SingleScvmmBaseline -BaseLineName "Security Updates" 
. Update-SingleScvmmBaseline -BaseLineName "Critical Updates" 
. Update-SingleScvmmBaseline -BaseLineName "Updates" 
. Update-SingleScvmmBaseline -BaseLineName "Update Rollups" 
. Update-SingleScvmmBaseline -BaseLineName "Hotfix" 
 
write-host "Start Compliance Scan for all Servers"  
Get-SCVMMManagedComputer | sort name | Start-SCComplianceScan -RunAsynchronously | FT Name,StatusString
