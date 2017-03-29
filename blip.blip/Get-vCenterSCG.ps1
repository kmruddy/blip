<#
	.Description
		This cmdlet checks vSphere Security Configuration Guideline (SCG) values from the module location for virtual machines and returns a list of non-compliant values

	.Synopsis
		This cmdlet checks virtual machines SCG compliance values

	.Notes
		Author: Steve Kaplan (steve@intolerable.net)
		Version History:

	.Example
		$results = Get-vCenterSCG -Server vCenter1.domain.local
		
		Description
		-----------
		Runs the STIG check for all documented findings on vCenter Server vCenter1.domain.local

	.Example
		$results = Get-vCenterSCG -Exclude vNetwork.limit-network-healthcheck
		
		Description
		-----------
		Runs the STIG check for all documented findings except 'vNetwork.limit-network-healthcheck' on all connected vCenter Servers

	.Example
		Get-vCenterSCG -Exclude vNetwork.limit-network-healthcheck -Export -Path C:\Temp\STIG
		
		Description
		-----------
		Runs the STIG check for all documented findings except 'vNetwork.limit-network-healthcheck' on all connected vCenter Servers and export the results to a file in C:\Temp\STIG

	.Parameter Server
		Specifies connected vCenter Server(s) to check STIG values on. If no value is passed to this parameter, the command runs on the default servers. For more information about default servers, see the description of Connect-VIServer.

	.Parameter All
		This will return the results for all values, not just those that were non-compliant (not recommended for more than a single VM)

	.Parameter Exclude
		A list of findings to be excluded from being checked / logged as part of the STIG check
	
	.Parameter Export
		Indicates that the results should be exported to a file rather than displayed in the shell window. Exported results will include all fields

	.Parameter Path
		The path where the exported results should be placed. File name will be generated automatically
#>
Function Get-vCenterSCG {
	[CmdletBinding(DefaultParameterSetName="None")]
	Param (
		[Parameter(Mandatory=$false,ValueFromPipeline=$true,Position=0)]
		[String[]]$Server,
		
		[Parameter(ParameterSetName="Exclusions")]
		[String[]]$Exclude,
		
		[Parameter(ParameterSetName="AllResults")]
		[Switch]$All,

		[Switch]$Export,
		[String]$Path = "c:\temp"
	)

	Begin {
		if ($Exclude -ne $null) { Write-Warning "The following STIG ID's will be excluded from being checked: $($Exclude -join ', ')" }

		$activity = "Checking vCenter Server Secuirity Configuration Guidelines"
		$EntityType = "vCenter"
		if ($Export) { $ExportResults = @() }
	}

	Process {
		$Servers = @()
		if ($Server -eq $null) { $Servers = $global:DefaultVIServers }
		else { 
			foreach ($vc in $Server) { 
				$vCenter = $global:DefaultVIServers | Where-Object { $_.Name -eq $vc }
				if ($vCenter) { $Servers += $vCenter }
			}
		}
		if ($Servers.count -eq 0) { Write-Error -Message "Not connected to any vCenter Servers. Please use Connect-VIServer to connect and try again." } 
		foreach ($entity in $Servers) {
			$results = @()

			# Advanced Option Checks (Many findings contained) -- DISA STIG Only
			#$results += Test-Checklist -Type vCenter

			# Network Configurations 
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Distributed vSwitches"
			$VDSwitches = Get-VDSwitch -Server $entity.Name

			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Non-Uplink Distributed Portgroups"
			$VDPortgroups = Get-VDPortgroup -VDSwitch $VDSwitches | Where-Object { $_.IsUplink -eq $false }

			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Distribured Portgroup Policies"
			$policies = Get-VDSecurityPolicy -VDPortgroup $VDPortgroups
		
			# Function to simplify Policy Checking
			Function Test-DistributedNetPolicy {
				Param ($GuidelineID,$RiskProfiles,$StigID,$StigCategory,$Setting,$Policy)
				
				$impacted = $policies | Where-Object { $_.$Policy -eq $true }
				Test-Guideline -GuidelineID $GuidelineID -RiskProfiles $RiskProfiles -StigID $StigID -StigCategory $StigCategory -StigCategory $Category -Setting "$($Setting) Policy: Distributed Virtual Portgroup" -Expected 0 -Current $impacted.count -Impacted ($impacted.Name -join ', ') -Remediation "Automated"
			}

			# VCWN-06-000014 - CAT I - MAC Address Change Policy on Distribued Virtual Portgroups
			$results += Test-DistributedNetPolicy -GuidelineID "vNetwork.reject-mac-changes-dvportgroup" -RiskProfiles "1,2,3" -StigID "VCWN-06-000014" -StigCategory "I" -Setting "MAC Address Change" -Policy "MacChanges"

			# VCWN-06-000013 - CAT II - Promiscuous Mode Policy on Distributed Virtual Portgroup
			$results += Test-DistributedNetPolicy -GuidelineID "vNetwork.reject-forged-transmit-dvportgroup" -RiskProfiles "1,2,3" -StigID "VCWN-06-000013" -StigCategory "II" -Setting "Allow Promiscuous Mode" -Policy "AllowPromiscuous"
			
			# VCWN-06-000015  - CAT II - Forged Transmits Policy on Distributed Virtual Portgroup
			$results += Test-DistributedNetPolicy -GuidelineID "vNetwork.reject-promiscuous-mode-dvportgroup" -RiskProfiles "1,2,3" -StigID "VCWN-06-000015" -StigCategory "II" -Setting "Forged Transmits" -Policy "ForgedTransmits"

			# VCWN-06-000016 - CAT II - NetFlow Collector Configuration for Distributed vSwitches and Portgroups
			$VDSNetFlow = $VDSwitches | Where-Object { $_.ExtensionData.config.IpfixConfig.CollectorIpAddress }
			$VDPNetFlow = $VDPortgroups | Where-Object { $_.ExtensionData.Config.defaultPortConfig.ipfixEnabled.Value }
			$results += Test-Guidance -GuidelineID "vNetwork.restrict-netflow-usage" -RiskProfiles "1,2,3" -StigID "VCWN-06-000016" -StigCategory "II" -Setting "Distributed vSwitch NetFlow Configured"   -Expected 0 -Current $VDSNetFlow.count -Impacted $VDSNetFlow -Remediation "Automated"
			$results += Test-Guidance -GuidelineID "vNetwork.restrict-netflow-usage" -RiskProfiles "1,2,3" -StigID "VCWN-06-000016" -StigCategory "II" -Setting "Distributed Portgroup NetFlow Configured" -Expected 0 -Current $VDSNetFlow.count -Impacted $VDPNetFlow -Remediation "Automated"

			<# Add back with -DISA flag
			#VCWN-06-000007 - CAT II - Network I/O Control Enablement
			$nioc = $VDSwitches | Where-Object { $_.ExtensionData.Config.NetworkResourceManagementEnabled -eq $false }
			$results += Test-Guidance -StigID "VCWN-06-000007" -StigCategory "II" -Setting "Network I/O Control Enabled" -Expected 0 -Current $nioc.count -Impacted ($nioc.Name -join ', ') -Remediation "Automated"

			# VCWN-06-000018 - CAT II - Native VLAN Configuration
			$nativevlan = $VDPortgroups | Where-Object { $_.VlanConfiguration.VlanId -eq $null }
			$results += Test-Guidance -StigID "VCWN-06-000018" -StigCategory "II" -Setting "Native VLAN Configured" -Expected 0 -Current $nativevlan.count -Impacted ($nativevlan.Name -join ', ') -Remediation "Manual"

			# VCWN-06-000019 - CAT II - Virtual Guest Tagging Configuration
			$guesttag = $VDPortgroups | Where-Object { $_.VlanConfiguration.VlanId -eq 4095 }
			$results += Test-Guidance -StigID "VCWN-06-000019" -StigCategory "II" -Setting "Virtual Guest Tagging Configured" -Expected 0 -Current $guesttag.count -Impacted ($guesttag.Name -join ', ') -Remediation "Manual"
			#>

			# VCWN-06-000012 - CAT III - Distributed vSwitch Health Check Enablement
			$impacted = @()
			foreach ($VDSwitch in $VDSwitches) {
			    $enabled = $false;
			    $healthcheck = $VDSwitch.ExtensionData.Config.HealthCheckConfig
			    foreach ($check in $healthcheck) {
			        if ($check.enable -eq $true) { $enabled = $true }
			    }
			    if ($enabled -eq $true) { $impacted += $VDSwitch.Name }
			}
			
			$results += Test-Guidance -GuidelineID "vNetwork.limit-network-healthcheck" -RiskProfiles "1,2,3" -StigID "VCWN-06-000012" -StigCategory "III" -Setting "Distributed vSwitch Health Check Enabled" -Expected 0 -Current $impacted.count -Impacted ($impacted -join ', ') -Remediation "Automated"

			# VCWN-06-000017 - CAT III - Distributed Portgroup Port Override Policy Configuration
			$impacted = @()
			foreach ($VDPortgroup in $VDPortgroups) { 
				$result = Test-PortgroupOverrides
				if ($result) { $Impacted += $result.Name }
			}
			$results += Test-Guidance -GuidelineID "vNetwork.restrict-port-level-overrides" -RiskProfiles "1,2,3" -StigID "VCWN-06-000017" -StigCategory "III" -Setting "Distributed Portgroup Override Policy Confiugration" -Expected 0 -Current $impacted.count -Impacted ($impacted -join ', ') -Remediation "Automated"

			<# Alarm Definition Validation -- Add in for DISA supportability
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all Alarm Definitions"
			$alarms = Get-AlarmDefinition -Server $entity
			$events = $alarms.ExtensionData.Info.Expression.Expression

			Function Test-AlarmDefintion {
				Param ($Finding,$Category,$TypeId,$Type)

				$definition = $events | Where-Object { $_.EventTypeId -eq $TypeId }
				if ($definition.count -ge 1) { $check = $true }
				else { $check = $false }
				Test-Guidance -StigID $Finding -StigCategory $Category -Setting "Alarm Definition: $($Type)" -Expected $true -Current $check -Remediation "Automated"
			}

			# VCWN-06-000048, 49, 50 - CAT II - Alarm Definitions for Permissions
			$results += Test-AlarmDefintion -StigID "VCWN-06-000048" -StigCategory "II" -TypeId "Vim.Event.PermissionAddedEvent"   -Type "Permissions Additions"
			$results += Test-AlarmDefintion -StigID "VCWN-06-000049" -StigCategory "II" -TypeId "Vim.Event.PermissionRemovedEvent" -Type "Permissions Removal"
			$results += Test-AlarmDefintion -StigID "VCWN-06-000048" -StigCategory "II" -TypeId "Vim.Event.PermissionUpdatedEvent" -Type "Permissions Updates"

			# VCWN-06-000008 - CAT III - Remote Syslog connectivity
			$results += Test-AlarmDefintion -StigID "VCWN-06-000008" -StigCategory "III" -TypeId "esx.problem.vmsyslogd.remote.failure" -Type "Remote Syslog Connectivity"
			#>

			# Return the results
			if ($Export) { $ExportResults += $results }
			else { $results }
		}
	}

	End { 
		if ($Export) { Export-Results }
	}
}