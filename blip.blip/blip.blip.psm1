Get-ChildItem $psScriptRoot *.ps1 | foreach { . $_.fullname }
Export-ModuleMember -Function @("Get-*","New-*","Set-*")

$stighome = $psScriptRoot
$FindingsHome = "$psScriptRoot\findings"

$stigtype = Get-VIProperty -Name STIGType -ErrorAction SilentlyContinue
if ($stigtype -ne $null) { $stigtype | Remove-VIProperty } 
New-VIProperty -ObjectType VirtualMachine -Name STIGType -Value { 
	Param ($vm)
	if ($vm.CustomFields.Item("Appliance")) {
		Switch ($vm.CustomFields.Item("Appliance")) { 
			"Yes"	{ "Appliance" }
			"No"	{ "Template" }
		}
	}
	else { "Desktop" }
}

Function Test-Checklist { 
	Param (
		[Parameter(Mandatory=$true)]
		[String]$Type
	)

	$result = @()
	Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation "Querying for all defined advanced options"
	$advopts = Get-AdvancedSetting -Entity $entity
	# Importing the correct Configuration Checklist
	if ($Type -eq "VM")      { $checklist = Import-Csv -Path "$FindingsHome\vm-advopts.csv" }
	if ($Type -eq "VMHost")  { $checklist = Import-Csv -Path "$FindingsHome\vmhost-advopts.csv" }
	if ($Type -eq "vCenter") { $checklist = Import-Csv -Path "$FindingsHome\vcenter-advopts.csv" }

	for ($i = 0; $i -lt $checklist.count; $i++) {
		$guideline = $checklist[$i]
		if ((Test-Exclusion $Exclude $guideline.Finding) -eq $false) {
			$current = "Checking current value against $($guideline.Finding)"
			$percent = ($i / $checklist.count)*100
			Write-Progress -Activity $activity -Status $entity.Name -CurrentOperation $current -PercentComplete $percent

			# Checking the posture of the virtual machine against the checklist
			$advopt = $advopts | Where-Object { $_.Name -eq $guideline.Key }
			if (!$advopt) { $impacted = "The advanced setting has no value configured" }
			$result += Test-Finding -Finding $guideline.Finding -StigCategory $guideline.Category -Setting $guideline.Key -Expected $guideline.value -Current $advopt.Value -Impacted $impacted -Remediation $guideline.Remediation
		}
	}
	$result
}

Function Test-Guidance {
	Param (
		$GuidelineID,
		$RiskProfiles,
		$StigID,
		$StigCategory,
		$Setting,
		$Expected,
		$Current,
		[Alias("Notes")]
		$Impacted,
		$Remediation
	) 

	$exclusion = Test-Exclusion $Exclude $GuidelineID
	if ($exclusion -eq $false) {
		Write-Progress -Activity $activity -Status "$($entity.Name)" -CurrentOperation $Setting
		if ($Expected -eq $Current) { $Compliance = $true }
		else { $Compliance = $false }

		#Creating PowerShell Object
		$result = New-Object PSObject
		Add-Member -MemberType NoteProperty -InputObject $result -Name Name 		-Value $entity.Name
		Add-Member -MemberType NoteProperty -InputObject $result -Name Type 		-Value $EntityType
		Add-Member -MemberType NoteProperty -InputObject $result -Name GuidelineID 	-Value $GuidelineID
		Add-Member -MemberType NoteProperty -InputObject $result -Name RiskProfiles	-Value $RiskProfiles
		Add-Member -MemberType NoteProperty -InputObject $result -Name StigID		-Value $StigID
		Add-Member -MemberType NoteProperty -InputObject $result -Name StigCategory	-Value $StigCategory
		Add-Member -MemberType NoteProperty -InputObject $result -Name Setting		-Value $Setting
		Add-Member -MemberType NoteProperty -InputObject $result -Name Expected		-Value $Expected
		Add-Member -MemberType NoteProperty -InputObject $result -Name Current 		-Value $Current
		Add-Member -MemberType NoteProperty -InputObject $result -Name Compliant	-Value $Compliance
		Add-Member -MemberType NoteProperty -InputObject $result -Name Remediation	-Value $Remediation
		Add-Member -MemberType NoteProperty -InputObject $result -Name Impacted		-Value $Impacted

		#Verifying whether to return the result
		if ($Compliance -eq $false -or $All -eq $true) {
			#Setting up the default view for the custom powershell object being returned
			$defaultProps = @("Name","Type","GuidelineID","RiskProfile","Compliant","Remediation")
			$defaultDisplayPropSet = New-Object System.Management.Automation.PSPropertySet("DefaultDisplayPropertySet",[string[]]$defaultProps)
			$defaultView = [System.Management.Automation.PSMemberInfo[]]@($defaultDisplayPropSet)
			$result | Add-Member MemberSet PSStandardMembers $defaultView
			$result
		}
	}
}

Function Test-Exclusion {
	Param (
		[Parameter(Position=0)]
		[String[]]$List,
		[Parameter(Position=1)]
		[String[]]$Finding
	)

	for ($f=0; $f -lt $Finding.count; $f++) {
		$check = $Finding[$f]
		for ($i=0; $i -lt $List.count;$i++) { 
			$exclusion = $List[$i]
			if ($exclusion -eq $check) { return $true } 
		}
	}
	return $false
}

Function Test-PortgroupOverrides {
	$policy = $VDPortgroup.ExtensionData.Config.Policy
	$finding = $false
	foreach ($property in ($policy | Get-Member -MemberType Properties).Name) {
		if ($property -eq "PortConfigResetAtDisconnect") {
			if ($policy.$property -eq $false) { $finding = $true }	
		}
		
		else {
			if ($policy.$property -eq $true) { $finding = $true }
		}
	}
	if ($finding -eq $true) { $VDPortgroup }
}

Function Export-Results {
	if ((Get-Item -Path $Path -ErrorAction SilentlyContinue) -eq $null) { 
		Write-Progress -Activity $activity -Status "Exporting results" -CurrentOperation "Creating export path"
		New-Item -Path $Path -Type Directory | Out-Null 
	}
	if (($ExportResults | Select Name -unique).Name.count -eq 1) { $file = ($ExportResults | Select-Object Name -Unique).Name.toLower() }
	else { $file = $STIGType.toLower() }
	$ExportFile = "$($Path)\$(Get-Date -format yyyy-MM-dd)_$file.csv"
	
	Write-Progress -Activity $activity -Status "Exporting results" -CurrentOperation "Exporting"
	$ExportResults | Select-Object * | Export-Csv -NoTypeInformation -Path $ExportFile

	Write-Host "Export of the STIG value check is available at: $ExportFile" -ForegroundColor Green
}