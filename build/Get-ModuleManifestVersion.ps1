[cmdletbinding()]
param(
	[Parameter(Mandatory)]
	[string] $ManifestPath,
	[Switch] $IncrementRev,
	[Switch] $AsPrerelease,
	[switch] $PatchAsYYMM
)
$symVer2Regex = "(?<Major>0|(?:[1-9]\d*))(?:\.(?<Minor>0|(?:[1-9]\d*))(?:\.(?<Patch>0|(?:[1-9]\d*)))?(?:\-(?<PreRelease>[0-9A-Z\.-]+))?(?:\+(?<Meta>[0-9A-Z\.-]+))?)?"
$PSModuleVersionOrig = $null
$PSModuleVersion = $null
$Prerelease = $null
$Meta = $null
$env:Patch
$PatchOld
$rev = $null
$ModuleManifest = Get-Content $ManifestPath -Raw
if ($ModuleManifest -match "(ModuleVersion\s*=)\s*'(.*)'"){
	Write-Verbose "ModuleVersion matched: [$($Matches[0])]"
	$PSModuleVersionOrig = $Matches[2]
	if ($Matches[2] -match $symVer2Regex){
		Write-Verbose "SymVer matched: [$($Matches[0])]"
		$Version = $Matches.Major
		$PatchOld = $Matches.Patch
		if ($Matches.Minor){$Version += "{0:\.0;\.#;\.0}" -f (Invoke-Expression $Matches.Minor)}else{$Version += ".0"}
		if($PatchAsYYMM -and $AsPrerelease){
			$env:Patch = "{0:yyMM}" -f (Get-Date).AddMonths(1)
		}elseif($PatchAsYYMM){
			$env:Patch = "$(Get-Date -Format yyMM)"
		}elseif($Matches.Patch){
			$env:Patch = "{0:0;#;0}" -f (Invoke-Expression $Matches.Patch)
		}else{
			$env:Patch += "0"
		}
		$Version += ".$env:Patch"
		$Prerelease = $Matches.PreRelease
		$Meta = $Matches.Meta
		if (!$Prerelease -and $ModuleManifest -match "(?<Mark>#?)\s?(Prerelease\s*=)\s*'(?<PreRelease>.*)'"){
			if (!$Matches.Mark -or ($Matches.Mark -and $AsPrerelease)){
				Write-Verbose "Prerelease matched: [$($Matches.PreRelease)]"
				$Prerelease = $Matches.PreRelease
				$PrereleaseOrig = "-$Prerelease"
			}
		}
		if (!$Meta -and $Prerelease -and "$Version-$Prerelease" -match $symVer2Regex -and $Matches.Meta){
			Write-Verbose "Meta matched: [$($Matches.Meta)]"
			$Prerelease = $Matches.PreRelease
			$Meta = $Matches.Meta
		}
		if ($IncrementRev -and $Prerelease -match "(?<Name>[A-Z\.-]+)(?<Rev>\d+)$"){
			Write-Verbose "Revision matched: [$($Matches[0])]"
			$Name = $Matches.Name
			if ($env:Patch -eq $PatchOld){
				Write-Verbose "Patch is same as old."
				$rev = Invoke-Expression $Matches.Rev
			} else {
				Write-Verbose "New patch, reseting revision to 0."
				$rev = 0
			}
			$env:Rev = (++$rev)
			$Prerelease = ("$Name{0:000}" -f $rev)
		}
		if ($AsPrerelease -and !$rev){
			$Prerelease += "1"
		}
		$PSModuleVersion = $Version
		$env:Version = $Version
	}
}
if ($Prerelease){
	$PSModuleVersion += "-$Prerelease"
	$env:Prerelease = "$Prerelease"
}
if ($Meta){
	$PSModuleVersion += "+$Meta"
	$env:Prerelease = "+$Meta"
}
$env:PSModuleVersion = $PSModuleVersion
if ("$PSModuleVersionOrig$PrereleaseOrig" -ne "$PSModuleVersion"){
	Write-Verbose "PSModuleVersion: $PSModuleVersionOrig$PrereleaseOrig -> $PSModuleVersion"
}
# For Azure Pipelines
Write-Output "##vso[task.setvariable variable=PSModuleVersion]$PSModuleVersion"
Write-Output "##vso[task.setvariable variable=Version]$env:Version"
Write-Output "##vso[task.setvariable variable=Prerelease]$env:Prerelease"
Write-Output "##vso[task.setvariable variable=Rev]$env:Rev"
