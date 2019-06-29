$Module = "IBM.IAM.AWS.SecurityToken"

if ($env:APPVEYOR_BUILD_VERSION){
	$Module = ".\IBM.IAM.AWS.SecurityToken\bin\Release\netstandard2.0\"
	Write-Host "Updating module manifest with AppVeyor version $env:APPVEYOR_BUILD_VERSION"
	$date = Get-Date -Format MM/dd/yyyy
	$ModuleManifestPath = "$($Module)IBM.IAM.AWS.SecurityToken.psd1"
	$ModuleManifest = Get-Content $ModuleManifestPath -Raw
	$ModuleManifest = $ModuleManifest -replace "(ModuleVersion\W*=)\W*'(.*)'", "`$1 '$env:APPVEYOR_BUILD_VERSION'"
	$ModuleManifest = $ModuleManifest -replace "(Generated on:)\W*(.*)", "`$1 $date"
	$ModuleManifest | Out-File -LiteralPath $ModuleManifestPath

	Get-Content $ModuleManifestPath -Raw
}
$NuGetApiKey = $null
if ($Env:NuGetApiKey){
	$NuGetApiKey = $Env:NuGetApiKey
} elseif (Test-Path '..\.Nuget.key') {
	$NuGetApiKey = (Get-Content -Raw '..\.Nuget.key')
}

if ($NuGetApiKey){
	Publish-Module -Path $Module -NuGetApiKey $NuGetApiKey
} else {
	Write-Error "Nuget API key is missing, please create the file and add one line that contains your API key for nuget or set the environment variable [NuGetApiKey]."
}