if (Test-Path '..\..\.Nuget.key'){
	Publish-Module -Name 'IBM.IAM.AWS.SecurityToken' -NuGetApiKey (Get-Content -Raw '..\..\.Nuget.key')
} else {
	Write-Error "Nuget API key file '.Nuget.key' is missing, please create it and add one line that contains your API key for nuget."
}
