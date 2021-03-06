# IBM - Identity and Access Management AWS SAML Integration
Authenticate a user against a IBM Identity and Access Management server and select role from SAML response.

Current Status: [![Build status](https://ci.appveyor.com/api/projects/status/r64vo2ba6eylaqlu?svg=true)](https://ci.appveyor.com/project/SimplerSoftware/ibm-iam-aws) [![Build status](https://ci.appveyor.com/api/projects/status/r64vo2ba6eylaqlu/branch/master?svg=true&passingText=master%3A%20passing&pendingText=master%3A%20pending&failingText=master%3A%20failed)](https://ci.appveyor.com/project/SimplerSoftware/ibm-iam-aws/branch/master)

All [releases](https://www.powershellgallery.com/packages/IBM.IAM.AWS.SecurityToken/) can be pulled from PowerShell Gallery using [PowerShellGet](https://www.powershellgallery.com/).
```PowerShell
> Install-Module -Name IBM.IAM.AWS.SecurityToken 
```

### PS Module Dependencies
* AWS.Tools.SecurityToken

## Example
```PowerShell
> $endpoint = "https://myiamserver.example.com/fim/sps/saml20/saml20/logininitial?RequestBinding=HTTPPost&PartnerId=urn:amazon:webservices&NameIdFormat=Email&AllowCreate=false"
> Set-AwsIbmSamlCredentials -IbmIamEndpoint $endpoint -StoreAs RoleAuth
> Get-EC2Region -ProfileName RoleAuth
> Get-EC2Instance -ProfileName RoleAuth
```
