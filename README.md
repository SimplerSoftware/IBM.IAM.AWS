# IBM.IAM.AWS.SecurityToken
Authenticate a user against a IBM Identity and Access Management server and select role from SAML response.

All [releases](https://www.powershellgallery.com/packages/IBM.IAM.AWS.SecurityToken/) can be pulled from PowerShell Galery using [PowerShellGet](https://www.powershellgallery.com/).
```PowerShell
> Install-Module -Name IBM.IAM.AWS.SecurityToken 
```

## Example
```PowerShell
> $endpoint = "https://myiamserver.example.com/fim/sps/saml20/saml20/logininitial?RequestBinding=HTTPPost&PartnerId=urn:amazon:webservices&NameIdFormat=Email&AllowCreate=false"
> Set-AWSSamlEndpoint -Endpoint $endpoint -StoreAs IBMAWSSaml
> Set-AwsIbmSamlCredentials -EndpointName IBMAWSSaml -StoreAs RoleAuth
> Get-EC2Region -ProfileName RoleAuth
> Get-EC2Instance -ProfileName RoleAuth
```
