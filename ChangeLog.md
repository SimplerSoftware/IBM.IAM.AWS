<!--
    Please leave this section at the top of the change log.

    Changes for the upcoming release should go under the section titled "Upcoming Release", and should adhere to the following format:

    ## Upcoming Release
    * Overview of change #1
        - Additional information about change #1
    * Overview of change #2
        - Additional information about change #4
        - Additional information about change #2
    * Overview of change #3
    * Overview of change #4
        - Additional information about change #4

    ## YYYY.MM.DD - Version X.Y.Z (Previous Release)
    * Overview of change #1
        - Additional information about change #1
-->
## Upcoming Release

## 2019.05.29 - 1.0.1905.49
* Revert back to .Net Framework 4.6.2 - AWSSDK.SecurityToken does not work correctly under .Net Standard 2.0 yet...

## 2019.05.29 - 1.0.1905.43
* Add full proxy support for SAML client and STS client.
* Moved project to .Net Standard type
* Support for PowerShell & PowerShell Core
* Refactor code to use as much of AWS libraries as possible.
* Add Get-AwsIbmSamlRoles CmdLet - Will just pull the SAML doc and list roles in doc.
* Add custom format view for returned types
* Add StoreAllRoles param switch to Set-AwsIbmSamlCredentials - will store all roles using the role name.
* Use shared AWS credential config location to store profiles
* Add RegionMap parameter to Set-AwsIbmSamlCredentials

## 2019.03.05 - 1.0.1903.13
* New SecurityProtocol parameter for Set-AwsIbmSamlCredentials cmdlet to choose what type of protocol to use for HTTPS.
* Handles login/authentication error when server returns the error in HTML instead of proper HTTP status code.
  * Can set HTML element and class with new parameters ErrorElement & ErrorClass
* Use AWS's updated SAMLAssertion class, it now works correctly with multiple roles per account
* Use AWS's updated SAMLAuthenticationController class
* Update Set-AwsIbmSamlCredentials cmdlet to use WriteError instead of ThrowTerminatingError
* Updated AWSSDK version to latest.

## 2018.10.08 - 1.0.1810.12
* Added support for requesting MFA OTP(one-time passwords) after login.
* Updated AWSSDK version to latest.

## 2018.06.13 - 1.0.1806.7
* Fixed array out of bounds exception

## 2018.06.13 - 1.0.1806.3
* Added SingleMatch parameter switch to Set-AwsIbmSamlCredentials cmdlet.
* Updated AWSSDK version to latest.

## 2018.05.24 - 1.0.1805.59
* Remove dependency on AWSPowerShell.

## 2018.05.20 - 1.0.1805.42
* Updated published version for PS gallery

## 2018.05.20 - 1.0.1805.32
* General availability of `IBM.IAM.AWS.SecurityToken` module
