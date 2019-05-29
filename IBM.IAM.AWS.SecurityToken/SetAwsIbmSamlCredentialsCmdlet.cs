using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using IBM.IAM.AWS.SecurityToken.SAML;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Net;
using System.Text.RegularExpressions;

namespace IBM.IAM.AWS.SecurityToken
{
    /// <summary>
    /// Authenticate a user against a IBM Identity and Access Management server and select role from SAML response.
    /// <para type="synopsis">Authenticates a user against IBM IAM server to utilize roles granted in AWS via AWS PowerShell cmdlets.</para>
    /// <para type="description">Authenticates a user against IBM IAM server to utilize roles granted in AWS via AWS PowerShell cmdlets.</para>
    /// <example>
    ///   <title>Default usage.</title>
    ///   <code>
    ///   $endpoint = 'https://sso.mycompany.com/saml20/logininitial'
    ///   Set-AWSSamlEndpoint -Endpoint $endpoint -StoreAs 'IBMEP'
    ///   Set-AwsIbmSamlCredentials -EndpointName 'IBMEP'
    ///   </code>
    /// </example>
    /// <example>
    ///   <title>Specifying a predefined username and password.</title>
    ///   <code>
    ///   $endpoint = 'https://sso.mycompany.com/saml20/logininitial'
    ///   Set-AWSSamlEndpoint -Endpoint $endpoint -StoreAs 'IBMEP'
    ///   Set-AwsIbmSamlCredentials -EndpointName 'IBMEP' -Credential (Get-Credential -UserName 'MyUsername' -Message 'IBM IAM SAML Server') -RegionMap @{;"West_EU_"="eu-west-1";"West_"="us-west-1";"East_"="us-east-1"}
    ///   </code>
    /// </example>
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "AwsIbmSamlCredentials", DefaultParameterSetName = StoreOneRoleParameterSet), 
        OutputType(typeof(StoredInfo))]
    public class SetAwsIbmSamlCredentials : PSCmdlet
    {
        private const string StoreOneRoleParameterSet = "StoreOneRole";
        private const string StoreAllRolesParameterSet = "StoreAllRoles";
        private IBMSAMAuthenticationController _controller;

        /// <summary>
        /// The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.
        /// <para type="description">The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public string EndpointName { get; set; }

        /// <summary>
        /// The AWS principal ARN for the role you want to assume.
        /// <para type="description">The AWS principal ARN for the role you want to assume.</para>
        /// </summary>
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = StoreOneRoleParameterSet)]
        public string PrincipalARN { get; set; }

        /// <summary>
        /// The AWS role ARN for the role you want to assume.
        /// <para type="description">The AWS role ARN for the role you want to assume.</para>
        /// </summary>
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = StoreOneRoleParameterSet)]
        public string RoleARN { get; set; }

        /// <summary>
        /// The credentials you want to use to auto-login to the IBM IAM server.
        /// <para type="description">The credentials you want to use to auto-login to the IBM IAM server.</para>
        /// </summary>
        [Parameter]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// Store a successful login into this profile name. Then use it with -ProfileName with AWS cmdlets.
        /// <para type="description">Store a successful login into this profile name. Then use it with -ProfileName with AWS cmdlets.</para>
        /// </summary>
        [Parameter(ParameterSetName = StoreOneRoleParameterSet)]
        public string StoreAs { get; set; }

        /// <summary>
        /// AWS account id to filter out roles only in a specific account.
        /// <para type="description">AWS account id to filter out roles only in a specific account.</para>
        /// </summary>
        [Parameter()]
        public string[] AwsAccountId { get; set; }

        /// <summary>
        /// Search for a specific keyword in a role to mark it as the default choice.
        /// <para type="description">Search for a specific keyword in a role to mark it as the default choice.</para>
        /// </summary>
        [Parameter(ParameterSetName = StoreOneRoleParameterSet)]
        public string HelpFindResource { get; set; }

        /// <summary>
        /// If only one role matches the value in HelpFindResource, then select that single role and don't ask the user which to use.
        /// <para type="description">If only one role matches the value in HelpFindResource, then select that single role and don't ask the user which to use.</para>
        /// </summary>
        [Parameter(ParameterSetName = StoreOneRoleParameterSet)]
        public SwitchParameter SingleMatch { get; set; }

        /// <summary>
        /// Set what Security Protocol to use when connecting over HTTPS. Default: TLS 1.2
        /// <para type="description">Set what Security Protocol to use when connecting over HTTPS. Default: TLS 1.2</para>
        /// </summary>
        [Parameter()]
        public SecurityProtocolType SecurityProtocol { get; set; } = SecurityProtocolType.Tls12;

        /// <summary>
        /// Set what HTML element will contain a error response if there is a error from bad login. Default: P
        /// <para type="description">Set what HTML element will contain a error response if there is a error from bad login. Default: P</para>
        /// </summary>
        [Parameter()]
        [ValidateNotNullOrEmpty]
        public string ErrorElement { get; set; } = "p";

        /// <summary>
        /// Set what HTML class the ErrorElement will contain for a error response if there is a error from bad login. Default: error
        /// <para type="description">Set what HTML class the ErrorElement will contain for a error response if there is a error from bad login. Default: error</para>
        /// </summary>
        [Parameter()]
        [ValidateNotNullOrEmpty]
        public string ErrorClass { get; set; } = "error";

        /// <summary>
        /// Assume role and store all roles in local AWS shared credential store
        /// <para type="description">Assume role and store all roles in local AWS shared credential store</para>
        /// </summary>
        [Parameter(Mandatory = true, ParameterSetName = StoreAllRolesParameterSet)]
        public SwitchParameter StoreAllRoles { get; set; }

        /// <summary>
        /// Region to use when calling SecurityTokenService's AssumeRoleWithSAML. Default: us-east-2
        /// <para type="description">Region to use when calling SecurityTokenService's AssumeRoleWithSAML. Default: us-east-2</para>
        /// </summary>
        [Parameter]
        [ValidateNotNullOrEmpty]
        public string STSEndpointRegion { get; set; } = RegionEndpoint.USEast2.SystemName;

        /// <summary>
        /// The address of the web proxy in Url form. (https://proxy.example.corp:8080)
        /// <para type="description">The address of the proxy in Url form. (https://proxy.example.corp:8080)</para>
        /// </summary>
        [Parameter()]
        public Uri ProxyAddress { get; set; }

        /// <summary>
        /// The credentials of the web proxy.
        /// <para type="description">The credentials of the web proxy.</para>
        /// </summary>
        [Parameter()]
        public ICredentials ProxyCredentials { get; set; }

        /// <summary>
        /// Indicates whether to bypass the proxy server for local addresses.
        /// <para type="description">Indicates whether to bypass the proxy server for local addresses.</para>
        /// </summary>
        [Parameter()]
        public SwitchParameter ProxyBypassOnLocal { get; set; }

        /// <summary>
        /// A address that does not use the proxy server.
        /// <para type="description">A address that does not use the proxy server.</para>
        /// </summary>
        [Parameter()]
        public string[] ProxyBypassList { get; set; }

        /// <summary>
        /// Hashtable mapping containing role names to AWS region endpoint system names. Role names can be valid regex strings, first match is returned. Note: If you want an exact match, for the role name be sure to prefix with ^ and suffix with $.
        /// <para type="description">Hashtable mapping containing role names to AWS region endpoint system names. Role names can be valid regex strings, first match is returned.</para>
        /// </summary>
        [Parameter()]
        public Hashtable RegionMap { get; set; } = null;

        /// <summary>
        /// 
        /// </summary>
        protected override void ProcessRecord()
        {
            try
            {
                string preselectedPrincipalAndRoleARN = null;
                NetworkCredential networkCredential = null;
                if (this.Credential != null)
                {
                    base.WriteVerbose("Network Credentials given, will attempt to use them.");
                    networkCredential = this.Credential.GetNetworkCredential();
                }
                bool hasPrinARN = this.ParameterWasBound("PrincipalARN") && !string.IsNullOrWhiteSpace(this.PrincipalARN);
                bool hasRoleARN = this.ParameterWasBound("RoleARN") && !string.IsNullOrWhiteSpace(this.RoleARN);
                if (hasPrinARN != hasRoleARN)
                    this.ThrowExecutionError("RoleARN must be specified with PrincipalARN.", this);
                if (hasPrinARN & hasRoleARN)
                    preselectedPrincipalAndRoleARN = $"{this.RoleARN},{this.PrincipalARN}";

                base.WriteVerbose($"Retrieving stored endpoint '{this.EndpointName}'.");
                SAMLEndpoint endpoint = new SAMLEndpointManager().GetEndpoint(this.EndpointName);
                if (endpoint == null)
                {
                    this.ThrowExecutionError("Endpoint not found. You must first call Set-AWSSamlEndpoint to store the endpoint URL to the IBM IDS site.", this);
                }
                RegionEndpoint regionEndpoint = RegionEndpoint.GetBySystemName(this.STSEndpointRegion);
                base.WriteVerbose($"Endpoint region set to {regionEndpoint.SystemName}.");
                // We can't use the nice controller they built, as it uses there own assertion class that has issues because of dictionary use. (Old Note, it is fixed now apparently.)
                _controller = new IBMSAMAuthenticationController(this, regionEndpoint.SystemName);
                _controller.ErrorElement = this.ErrorElement;
                _controller.ErrorClass = this.ErrorClass;
                _controller.SecurityProtocol = this.SecurityProtocol;
                _controller.Logger = (m, t) => {
                    switch (t)
                    {
                        case LogType.Debug:
                            this.WriteDebug(m);
                            break;
                        case LogType.Info:
                            this.WriteInformation(new InformationRecord(m, ""));
                            break;
                        case LogType.Warning:
                            this.WriteWarning(m);
                            break;
                        case LogType.Error:
                            this.WriteError(new ErrorRecord(new Exception(m), "5000", ErrorCategory.NotSpecified, this));
                            break;
                    }
                };

                base.WriteVerbose("Authenticating with endpoint to verify role data...");
                var _awsAuthController = new Amazon.SecurityToken.SAML.SAMLAuthenticationController(
                    _controller,
                    new IBMSAMLAuthenticationResponseParser(),
                    this.GetWebProxy()
                    );
                var sAMLAssertion = _awsAuthController.GetSAMLAssertion(endpoint.EndpointUri.ToString(), networkCredential, endpoint.AuthenticationType.ToString());

                AnonymousAWSCredentials anonCred = new AnonymousAWSCredentials();
                AmazonSecurityTokenServiceConfig cfg = new AmazonSecurityTokenServiceConfig();
                cfg.RegionEndpoint = RegionEndpoint.GetBySystemName(this.STSEndpointRegion ?? cfg.RegionEndpoint.SystemName);
                if (this.HasWebProxy)
                    cfg.SetWebProxy(this.GetWebProxy());
                AmazonSecurityTokenServiceClient sts = new AmazonSecurityTokenServiceClient(anonCred, cfg);

                if (this.StoreAllRoles)
                {
                    var AuthnStatement = GetSAMLAuthnStatement(sAMLAssertion.AssertionDocument);
                    var AttributeStatement = GetSAMLAttributeStatement(sAMLAssertion.AssertionDocument);
                    var config = new SharedCredentialsFile();
                    SAMLImmutableCredentials creds = null;
                    SAMLCredential[] roles = null;
                    if (AwsAccountId != null && AwsAccountId.Length > 0)
                        roles = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToArray();
                    else
                        roles = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).ToArray();

                    foreach (var role in roles)
                    {
                        creds = null;
                        this.WriteVerbose($"Getting [{role.PrincipalArn}] tokens using [{role.RoleArn}]");
                        try
                        {
                            base.WriteVerbose($"Saving role '{role.Value}' to profile '{role.RoleArn.Resource}'.");
                            creds = AssumeRole(sts, config, role.RoleArn.Resource, sAMLAssertion, role);
                        }
                        catch (ExpiredTokenException ex)
                        {
                            this.WriteVerbose($"Could not Assume Role: {role.RoleArn.Resource}");
                            this.WriteVerbose("Attempting to Refresh Token");
                            // Updating Assertion Document
                            sAMLAssertion = _awsAuthController.GetSAMLAssertion(endpoint.EndpointUri.ToString(), networkCredential, endpoint.AuthenticationType.ToString());
                            this.WriteVerbose("Retrying this operation");
                            creds = AssumeRole(sts, config, role.RoleArn.Resource, sAMLAssertion, role);
                            this.WriteVerbose($"RetryResult: {creds}");
                        }
                        catch (AmazonSecurityTokenServiceException ex)
                        {
                            this.WriteError(new ErrorRecord(ex, "5000", ErrorCategory.NotSpecified, this));
                        }
                        if (creds != null)
                        {
                            this.WriteObject(new StoredInfo
                            {
                                StoreAs = role.RoleArn.Resource,
                                AssertionDoc = sAMLAssertion.AssertionDocument,
                                AssertionExpires = AuthnStatement.SessionNotOnOrAfter > AttributeStatement.SessionNotOnOrAfter ? AuthnStatement.SessionNotOnOrAfter : AttributeStatement.SessionNotOnOrAfter,
                                Expires = creds.Expires.ToLocalTime(),
                                PrincipalArn = role.PrincipalArn,
                                RoleArn = role.RoleArn
                            });
                        }
                    }
                }
                else
                {
                    StoredInfo sendToPipeline = this.SelectAndStoreProfileForRole(sts, sAMLAssertion, preselectedPrincipalAndRoleARN, networkCredential, regionEndpoint);
                    base.WriteObject(sendToPipeline);
                }
            }
            catch (IbmIamErrorException ex)
            {
                base.WriteError(new ErrorRecord(ex, ex.ErrorCode, ErrorCategory.NotSpecified, this));
            }
            catch (IbmIamPasswordExpiredException ex)
            {
                base.WriteError(new ErrorRecord(ex, "PasswordExpired", ErrorCategory.AuthenticationError, this));
            }
            catch (Exception ex)
            {
                base.WriteError(new ErrorRecord(new ArgumentException("Unable to set credentials: " + ex.Message, ex), "ArgumentException", ErrorCategory.InvalidArgument, this));
            }
        }

        private bool TestPreselectedRoleAvailable(string targetPrincipalAndRoleARNs, ICollection<string> roleARNs)
        {
            if (string.IsNullOrEmpty(targetPrincipalAndRoleARNs))
                return false;
            foreach (var role in roleARNs)
            {
                if (role.Equals(targetPrincipalAndRoleARNs, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            base.WriteVerbose($"The specified principal and role ARNs, {targetPrincipalAndRoleARNs}, could not be found in the SAML response.");
            return false;
        }

        internal WebProxy GetWebProxy()
        {
            if (this.ProxyAddress != null){
                return new WebProxy(this.ProxyAddress, this.ProxyBypassOnLocal, this.ProxyBypassList, this.ProxyCredentials);
            }
            return null;
        }
        internal bool HasWebProxy { get { return this.ProxyAddress != null; } }

        private StoredInfo SelectAndStoreProfileForRole(IAmazonSecurityTokenService sts, Amazon.SecurityToken.SAML.SAMLAssertion sAMLAssertion, string preselectedPrincipalAndRoleARN, NetworkCredential networkCredential, RegionEndpoint stsEndpointRegion)
        {
            string roleArn = preselectedPrincipalAndRoleARN;
            if (!this.TestPreselectedRoleAvailable(preselectedPrincipalAndRoleARN, sAMLAssertion.RoleSet.Select(arn => arn.Value).ToList()))
            {
                if (sAMLAssertion.RoleSet.Count == 1)
                {
                    roleArn = sAMLAssertion.RoleSet.First().Value;
                    base.WriteVerbose(string.Format("Only one role available, pre-selecting role ARN {0}", preselectedPrincipalAndRoleARN));
                }
                else
                {
                    IList<SAMLCredential> roleSet = null;
                    if (AwsAccountId != null && AwsAccountId.Length > 0)
                        roleSet = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToList();
                    else
                        roleSet = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).ToList();

                    Collection<ChoiceDescription> collection = new Collection<ChoiceDescription>();
                    char c = 'A';
                    foreach (var cred in roleSet.OrderBy(r => r.RoleArn.AccountId).ThenBy(r => r.RoleArn.Resource))
                    {
                        string label;
                        if (sAMLAssertion.RoleSet.Count <= 26 && c <= 'Z')
                        {
                            label = $"&{c} - {cred.RoleArn.Resource}";
                            c++;
                        }
                        else
                            label = cred.RoleArn.Resource;

                        collection.Add(new ChoiceDescription(label, cred.Value));
                    }

                    bool userChooses = true;
                    int idxDefault = 0;
                    if (!string.IsNullOrWhiteSpace(this.HelpFindResource))
                    {
                        var fnd = collection.Where(r => r.Label.IndexOf(this.HelpFindResource, StringComparison.InvariantCultureIgnoreCase) >= 0).ToArray();
                        if (fnd.Length == 1 && this.SingleMatch)
                        {
                            WriteVerbose($"Found single match of role with the value '{this.HelpFindResource}', using that specific role only.");
                            roleArn = collection[collection.IndexOf(fnd[0])].HelpMessage;
                            userChooses = false;
                        }
                        else if (fnd.Length >= 1)
                            idxDefault = collection.IndexOf(fnd[0]); // Pre-select the first role found with the HelpFindResource's value
                    }
                    if (userChooses)
                    {
                        int index = base.Host.UI.PromptForChoice("Select Role", "Select the role to be assumed when this profile is active", collection, idxDefault);
                        roleArn = collection[index].HelpMessage;
                    }
                }
            }
            if (string.IsNullOrEmpty(roleArn))
                this.ThrowExecutionError("A role is required before the profile can be stored.", this);

            var role = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).FirstOrDefault(r => r.Value.Equals(roleArn, StringComparison.OrdinalIgnoreCase));
            base.WriteVerbose($"Saving to profile '{this.StoreAs ?? role.RoleArn.Resource}'.");

            var config = new SharedCredentialsFile();
            var creds = AssumeRole(sts, config, this.StoreAs ?? role.RoleArn.Resource, sAMLAssertion, role);

            base.WriteVerbose($"Stored AWS Credentials as {this.StoreAs ?? role.RoleArn.Resource}.\r\nUse 'Set-AWSCredentials -ProfileName {this.StoreAs ?? role.RoleArn.Resource}' to load this profile and obtain temporary AWS credentials.");

            var AuthnStatement = GetSAMLAuthnStatement(sAMLAssertion.AssertionDocument);
            var AttributeStatement = GetSAMLAttributeStatement(sAMLAssertion.AssertionDocument);

            return new StoredInfo
            {
                StoreAs = this.StoreAs ?? role.RoleArn.Resource,
                AssertionDoc = _controller._lastAssertion,
                AssertionExpires = AuthnStatement.SessionNotOnOrAfter > AttributeStatement.SessionNotOnOrAfter ? AuthnStatement.SessionNotOnOrAfter : AttributeStatement.SessionNotOnOrAfter,
                Expires = creds.Expires.ToLocalTime(),
                PrincipalArn = role.PrincipalArn,
                RoleArn = role.RoleArn
            };
        }

        private bool ParameterWasBound(string parameterName)
        {
            return base.MyInvocation.BoundParameters.ContainsKey(parameterName);
        }
        private void ThrowExecutionError(string message, object errorSource)
        {
            this.ThrowExecutionError(message, errorSource, null);
        }
        private void ThrowExecutionError(string message, object errorSource, Exception innerException)
        {
            base.ThrowTerminatingError(
                new ErrorRecord(
                    new InvalidOperationException(message, innerException), 
                    (innerException == null) ? "InvalidOperationException" : innerException.GetType().ToString(), 
                    ErrorCategory.InvalidOperation, 
                    errorSource
                    )
                );
        }

        private SAMLAuthnStatement GetSAMLAuthnStatement(string assertionDocument)
        {
            System.Xml.XmlDocument xDoc = new System.Xml.XmlDocument();
            byte[] bytes = Convert.FromBase64String(assertionDocument);
            xDoc.LoadXml(System.Text.Encoding.UTF8.GetString(bytes));
            System.Xml.XmlNamespaceManager xmlNamespaceManager = new System.Xml.XmlNamespaceManager(xDoc.NameTable);
            xmlNamespaceManager.AddNamespace("saml", SAMLAssertion.AssertionNamespace);

            var assertion = xDoc.DocumentElement["Assertion", SAMLAssertion.AssertionNamespace];
            return new SAMLAuthnStatement(assertion["AuthnStatement", SAMLAssertion.AssertionNamespace]);
        }
        private SAMLAttributeStatement GetSAMLAttributeStatement(string assertionDocument)
        {
            System.Xml.XmlDocument xDoc = new System.Xml.XmlDocument();
            byte[] bytes = Convert.FromBase64String(assertionDocument);
            xDoc.LoadXml(System.Text.Encoding.UTF8.GetString(bytes));
            System.Xml.XmlNamespaceManager xmlNamespaceManager = new System.Xml.XmlNamespaceManager(xDoc.NameTable);
            xmlNamespaceManager.AddNamespace("saml", SAMLAssertion.AssertionNamespace);

            var assertion = xDoc.DocumentElement["Assertion", SAMLAssertion.AssertionNamespace];
            var issueInstant = DateTime.Parse(assertion?.Attributes["IssueInstant"]?.Value ?? "1/1/1900");
            return new SAMLAttributeStatement(assertion["AttributeStatement", SAMLAssertion.AssertionNamespace], issueInstant, xmlNamespaceManager);
        }

        SAMLImmutableCredentials AssumeRole(IAmazonSecurityTokenService sts, ICredentialProfileStore config, string profileName, Amazon.SecurityToken.SAML.SAMLAssertion assertion, SAMLCredential role, int duration = 60)
        {
            var credential = AssumeRole(sts, assertion, role, duration);
            AddRoleToConfig(config ?? throw new ArgumentNullException(nameof(config)),
                profileName,
                role ?? throw new ArgumentNullException(nameof(role)),
                credential);
            return credential;
        }
        SAMLImmutableCredentials AssumeRole(IAmazonSecurityTokenService sts, Amazon.SecurityToken.SAML.SAMLAssertion assertion, SAMLCredential role, int duration = 60)
        {
            return assertion.GetRoleCredentials(sts, role.Value, TimeSpan.FromMinutes(duration));
        }
        private void AddRoleToConfig(ICredentialProfileStore config, string profileName, SAMLCredential role, SAMLImmutableCredentials t)
        {
            if (!config.TryGetProfile(profileName ?? role.RoleArn.Resource, out CredentialProfile profile))
            {
                var options = new CredentialProfileOptions();
                profile = new CredentialProfile(profileName ?? role.RoleArn.Resource, options);
            }
            profile.Options.AccessKey = t.AccessKey;
            profile.Options.SecretKey = t.SecretKey;
            profile.Options.Token = t.Token;

            var role_region = GetRoleRegion(role);
            if (role_region != null)
            {
                WriteDebug($"Adding auto-magic region option to {profile.Name}");
                profile.Region = role_region;
            }
            else if (!string.IsNullOrWhiteSpace(this.STSEndpointRegion))
            {
                WriteDebug($"Adding STS region option to {profile.Name}");
                profile.Region = RegionEndpoint.GetBySystemName(this.STSEndpointRegion);
            }
            config.RegisterProfile(profile);
        }

        RegionEndpoint GetRoleRegion(SAMLCredential role)
        {
            if (RegionMap == null)
                return null;

            foreach (string roleName in RegionMap.Keys)
            {
                this.WriteVerbose($"Testing '{role.RoleArn.Resource}' to see if it matches '{roleName}'");
                if (Regex.IsMatch(role.RoleArn.Resource, roleName))
                {
                    this.WriteVerbose($"Role name/pattern matched! Returning endpoint '{RegionMap[roleName]}'");
                    return RegionEndpoint.GetBySystemName((string)RegionMap[roleName]);
                }
            }
            this.WriteVerbose("No Region Pattern Recognized");
            return null;
        }

    }
}
