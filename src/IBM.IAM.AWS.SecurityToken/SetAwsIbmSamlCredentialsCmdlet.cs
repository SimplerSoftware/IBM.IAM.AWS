using IBM.IAM.AWS.SecurityToken.SAML;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.IO;
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
    ///   Set-AwsIbmSamlCredentials -IbmIamEndpoint $endpoint
    ///   </code>
    /// </example>
    /// <example>
    ///   <title>Specifying a predefined username and password.</title>
    ///   <code>
    ///   $endpoint = 'https://sso.mycompany.com/saml20/logininitial'
    ///   Set-AwsIbmSamlCredentials -IbmIamEndpoint $endpoint -Credential (Get-Credential -UserName 'MyUsername' -Message 'IBM IAM SAML Server') -RegionMap @{;"West_EU_"="eu-west-1";"West_"="us-west-1";"East_"="us-east-1"}
    ///   </code>
    /// </example>
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "AwsIbmSamlCredentials", DefaultParameterSetName = StoreOneRoleParameterSet),
        OutputType(typeof(StoredInfo))]
    public class SetAwsIbmSamlCredentials : PSCmdlet
    {
        private const string StoreOneRoleParameterSet = "StoreOneRole";
        private const string StoreAllRolesParameterSet = "StoreAllRoles";
        const string Ellipsis = "…";

        /// <summary>
        /// The endpoint URL to the IBM IAM server.
        /// <para type="description">The endpoint URL to the IBM IAM server.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public Uri IbmIamEndpoint { get; set; }

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
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "CmdLet properties do not return values.")]
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
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "CmdLet properties do not return values.")]
        public string[] ProxyBypassList { get; set; }

        /// <summary>
        /// Duration in minutes how long the credentials session token will be valid for.
        /// <para type="description">Duration in minutes how long the credentials session token will be valid for.</para>
        /// </summary>
        [Parameter()]
        [ValidateRange(15, 720)]
        public int TokenDurationInMinutes { get; set; } = 60;


        /// <summary>
        /// 
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exceptions get written to PS error stream.")]
        protected override void ProcessRecord()
        {
            try
            {
                string preselectedPrincipalAndRoleARN = null;
                NetworkCredential networkCredential = null;
                if (this.Credential != null)
                {
                    base.WriteVerbose(Lang.UseGivenNetworkCredentials);
                    networkCredential = this.Credential.GetNetworkCredential();
                }
                bool hasPrinARN = this.ParameterWasBound(nameof(PrincipalARN)) && !string.IsNullOrWhiteSpace(this.PrincipalARN);
                bool hasRoleARN = this.ParameterWasBound(nameof(RoleARN)) && !string.IsNullOrWhiteSpace(this.RoleARN);
                if (hasPrinARN != hasRoleARN)
                    this.ThrowExecutionError(Lang.PrincipalRequiredWithRole, this);
                if (hasPrinARN & hasRoleARN)
                    preselectedPrincipalAndRoleARN = $"{this.RoleARN},{this.PrincipalARN}";

                ServicePointManager.SecurityProtocol = this.SecurityProtocol;
                IbmIam2AwsSamlScreenScrape ibm2Aws = new IbmIam2AwsSamlScreenScrape(this)
                {
                    ErrorClass = this.ErrorClass,
                    ErrorElement = this.ErrorElement,
                    Proxy = this.GetWebProxy(),
                    Credentials = networkCredential,
                    Logger = (m, t) =>
                    {
                        switch (t)
                        {
                            case LogType.Debug:
                                this.WriteVerbose(m);
                                break;
                            case LogType.Info:
                                this.Host.UI.WriteLine(m);
                                //_cmdlet.WriteInformation(new InformationRecord(m, ""));
                                break;
                            case LogType.Warning:
                                this.WriteWarning(m);
                                break;
                            case LogType.Error:
                                this.WriteError(new ErrorRecord(new Exception(m), "5000", ErrorCategory.NotSpecified, this));
                                break;
                        }
                    }
                };

                var assertion = ibm2Aws.RetrieveSAMLAssertion(IbmIamEndpoint);
                var roles = ibm2Aws.GetRolesFromAssertion();

                if (this.StoreAllRoles)
                {
                    if (AwsAccountId != null && AwsAccountId.Length > 0)
                        roles = roles.Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToArray();

                    foreach (var role in roles)
                    {

                        this.WriteVerbose($"Getting [{role.PrincipalArn}] tokens using [{role.RoleArn}]");
                        try
                        {
                            var aRole = this.ExecuteCmdletInPipeline<dynamic>("Use-STSRoleWithSAML", new
                            {
                                SAMLAssertion = ibm2Aws.Assertion,
                                RoleArn = role.RoleArn.OriginalString,
                                PrincipalArn = role.PrincipalArn.OriginalString,
                                DurationInSeconds = 60 * this.TokenDurationInMinutes
                            }).FirstOrDefault();
                            this.WriteObject(new StoredInfo
                            {
                                AssertionDoc = assertion,
                                Expires = aRole.Credentials.Expiration,
                                PrincipalArn = role.PrincipalArn,
                                RoleArn = role.RoleArn,
                                StoreAs = this.StoreAs ?? role.RoleArn.Resource
                            });
                            base.WriteVerbose($"Saving role '{role.Value}' to profile '{role.RoleArn.Resource}'.");
                            var home = this.GetVariableValue("HOME") as string;
                            _ = this.ExecuteCmdletInPipeline("Set-AWSCredential", new
                            {
                                ProfileLocation = Path.Combine(home, ".aws", "credentials"),
                                AccessKey = aRole.Credentials.AccessKeyId,
                                SecretKey = aRole.Credentials.SecretAccessKey,
                                aRole.Credentials.SessionToken,
                                StoreAs = role.RoleArn.Resource
                            });
                        }
                        //catch (ExpiredTokenException ex)
                        //{
                        //    this.WriteVerbose($"Could not Assume Role: {role.RoleArn.Resource}");
                        //    this.WriteVerbose("Attempting to Refresh Token");
                        //    // Updating Assertion Document
                        //    sAMLAssertion = _awsAuthController.GetSAMLAssertion(endpoint.EndpointUri.ToString(), networkCredential, endpoint.AuthenticationType.ToString());
                        //    this.WriteVerbose("Retrying this operation");
                        //    creds = AssumeRole(sts, config, role.RoleArn.Resource, sAMLAssertion, role, this.TokenDurationInMinutes);
                        //    this.WriteVerbose($"RetryResult: {creds}");
                        //}
                        catch (Exception ex)
                        {
                            this.WriteError(new ErrorRecord(ex, "5000", ErrorCategory.NotSpecified, this));
                        }
                    }
                }
                else
                {
                    StoredInfo sendToPipeline = this.SelectAndStoreProfileForRole(assertion, roles, preselectedPrincipalAndRoleARN);
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

        private StoredInfo SelectAndStoreProfileForRole(string assertion, IList<SAMLCredential> roleSet, string preselectedPrincipalAndRoleARN)
        {
            string roleArn = preselectedPrincipalAndRoleARN;
            if (!this.TestPreselectedRoleAvailable(preselectedPrincipalAndRoleARN, roleSet.Select(arn => arn.Value).ToList()))
            {
                if (roleSet.Count == 1)
                {
                    roleArn = roleSet.First().Value;
                    base.WriteVerbose($"Only one role available, pre-selecting role ARN {preselectedPrincipalAndRoleARN}");
                }
                else
                {
                    if (AwsAccountId != null && AwsAccountId.Length > 0)
                        roleSet = roleSet.Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToList();

                    var width = this.Host.UI.RawUI.WindowSize.Width - 4; // $MenuOptions.MaxWidth - 4
                    List<char> okchars = new List<char>();
                    for (char c = 'A'; c <= 'Z'; c++) okchars.Add(c); // A - Z
                    for (char c = '0'; c <= '9'; c++) okchars.Add(c); // 0 - 9
                    for (char c = '!'; c <= '/'; c++) okchars.Add(c); // ! - /
                    for (char c = ':'; c <= '>'; c++) okchars.Add(c); // : - >
                    for (char c = '['; c <= '_'; c++) okchars.Add(c); // [ - _
                    for (char c = '{'; c <= '~'; c++) okchars.Add(c); // { - ~

                    Collection<ChoiceDescription> collection = new Collection<ChoiceDescription>();
                    int idx = 0;
                    foreach (var cred in roleSet.OrderBy(r => r.RoleArn.AccountId).ThenBy(r => r.RoleArn.Resource))
                    {
                        string label;
                        if (roleSet.Count <= okchars.Count)
                        {
                            label = $"&{okchars[idx]} - {cred.RoleArn.Resource}";
                            label = NewSpaceDelimitedText(label, width) + ".";
                        }
                        else
                            label = cred.RoleArn.Resource;

                        collection.Add(new ChoiceDescription(label, cred.Value));
                        idx++;
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
                        int index = base.Host.UI.PromptForChoice(Lang.SelectRoleCaption, Lang.SelectRoleMessage, collection, idxDefault);
                        roleArn = collection[index].HelpMessage;
                    }
                }
            }
            if (string.IsNullOrEmpty(roleArn))
                this.ThrowExecutionError(Lang.ErrorNoRoleSelected, this);

            var role = roleSet.FirstOrDefault(r => r.Value.Equals(roleArn, StringComparison.OrdinalIgnoreCase));
            this.WriteVerbose($"Getting [{role.PrincipalArn}] tokens using [{role.RoleArn}]");
            var aRole = this.ExecuteCmdletInPipeline<dynamic>("Use-STSRoleWithSAML", new
            {
                SAMLAssertion = assertion,
                RoleArn = role.RoleArn.OriginalString,
                PrincipalArn = role.PrincipalArn.OriginalString,
                DurationInSeconds = 60 * TokenDurationInMinutes
            }).FirstOrDefault();
            base.WriteVerbose($"Saving to profile '{this.StoreAs ?? role.RoleArn.Resource}'.");

            var home = this.GetVariableValue("HOME") as string;
            _ = this.ExecuteCmdletInPipeline("Set-AWSCredential", new
            {
                ProfileLocation = Path.Combine(home, ".aws", "credentials"),
                AccessKey = aRole.Credentials.AccessKeyId,
                SecretKey = aRole.Credentials.SecretAccessKey,
                aRole.Credentials.SessionToken,
                StoreAs = this.StoreAs ?? role.RoleArn.Resource
            });

            base.WriteVerbose($"Stored AWS Credentials as {this.StoreAs ?? role.RoleArn.Resource}.\r\nUse 'Set-AWSCredentials -ProfileName {this.StoreAs ?? role.RoleArn.Resource}' to load this profile and obtain temporary AWS credentials.");

            return new StoredInfo { 
                AssertionDoc = assertion,
                Expires = aRole.Credentials.Expiration,
                PrincipalArn = role.PrincipalArn,
                RoleArn = role.RoleArn,
                StoreAs = this.StoreAs ?? role.RoleArn.Resource
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
        internal string NewSpaceDelimitedText(string Text, int? MaxWidth = null, Alignment Justified = Alignment.Undefined)
        {

            if (!MaxWidth.HasValue)
                MaxWidth = Host.UI.RawUI.WindowSize.Width;
            string textLine = string.Empty;
            var textLength = $"{Text}".Length;
            if (Justified == Alignment.Center)
            {
                var textBlanks = ((MaxWidth.Value - 2) - textLength) / 2;
                if (textBlanks <= 0)
                {
                    textLine = $"{Text}";
                }
                else
                {
                    textLine = new string(' ', textBlanks) + $"{Text}";
                }
                textLine += new string(' ', MaxWidth.Value - textLine.Length);
            }
            else if (Justified == Alignment.Right)
            {
                if (textLength > MaxWidth)
                {
                    Text = $"{Text}".Substring(0, MaxWidth.Value - Ellipsis.Length);
                    Text += Ellipsis;
                }
                else if ($"{Text}".Length < MaxWidth)
                {
                    textLine += new string(' ', MaxWidth.Value - $"{Text}".Length);
                }
                textLine += $"{Text}";
            }
            else
            {
                if (textLength > MaxWidth)
                {
                    Text = $"{Text}".Substring(0, MaxWidth.Value - Ellipsis.Length);
                    Text += Ellipsis;
                }

                textLine = $"{Text}";
                if (textLine.Length < MaxWidth)
                {
                    textLine += new string(' ', MaxWidth.Value - textLine.Length);
                }
            }
            return textLine;
        }
    }
}
