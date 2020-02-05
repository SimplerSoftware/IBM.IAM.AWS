using IBM.IAM.AWS.SecurityToken.SAML;
using System;
using System.Collections;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Globalization;
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
    ///   Get-AwsIbmSamlRoles -IbmIamEndpoint $endpoint
    ///   </code>
    /// </example>
    /// <example>
    ///   <title>Specifying a predefined username and password.</title>
    ///   <code>
    ///   $endpoint = 'https://sso.mycompany.com/saml20/logininitial'
    ///   Get-AwsIbmSamlRoles -IbmIamEndpoint $endpoint -Credential (Get-Credential -UserName 'MyUsername' -Message 'IBM IAM SAML Server')
    ///   </code>
    /// </example>
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AwsIbmSamlRoles"), 
        OutputType(typeof(SAMLCredential))]
    public class GetAwsIbmSamlRolesCmdlet : PSCmdlet
    {
        /// <summary>
        /// The endpoint URL to the IBM IAM server.
        /// <para type="description">The endpoint URL to the IBM IAM server.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public Uri IbmIamEndpoint { get; set; }

        /// <summary>
        /// The credentials you want to use to auto-login to the IBM IAM server.
        /// <para type="description">The credentials you want to use to auto-login to the IBM IAM server.</para>
        /// </summary>
        [Parameter]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// AWS account id to filter out roles only in a specific account.
        /// <para type="description">AWS account id to filter out roles only in a specific account.</para>
        /// </summary>
        [Parameter()]
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Performance", "CA1819:Properties should not return arrays", Justification = "CmdLet properties do not return values.")]
        public string[] AwsAccountId { get; set; }

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
        /// 
        /// </summary>
        [System.Diagnostics.CodeAnalysis.SuppressMessage("Design", "CA1031:Do not catch general exception types", Justification = "Exceptions get written to PS error stream.")]
        protected override void ProcessRecord()
        {
            try
            {
                NetworkCredential networkCredential = null;
                if (this.Credential != null)
                {
                    base.WriteVerbose(Lang.UseGivenNetworkCredentials);
                    networkCredential = this.Credential.GetNetworkCredential();
                }

                ServicePointManager.SecurityProtocol = this.SecurityProtocol;
                IbmIam2AwsSamlScreenScrape aad2Aws = new IbmIam2AwsSamlScreenScrape(this)
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

                var assertion = aad2Aws.RetrieveSAMLAssertion(IbmIamEndpoint);
                var roles = aad2Aws.GetRolesFromAssertion();

                if (AwsAccountId != null && AwsAccountId.Length > 0)
                    roles = roles.Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToArray();


                foreach (var role in roles)
                {
                    this.WriteObject(role);
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
                base.WriteError(new ErrorRecord(new ArgumentException(string.Format(CultureInfo.CurrentCulture, Lang.ErrorUnableSetCredentials, ex.Message), ex), "ArgumentException", ErrorCategory.InvalidArgument, this));
            }
        }

        internal WebProxy GetWebProxy()
        {
            if (this.ProxyAddress != null){
                return new WebProxy(this.ProxyAddress, this.ProxyBypassOnLocal, this.ProxyBypassList, this.ProxyCredentials);
            }
            return null;
        }
        internal bool HasWebProxy { get { return this.ProxyAddress != null; } }

    }
}
