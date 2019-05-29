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
    ///   Get-AwsIbmSamlRoles -EndpointName 'IBMEP'
    ///   </code>
    /// </example>
    /// <example>
    ///   <title>Specifying a predefined username and password.</title>
    ///   <code>
    ///   $endpoint = 'https://sso.mycompany.com/saml20/logininitial'
    ///   Set-AWSSamlEndpoint -Endpoint $endpoint -StoreAs 'IBMEP'
    ///   Get-AwsIbmSamlRoles -EndpointName 'IBMEP' -Credential (Get-Credential -UserName 'MyUsername' -Message 'IBM IAM SAML Server')
    ///   </code>
    /// </example>
    /// </summary>
    [Cmdlet(VerbsCommon.Get, "AwsIbmSamlRoles"), 
        OutputType(typeof(SAMLCredential))]
    public class GetAwsIbmSamlRolesCmdlet : PSCmdlet
    {
        private IBMSAMAuthenticationController _controller;

        /// <summary>
        /// The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.
        /// <para type="description">The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public string EndpointName { get; set; }

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

        protected override void ProcessRecord()
        {
            try
            {
                NetworkCredential networkCredential = null;
                if (this.Credential != null)
                {
                    base.WriteVerbose("Network Credentials given, will attempt to use them.");
                    networkCredential = this.Credential.GetNetworkCredential();
                }

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
                _controller.Logger = (m, t) =>
                {
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
                SAMLCredential[] roles = null;
                if (AwsAccountId != null && AwsAccountId.Length > 0)
                    roles = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).Where(r => AwsAccountId.Contains(r.PrincipalArn.AccountId, StringComparer.OrdinalIgnoreCase)).ToArray();
                else
                    roles = sAMLAssertion.RoleSet.Select(r => new SAMLCredential(r)).ToArray();


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
                base.WriteError(new ErrorRecord(new ArgumentException("Unable to set credentials: " + ex.Message, ex), "ArgumentException", ErrorCategory.InvalidArgument, this));
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

    }
}
