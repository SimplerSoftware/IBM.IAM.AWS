using Amazon.SecurityToken.SAML;
using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading.Tasks;
using System.Net.Http;
using Amazon.SecurityToken.Model;
using Amazon.Runtime.CredentialManagement;
using Amazon;
using Amazon.Runtime;
using Amazon.SecurityToken;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    internal class IBMSAMAuthenticationController : IAuthenticationController
    {
        const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063";
        private static Regex SAMLResponseField = new Regex("SAMLResponse\\W+value\\=\\\"([^\\\"]+)\\\"");

        PSCmdlet _cmdlet;
        private string _region;
        private IbmIam2AwsSamlScreenScrape _asserionClient;
        private IWebProxy _lastProxy;
        internal string _lastAssertion;

        public SecurityProtocolType SecurityProtocol { get; set; }
        public string ErrorElement { get; set; } = "p";
        public string ErrorClass { get; set; } = "error";
        public Action<string, LogType> Logger => _asserionClient.Logger;

        public IBMSAMAuthenticationController(PSCmdlet cmdlet, string region)
        {
            _cmdlet = cmdlet ?? throw new ArgumentNullException(nameof(cmdlet));
            _region = region;
            _asserionClient = new IbmIam2AwsSamlScreenScrape(cmdlet);
        }

        public string Authenticate(Uri identityProvider, ICredentials credentials, string authenticationType, IWebProxy proxySettings)
        {
            string result = null;
            //ImpersonationState impersonationState = null;
            try
            {
                 _lastAssertion = _asserionClient.RetrieveSAMLAssertion(identityProvider, credentials, authenticationType, proxySettings);
            }
            catch (IbmIamException)
            {
                throw;
            }
            catch (Exception ex)
            {
                throw new AdfsAuthenticationControllerException(ex.ToString(), ex);
            }
            finally
            {
                //if (impersonationState != null)
                //{
                //    impersonationState.Dispose();
                //}
            }
            throw new Amazon.Runtime.FederatedAuthenticationFailureException("Invalid credentials or an error occurred on server. No SAML response found from server's response.");
        }
    }

    class FormResponse
    {
        public string Action { get; set; }
        public Dictionary<string, string> FormData { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> LabelData { get; set; } = new Dictionary<string, string>();
    }
}