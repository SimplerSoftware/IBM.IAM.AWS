using Amazon.SecurityToken.SAML;
using System;
using System.Collections;
using System.Globalization;
using System.Reflection;
using System.Text.RegularExpressions;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    internal class IBMSAMLAuthenticationResponseParser : IAuthenticationResponseParser
    {
        //public SAMLAssertion Parse(string authenticationResponse)
        //{
        //    string assertion = string.Empty;
        //    MatchCollection response = IBMSAMLAuthenticationResponseParser.SAMLResponseField.Matches(authenticationResponse);
        //    if (resposne.Count == 0)
        //        throw new Amazon.Runtime.FederatedAuthenticationFailureException("Invalid credentials or an error occurred on server. No SAML response found from server's response.");
        //    foreach (Match data in response)
        //    {
        //        assertion = data.Groups[1].Value;
        //    }

        //    // Originally tried to use AWS SAMLAssertion, witch they set to internal for some lovely reason.
        //    //BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;
        //    //CultureInfo culture = null; // use InvariantCulture or other if you prefer
        //    //SAMLAssertion samlAssertion = Activator.CreateInstance(typeof(SAMLAssertion), flags, null, new object[] { assertion }, culture) as SAMLAssertion;
        //    //return samlAssertion;
        //    return new SAMLAssertion(assertion);
        //}

        Amazon.SecurityToken.SAML.SAMLAssertion IAuthenticationResponseParser.Parse(string authenticationResponse)
        {

            // Originally tried to use AWS SAMLAssertion, witch they set to internal for some lovely reason.
            BindingFlags flags = BindingFlags.NonPublic | BindingFlags.Instance;
            CultureInfo culture = null; // use InvariantCulture or other if you prefer
            Amazon.SecurityToken.SAML.SAMLAssertion samlAssertion = Activator.CreateInstance(typeof(Amazon.SecurityToken.SAML.SAMLAssertion), flags, null, new object[] { authenticationResponse }, culture) as Amazon.SecurityToken.SAML.SAMLAssertion;
            return samlAssertion;
            //return new Amazon.SecurityToken.SAML.SAMLAssertion(assertion);
        }
    }
}
