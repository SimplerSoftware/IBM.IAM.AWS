using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLAuthnStatement
    {
        public SAMLAuthnStatement(XmlElement authnStatement)
        {
            this.SessionNotOnOrAfter = DateTime.Parse(authnStatement?.Attributes["SessionNotOnOrAfter"]?.Value ?? "1/1/1900");
            this.SessionIndex = authnStatement?.Attributes["SessionIndex"]?.Value;
            this.AuthnInstant = authnStatement?.Attributes["AuthnInstant"]?.Value;
            this.AuthnContext = authnStatement?["AuthnContext", SAMLAssertion.AssertionNamespace]?["AuthnContextClassRef", SAMLAssertion.AssertionNamespace]?.InnerText;
        }

        public DateTime SessionNotOnOrAfter { get; private set; }
        public string SessionIndex { get; private set; }
        public string AuthnInstant { get; private set; }
        public string AuthnContext { get; private set; }
    }
}
