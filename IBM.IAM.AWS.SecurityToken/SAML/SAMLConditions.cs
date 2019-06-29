using System;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLConditions
    {
        public SAMLConditions(XmlElement conditions)
        {
            this.NotOnOrAfter = DateTime.Parse(conditions?.Attributes["NotOnOrAfter"]?.Value ?? "1/1/1900");
            this.NotBefore = DateTime.Parse(conditions?.Attributes["NotBefore"]?.Value ?? "1/1/1900");
            this.AudienceRestriction = conditions?["AudienceRestriction", SAMLAssertion.AssertionNamespace]?["Audience", SAMLAssertion.AssertionNamespace]?.InnerText;
        }

        public DateTime NotOnOrAfter { get; private set; }
        public DateTime NotBefore { get; private set; }
        public string AudienceRestriction { get; private set; }
    }
}
