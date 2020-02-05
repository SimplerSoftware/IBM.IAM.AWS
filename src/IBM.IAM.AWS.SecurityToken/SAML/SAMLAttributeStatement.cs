using System;
using System.Collections.Generic;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    class SAMLAttributeStatement
    {
        private DateTime issueInstant;

        public List<string> Roles { get; } = new List<string>();
        public string TenantId { get; }
        public string ObjectIdentifier { get; }
        public string Givenname { get; }
        public string Surname { get; }
        public ushort SessionDuration { get; private set; }
        public DateTime SessionNotOnOrAfter { get => issueInstant.AddSeconds(SessionDuration); }
        public string Name { get; }
        public string RoleSessionName { get; }

        public SAMLAttributeStatement(XmlElement authnStatement, DateTime issueInstant, XmlNamespaceManager xmlNamespaceManager)
        {
            this.issueInstant = issueInstant;
            this.TenantId = authnStatement.SelectSingleNode("saml:Attribute[@Name='http://schemas.microsoft.com/identity/claims/tenantid']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            this.ObjectIdentifier = authnStatement.SelectSingleNode("saml:Attribute[@Name='http://schemas.microsoft.com/identity/claims/objectidentifier']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            this.Givenname = authnStatement.SelectSingleNode("saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            this.Surname = authnStatement.SelectSingleNode("saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            this.Name = authnStatement.SelectSingleNode("saml:Attribute[@Name='http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            this.RoleSessionName = authnStatement.SelectSingleNode("saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/RoleSessionName']/saml:AttributeValue", xmlNamespaceManager)?.InnerText;
            foreach (XmlNode node in authnStatement.SelectNodes("saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']/saml:AttributeValue", xmlNamespaceManager))
                this.Roles.Add(node.InnerText);
            this.SessionDuration = ushort.Parse(authnStatement.SelectSingleNode("saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/SessionDuration']/saml:AttributeValue", xmlNamespaceManager)?.InnerText ?? "0");
        }

    }
}
