using Amazon.Runtime;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLAssertion
    {
        internal const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
        internal const string RoleXPath = "//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']";
        internal const string NotRoleXPath = "//saml:Attribute[not(@Name='https://aws.amazon.com/SAML/Attributes/Role')]";

        public string AssertionDocument
        {
            get;
            private set;
        }
        public string Issuer
        {
            get;
            private set;
        }
        public string Status
        {
            get;
            private set;
        }
        public SAMLSubject Subject { get; private set; }
        public SAMLConditions Conditions { get; private set; }
        public SAMLAuthnStatement AuthnStatement { get; private set; }
        public Dictionary<string, string> Attributes { get; private set; } = new Dictionary<string, string>();
        public IList<SAMLCredential> RoleSet
        {
            get;
            private set;
        }

        public SAMLImmutableCredentials GetRoleCredentials(IAmazonSecurityTokenService stsClient, string principalAndRoleArns, TimeSpan duration)
        {
            string[] array = principalAndRoleArns.Split(',');
            AmazonResourceName arnRole = AmazonResourceName.Parse(array[0]);
            AmazonResourceName arnPrincipal = AmazonResourceName.Parse(array[1]);
            SAMLCredential found = null;
            foreach (var current in this.RoleSet)
            {
                if (current.RoleArn.Equals(arnRole) && current.PrincipalArn.Equals(arnPrincipal))
                {
                    found = current;
                    break;
                }
            }
            if (found == null)
            {
                throw new ArgumentException("Unknown or invalid role specified.");
            }
            AssumeRoleWithSAMLResponse assumeRoleWithSAMLResponse = stsClient.AssumeRoleWithSAML(new AssumeRoleWithSAMLRequest
            {
                SAMLAssertion = this.AssertionDocument,
                RoleArn = found.RoleArn.OriginalString,
                PrincipalArn = found.PrincipalArn.OriginalString,
                DurationSeconds = (int)duration.TotalSeconds
            });
            return new SAMLImmutableCredentials(assumeRoleWithSAMLResponse.Credentials.GetCredentials(),
                assumeRoleWithSAMLResponse.Credentials.Expiration.ToUniversalTime(),
                assumeRoleWithSAMLResponse.Subject);
        }

        internal SAMLAssertion(string assertion)
        {
            this.AssertionDocument = assertion;
            this.RoleSet = this.ExtractRoleData();
        }

        private IList<SAMLCredential> ExtractRoleData()
        {
            XmlDocument xDoc = new XmlDocument();
            byte[] bytes = Convert.FromBase64String(this.AssertionDocument);
            xDoc.LoadXml(Encoding.UTF8.GetString(bytes));
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(xDoc.NameTable);
            xmlNamespaceManager.AddNamespace("saml", SAMLAssertion.AssertionNamespace);
            this.Issuer = xDoc.DocumentElement["Issuer", SAMLAssertion.AssertionNamespace]?.InnerText;
            this.Status = xDoc.DocumentElement["Status", SAMLAssertion.ProtocolNamespace]?["StatusCode", SAMLAssertion.ProtocolNamespace]?.Attributes["Value"]?.InnerText;

            var assertion = xDoc.DocumentElement["Assertion", SAMLAssertion.AssertionNamespace];
            this.Subject = new SAMLSubject(assertion["Subject", SAMLAssertion.AssertionNamespace]);
            this.Conditions = new SAMLConditions(assertion["Conditions", SAMLAssertion.AssertionNamespace]);
            this.AuthnStatement = new SAMLAuthnStatement(assertion["AuthnStatement", SAMLAssertion.AssertionNamespace]);

            XmlNodeList xNotRoleList = assertion.SelectNodes(SAMLAssertion.NotRoleXPath, xmlNamespaceManager);
            foreach (XmlNode node in xNotRoleList)
            {
                string name = node.Attributes["Name"]?.Value;
                string value = node["AttributeValue", SAMLAssertion.AssertionNamespace]?.InnerText;
                if (!string.IsNullOrWhiteSpace(name))
                    Attributes.Add(name, value);
            }

            XmlNodeList xRoleList = assertion.SelectNodes(SAMLAssertion.RoleXPath, xmlNamespaceManager);
            IList<SAMLCredential> lstSAML = new List<SAMLCredential>();
            if (xRoleList != null && xRoleList.Count > 0)
            {
                XmlNodeList xRoles = xRoleList[0].ChildNodes;
                foreach (XmlNode xRole in xRoles)
                {
                    if (!string.IsNullOrEmpty(xRole.InnerText))
                    {
                        string[] array = xRole.InnerText.Split(',');
                        AmazonResourceName arnRole = AmazonResourceName.Parse(array[0]);
                        AmazonResourceName arnPrincipal = AmazonResourceName.Parse(array[1]);
                        lstSAML.Add(new SAMLCredential
                        {
                            RoleArn = arnRole,
                            PrincipalArn = arnPrincipal
                        });
                    }
                }
            }
            return lstSAML;
        }
    }
}
