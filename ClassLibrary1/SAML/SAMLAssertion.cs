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
        private const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";

        private const string RoleXPath = "//response:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']";

        public string AssertionDocument
        {
            get;
            private set;
        }

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
            xmlNamespaceManager.AddNamespace("response", "urn:oasis:names:tc:SAML:2.0:assertion");
            XmlNodeList xRoleList = xDoc.DocumentElement.SelectNodes("//response:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']", xmlNamespaceManager);
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
