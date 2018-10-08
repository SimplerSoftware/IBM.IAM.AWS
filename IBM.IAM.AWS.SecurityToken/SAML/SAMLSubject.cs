using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLSubject
    {

        public SAMLSubject(XmlElement subject)
        {
            this.NameID = subject?["NameID", SAMLAssertion.AssertionNamespace].InnerText;
            this.SubjectConfirmation = new SAMLSubjectConfirmation(subject?["SubjectConfirmation", SAMLAssertion.AssertionNamespace]);
        }

        public string NameID { get; private set; }
        public SAMLSubjectConfirmation SubjectConfirmation { get; private set; }
    }

    public class SAMLSubjectConfirmation
    {
        public SAMLSubjectConfirmation(XmlElement subjectConfirmation)
        {
            this.Method = subjectConfirmation?.Attributes["Method"]?.Value;
            var data = subjectConfirmation?["SubjectConfirmationData", SAMLAssertion.AssertionNamespace];
            this.Recipient = data?.Attributes["Recipient"]?.Value;
            this.NotOnOrAfter = DateTime.Parse(data?.Attributes["NotOnOrAfter"]?.Value ?? "1/1/1900");
        }

        public string Method { get; private set; }
        public string Recipient { get; private set; }
        public DateTime NotOnOrAfter { get; private set; }
    }
}
