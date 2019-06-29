
namespace IBM.IAM.AWS.SecurityToken.SAML
{
    internal static class SAMLAssertion
    {
        internal const string AssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion";
        internal const string ProtocolNamespace = "urn:oasis:names:tc:SAML:2.0:protocol";
        internal const string RoleXPath = "//saml:Attribute[@Name='https://aws.amazon.com/SAML/Attributes/Role']";
        internal const string NotRoleXPath = "//saml:Attribute[not(@Name='https://aws.amazon.com/SAML/Attributes/Role')]";
    }
}
