using System;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class IbmIamException : Exception
    {
        public IbmIamException(string message)
            : base(message)
        {
        }
    }
}
