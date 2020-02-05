using System;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Generic error from IBM IAM server
    /// </summary>
    public class IbmIamException : Exception
    {
        internal IbmIamException(string message)
            : base(message)
        {
        }
    }
}
