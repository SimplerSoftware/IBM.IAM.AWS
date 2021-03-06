﻿namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Password expired error from IBM IAM server
    /// </summary>
    public class IbmIamPasswordExpiredException : IbmIamException
    {
        internal IbmIamPasswordExpiredException(string message)
            : base(message)
        {
        }

        internal IbmIamPasswordExpiredException()
        {
        }

        internal IbmIamPasswordExpiredException(string message, System.Exception innerException) : base(message, innerException)
        {
        }
    }

}
