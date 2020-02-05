using System;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Results of the authentication attempt.
    /// <para type="description">Results of the authentication attempt.</para>
    /// </summary>
    public class StoredInfo
    {
        /// <summary>
        /// Profile name the role was stored as.
        /// </summary>
        public string StoreAs { get; internal set; }
        /// <summary>
        /// This property is no longer being set.
        /// </summary>
        [Obsolete("This property is no longer being set.", true)]
        public DateTime AssertionExpires { get; internal set; }
        /// <summary>
        /// Principal ARN of role.
        /// </summary>
        public AmazonResourceName PrincipalArn { get; internal set; }
        /// <summary>
        /// Role ARN of role.
        /// </summary>
        public AmazonResourceName RoleArn { get; internal set; }
        /// <summary>
        /// Date &amp; time token expires.
        /// </summary>
        public DateTime Expires { get; internal set; }
        /// <summary>
        /// SAML assertion doc that was used to assume role.
        /// </summary>
        public string AssertionDoc { get; internal set; }
    }
}
