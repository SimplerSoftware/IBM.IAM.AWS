using System.Collections.Generic;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// AWS Principal and Role ARNs
    /// <para type="description">AWS Principal and Role ARNs</para>
    /// </summary>
    class SAMLCredential
    {
        /// <summary>
        /// Default empty Credential
        /// </summary>
        public SAMLCredential()
        {
        }
        /// <summary>
        /// Parse Credential from Value of KeyValuePair
        /// </summary>
        /// <param name="r">KeyValuePair with value set as full ARN of Credential</param>
        public SAMLCredential(KeyValuePair<string, string> r)
        {
            string[] array = r.Value.Split(',');
            RoleArn = AmazonResourceName.Parse(array[0]);
            PrincipalArn = AmazonResourceName.Parse(array[1]);
        }

        /// <summary>
        /// Role ARN
        /// </summary>
        public AmazonResourceName RoleArn { get; internal set; }
        /// <summary>
        /// Principal ARN
        /// </summary>
        public AmazonResourceName PrincipalArn { get; internal set; }
        /// <summary>
        /// Credential in original string format.
        /// </summary>
        public string Value => $"{this.RoleArn.OriginalString},{this.PrincipalArn.OriginalString}";

        /// <summary>
        /// Credential in original string format.
        /// </summary>
        /// <returns></returns>
        public override string ToString() => this.Value;
    }
}
