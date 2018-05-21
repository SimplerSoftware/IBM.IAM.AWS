using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Results of the authentication attempt.
    /// <para type="description">Results of the authentication attempt.</para>
    /// </summary>
    public class StoredInfo
    {
        public string StoreAs { get; internal set; }
        public AmazonResourceName PrincipalArn { get; internal set; }
        public AmazonResourceName RoleArn { get; internal set; }
    }
}
