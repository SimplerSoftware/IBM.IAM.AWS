using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLCredential
    {
        public AmazonResourceName RoleArn { get; internal set; }
        public AmazonResourceName PrincipalArn { get; internal set; }
        public string Value { get { return $"{this.RoleArn.OriginalString},{this.PrincipalArn.OriginalString}"; } }
    }
}
