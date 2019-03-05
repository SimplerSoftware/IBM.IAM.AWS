using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class SAMLCredential
    {
        public SAMLCredential()
        {
        }
        public SAMLCredential(KeyValuePair<string, string> r)
        {
            string[] array = r.Value.Split(',');
            RoleArn = AmazonResourceName.Parse(array[0]);
            PrincipalArn = AmazonResourceName.Parse(array[1]);
        }

        public AmazonResourceName RoleArn { get; internal set; }
        public AmazonResourceName PrincipalArn { get; internal set; }
        public string Value { get { return $"{this.RoleArn.OriginalString},{this.PrincipalArn.OriginalString}"; } }
    }
}
