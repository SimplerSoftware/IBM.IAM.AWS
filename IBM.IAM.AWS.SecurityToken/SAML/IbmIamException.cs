using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

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
