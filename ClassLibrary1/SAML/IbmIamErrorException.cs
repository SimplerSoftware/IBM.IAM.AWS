using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class IbmIamErrorException : IbmIamException
    {
        public string ErrorCode { get; private set; }

        //https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html
        public string ProductIdentifiers { get { return ErrorCode.Take(3).ToString(); } }
        public string ComponentIdentifiers { get { return ErrorCode.Skip(3).Take(2).ToString(); } }
        public string MessageNumber { get { return ErrorCode.Skip(5).Take(4).ToString(); } }
        public string Severity { get { return ErrorCode.Skip(9).Take(1).ToString(); } }

        public IbmIamErrorException(string message, string errorCode)
            : base(message)
        {
            this.ErrorCode = errorCode;
        }
    }
}
