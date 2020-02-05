using System.Linq;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Error from IBM IAM server
    /// </summary>
    /// <remarks>https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html</remarks>
    public class IbmIamErrorException : IbmIamException
    {
        /// <summary>
        /// Error Code
        /// </summary>
        public string ErrorCode { get; private set; }

        /// <summary>
        /// Product identifier section of <see cref="ErrorCode"/>
        /// </summary>
        /// <remarks>https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html</remarks>
        public string ProductIdentifiers { get { return ErrorCode.Take(3).ToString(); } }
        /// <summary>
        /// Component identifier section of <see cref="ErrorCode"/>
        /// </summary>
        /// <remarks>https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html</remarks>
        public string ComponentIdentifiers { get { return ErrorCode.Skip(3).Take(2).ToString(); } }
        /// <summary>
        /// Message number section of <see cref="ErrorCode"/>
        /// </summary>
        /// <remarks>https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html</remarks>
        public string MessageNumber { get { return ErrorCode.Skip(5).Take(4).ToString(); } }
        /// <summary>
        /// Severity section of <see cref="ErrorCode"/>
        /// </summary>
        /// <remarks>https://www.ibm.com/support/knowledgecenter/en/SSPREK_7.0.0/com.ibm.isam.doc_70/messages/message_formats.html</remarks>
        public string Severity { get { return ErrorCode.Skip(9).Take(1).ToString(); } }

        internal IbmIamErrorException(string message, string errorCode)
            : base(message)
        {
            this.ErrorCode = errorCode;
        }
    }
}
