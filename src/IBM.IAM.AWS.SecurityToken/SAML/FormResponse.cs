using System;
using System.Collections.Generic;
using System.Text;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    class FormResponse
    {
        public string Action { get; set; }
        public Dictionary<string, string> FormData { get; set; } = new Dictionary<string, string>();
        public Dictionary<string, string> LabelData { get; set; } = new Dictionary<string, string>();
    }
}
