using AWSSAML;
using BP.AWS.SecurityToken.SAML;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Test
{
    class Program
    {
        static void Main(string[] args)
        {
            SetAwsIbmSamlCredentials cmd = new SetAwsIbmSamlCredentials();
            cmd.EndpointName = "BPAWSSaml";
            cmd.StoreAs = "Test";

            cmd.proc();
        }
    }
}
