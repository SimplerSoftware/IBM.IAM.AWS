using System;
using System.Text.RegularExpressions;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    public class AmazonResourceName
    {
        public string OriginalString { get; private set; }
        public string Partition { get; private set; }
        public string Service { get; private set; }
        public string Region { get; private set; }
        public string AccountId { get; private set; }
        public string ResourceType { get; private set; }
        public string Resource { get; private set; }
        public string ResourceDivider { get; private set; }

        public static AmazonResourceName Parse(string arnString)
        {
            Regex rgxARN = new Regex("arn:(?<partition>[^:]*):(?<service>[^:]*):(?<region>[^:]*):(?<accountid>[^:]*):(?<resourcetype>[^:/]*)(?<resourcedivider>/|:)?(?<resource>[^:]*)$");
            Match mch;
            if ((mch = rgxARN.Match(arnString)).Success)
            {
                return new AmazonResourceName() {
                    OriginalString = arnString,
                    Partition = mch.Groups["partition"].Value,
                    Service = mch.Groups["service"].Value,
                    Region = mch.Groups["region"].Value,
                    AccountId = mch.Groups["accountid"].Value,
                    ResourceType = mch.Groups["resourcetype"].Value,
                    Resource = mch.Groups["resource"].Value,
                    ResourceDivider = mch.Groups["resourcedivider"].Value
                };
            }
            throw new FormatException("The passed string value is not in a well formatted ARN format. View the help link for more info. ") {
                HelpLink = "https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"
            };
        }

        public override string ToString()
        {
            return $"arn:{Partition}:{Service}:{Region}:{AccountId}:{ResourceType}{ResourceDivider}{Resource}";
        }
        public override bool Equals(object obj)
        {
            if (obj is string)
                return this.OriginalString.Equals(obj as string, StringComparison.OrdinalIgnoreCase);
            else if (obj is AmazonResourceName)
                return this.OriginalString.Equals((obj as AmazonResourceName).OriginalString, StringComparison.OrdinalIgnoreCase);

            return base.Equals(obj);
        }
    }
}
