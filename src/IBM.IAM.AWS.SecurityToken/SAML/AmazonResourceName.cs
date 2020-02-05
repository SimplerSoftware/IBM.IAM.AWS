using System;
using System.Text.RegularExpressions;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Amazon Resource Name (ARN)
    /// </summary>
    public class AmazonResourceName
    {
        /// <summary>
        /// ARN in original format that was parsed.
        /// </summary>
        public string OriginalString { get; private set; }
        /// <summary>
        /// Partition section of ARN
        /// </summary>
        public string Partition { get; private set; }
        /// <summary>
        /// Service section of ARN
        /// </summary>
        public string Service { get; private set; }
        /// <summary>
        /// Region section of ARN
        /// </summary>
        public string Region { get; private set; }
        /// <summary>
        /// Account ID section of ARN
        /// </summary>
        public string AccountId { get; private set; }
        /// <summary>
        /// Resource Type section of ARN
        /// </summary>
        public string ResourceType { get; private set; }
        /// <summary>
        /// Resource Name section of ARN
        /// </summary>
        public string Resource { get; private set; }
        /// <summary>
        /// Resource Divider character used in ARN resource section
        /// </summary>
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
            throw new FormatException(Lang.ErrorUnrecognizedArn) {
                HelpLink = "https://docs.aws.amazon.com/general/latest/gr/aws-arns-and-namespaces.html"
            };
        }

        /// <summary>
        /// OriginalString that was parsed
        /// </summary>
        /// <returns></returns>
        public override string ToString()
        {
            return this.OriginalString;
        }
        /// <summary>
        ///  Determines whether this ARB and a specified ARN have the same value.
        /// </summary>
        /// <param name="obj"><see cref="String"/> or <see cref="AmazonResourceName"/></param>
        /// <returns></returns>
        public override bool Equals(object obj)
        {
            if (obj is string)
                return this.OriginalString.Equals(obj as string, StringComparison.OrdinalIgnoreCase);
            else if (obj is AmazonResourceName)
                return this.OriginalString.Equals((obj as AmazonResourceName).OriginalString, StringComparison.OrdinalIgnoreCase);

            return base.Equals(obj);
        }
        /// <summary>
        /// Returns the hash code for this ARN.
        /// </summary>
        /// <returns></returns>
        public override int GetHashCode()
        {
            return this.ToString().GetHashCode();
        }
    }
}
