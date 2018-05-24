using Amazon;
using Amazon.Runtime;
using Amazon.Runtime.CredentialManagement;
using Amazon.SecurityToken;
using Amazon.SecurityToken.Model;
using System;
using System.Collections.Generic;
using System.Collections.ObjectModel;
using System.Linq;
using System.Management.Automation;
using System.Management.Automation.Host;
using System.Net;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    /// <summary>
    /// Authenticate a user against a IBM Identity and Access Management server and select role from SAML response.
    /// <para type="synopsis">Authenticates a user against IBM IAM server to utilize roles granted in AWS via AWS PowerShell cmdlets.</para>
    /// <para type="description">Authenticates a user against IBM IAM server to utilize roles granted in AWS via AWS PowerShell cmdlets.</para>
    /// <example>
    ///   <title>Default usage. </title>
    ///   <code>Set-AwsIbmSamlCredentials -EndpointName 'IBMEP'</code>
    /// </example>
    /// <example>
    ///   <title>Specifying a predefined username and password. </title>
    ///   <code>Set-AwsIbmSamlCredentials -EndpointName 'IBMEP' -Credential (Get-Credential -UserName 'MyUsername' -Message 'IBM IAM SAML Server') </code>
    /// </example>
    /// </summary>
    [Cmdlet(VerbsCommon.Set, "AwsIbmSamlCredentials", DefaultParameterSetName = "StoreOneRole"), 
        OutputType(typeof(StoredInfo))]
    public class SetAwsIbmSamlCredentials : PSCmdlet
    {
        const string RolePrompt = "Select the role to be assumed when this profile is active";

        private const string StoreOneRoleParameterSet = "StoreOneRole";

        /// <summary>
        /// The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.
        /// <para type="description">The name of the endpoint you gave when calling Set-AWSSamlEndpoint with your URL to the IBM IAM server.</para>
        /// </summary>
        [Parameter(Mandatory = true, ValueFromPipeline = true)]
        public string EndpointName { get; set; }

        /// <summary>
        /// The AWS principal ARN for the role you want to assume.
        /// <para type="description">The AWS principal ARN for the role you want to assume.</para>
        /// </summary>
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = "StoreOneRole")]
        public string PrincipalARN { get; set; }

        /// <summary>
        /// The AWS role ARN for the role you want to assume.
        /// <para type="description">The AWS role ARN for the role you want to assume.</para>
        /// </summary>
        [Parameter(ValueFromPipelineByPropertyName = true, ParameterSetName = "StoreOneRole")]
        public string RoleARN { get; set; }

        /// <summary>
        /// The credentials you want to use to auto-login to the IBM IAM server.
        /// <para type="description">The credentials you want to use to auto-login to the IBM IAM server.</para>
        /// </summary>
        [Parameter]
        public PSCredential Credential { get; set; }

        /// <summary>
        /// Store a successful login into this profile name. Then use it with -ProfileName with AWS cmdlets.
        /// <para type="description">Store a successful login into this profile name. Then use it with -ProfileName with AWS cmdlets.</para>
        /// </summary>
        [Parameter(Mandatory = true)]
        public string StoreAs { get; set; }

        /// <summary>
        /// AWS account id to filter out roles only in a specific account.
        /// <para type="description">AWS account id to filter out roles only in a specific account.</para>
        /// </summary>
        [Parameter(Mandatory = false)]
        public string AwsAccountId { get; set; }

        /// <summary>
        /// Search for a specific keyword in a role to mark it as the default choice.
        /// <para type="description">Search for a specific keyword in a role to mark it as the default choice.</para>
        /// </summary>
        [Parameter(Mandatory = false)]
        public string HelpFindResource { get; set; }

        /// <summary>
        /// Physical location to store authenticated profile.
        /// <para type="description">Physical location to store authenticated profile.</para>
        /// </summary>
        [Parameter(ValueFromPipelineByPropertyName = true, Mandatory = false)]
        public string ProfileLocation { get; set; }

        // We can't store multiple roles until the nice built-in SAMLAuthenticationController gets fixed to support multiple roles in the same account
        //[Parameter(Mandatory = true, ParameterSetName = "StoreAllRoles")]
        //public SwitchParameter StoreAllRoles { get; set; }

        /// <summary>
        /// Region to use when calling SecurityTokenService's AssumeRoleWithSAML.
        /// <para type="description">Region to use when calling SecurityTokenService's AssumeRoleWithSAML.</para>
        /// </summary>
        [Parameter]
        public string STSEndpointRegion { get; set; } = "us-east-2";

        protected override void ProcessRecord()
        {
            try
            {
                string preselectedPrincipalAndRoleARN = null;
                NetworkCredential networkCredential = null;
                if (this.Credential != null)
                {
                    base.WriteVerbose("Network Credentials given, will attempt to use them.");
                    networkCredential = this.Credential.GetNetworkCredential();
                }
                bool hasPrinARN = this.ParameterWasBound("PrincipalARN") && !string.IsNullOrWhiteSpace(this.PrincipalARN);
                bool hasRoleARN = this.ParameterWasBound("RoleARN") && !string.IsNullOrWhiteSpace(this.RoleARN);
                if (hasPrinARN != hasRoleARN)
                    this.ThrowExecutionError("RoleARN must be specified with PrincipalARN.", this);
                if (hasPrinARN & hasRoleARN)
                    preselectedPrincipalAndRoleARN = $"{this.RoleARN},{this.PrincipalARN}";

                base.WriteVerbose($"Retrieving stored endpoint '{this.EndpointName}'.");
                SAMLEndpoint endpoint = new SAMLEndpointManager().GetEndpoint(this.EndpointName);
                if (endpoint == null)
                {
                    this.ThrowExecutionError("Endpoint not found. You must first call Set-AWSSamlEndpoint to store the endpoint URL to the IBM IDS site.", this);
                }
                // We can't use the nice controller they built, as it uses there own assertion class that has issues because of dictionary use.
                // var sAMLAssertion = new SAMLAuthenticationController(new IBMSAMAuthenticationController(this),new IBMSAMLAuthenticationResponseParser(), null).GetSAMLAssertion(endpoint.EndpointUri.ToString(), networkCredential, endpoint.AuthenticationType.ToString());
                base.WriteVerbose("Authenticating with endpoint to verify role data...");
                string authenticationResponse = new IBMSAMAuthenticationController(this).Authenticate(endpoint.EndpointUri, networkCredential, endpoint.AuthenticationType.ToString(), null);
                base.WriteVerbose("Parsing authentication response...");
                var sAMLAssertion = new IBMSAMLAuthenticationResponseParser().Parse(authenticationResponse);
                RegionEndpoint regionEndpoint = RegionEndpoint.USEast2;
                if (!string.IsNullOrEmpty(this.STSEndpointRegion))
                {
                    regionEndpoint = RegionEndpoint.GetBySystemName(this.STSEndpointRegion);
                    base.WriteVerbose($"Endpoint region set to {regionEndpoint.SystemName}.");
                }

                // We can't store multiple roles until the nice built-in SAMLAuthenticationController gets fixed to support multiple roles in the same subscription
                //if (this.StoreAllRoles)
                //{
                //    string userIdentity = null;
                //    if (networkCredential != null)
                //    {
                //        if (string.IsNullOrEmpty(networkCredential.Domain))
                //        {
                //            userIdentity = networkCredential.UserName;
                //        }
                //        else
                //        {
                //            userIdentity = string.Format("{0}\\{1}", networkCredential.Domain, networkCredential.UserName);
                //        }
                //    }
                //    foreach (var role in sAMLAssertion.RoleSet)
                //    {
                //        string arns = role.Value;
                //        base.WriteVerbose($"Saving role '{arns}' to profile '{role.PrincipalArn.AccountId}'.");
                //        this.RegisterProfile(
                //            new CredentialProfileOptions() {
                //                EndpointName = this.EndpointName,
                //                RoleArn = arns,
                //                UserIdentity = userIdentity
                //            },
                //            role.PrincipalArn.AccountId,
                //            null,
                //            regionEndpoint
                //        );
                //        base.WriteObject(role.PrincipalArn.AccountId);
                //    }
                //    //IDictionary<string, string> roleSet = sAMLAssertion.RoleSet;
                //    //using (IEnumerator<string> enumerator = roleSet.Keys.GetEnumerator())
                //    //{
                //    //    while (enumerator.MoveNext())
                //    //    {
                //    //        string accountId = enumerator.Current;
                //    //        string arns = roleSet[accountId];
                //    //        base.WriteVerbose(string.Format("Saving role '{0}' to profile '{1}'.", arns, accountId));
                //    //        SettingsStore.RegisterProfile(new CredentialProfileOptions
                //    //        {
                //    //            EndpointName = this.EndpointName,
                //    //            RoleArn = arns,
                //    //            UserIdentity = userIdentity
                //    //        }, accountId, null, regionEndpoint);
                //    //        base.WriteObject(accountId);
                //    //    }
                //    //}
                //}
                //else
                {
                    StoredInfo sendToPipeline = this.SelectAndStoreProfileForRole(sAMLAssertion, preselectedPrincipalAndRoleARN, networkCredential, regionEndpoint);
                    base.WriteObject(sendToPipeline);
                }
            }
            catch (IbmIamErrorException ex)
            {
                base.ThrowTerminatingError(new ErrorRecord(ex, ex.ErrorCode, ErrorCategory.NotSpecified, this));
            }
            catch (IbmIamPasswordExpiredException ex)
            {
                base.ThrowTerminatingError(new ErrorRecord(ex, "PasswordExpired", ErrorCategory.AuthenticationError, this));
            }
            catch (Exception ex)
            {
                base.ThrowTerminatingError(new ErrorRecord(new ArgumentException("Unable to set credentials: " + ex.Message, ex), "ArgumentException", ErrorCategory.InvalidArgument, this));
            }
        }

        private bool TestPreselectedRoleAvailable(string targetPrincipalAndRoleARNs, ICollection<string> roleARNs)
        {
            if (string.IsNullOrEmpty(targetPrincipalAndRoleARNs))
                return false;
            foreach (var role in roleARNs)
            {
                if (role.Equals(targetPrincipalAndRoleARNs, StringComparison.OrdinalIgnoreCase))
                    return true;
            }
            base.WriteVerbose($"The specified principal and role ARNs, {targetPrincipalAndRoleARNs}, could not be found in the SAML response.");
            return false;
        }

        private StoredInfo SelectAndStoreProfileForRole(IBM.IAM.AWS.SecurityToken.SAML.SAMLAssertion sAMLAssertion, string preselectedPrincipalAndRoleARN, NetworkCredential networkCredential, RegionEndpoint stsEndpointRegion)
        {
            string roleArn = preselectedPrincipalAndRoleARN;
            if (!this.TestPreselectedRoleAvailable(preselectedPrincipalAndRoleARN, sAMLAssertion.RoleSet.Select(arn => arn.Value).ToList()))
            {
                if (sAMLAssertion.RoleSet.Count == 1)
                {
                    roleArn = sAMLAssertion.RoleSet.First().Value;
                    base.WriteVerbose(string.Format("Only one role available, pre-selecting role ARN {0}", preselectedPrincipalAndRoleARN));
                }
                else
                {
                    IList<SAMLCredential> roleSet = null;
                    if (!string.IsNullOrWhiteSpace(this.AwsAccountId))
                        roleSet = sAMLAssertion.RoleSet.Where(r => r.RoleArn.AccountId.Equals(this.AwsAccountId, StringComparison.InvariantCultureIgnoreCase)).ToList();
                    else
                        roleSet = sAMLAssertion.RoleSet;

                    Collection<ChoiceDescription> collection = new Collection<ChoiceDescription>();
                    char c = 'A';
                    foreach (var cred in roleSet.OrderBy(r => r.RoleArn.AccountId).ThenBy(r => r.RoleArn.Resource))
                    {
                        string label;
                        if (sAMLAssertion.RoleSet.Count <= 26 && c <= 'Z')
                        {
                            label = $"&{c} - {cred.RoleArn.Resource}";
                            c++;
                        }
                        else
                            label = cred.RoleArn.Resource;

                        collection.Add(new ChoiceDescription(label, cred.Value));
                    }
                    int idxDefault = 0;
                    if (!string.IsNullOrWhiteSpace(this.HelpFindResource))
                    {
                        var fnd = collection.Where(r => r.Label.IndexOf(this.HelpFindResource, StringComparison.InvariantCultureIgnoreCase) >= 0).FirstOrDefault();
                        if (fnd != null)
                            idxDefault = collection.IndexOf(fnd);
                    }
                    int index = base.Host.UI.PromptForChoice("Select Role", "Select the role to be assumed when this profile is active", collection, idxDefault);
                    roleArn = collection[index].HelpMessage;
                }
            }
            if (string.IsNullOrEmpty(roleArn))
                this.ThrowExecutionError("A role is required before the profile can be stored.", this);

            base.WriteVerbose($"Saving to profile '{this.StoreAs}'.");
            string userIdentity = null;
            if (networkCredential != null)
            {
                userIdentity = (string.IsNullOrEmpty(networkCredential.Domain) ? networkCredential.UserName : (networkCredential.Domain + "\\" + networkCredential.UserName));
            }
            var role = sAMLAssertion.RoleSet.FirstOrDefault(r => r.Value.Equals(roleArn, StringComparison.OrdinalIgnoreCase));
            //BasicAWSCredentials basicCreds = new BasicAWSCredentials("", "");
            AnonymousAWSCredentials anonCred = new AnonymousAWSCredentials();
            AmazonSecurityTokenServiceClient sts = new AmazonSecurityTokenServiceClient(anonCred, stsEndpointRegion);
            base.WriteVerbose($"Calling AssumeRoleWithSAML at the {stsEndpointRegion.SystemName} region to retrieve Access and Secret Keys.");
            AssumeRoleWithSAMLResponse response = sts.AssumeRoleWithSAML(new AssumeRoleWithSAMLRequest() {
                PrincipalArn = role.PrincipalArn.OriginalString,
                RoleArn = role.RoleArn.OriginalString,
                SAMLAssertion = sAMLAssertion.AssertionDocument,
                DurationSeconds = 3600
            });
            this.RegisterProfile(
                new CredentialProfileOptions()
                {
                    AccessKey = response.Credentials.AccessKeyId,
                    SecretKey = response.Credentials.SecretAccessKey,
                    Token = response.Credentials.SessionToken
                },
                this.StoreAs,
                this.ProfileLocation,
                stsEndpointRegion);
            base.WriteVerbose($"Stored AWS Credentials as {this.StoreAs}.\r\nUse 'Set-AWSCredentials -ProfileName {this.StoreAs}' to load this profile and obtain temporary AWS credentials.");
            return new StoredInfo {
                StoreAs = this.StoreAs,
                PrincipalArn = role.PrincipalArn,
                RoleArn = role.RoleArn
            };
        }

        private void RegisterProfile(CredentialProfileOptions profileOptions, string storeAs, string profileLocation, RegionEndpoint region)
        {
            CredentialProfile credentialProfile = new CredentialProfile(storeAs, profileOptions);
            credentialProfile.Region = region;
            new CredentialProfileStoreChain(profileLocation).RegisterProfile(credentialProfile);
        }

        private bool ParameterWasBound(string parameterName)
        {
            return base.MyInvocation.BoundParameters.ContainsKey(parameterName);
        }
        private void ThrowExecutionError(string message, object errorSource)
        {
            this.ThrowExecutionError(message, errorSource, null);
        }
        private void ThrowExecutionError(string message, object errorSource, Exception innerException)
        {
            base.ThrowTerminatingError(
                new ErrorRecord(
                    new InvalidOperationException(message, innerException), 
                    (innerException == null) ? "InvalidOperationException" : innerException.GetType().ToString(), 
                    ErrorCategory.InvalidOperation, 
                    errorSource
                    )
                );
        }

    }
}
