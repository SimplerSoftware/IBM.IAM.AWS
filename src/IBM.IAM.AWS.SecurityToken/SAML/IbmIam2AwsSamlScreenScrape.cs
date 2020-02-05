using System;
using System.Collections;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Management.Automation;
using System.Net;
using System.Runtime.InteropServices;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Xml;

namespace IBM.IAM.AWS.SecurityToken.SAML
{
    class IbmIam2AwsSamlScreenScrape
    {
        const string UserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/52.0.2743.116 Safari/537.36 Edge/15.15063";
        private static readonly Regex SAMLResponseField = new Regex("SAMLResponse\\W+value\\=\\\"([^\\\"]+)\\\"");
        private readonly PSCmdlet _cmdlet;

        public string Assertion { get; private set; }
        public SecurityProtocolType SecurityProtocol { get; set; }
        public Action<string, LogType> Logger { get; set; } = null;
        public string ErrorElement { get; set; } = "p";
        public string ErrorClass { get; set; } = "error";
        public IWebProxy Proxy { get; set; } = null;
        public NetworkCredential Credentials { get; set; }

        public IbmIam2AwsSamlScreenScrape(PSCmdlet cmdlet)
        {
            _cmdlet = cmdlet ?? throw new ArgumentNullException(nameof(cmdlet));
        }

        public string RetrieveSAMLAssertion(Uri identityProvider)
        {
            string result = null;
            //ImpersonationState impersonationState = null;
            try
            {
                CookieContainer cookies = new CookieContainer();
                //if (credentials != null)
                //{
                //    impersonationState = ImpersonationState.Impersonate(credentials.GetCredential(identityProvider, authenticationType));
                //}
                using (HttpWebResponse httpWebResponse = this.QueryProvider(identityProvider, cookies, null))
                {
                    using (StreamReader streamReader = new StreamReader(httpWebResponse.GetResponseStream()))
                        result = streamReader.ReadToEnd();
                    LoggerInternal(Lang.DebugIdpResponded, LogType.Debug);
                    Dictionary<string, string> values = new Dictionary<string, string>();
                    if (Credentials != null)
                    {
                        values.Add("USERNAME", Credentials.UserName);
                        values.Add("PASSWORD", Credentials.Password);
                    }
                    var formResponse = GetFormData(result, values);

                    bool stopRequest = false;
                    int tryCount = 1;
                    do
                    {
                        Uri postTo = new Uri(httpWebResponse.ResponseUri, formResponse.Action);
                        using (HttpWebResponse httpWebResponsePost = this.PostProvider(postTo, cookies, httpWebResponse.ResponseUri, formResponse.FormData))
                        {
                            if (httpWebResponsePost.StatusCode == HttpStatusCode.Found)
                            {
                                string location = httpWebResponsePost.Headers[HttpResponseHeader.Location];
                                if (!string.IsNullOrWhiteSpace(location))
                                {
                                    Uri uLocation = new Uri(location);
                                    var qry = new UrlEncodingParser(uLocation);
                                    if (qry.AllKeys.Contains("TAM_OP", StringComparer.CurrentCultureIgnoreCase))
                                    {
                                        string TAM_OP = qry["TAM_OP"];
                                        //https://www.ibm.com/support/knowledgecenter/en/SSPREK_9.0.0/com.ibm.isam.doc/wrp_config/concept/con_op_redir.html
                                        switch (TAM_OP.ToUpperInvariant())
                                        {
                                            case "ACCT_INACTIVATED":
                                                throw new IbmIamException(Lang.Error_ACCT_INACTIVATED);
                                            case "ACCT_LOCKED":
                                                throw new IbmIamException(Lang.Error_ACCT_LOCKED);
                                            case "CERT_LOGIN":
                                                throw new IbmIamException(Lang.Error_CERT_LOGIN);
                                            case "CERT_STEPUP_HTTP":
                                                throw new IbmIamException(Lang.Error_CERT_STEPUP_HTTP);
                                            case "EAI_AUTH_ERROR":
                                                throw new IbmIamException(Lang.Error_EAI_AUTH_ERROR);
                                            case "ERROR":
                                                {
                                                    string ERROR_CODE = qry["ERROR_CODE"];
                                                    switch (ERROR_CODE.ToUpperInvariant())
                                                    {
                                                        case "0XPWDEXPRD":
                                                            string url = qry["URL"];
                                                            throw new IbmIamPasswordExpiredException(Lang.Error_0XPWDEXPRD) { HelpLink = url };
                                                        default:
                                                            throw new IbmIamErrorException(string.Format(CultureInfo.CurrentCulture, Lang.Error_Unknown_Error_Code, ERROR_CODE), ERROR_CODE);
                                                    }
                                                }
                                            case "FAILED_CERT":
                                                throw new IbmIamException(Lang.Error_FAILED_CERT);
                                            case "HELP":
                                                throw new IbmIamException(Lang.Error_HELP);
                                            case "LOGIN":
                                                throw new IbmIamException(Lang.Error_LOGIN);
                                            case "LOGIN_SUCCESS":
                                                throw new IbmIamException(Lang.Error_LOGIN_SUCCESS);
                                            case "LOGOUT":
                                                throw new IbmIamException(Lang.Error_LOGOUT);
                                            case "PASSWD":
                                                throw new IbmIamException(Lang.Error_PASSWD);
                                            case "PASSWD_EXP":
                                                {
                                                    string url = qry["URL"];
                                                    throw new IbmIamPasswordExpiredException(Lang.Error_PASSWD_EXP) { HelpLink = url };
                                                }
                                            case "PASSWD_REP_FAILURE":
                                                throw new IbmIamException(Lang.Error_PASSWD_REP_FAILURE);
                                            case "PASSWD_REP_SUCCESS":
                                                throw new IbmIamException(Lang.Error_PASSWD_REP_SUCCESS);
                                            case "PASSWD_WARN":
                                                throw new IbmIamException(Lang.Error_PASSWD_WARN);
                                            case "PASSWD_WARN_FAILURE":
                                                throw new IbmIamException(Lang.Error_PASSWD_WARN_FAILURE);
                                            case "STEPUP":
                                                throw new IbmIamException(Lang.Error_STEPUP);
                                            case "SWITCH_USER":
                                                throw new IbmIamException(Lang.Error_SWITCH_USER);
                                            case "TOO_MANY_SESSIONS":
                                                throw new IbmIamException(Lang.Error_TOO_MANY_SESSIONS);
                                            default:
                                                throw new IbmIamException(string.Format(CultureInfo.CurrentCulture, Lang.Error_Unknown_Operation_Response, TAM_OP));
                                        }
                                    }
                                    else
                                    {
                                        using (HttpWebResponse httpRedirectResponse = this.QueryProvider(uLocation, cookies, httpWebResponse.ResponseUri, true))
                                        {
                                            using (StreamReader streamReader = new StreamReader(httpRedirectResponse.GetResponseStream()))
                                            {
                                                result = streamReader.ReadToEnd();
                                                if (!SAMLResponseField.IsMatch(result))
                                                {
                                                    // This should be asking for the MFA now
                                                    formResponse = GetFormData(result, values);
                                                }
                                                else
                                                {
                                                    stopRequest = true;
                                                    MatchCollection resposne = SAMLResponseField.Matches(result);
                                                    foreach (Match data in resposne)
                                                    {
                                                        return Assertion = data.Groups[1].Value;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                            else
                            {
                                using (StreamReader streamReader = new StreamReader(httpWebResponsePost.GetResponseStream()))
                                {
                                    result = streamReader.ReadToEnd();
                                    string errMsg = CheckErrorMessage(result);
                                    if (!string.IsNullOrWhiteSpace(errMsg))
                                    {
                                        throw new IbmIamException(errMsg);
                                    }
                                    else if (!SAMLResponseField.IsMatch(result))
                                    {
                                        // This should be asking for the MFA now
                                        formResponse = GetFormData(result, values);
                                    }
                                    else
                                    {
                                        stopRequest = true;
                                        MatchCollection resposne = SAMLResponseField.Matches(result);
                                        foreach (Match data in resposne)
                                        {
                                            return Assertion = data.Groups[1].Value;
                                        }
                                    }
                                }
                            }
                        }
                        tryCount++;
                    }
                    while (!stopRequest && tryCount < 5);
                }
            }
            finally
            {
                //if (impersonationState != null)
                //{
                //    impersonationState.Dispose();
                //}
            }
            throw new Exception(Lang.ErrorInvalidCredentials);
        }
      
        private HttpWebResponse QueryProvider(Uri identityProvider, CookieContainer cookies, Uri referer, bool autoRedirect = true)
        {
            LoggerInternal($"Querying identity provider on host '{identityProvider.Host}' via {identityProvider.Scheme}.", LogType.Debug);
            ServicePointManager.SecurityProtocol = this.SecurityProtocol;
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(identityProvider);
            httpWebRequest.UserAgent = UserAgent;
            httpWebRequest.Referer = referer?.ToString();
            httpWebRequest.KeepAlive = true;
            httpWebRequest.PreAuthenticate = true;
            httpWebRequest.AllowAutoRedirect = autoRedirect;
            httpWebRequest.CookieContainer = cookies;
            if (this.Proxy != null)
            {
                LoggerInternal(Lang.DebugProxyUsed, LogType.Debug);
                httpWebRequest.Proxy = this.Proxy;
            }
            httpWebRequest.UseDefaultCredentials = true;
            var rspns = (HttpWebResponse)httpWebRequest.GetResponse();
            LoggerInternal($"Query returned status '{(int)rspns.StatusCode}' '{rspns.StatusDescription}'.", LogType.Debug);
            return rspns;
        }

        private HttpWebResponse PostProvider(Uri identityProvider, CookieContainer cookies, Uri referer, Dictionary<string, string> formData)
        {
            // Create POST data and convert it to a byte array.  
            StringBuilder postData = new StringBuilder();
            foreach (string key in formData.Keys)
            {
                if (postData.Length == 0)
                    postData.Append($"{key}={WebUtility.UrlEncode(formData[key])}");
                else
                    postData.Append($"&{key}={WebUtility.UrlEncode(formData[key])}");
            }
            byte[] byteArray = Encoding.UTF8.GetBytes(postData.ToString());

            LoggerInternal($"Posting to identity provider on host '{identityProvider.Host}' via {identityProvider.Scheme}.", LogType.Debug);
            ServicePointManager.SecurityProtocol = this.SecurityProtocol;
            HttpWebRequest httpWebRequest = (HttpWebRequest)WebRequest.Create(identityProvider);
            httpWebRequest.UserAgent = UserAgent;
            httpWebRequest.Referer = referer?.ToString();
            httpWebRequest.KeepAlive = true;
            httpWebRequest.PreAuthenticate = true;
            httpWebRequest.AllowAutoRedirect = false;
            httpWebRequest.CookieContainer = cookies;
            httpWebRequest.Method = "POST";
            httpWebRequest.ContentType = "application/x-www-form-urlencoded";
            httpWebRequest.ContentLength = byteArray.Length;
            if (this.Proxy != null)
            {
                LoggerInternal(Lang.DebugProxyUsed, LogType.Debug);
                httpWebRequest.Proxy = this.Proxy;
            }

            Stream dataStream = httpWebRequest.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();
            var rspns = (HttpWebResponse)httpWebRequest.GetResponse();
            LoggerInternal($"Post returned status '{(int)rspns.StatusCode}' '{rspns.StatusDescription}'.", LogType.Debug);
            return rspns;
        }

        private FormResponse GetFormData(string htmlResults, Dictionary<string, string> predefinedValues)
        {
            // <form class="form-signin" role="form" method="post" action="Login">
            Regex rgxForm = new Regex(@"<form\s(?<Attr>[^>]*)/?>(?<Content>[\s\w\S\W]*)</form>");
            Regex rgxAtrAction = new Regex(@"(?<=\baction=""|')[^ ""']*");
            var forms = rgxForm.Matches(htmlResults);
            if (forms.Count == 1)
            {
                LoggerInternal(Lang.DebugFoundForm, LogType.Debug);
                FormResponse formResponse = new FormResponse();
                string formAttributes = forms[0].Groups["Attr"].Value;
                string formContent = forms[0].Groups["Content"].Value;

                Match mAtt;
                if ((mAtt = rgxAtrAction.Match(formAttributes)).Success)
                    formResponse.Action = mAtt.Value;

                //  <input type="username" class="form-control nv-text-input" name="username" required autofocus></input>
                Regex rgxInputs = new Regex(@"<input\s([^>]*)/?>");
                Regex rgxAtrType = new Regex(@"(?<=\stype=[""']+)[^""']*|(?<=\stype=)[\w]+");
                Regex rgxAtrName = new Regex(@"(?<=\sname=[""']+)[^""']*|(?<=\sname=)[\w]+");
                Regex rgxAtrValue = new Regex(@"(?<=\svalue=[""']+)[^""']*|(?<=\svalue=)[\w]+");
                Regex rgxLabels = new Regex(@"<label\s([^>]*)>([^<]+)</label>");
                Regex rgxAtrFor = new Regex(@"(?<=\sfor=[""']+)[^""']*|(?<=\sfor=)[\w]+");

                var fLabels = rgxLabels.Matches(formContent);
                LoggerInternal($"Found {fLabels.Count} label(s) in form. (Some may be hidden fields.)", LogType.Debug);
                foreach (Match match in fLabels)
                {
                    string name = null;
                    string value = null;
                    if (match.Success)
                    {
                        if ((mAtt = rgxAtrFor.Match(match.Groups[1].Value)).Success)
                            name = mAtt.Value;
                        value = WebUtility.HtmlDecode(match.Groups[2].Value);
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            if (formResponse.LabelData.ContainsKey(name))
                                formResponse.LabelData[name] = value;
                            else
                                formResponse.LabelData.Add(name, value);
                        }
                    }
                }

                var fInputs = rgxInputs.Matches(formContent);
                LoggerInternal($"Found {fInputs.Count} input(s) in form. (Some may be hidden fields.)", LogType.Debug);
                foreach (Match match in fInputs)
                {
                    string name = null;
                    string type = null;
                    string value = null;
                    if (match.Success)
                    {
                        if ((mAtt = rgxAtrName.Match(match.Value)).Success)
                            name = mAtt.Value;
                        if ((mAtt = rgxAtrType.Match(match.Value)).Success)
                            type = mAtt.Value;
                        if ((mAtt = rgxAtrValue.Match(match.Value)).Success)
                            value = WebUtility.HtmlDecode(mAtt.Value);
                        if (!type.Equals("hidden", StringComparison.InvariantCultureIgnoreCase) && !type.Equals("submit", StringComparison.InvariantCultureIgnoreCase))
                        {
                            string displayName = name;
                            if (formResponse.LabelData.ContainsKey(name))
                                displayName = $"{formResponse.LabelData[name]}".Trim();
                            if (!displayName.EndsWith(":", StringComparison.InvariantCultureIgnoreCase))
                                displayName += ":";
                            _cmdlet.Host.UI.Write($"{displayName} ");
                            if (predefinedValues != null && predefinedValues.ContainsKey(name.ToUpperInvariant()))
                            {
                                _cmdlet.Host.UI.WriteLine($"(using predefined {name})");
                                value = predefinedValues[name.ToUpperInvariant()];
                            }
                            else if (type.Equals("password", StringComparison.InvariantCultureIgnoreCase))
                            {
                                using (SecureString secStr = _cmdlet.Host.UI.ReadLineAsSecureString())
                                {
                                    value = SecureStringToString(secStr);
                                }
                            }
                            else
                                value = _cmdlet.Host.UI.ReadLine();
                        }
                        if (!string.IsNullOrWhiteSpace(name))
                        {
                            if (formResponse.FormData.ContainsKey(name))
                                formResponse.FormData[name] = value;
                            else
                                formResponse.FormData.Add(name, value);
                        }
                    }
                }

                return formResponse;
            }
            else
            {
                throw new NotSupportedException(Lang.ErrorFoundMultiForms);
            }
        }
       
        private string CheckErrorMessage(string htmlResults)
        {
            // (?<=<p\s[\s\w\S\W]*class=["']*error["']*[^>]*>)(?<Content>.+?)(?=</p>)
            if (string.IsNullOrWhiteSpace(this.ErrorClass))
            {
                Regex rgxElmErr = new Regex($@"(?<=<{this.ErrorElement}[^>]*>)(?<Content>.+?)(?=</{this.ErrorElement}>)", RegexOptions.IgnoreCase);
                var mtch = rgxElmErr.Match(htmlResults);
                if (mtch.Success)
                {
                    return mtch.Groups["Content"].Value;
                }
            }
            else
            {
                Regex rgxElmErr = new Regex($@"(?<=<{this.ErrorElement}\s[\s\w\S\W]*class=[""']*{this.ErrorClass}[""']*[^>]*>)(?<Content>.+?)(?=</{this.ErrorElement}>)", RegexOptions.IgnoreCase);
                var mtch = rgxElmErr.Match(htmlResults);
                if (mtch.Success)
                {
                    return mtch.Groups["Content"].Value;
                }
            }
            return null;
        }
        
        private static string SecureStringToString(SecureString value)
        {
            IntPtr valuePtr = IntPtr.Zero;
            try
            {
                valuePtr = Marshal.SecureStringToGlobalAllocUnicode(value);
                return Marshal.PtrToStringUni(valuePtr);
            }
            finally
            {
                Marshal.ZeroFreeGlobalAllocUnicode(valuePtr);
            }
        }

        public IList<SAMLCredential> GetRolesFromAssertion()
        {
            var payload = System.Text.Encoding.Default.GetString(Convert.FromBase64String(this.Assertion));

            IList<SAMLCredential> lstSAML = new List<SAMLCredential>();

            XmlDocument xDoc = new XmlDocument();
            xDoc.LoadXml(payload);
            XmlNamespaceManager xmlNamespaceManager = new XmlNamespaceManager(xDoc.NameTable);
            xmlNamespaceManager.AddNamespace("saml", "urn:oasis:names:tc:SAML:2.0:assertion");
            foreach (XmlElement attribute in xDoc.SelectNodes(".//saml:Attribute[@Name]", xmlNamespaceManager))
            {
                if (attribute.GetAttribute("Name") == "https://aws.amazon.com/SAML/Attributes/Role")
                {
                    foreach (XmlElement value in attribute.SelectNodes("saml:AttributeValue", xmlNamespaceManager))
                    {
                        string[] array = value.InnerText.Split(',');
                        AmazonResourceName arnRole = AmazonResourceName.Parse(array[0]);
                        AmazonResourceName arnPrincipal = AmazonResourceName.Parse(array[1]);
                        lstSAML.Add(new SAMLCredential
                        {
                            RoleArn = arnRole,
                            PrincipalArn = arnPrincipal
                        });
                    }
                }
            }

            return lstSAML;
        }


        private void LoggerInternal(string message, LogType type = LogType.Info)
        {
            Logger?.Invoke(message, type);
        }

    }
}
