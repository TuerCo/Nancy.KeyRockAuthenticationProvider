using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider.Configuration
{
    internal class KeyRockUrls : ConfigurationElement
    {
        [ConfigurationProperty("baseUrl", IsRequired=true)]
        internal string BaseUrl
        {
            get { return (string)this["baseUrl"]; }
        }

        [ConfigurationProperty("authenticationRedirectionUrl", IsRequired = true)]
        internal string AuthenticationRedirectionUrl
        {
            get { return (string)this["authenticationRedirectionUrl"]; }
        }
    }
}
