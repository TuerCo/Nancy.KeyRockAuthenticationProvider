using System;
using System.Collections.Generic;
using System.Configuration;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider.Configuration
{
    internal static class ProviderConfigHelper
    {
        internal static Configuration UseConfig(string sectionName = "keyRock")
        {
            if (string.IsNullOrEmpty(sectionName))
            {
                throw new ArgumentNullException(sectionName);
            }

            var configSection = ConfigurationManager.GetSection(sectionName) as KeyRockConfiguration;

            return new Configuration
            {
                BaseUrl = configSection.Urls.BaseUrl,
                AuthenticateRedirectionUrl = configSection.Urls.AuthenticationRedirectionUrl
            };
        }
    }
}
