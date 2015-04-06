using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider.Configuration
{
    internal class Configuration
    {
        internal string BaseUrl { get; set; }
        internal string AuthenticateRedirectionUrl { get; set; }

        private static Lazy<Configuration> _config = new Lazy<Configuration>(() =>
        {
            return ProviderConfigHelper.UseConfig();
        });

        internal static Configuration GetConfiguration()
        {
            return _config.Value;
        }
    }
}
