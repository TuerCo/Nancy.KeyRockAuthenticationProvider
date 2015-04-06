using System;
using System.Collections.Generic;
using System.Configuration;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider.Configuration
{
    internal class KeyRockConfiguration : ConfigurationSection
    {
        [ConfigurationProperty("urls", IsRequired=true)]
        internal KeyRockUrls Urls
        {
            get { return (KeyRockUrls)this["urls"]; }
        }
    }
}
