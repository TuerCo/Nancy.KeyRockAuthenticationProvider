﻿using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider
{
    public class AccessTokenResult
    {
        public string access_token { get; set; }
        public int expires_in { get; set; }
    }
}