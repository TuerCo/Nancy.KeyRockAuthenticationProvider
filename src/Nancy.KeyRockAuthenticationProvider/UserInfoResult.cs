using SimpleAuthentication.Core;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider.KeyRock
{
    public class UserInfoResult : UserInformation
    {
        public new int Id { get; set; }
        public int ActorId { get; set; }
        public string NickName { get; set; }
        public string DisplayName { get; set; }
        public new string Email { get; set; }
        public List<Role> Roles { get; set; }
        public List<Organization> Organizations { get; set; }
    }

    public class Role
    {
        public int Id { get; set; }
        public string Name { get; set; }
    }

    public class Organization
    {
        public int Id { get; set; }
        public int ActorId { get; set; }
        public string DisplayName { get; set; }
        public List<Role> Roles { get; set; }
    }
}
