using Nancy;
using SimpleAuthentication.Core.Tracing;

namespace SimpleAuthentication.Sample.NancyAuto.Modules
{
    public class HomeModule : NancyModule
    {
        public HomeModule()
        {
            Get["/"] = _ => View["index"];
        }
    }
}