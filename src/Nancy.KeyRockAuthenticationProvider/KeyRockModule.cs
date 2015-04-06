using Nancy.SimpleAuthentication;
using Nancy.SimpleAuthentication.Caching;
using SimpleAuthentication.Core;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Nancy.KeyRockAuthenticationProvider
{
    public class KeyRockModule : NancyModule
    {
        private const string SessionKeyState = "SimpleAuthentication-StateKey-cf92a651-d638-4ce4-a393-f612d3be4c3a";
        private const string SessionKeyRedirectToUrl = "SimpleAuthentication-RedirectUrlKey-cf92a651-d638-4ce4-a393-f612d3be4c3a";
        private const string SessionKeyRedirectToProviderUrl = "SimpleAuthentication-RedirectToProviderUrlKey-cf92a651-d638-4ce4-a393-f612d3be4c3a";

        private readonly AuthenticationProviderFactory _authenticationProviderFactory;
        private readonly IAuthenticationCallbackProvider _callbackProvider;

        public ICache Cache { get; set; }

        public KeyRockModule(IAuthenticationCallbackProvider callbackProvider)
        {
            Before += context =>
            {
                if (Cache == null)
                {
                    Cache = new SessionCache(context.Request.Session);
                }

                return null;
            };

            _callbackProvider = callbackProvider;
            _authenticationProviderFactory = new AuthenticationProviderFactory();

            Get["/authenticate/keyrock"] = parameters =>
            {
                var providerKey = (string)Request.Query.providerkey;
                if (string.IsNullOrEmpty(providerKey))
                {
                    throw new ArgumentException(
                        "ProviderKey value missing. You need to supply a valid provider key so we know where to redirect the user Eg. providerkey=google.");
                }

                var previousRedirectUrl = string.IsNullOrEmpty((string)Cache[SessionKeyRedirectToProviderUrl])
                                              ? "N.A."
                                              : (string)Cache[SessionKeyRedirectToProviderUrl];

                #region Deserialize Tokens, etc.

                // Retrieve any (previously) serialized access token stuff. (eg. public/private keys and state).
                // TODO: Check if this is an access token or an auth token thingy-thing.
                var state = Cache[SessionKeyState] as string;
                var redirectToUrl = Cache[SessionKeyRedirectToUrl] as string;

                #endregion

                // Lets now start to setup the view model.
                var model = new AuthenticateCallbackData();

                #region Retrieve the User Information

                try
                {
                    // Which provider did we just authenticate with?
                    var provider = _authenticationProviderFactory.AuthenticationProviders["keyrock"];

                    // Where do we return to, after we've authenticated?
                    var callbackUri = GenerateCallbackUri(provider.Name);

                    var queryString = new NameValueCollection();
                    foreach (var key in Request.Query.Keys)
                    {
                        queryString.Add(key, Request.Query[key]);
                    }

                    // Grab the user information.
                    model.AuthenticatedClient = provider.AuthenticateClient(queryString, state, callbackUri);
                }
                catch (Exception exception)
                {
                    model.Exception = exception;
                }

                #endregion

                // Do we have an optional redirect resource? Usually a previous referer?
                if (redirectToUrl != null)
                {
                    model.ReturnUrl = redirectToUrl;
                }

                // Finally! We can hand over the logic to the consumer to do whatever they want.
                return _callbackProvider.Process(this, model);
            };

            Get["/authentication/redirect/keyrock"] = _ =>
            {
                var provider = _authenticationProviderFactory.AuthenticationProviders["keyrock"];

                //// Most providers don't need any pre-setup crap, to redirect to authenticate.
                //// But of course, there's always one - OpenId. We have no idea WHERE we want to
                //// redirect to, so we need to do a particular check here.
                //// Of course, any value here could be used for any other provider. But that would be weird.
                //// TODO: Confirm this is not a security threat / open to abuse in some way.
                //if (identifier != null)
                //{
                //    provider.AuthenticateRedirectionUrl = identifier;
                //}

                //// Where do we return to, after we've authenticated?
                var callbackUri = GenerateCallbackUri("keyrock");

                // Determine where we need to redirect to.
                var redirectToAuthenticateSettings = provider.RedirectToAuthenticate(callbackUri);

                // Remember any important information for after we've come back.
                Cache[SessionKeyState] = redirectToAuthenticateSettings.State;
                Cache[SessionKeyRedirectToUrl] = DetermineReturnUrl();
                Cache[SessionKeyRedirectToProviderUrl] = redirectToAuthenticateSettings.RedirectUri.AbsoluteUri;

                // Now redirect :)
                return Response.AsRedirect(redirectToAuthenticateSettings.RedirectUri.AbsoluteUri);
            };
        }

        private Uri GenerateCallbackUri(string providerName)
        {
            return SystemHelpers.CreateCallBackUri(providerName, Request.Url, Request.Url.BasePath + "/authenticate/keyrock");
        }

        private string _returnToUrlParameterKey;

        public string ReturnToUrlParameterKey
        {
            get { return (string.IsNullOrEmpty(_returnToUrlParameterKey) ? "returnUrl" : _returnToUrlParameterKey); }
            set { _returnToUrlParameterKey = value; }
        }

        private string DetermineReturnUrl()
        {
            var returnUrl = Request.Query[ReturnToUrlParameterKey];

            return string.IsNullOrEmpty(returnUrl)
                       ? Request.Headers.Referrer
                       : returnUrl;
        }
    }
}
