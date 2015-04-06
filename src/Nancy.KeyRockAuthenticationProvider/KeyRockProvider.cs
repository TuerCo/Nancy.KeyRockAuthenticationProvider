using System.Net;
using Nancy.Helpers;
using RestSharp;
using SimpleAuthentication.Core;
using SimpleAuthentication.Core.Exceptions;
using SimpleAuthentication.Core.Providers;
using System;
using System.Collections.Generic;
using System.Collections.Specialized;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using Nancy.KeyRockAuthenticationProvider.KeyRock;
using Nancy.KeyRockAuthenticationProvider.Configuration;

namespace Nancy.KeyRockAuthenticationProvider
{
    public class KeyRockProvider : BaseOAuth20Provider<AccessTokenResult>
    {
        private string BaseUrl;
        private string _code;

        public KeyRockProvider(ProviderParams providerParams) : this("KeyRock", providerParams)
        {
            var configuration = Configuration.Configuration.GetConfiguration();

            BaseUrl = configuration.BaseUrl;
            AuthenticateRedirectionUrl = new Uri(configuration.AuthenticateRedirectionUrl);
        }

        protected KeyRockProvider(string name, ProviderParams providerParams)
            : base(name, providerParams)
        {
        }

        #region BaseOAuth20Token<AccessTokenResult> Implementation

        protected override string CreateRedirectionQuerystringParameters(Uri callbackUri, string state)
        {
            if (callbackUri == null)
            {
                throw new ArgumentNullException("callbackUri");
            }

            if (string.IsNullOrEmpty(state))
            {
                throw new ArgumentNullException("state");
            }

            // REFERENCE: https://github.com/ging/fi-ware-idm/wiki/Using-the-FI-LAB-instance
            return string.Format("response_type=code&client_id={0}&redirect_uri={1}{2}{3}",
                                 PublicApiKey, callbackUri.AbsoluteUri, GetScope(), GetQuerystringState(state))
                         .ToLowerInvariant();
        }

        protected override string RetrieveAuthorizationCode(NameValueCollection queryStringParameters)
        {
            if (queryStringParameters == null)
            {
                throw new ArgumentNullException("queryStringParameters");
            }

            if (queryStringParameters.Count <= 0)
            {
                throw new ArgumentOutOfRangeException("queryStringParameters");
            }

            var code = queryStringParameters["code"];

            // Maybe we have an error?
            var errorReason = queryStringParameters["error_reason"];
            var error = queryStringParameters["error"];
            var errorDescription = queryStringParameters["error_description"];
            if (!string.IsNullOrEmpty(errorReason) &&
                !string.IsNullOrEmpty(error) &&
                !string.IsNullOrEmpty(errorDescription))
            {
                var errorMessage = string.Format("Reason: {0}. Error: {1}. Description: {2}.",
                                                 string.IsNullOrEmpty(errorReason) ? "-no error reason-" : errorReason,
                                                 string.IsNullOrEmpty(error) ? "-no error-" : error,
                                                 string.IsNullOrEmpty(errorDescription)
                                                     ? "-no error description-"
                                                     : errorDescription);

                throw new AuthenticationException(errorMessage);
            }

            if (string.IsNullOrEmpty(code))
            {
                const string errorMessage = "No code parameter provided in the response query string from KeyRock.";

                throw new AuthenticationException(errorMessage);
            }
            _code = code;
            return code;
        }

        protected override IRestResponse<AccessTokenResult> ExecuteRetrieveAccessToken(string authorizationCode,
                                                                                       Uri redirectUri)
        {
            if (string.IsNullOrEmpty(authorizationCode))
            {
                throw new ArgumentNullException("authorizationCode");
            }

            if (redirectUri == null ||
                string.IsNullOrEmpty(redirectUri.AbsoluteUri))
            {
                throw new ArgumentNullException("redirectUri");
            }

            var restRequest = new RestRequest("oauth2/token");
            restRequest.AddParameter("code", _code);
            restRequest.AddParameter("grant_type", "authorization_code");//authorizationCode);
            restRequest.AddParameter("redirect_uri", redirectUri.AbsoluteUri.ToLowerInvariant());
            restRequest.AddHeader("Content-Type", "application/x-www-form-urlencoded");

            var restClient = RestClientFactory.CreateRestClient(BaseUrl);

            restClient.Authenticator = new HttpBasicAuthenticator(PublicApiKey, SecretApiKey);

            return restClient.Post<AccessTokenResult>(restRequest);
        }

        protected override AccessToken MapAccessTokenResultToAccessToken(AccessTokenResult accessTokenResult)
        {
            if (accessTokenResult == null)
            {
                throw new ArgumentNullException("accessTokenResult");
            }

            if (string.IsNullOrEmpty(accessTokenResult.access_token) ||
                accessTokenResult.expires_in <= 0)
            {
                var errorMessage =
                    string.Format(
                        "Retrieved a KeyRock Access Token but there's an error with either the access_token and/or expires_on parameters. Access Token: {0}. Expires In: {1}.",
                        string.IsNullOrEmpty(accessTokenResult.access_token)
                            ? "-no access token-"
                            : accessTokenResult.access_token,
                        accessTokenResult.expires_in.ToString());

                throw new AuthenticationException(errorMessage);
            }

            return new AccessToken
            {
                PublicToken = accessTokenResult.access_token,
                ExpiresOn = DateTime.UtcNow.AddSeconds(accessTokenResult.expires_in)
            };
        }

        protected override UserInformation RetrieveUserInformation(AccessToken accessToken)
        {
            if (accessToken == null)
            {
                throw new ArgumentNullException("accessToken");
            }

            if (string.IsNullOrEmpty(accessToken.PublicToken))
            {
                throw new ArgumentException("accessToken.PublicToken");
            }

            IRestResponse<UserInfoResult> response;

            try
            {
                var restRequest = new RestRequest("user");
                restRequest.AddParameter("access_token", accessToken.PublicToken);

                var restClient = RestClientFactory.CreateRestClient(BaseUrl);

                response = restClient.Execute<UserInfoResult>(restRequest);
            }
            catch (Exception exception)
            {
                var authenticationException =
                    new AuthenticationException("Failed to retrieve any UserInfoResult data from the KeyRock Api.", exception);
                var errorMessage = authenticationException.RecursiveErrorMessages();
                throw new AuthenticationException(errorMessage, exception);
            }

            if (response == null ||
                response.StatusCode != System.Net.HttpStatusCode.OK ||
                response.Data == null)
            {
                var errorMessage = string.Format(
                    "Failed to obtain some 'User' data from the KeyRock api OR the the response was not an HTTP Status 200 OK. Response Status: {0}. Response Description: {1}. Error Message: {2}.",
                    response == null ? "-- null response --" : response.StatusCode.ToString(),
                    response == null ? string.Empty : response.StatusDescription,
                    response == null
                        ? string.Empty
                        : response.ErrorException == null
                              ? "--no error exception--"
                              : response.ErrorException.RecursiveErrorMessages());

                throw new AuthenticationException(errorMessage);
            }

            var userInfoResult = response.Data;

            return new UserInformation
            {
                Email = userInfoResult.Email,
                Id = userInfoResult.ActorId.ToString(),
                Name = userInfoResult.DisplayName,
                UserName = userInfoResult.NickName,
                Gender = GenderType.Unknown
            };
        }

        #endregion

        public override IEnumerable<string> DefaultScopes
        {
            get { return new[] { "email" }; }
        }

        public override string ScopeSeparator
        {
            get { return ","; }
        }
    }
}
