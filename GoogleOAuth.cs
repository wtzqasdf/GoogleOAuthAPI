using System;
using System.Collections.Generic;
using System.Linq;
using System.Collections.Specialized;
using System.Text;
using System.Threading.Tasks;
using System.Net;
using System.Web;
using System.IO;
using Newtonsoft.Json;

namespace OAuth
{
    public class GoogleOAuth
    {
        private const string GoogleAuthUrl = "https://accounts.google.com/o/oauth2/v2/auth";
        private const string GoogleTokenUrl = "https://oauth2.googleapis.com/token";
        private const string GoogleUserInfoUrl = "https://www.googleapis.com/oauth2/v3/userinfo";

        private string _clientId;
        private string _clientSecret;
        private string _redirectUrl;
        private string _stateSecret;
        private string[] _scopes;

        public GoogleOAuth(
            string clientId,
            string clientSecret,
            string redirectUrl,
            string stateSecret)
        {
            this._clientId = clientId;
            this._clientSecret = clientSecret;
            this._redirectUrl = redirectUrl;
            this._stateSecret = stateSecret;
            this._scopes = new string[] 
            {
                "https://www.googleapis.com/auth/userinfo.profile",
                "https://www.googleapis.com/auth/userinfo.email"
            };
        }

        /// <summary>
        /// 取得使用者驗證請求URL
        /// </summary>
        public string GetAuthUrl()
        {
            NameValueCollection colle = HttpUtility.ParseQueryString("");
            colle.Add("client_id", this._clientId);
            colle.Add("response_type", "code");
            colle.Add("redirect_uri", this._redirectUrl);
            colle.Add("state", this.GenerateHashState());
            colle.Add("scope", string.Join(' ', this._scopes));
            return $"{GoogleAuthUrl}?{colle.ToString()}";
        }

        /// <summary>
        /// 從使用者驗證的帳號Code取得存取Token
        /// </summary>
        public TokenData GetAccessToken(string authCode)
        {
            NameValueCollection colle = HttpUtility.ParseQueryString("");
            colle.Add("code", authCode);
            colle.Add("client_id", this._clientId);
            colle.Add("client_secret", this._clientSecret);
            colle.Add("grant_type", "authorization_code");
            colle.Add("redirect_uri", this._redirectUrl);
            string json = HttpRequest(GoogleTokenUrl, "POST", out bool isSuccess, colle.ToString(), null);
            return isSuccess ? JsonConvert.DeserializeObject<TokenData>(json) : null;
        }

        /// <summary>
        /// 取得使用者資訊
        /// </summary>
        public UserInfo GetUserInfo(TokenData data)
        {
            string json = HttpRequest(GoogleUserInfoUrl, "GET", out bool isSuccess, null, data.AccessToken);
            return isSuccess ? JsonConvert.DeserializeObject<UserInfo>(json) : null;
        }

        /// <summary>
        /// State驗證
        /// </summary>
        public bool StateVerify(string stateHash)
        {
            return Crypt.BCrypt.Verify(this._stateSecret, stateHash);
        }

        private string GenerateHashState()
        {
            return Crypt.BCrypt.HashPassword(this._stateSecret);
        }

        private string HttpRequest(string url, string method, out bool isSuccess, string body = null, string bearer = null)
        {
            HttpWebRequest req = (HttpWebRequest)HttpWebRequest.Create(url);
            req.Method = method;
            req.ContentType = "application/x-www-form-urlencoded";
            if (bearer != null)
            {
                req.Headers.Add("Authorization", $"Bearer {bearer}");
            }
            if (body != null)
            {
                using (Stream stream = req.GetRequestStream())
                {
                    byte[] bytes = Encoding.UTF8.GetBytes(body);
                    stream.Write(bytes, 0, bytes.Length);
                }
            }
            string content = "";
            try
            {
                WebResponse res = req.GetResponse();
                using (Stream stream = res.GetResponseStream())
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        content = reader.ReadToEnd();
                    }
                }
                isSuccess = true;
            }
            catch (WebException ex)
            {
                WebResponse res = ex.Response;
                using (Stream stream = res.GetResponseStream())
                {
                    using (StreamReader reader = new StreamReader(stream))
                    {
                        DebugHelper.WriteLine(this, reader.ReadToEnd());
                    }
                }
                isSuccess = false;
            }
            return content;
        }

        public class TokenData
        {
            [JsonProperty("access_token")]
            public string AccessToken { get; set; }

            [JsonProperty("expires_in")]
            public int ExpiresIn { get; set; }

            [JsonProperty("scope")]
            public string Scope { get; set; }

            [JsonProperty("token_type")]
            public string TokenType { get; set; }

            [JsonProperty("id_token")]
            public string IdToken { get; set; }
        }

        public class UserInfo
        {
            [JsonProperty("sub")]
            public string Id { get; set; }

            [JsonProperty("name")]
            public string Name { get; set; }

            [JsonProperty("email")]
            public string Email { get; set; }
        }
    }
}
