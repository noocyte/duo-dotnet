using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net.Http;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Duo.DotNet.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class DuoCallback : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<DuoCallback> _logger;
        private readonly DuosecurityConfig _mfaConfig;

        private const string OAUTH_V1_TOKEN_ENDPOINT = "https://{0}/oauth/v1/token";


        public DuoCallback(SignInManager<IdentityUser> signInManager,
            ILogger<DuoCallback> logger,
            IOptions<DuosecurityConfig> mfaConfig)
        {
            _signInManager = signInManager;
            _logger = logger;
            _mfaConfig = mfaConfig.Value;
        }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }


        public async Task OnGetAsync(string returnUrl = null)
        {
            // this could be the call back from Duo!
            if (HttpContext.Request.Query.ContainsKey("state"))
            {
                _logger.LogInformation("Duo Callback success!");

                // do we need to do more?? 
                var authToken = GenerateAuthToken(_mfaConfig);
                if (!Request.Query.TryGetValue("code", out var code))
                    return; // what?

                var client = new HttpClient();
                var authUrl = string.Format(OAUTH_V1_TOKEN_ENDPOINT, _mfaConfig.Hostname);

                var healthContent = new MultipartFormDataContent
                    {
                        { new StringContent("authorization_code"), "grant_type" },
                        { new StringContent(code.ToString()),  "code" },
                        { new StringContent(_mfaConfig.RedirectUrl), "redirect_uri" },
                        { new StringContent("urn:ietf:params:oauth:client-assertion-type:jwt-bearer"), "client_assertion_type" },
                        { new StringContent(authToken), "client_assertion"}
                    };

                var authResponse = await client.PostAsync(authUrl, healthContent);

                var respCon = await authResponse.Content.ReadAsStringAsync();
                //var response = JsonConvert.DeserializeObject<AuthTokenResponse>(respCon);
                //var duoToken = new JwtSecurityTokenHandler().ReadJwtToken(response.id_token);

                // we should verify token and check that it was really success...

                ReturnUrl = Url.Content("/");
                return;
            }

            if (!string.IsNullOrEmpty(ErrorMessage))
            {
                ModelState.AddModelError(string.Empty, ErrorMessage);
            }

            returnUrl ??= Url.Content("~/");

            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            ReturnUrl = returnUrl;
        }

        private static string GenerateAuthToken(DuosecurityConfig config)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.ClientSecret));

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("sub", config.ClientId),
                    new Claim("jti", Guid.NewGuid().ToString())
                }),

                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = config.ClientId,
                IssuedAt = DateTime.UtcNow,
                Audience = string.Format(OAUTH_V1_TOKEN_ENDPOINT, config.Hostname),
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha512)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }

    public class AuthTokenResponse
    {
        public string access_token { get; set; }
        public string id_token { get; set; }
        public int expires_in { get; set; }
        public string token_type { get; set; }
    }


    public class IdToken
    {
        public string iss { get; set; }
        public string sub { get; set; }
        public string aud { get; set; }
        public int exp { get; set; }
        public int iat { get; set; }
        public int auth_time { get; set; }
        public Auth_Result auth_result { get; set; }
        public Auth_Context auth_context { get; set; }
        public string preferred_username { get; set; }
    }

    public class Auth_Result
    {
        public string result { get; set; }
        public string status { get; set; }
        public string status_msg { get; set; }
    }

    public class Auth_Context
    {
        public string txid { get; set; }
        public int timestamp { get; set; }
        public User user { get; set; }
        public Application application { get; set; }
        public Auth_Device auth_device { get; set; }
        public Access_Device access_device { get; set; }
        public string factor { get; set; }
        public string event_type { get; set; }
        public string result { get; set; }
        public string reason { get; set; }
        public string alias { get; set; }
        public DateTime isotimestamp { get; set; }
        public string email { get; set; }
        public object ood_software { get; set; }
    }

    public class User
    {
        public string name { get; set; }
        public string key { get; set; }
        public object[] groups { get; set; }
    }

    public class Application
    {
        public string name { get; set; }
        public string key { get; set; }
    }

    public class Auth_Device
    {
        public string ip { get; set; }
        public Location location { get; set; }
        public string name { get; set; }
    }

    public class Location
    {
        public string city { get; set; }
        public string state { get; set; }
        public string country { get; set; }
    }

    public class Access_Device
    {
        public string ip { get; set; }
        public Location location { get; set; }
        public object hostname { get; set; }
        public string epkey { get; set; }
        public string os { get; set; }
        public string os_version { get; set; }
        public string browser { get; set; }
        public string browser_version { get; set; }
        public string flash_version { get; set; }
        public string java_version { get; set; }
        public string is_encryption_enabled { get; set; }
        public string is_firewall_enabled { get; set; }
        public string is_password_set { get; set; }
    }
}
