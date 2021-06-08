using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
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
        private readonly UserManager<IdentityUser> _userManager;
        private readonly IOptions<DuosecurityConfig> _mfaConfig;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<DuoCallback> _logger;

        private const string OAUTH_V1_HEALTH_CHECK_ENDPOINT = "https://{0}/oauth/v1/health_check";
        private const string OAUTH_V1_AUTHORIZE_ENDPOINT = "https://{0}/oauth/v1/authorize";
        private const string OAUTH_V1_TOKEN_ENDPOINT = "https://{0}/oauth/v1/token";

        public DuoCallback(SignInManager<IdentityUser> signInManager,
            ILogger<DuoCallback> logger,
            UserManager<IdentityUser> userManager,
            IOptions<DuosecurityConfig> mfaConfig)
        {
            _userManager = userManager;
            _mfaConfig = mfaConfig;
            _signInManager = signInManager;
            _logger = logger;
        }

        [BindProperty]
        public InputModel Input { get; set; }

        public IList<AuthenticationScheme> ExternalLogins { get; set; }

        public string ReturnUrl { get; set; }

        [TempData]
        public string ErrorMessage { get; set; }

        public class InputModel
        {
            [Required]
            [EmailAddress]
            public string Email { get; set; }

            [Required]
            [DataType(DataType.Password)]
            public string Password { get; set; }

            [Display(Name = "Remember me?")]
            public bool RememberMe { get; set; }
        }

        public async Task OnGetAsync(string returnUrl = null)
        {
            // this could be the call back from Duo!
            if (HttpContext.Request.Query.ContainsKey("state"))
            {
                // Success! Redirect to home page for now...
                // do we need to do more?? 
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

        public async Task<IActionResult> OnPostAsync(string returnUrl = null)
        {
            returnUrl ??= Url.Content("~/");

            ExternalLogins = (await _signInManager.GetExternalAuthenticationSchemesAsync()).ToList();

            if (ModelState.IsValid)
            {
                // This doesn't count login failures towards account lockout
                // To enable password failures to trigger account lockout, set lockoutOnFailure: true
                var result = await _signInManager.PasswordSignInAsync(Input.Email, Input.Password, Input.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    _logger.LogInformation("User logged in.");
                    var token = GenerateHealthToken(_mfaConfig.Value);

                    var client = new HttpClient();
                    var healthUrl = string.Format(OAUTH_V1_HEALTH_CHECK_ENDPOINT, _mfaConfig.Value.Hostname);

                    var healthContent = new MultipartFormDataContent();
                    healthContent.Add(new StringContent(token), "client_assertion");
                    healthContent.Add(new StringContent(_mfaConfig.Value.ClientId), "client_id");
                    var healtResponse = await client.PostAsync(healthUrl, healthContent);

                    var respCon = await healtResponse.Content.ReadAsStringAsync();
                    var state = Guid.NewGuid().ToString();
                    var authzToken = GenerateAuthzToken(_mfaConfig.Value, state, Input.Email);
                    var authzUrl = string.Format(OAUTH_V1_AUTHORIZE_ENDPOINT, _mfaConfig.Value.Hostname);
                    var queryStringDict = new Dictionary<string, string>
                    {
                        {"response_type", "code" },
                        {"client_id", _mfaConfig.Value.ClientId },
                        {"request", authzToken },
                    };
                    var authzCompleteUrl = QueryHelpers.AddQueryString(authzUrl, queryStringDict);

                    return Redirect(authzCompleteUrl);
                }
                if (result.RequiresTwoFactor)
                {
                    return RedirectToPage("./LoginWith2fa", new { ReturnUrl = returnUrl, RememberMe = Input.RememberMe });
                }
                if (result.IsLockedOut)
                {
                    _logger.LogWarning("User account locked out.");
                    return RedirectToPage("./Lockout");
                }
                else
                {
                    ModelState.AddModelError(string.Empty, "Invalid login attempt.");
                    return Page();
                }
            }

            // If we got this far, something failed, redisplay form
            return Page();
        }

        private string GenerateHealthToken(DuosecurityConfig config)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.ClientSecret));

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("sub", config.ClientId),
                    new Claim("jti", Guid.NewGuid().ToString() )
                }),
                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = config.ClientId,
                IssuedAt = DateTime.UtcNow,
                Audience = string.Format(OAUTH_V1_HEALTH_CHECK_ENDPOINT, config.Hostname),
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha512)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }

        private string GenerateAuthzToken(DuosecurityConfig config, string state, string username)
        {
            var mySecurityKey = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(config.ClientSecret));

            var tokenHandler = new JwtSecurityTokenHandler();
            var tokenDescriptor = new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]
                {
                    new Claim("sub", config.ClientId),
                    new Claim("jti", Guid.NewGuid().ToString() ),
                    new Claim("redirect_uri", config.RedirectUrl),
                    new Claim("client_id",config.ClientId),
                    new Claim("state", state),
                    new Claim("response_type", "code"),
                    new Claim("duo_uname", username),
                    //new Claim("use_duo_code_attribute", "true"),
                    new Claim("scope", "openid")
                }),

                Expires = DateTime.UtcNow.AddMinutes(5),
                Issuer = config.ClientId,
                IssuedAt = DateTime.UtcNow,
                Audience = string.Format("https://{0}", config.Hostname),
                SigningCredentials = new SigningCredentials(mySecurityKey, SecurityAlgorithms.HmacSha512)
            };

            var token = tokenHandler.CreateToken(tokenDescriptor);
            return tokenHandler.WriteToken(token);
        }
    }
}
