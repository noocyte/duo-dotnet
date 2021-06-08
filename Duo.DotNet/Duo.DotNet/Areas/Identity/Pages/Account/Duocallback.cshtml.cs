using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Logging;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Duo.DotNet.Areas.Identity.Pages.Account
{
    [AllowAnonymous]
    public class DuoCallback : PageModel
    {
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<DuoCallback> _logger;

        public DuoCallback(SignInManager<IdentityUser> signInManager,
            ILogger<DuoCallback> logger)
        {
            _signInManager = signInManager;
            _logger = logger;
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
    }
}
