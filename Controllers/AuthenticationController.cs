using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OpenIddict.Client.AspNetCore;
using OAuthServer.Models;
using System.Security.Claims;
using static OpenIddict.Abstractions.OpenIddictConstants;
using Microsoft.AspNetCore.Authentication.Cookies;

namespace OAuthServer.Controllers;

public class AuthenticationController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AuthenticationController> _logger;

    public AuthenticationController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<AuthenticationController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    [HttpGet("~/login")]
    public IActionResult Login(string returnUrl = "/")
    {
        var properties = new AuthenticationProperties { RedirectUri = returnUrl };
        return Challenge(properties, OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);
    }

    [HttpGet("~/callback/login/{provider}"), HttpPost("~/callback/login/{provider}")]
    public async Task<IActionResult> LogInCallback()
    {
        // Retrieve the authorization data validated by OpenIddict as part of the callback handling.
        var result = await HttpContext.AuthenticateAsync(OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

        if (result.Principal is not ClaimsPrincipal { Identity.IsAuthenticated: true })
        {
            throw new InvalidOperationException("The external authorization data cannot be used for authentication.");
        }

        var email = result.Principal.FindFirstValue(ClaimTypes.Email);
        if (string.IsNullOrEmpty(email))
        {
            return BadRequest("Email claim is required.");
        }

        // Try to find existing user
        var user = await _userManager.FindByEmailAsync(email);
        if (user == null)
        {
            // Create a new user if none exists
            user = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true // Since GitHub has verified the email
            };

            var createResult = await _userManager.CreateAsync(user);
            if (!createResult.Succeeded)
            {
                return BadRequest($"Error creating user account: {string.Join(", ", createResult.Errors.Select(e => e.Description))}");
            }
        }

        // Build an identity for the cookie
        var identity = new ClaimsIdentity(authenticationType: "ExternalLogin");
        identity.AddClaim(new Claim(ClaimTypes.Email, email));
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName));

        // Build the authentication properties
        var properties = new AuthenticationProperties(result.Properties.Items)
        {
            RedirectUri = result.Properties.RedirectUri ?? "/"
        };

        // Store the access token if available
        properties.StoreTokens(result.Properties.GetTokens().Where(token => token.Name is
            OpenIddictClientAspNetCoreConstants.Tokens.BackchannelAccessToken or
            OpenIddictClientAspNetCoreConstants.Tokens.BackchannelIdentityToken or
            OpenIddictClientAspNetCoreConstants.Tokens.RefreshToken));

        await HttpContext.SignInAsync(
            CookieAuthenticationDefaults.AuthenticationScheme,
            new ClaimsPrincipal(identity),
            properties);

        return Redirect(properties.RedirectUri);
    }

    [HttpPost("~/logout")]
    public async Task<IActionResult> LogOut()
    {
        await HttpContext.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
        return Redirect("/");
    }
}
