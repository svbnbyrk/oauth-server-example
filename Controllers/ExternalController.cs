using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using OAuthServer.Data;
using OpenIddict.Abstractions;
using OpenIddict.Client.AspNetCore;
using OpenIddict.Server.AspNetCore;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using static OpenIddict.Abstractions.OpenIddictConstants;

namespace Controllers
{
    [ApiController]
    [Route("external")]
    public class ExternalController : Controller
    {
        private readonly ApplicationDbContext _context;

        public ExternalController(ApplicationDbContext context)
        {
            _context = context;
        }

        [HttpPost("callback")]
        [IgnoreAntiforgeryToken]
        public async Task<IActionResult> Callback()
        {
            // Authenticate the user with the external provider
            var result = await HttpContext.AuthenticateAsync(
                OpenIddictClientAspNetCoreDefaults.AuthenticationScheme);

            if (result?.Principal is not ClaimsPrincipal principal)
            {
                return BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidRequest,
                    ErrorDescription = "The external authentication failed"
                });
            }

            // Retrieve the user info from the external principal
            var identifier = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var email = principal.FindFirst(ClaimTypes.Email)?.Value;
            var name = principal.FindFirst(ClaimTypes.Name)?.Value;
            var provider = principal.FindFirst(OpenIddictClientAspNetCoreConstants.Properties.ProviderName)?.Value;

            if (string.IsNullOrEmpty(identifier) || string.IsNullOrEmpty(provider))
            {
                return BadRequest(new OpenIddictResponse
                {
                    Error = Errors.InvalidRequest,
                    ErrorDescription = "The external authentication response was invalid"
                });
            }

            // Find or create the user in your database
            var user = await _context.Users
                .Include(u => u.ExternalProviders)
                .Include(u => u.Roles)
                .FirstOrDefaultAsync(u => u.ExternalProviders
                    .Any(ep => ep.ProviderName == provider && ep.ProviderKey == identifier));

            if (user is null)
            {
                // Check if we have an email and try to match existing users
                if (!string.IsNullOrEmpty(email))
                {
                    user = await _context.Users
                        .Include(u => u.ExternalProviders)
                        .Include(u => u.Roles)
                        .FirstOrDefaultAsync(u => u.Email == email);
                }

                if (user is null)
                {
                    // Create a new user
                    user = new User
                    {
                        Id = Guid.NewGuid(),
                        UserName = email ?? $"{provider}-{identifier}",
                        Email = email,
                        EmailVerified = !string.IsNullOrEmpty(email),
                        IsActive = true
                    };   

                    _context.Users.Add(user);
                }  

                // Add the external provider
                user.ExternalProviders.Add(new ExternalProvider
                {
                    ProviderName = provider,
                    ProviderKey = identifier,
                    AccessToken = principal.FindFirst(OpenIddictClientAspNetCoreConstants.Properties.StateTokenPrincipal)?.Value,
                    RefreshToken = principal.FindFirst(OpenIddictClientAspNetCoreConstants.Properties.RefreshTokenPrincipal)?.Value
                });

                await _context.SaveChangesAsync();
            }

            // Create the claims principal for OpenIddict
            var identity = new ClaimsIdentity(
                authenticationType: OpenIddictServerAspNetCoreDefaults.AuthenticationScheme,
                nameType: ClaimTypes.Name,
                roleType: ClaimTypes.Role);

            identity.AddClaim(ClaimTypes.NameIdentifier, user.Id.ToString());
            identity.AddClaim(ClaimTypes.Name, user.UserName);
            identity.AddClaims(user.Roles.Select(role => new Claim(ClaimTypes.Role, role.Name)));

            if (!string.IsNullOrEmpty(user.Email))
            {
                identity.AddClaim(ClaimTypes.Email, user.Email);
                identity.AddClaim(Claims.EmailVerified, user.EmailVerified.ToString().ToLower());
            }

            var principal = new ClaimsPrincipal(identity);

            // Set the scopes (adjust based on your requirements)
            principal.SetScopes(Scopes.OpenId, Scopes.Email, Scopes.Profile, Scopes.Roles);
            principal.SetResources("resource_server"); // Your API resource

            // Add claims to the access token
            foreach (var claim in principal.Claims)
            {
                claim.SetDestinations(GetDestinations(claim, principal));
            }

            // Return the OpenIddict sign-in result
            return SignIn(principal, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }
} 