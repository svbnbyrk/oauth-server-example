using Microsoft.AspNetCore.Identity;
using OAuthServer.Models;
using OAuthServer.Services.Interfaces;
using OpenIddict.Abstractions;
using System.Security.Claims;
using System.Collections.Generic;
using System.Collections.Immutable;
using System.Linq;

namespace OAuthServer.Services;

public class AccountService : IAccountService
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly ISessionService _sessionService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AccountService(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        ISessionService sessionService,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictScopeManager scopeManager)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenService = tokenService;
        _sessionService = sessionService;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _scopeManager = scopeManager;
    }

    public async Task<(bool success, string? error, AuthenticationResult? result)> HandleExternalLoginAsync(
        ExternalLoginInfo info,
        string clientType)
    {
        var result = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);
        if (result.Succeeded)
        {
            var user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
            if (user == null)
            {
                return (false, "User not found", null);
            }

            var authResult = await GenerateAuthenticationResultAsync(user, clientType);
            return (true, null, authResult);
        }

        return await CreateExternalUserAsync(info, clientType);
    }

    private async Task<(bool success, string? error, AuthenticationResult? result)> CreateExternalUserAsync(
        ExternalLoginInfo info,
        string clientType)
    {
        var email = info.Principal.FindFirstValue(ClaimTypes.Email);
        if (string.IsNullOrEmpty(email))
        {
            return (false, "Email not provided by external provider", null);
        }

        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = info.Principal.FindFirstValue(ClaimTypes.GivenName),
            LastName = info.Principal.FindFirstValue(ClaimTypes.Surname)
        };

        var createResult = await _userManager.CreateAsync(user);
        if (!createResult.Succeeded)
        {
            return (false, $"Error creating user: {string.Join(", ", createResult.Errors.Select(e => e.Description))}", null);
        }

        var addLoginResult = await _userManager.AddLoginAsync(user, info);
        if (!addLoginResult.Succeeded)
        {
            return (false, $"Error adding external login: {string.Join(", ", addLoginResult.Errors.Select(e => e.Description))}", null);
        }

        var authResult = await GenerateAuthenticationResultAsync(user, clientType);
        return (true, null, authResult);
    }

    private async Task<AuthenticationResult> GenerateAuthenticationResultAsync(ApplicationUser user, string clientType)
    {
        var (accessToken, refreshToken) = await _tokenService.GenerateTokens(user, clientType);
        var roles = await _userManager.GetRolesAsync(user);

        return new AuthenticationResult
        {
            AccessToken = accessToken,
            RefreshToken = refreshToken,
            TokenType = "Bearer",
            Roles = roles
        };
    }

    public async Task<(bool success, string? error)> RegisterAsync(RegistrationRequest request)
    {
        // Check if email already exists
        var existingUserByEmail = await _userManager.FindByEmailAsync(request.Email);
        if (existingUserByEmail != null)
        {
            return (false, "Email already registered");
        }

        // Check if username already exists
        var existingUserByUsername = await _userManager.FindByNameAsync(request.Username);
        if (existingUserByUsername != null)
        {
            return (false, "Username already taken");
        }

        // Create new user
        var user = new ApplicationUser
        {
            UserName = request.Username,
            Email = request.Email,
            EmailConfirmed = true // You might want to add email confirmation later
        };

        var result = await _userManager.CreateAsync(user, request.Password);

        if (result.Succeeded)
        {
            return (true, null);
        }

        return (false, string.Join(", ", result.Errors.Select(e => e.Description)));
    }

    public async Task<List<UserSession>> GetUserSessionsAsync(string userId)
    {   
        var authorizations = await _sessionService.GetActiveSessionsAsync(userId);
        var sessions = new List<UserSession>();

        foreach (var authorization in authorizations)
        {
            var clientId = await _authorizationManager.GetApplicationIdAsync(authorization);
            if (clientId != null)
            {
                var application = await _applicationManager.FindByIdAsync(clientId);
                if (application != null)
                {
                    sessions.Add(new UserSession
                    {
                        Id = await _authorizationManager.GetIdAsync(authorization),
                        ClientId = await _applicationManager.GetClientIdAsync(application),
                        CreatedAt = await _authorizationManager.GetCreationDateAsync(authorization) ?? DateTime.UtcNow,
                        Scopes = await _authorizationManager.GetScopesAsync(authorization)
                    });
                }
            }
        }

        return sessions;
    }

    public async Task RevokeSessionAsync(string userId, string clientId)
    {
        var authorizations = await _sessionService.GetActiveSessionsAsync(userId);
        
        foreach (var authorization in authorizations)
        {
            var authClientId = await _authorizationManager.GetApplicationIdAsync(authorization);
            var application = await _applicationManager.FindByIdAsync(authClientId);
            
            if (application != null && await _applicationManager.GetClientIdAsync(application) == clientId)
            {
                await _sessionService.RevokeSessionAsync(await _authorizationManager.GetIdAsync(authorization));
            }
        }
    }

    public async Task RevokeAllSessionsAsync(string userId)
    {
        await _sessionService.RevokeAllSessionsAsync(userId);
    }

    public async Task LogoutAsync(string userId, string clientId)
    {
        await RevokeSessionAsync(userId, clientId);
    }

    public async Task<object> CreateAuthorizationAsync(string userId, string clientId, string[] scopes)
    {
        return await _sessionService.CreateSessionAsync(userId, clientId, scopes.ToImmutableArray());
    }

    public async Task<IEnumerable<string>> GetResourcesAsync(IEnumerable<string> scopes)
    {
        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync(scopes.ToImmutableArray()))
        {
            resources.Add(resource);
        }
        return resources;
    }
}
