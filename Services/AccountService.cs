using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OpenIddict.Core;
using OAuthServer.Models;
using System.Security.Claims;
using System.Collections.Immutable;
using Microsoft.EntityFrameworkCore;

namespace OAuthServer.Services;

public class AccountService
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly TokenService _tokenService;
    private readonly SessionService _sessionService;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictScopeManager _scopeManager;

    public AccountService(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        TokenService tokenService,
        SessionService sessionService,
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

    public async Task<(bool success, string? error, AuthenticationResult? result)> AuthenticateAsync(TokenRequest request)
    {
        if (!_tokenService.ValidateClientCredentials(request.ClientId, request.ClientSecret, request.ClientType))
        {
            return (false, "Invalid client credentials", null);
        }

        var user = await _userManager.FindByEmailAsync(request.Email);
        if (user == null)
        {
            return (false, "Invalid credentials", null);
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, request.Password, false);
        if (!result.Succeeded)
        {
            return (false, "Invalid credentials", null);
        }

        var authResult = await GenerateAuthenticationResultAsync(user, request.ClientType);
        return (true, null, authResult);
    }

    public async Task<(bool success, string? error, AuthenticationResult? result)> RefreshTokenAsync(RefreshTokenRequest request)
    {
        if (!_tokenService.ValidateClientCredentials(request.ClientId, request.ClientSecret, request.ClientType))
        {
            return (false, "Invalid client credentials", null);
        }

        var principal = _tokenService.ValidateToken(request.AccessToken);
        if (principal == null)
        {
            return (false, "Invalid access token", null);
        }

        var userId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (string.IsNullOrEmpty(userId))
        {
            return (false, "Invalid token claims", null);
        }

        var isValidRefreshToken = await _tokenService.ValidateRefreshToken(userId, request.ClientType, request.RefreshToken);
        if (!isValidRefreshToken)
        {
            return (false, "Invalid refresh token", null);
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return (false, "User not found", null);
        }

        var authResult = await GenerateAuthenticationResultAsync(user, request.ClientType);
        return (true, null, authResult);
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

    public async Task<IEnumerable<string>> GetUserSessionsAsync(string userId)
    {
        return await _sessionService.GetUserActiveSessions(userId);
    }

    public async Task RevokeSessionAsync(string userId, string clientType)
    {
        await _tokenService.RevokeRefreshToken(userId, clientType);
    }

    public async Task RevokeAllSessionsAsync(string userId)
    {
        await _tokenService.RevokeAllRefreshTokens(userId);
    }

    public async Task LogoutAsync(string userId, string clientType)
    {
        await _tokenService.RevokeRefreshToken(userId, clientType);
        await _signInManager.SignOutAsync();
    }

    public async Task<IEnumerable<string>> GetResourcesAsync(IEnumerable<string> scopes)
    {
        var resources = new List<string>();
        await foreach (var resource in _scopeManager.ListResourcesAsync((ImmutableArray<string>)scopes))
        {
            resources.Add(resource);
        }
        return resources;
    }

    public async Task<object> CreateAuthorizationAsync(ApplicationUser user, string? clientId, IEnumerable<string> scopes)
    {
        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            throw new InvalidOperationException("The application cannot be found.");
        }

        var applicationId = await _applicationManager.GetIdAsync(application);
        var userId = await _userManager.GetUserIdAsync(user);

        var authorizations = new List<object>();
        await foreach (var a in _authorizationManager.FindAsync(
            subject: userId,
            client: applicationId,
            status: OpenIddictConstants.Statuses.Valid,
            type: OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes: scopes.ToImmutableArray()))
        {
            authorizations.Add(a);
        }

        var authorization = authorizations.FirstOrDefault();
        if (authorization == null)
        {
            authorization = await _authorizationManager.CreateAsync(
                principal: new ClaimsPrincipal(new ClaimsIdentity()),
                subject: userId,
                client: applicationId,
                type: OpenIddictConstants.AuthorizationTypes.Permanent,
                scopes: scopes.ToImmutableArray());
        }

        return authorization;
    }
}
