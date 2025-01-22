using Microsoft.AspNetCore.Identity;
using OAuthServer.Services.Interfaces;
using OpenIddict.Abstractions;
using System.Security.Claims;
using OAuthServer.Models;
using System.Collections.Immutable;

namespace OAuthServer.Services;

public class SessionService : ISessionService
{
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IRedisSessionStore _redisSessionStore;
    private readonly IIdentityClientRoleService _clientRoleService;

    public SessionService(
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictApplicationManager applicationManager,
        UserManager<ApplicationUser> userManager,
        IRedisSessionStore redisSessionStore,
        IIdentityClientRoleService clientRoleService)
    {
        _authorizationManager = authorizationManager;
        _applicationManager = applicationManager;
        _userManager = userManager;
        _redisSessionStore = redisSessionStore;
        _clientRoleService = clientRoleService;
    }

    public async Task<object> CreateSessionAsync(string userId, string clientId, ImmutableArray<string> scopes)
    {
        // Get or create the application
        var application = await _applicationManager.FindByClientIdAsync(clientId) ??
            throw new InvalidOperationException("The application cannot be found.");

        // Get client-specific identity with roles
        var identity = await _clientRoleService.GetUserClaimsIdentityAsync(userId, clientId);

        // Create a new authorization
        var authorization = await _authorizationManager.CreateAsync(
            principal: new ClaimsPrincipal(identity),
            subject: userId,
            client: await _applicationManager.GetIdAsync(application),
            type: OpenIddictConstants.AuthorizationTypes.Permanent,
            scopes: scopes);

        var session = new UserSession
        {
            Id = await _authorizationManager.GetIdAsync(authorization),
            UserId = userId,
            ClientId = clientId,
            CreatedAt = DateTimeOffset.UtcNow,
            Scopes = scopes
        };

        await _redisSessionStore.StoreSessionAsync(session.Id, session, TimeSpan.FromDays(30));
        
        return authorization;
    }

    public async Task<object> GetSessionAsync(string authorizationId)
    {
        return await _authorizationManager.FindByIdAsync(authorizationId);
    }

    public async Task<List<object>> GetActiveSessionsAsync(string userId)
    {
        var sessions = await _redisSessionStore.GetUserSessionsAsync(userId);
        var authorizations = new List<object>();

        foreach (var session in sessions)
        {
            var authorization = await _authorizationManager.FindByIdAsync(session.Id);
            if (authorization != null)
            {
                authorizations.Add(authorization);
            }
            else
            {
                // Clean up Redis if authorization no longer exists
                await _redisSessionStore.RemoveSessionAsync(session.Id);
            }
        }

        return authorizations;
    }

    public async Task<List<object>> GetActiveSessionsAsync(string userId, string clientId)
    {
        var sessions = await _redisSessionStore.GetUserSessionsAsync(userId);
        var authorizations = new List<object>();

        foreach (var session in sessions)
        {
            if (session.ClientId == clientId)
            {
                var authorization = await _authorizationManager.FindByIdAsync(session.Id);
                if (authorization != null)
                {
                    authorizations.Add(authorization);
                }
                else
                {
                    // Clean up Redis if authorization no longer exists
                    await _redisSessionStore.RemoveSessionAsync(session.Id);
                }
            }
        }

        return authorizations;
    }

    public async Task RevokeSessionAsync(string? authorizationId)
    {
        var authorization = await _authorizationManager.FindByIdAsync(authorizationId);
        if (authorization != null)
        {
            await _authorizationManager.TryRevokeAsync(authorization);
        }
    }

    public async Task RevokeAllSessionsAsync(string userId)
    {
        var sessions = await _redisSessionStore.GetUserSessionsAsync(userId);
        foreach (var session in sessions)
        {
            var authorization = await _authorizationManager.FindByIdAsync(session.Id);
            if (authorization != null)
            {
                await _authorizationManager.TryRevokeAsync(authorization);
            }
            await _redisSessionStore.RemoveSessionAsync(session.Id);
        }
    }

    public async Task<bool> ValidateSessionAsync(string authorizationId, string clientId)
    {
        if (string.IsNullOrEmpty(authorizationId) || string.IsNullOrEmpty(clientId))
        {
            return false;
        }

        var authorization = await _authorizationManager.FindByIdAsync(authorizationId);
        if (authorization == null)
        {
            return false;
        }

        var application = await _applicationManager.FindByClientIdAsync(clientId);
        if (application == null)
        {
            return false;
        }

        var validationResult = _authorizationManager.ValidateAsync(authorization);
        if (validationResult != null)
        {
            return false;
        }

        // Check if the authorization belongs to the specified client
        var authorizationClientId = await _authorizationManager.GetApplicationIdAsync(authorization);
        var applicationId = await _applicationManager.GetIdAsync(application);

        return authorizationClientId == applicationId;
    }
}
