using System.Collections.Immutable;
using OpenIddict.Abstractions;

namespace OAuthServer.Services.Interfaces;

public interface ISessionService
{
    Task<object> CreateSessionAsync(string userId, string clientId, ImmutableArray<string> scopes);
    Task<object> GetSessionAsync(string authorizationId);
    Task<List<object>> GetActiveSessionsAsync(string userId);
    Task<List<object>> GetActiveSessionsAsync(string userId, string clientId);
    Task RevokeSessionAsync(string? authorizationId);
    Task RevokeAllSessionsAsync(string userId);
    Task<bool> ValidateSessionAsync(string authorizationId, string clientId);
}
