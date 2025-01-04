using Microsoft.AspNetCore.Identity;
using OAuthServer.Models;
using OpenIddict.Abstractions;

namespace OAuthServer.Services.Interfaces;

public interface IAccountService
{
    Task<(bool success, string? error)> RegisterAsync(RegistrationRequest request);
    Task<List<UserSession>> GetUserSessionsAsync(string userId);
    Task RevokeSessionAsync(string userId, string clientType);
    Task RevokeAllSessionsAsync(string userId);
    Task LogoutAsync(string userId, string clientType);
    Task<object> CreateAuthorizationAsync(string userId, string clientId, string[] scopes);
}
