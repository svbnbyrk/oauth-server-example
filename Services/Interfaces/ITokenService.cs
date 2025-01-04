using OAuthServer.Models;
using OAuthServer.Models.OAuth;
using System.Security.Claims;

namespace OAuthServer.Services.Interfaces;

public interface ITokenService
{
    Task<(string accessToken, string refreshToken)> GenerateTokens(ApplicationUser user, string clientType);
    Task<TokenResponse> HandlePasswordGrantType(string username, string password, string clientId);
    Task<TokenResponse> HandleRefreshTokenGrantType(ClaimsPrincipal principal, string clientId);
    bool ValidateClientCredentials(string clientId, string clientSecret, string clientType);
}
