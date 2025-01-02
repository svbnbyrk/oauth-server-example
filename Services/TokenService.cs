using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OAuthServer.Models;

namespace OAuthServer.Services;

public class TokenService
{
    private readonly TokenConfiguration _configuration;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SessionService _sessionService;

    public TokenService(
        TokenConfiguration configuration,
        UserManager<ApplicationUser> userManager,
        SessionService sessionService)
    {
        _configuration = configuration;
        _userManager = userManager;
        _sessionService = sessionService;
    }

    public async Task<(string accessToken, string refreshToken)> GenerateTokens(ApplicationUser user, string clientType)
    {
        var clientSettings = _configuration.ClientSettings[clientType];
        var userRoles = await _userManager.GetRolesAsync(user);
        
        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(ClaimTypes.Name, user.UserName ?? string.Empty),
            new Claim(ClaimTypes.Email, user.Email ?? string.Empty),
            new Claim("client_type", clientType)
        };

        // Add roles as claims
        foreach (var role in userRoles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        // Add scopes as claims
        foreach (var scope in clientSettings.AllowedScopes)
        {
            claims.Add(new Claim("scope", scope));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecretKey));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var accessToken = new JwtSecurityToken(
            issuer: _configuration.Issuer,
            audience: _configuration.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddMinutes(clientSettings.AccessTokenLifetimeMinutes),
            signingCredentials: credentials
        );

        var refreshToken = GenerateRefreshToken();
        var refreshTokenExpiryTime = DateTime.UtcNow.AddDays(clientSettings.RefreshTokenLifetimeDays);

        // Store session in Redis
        await _sessionService.StoreUserSession(user.Id, clientType, refreshToken, refreshTokenExpiryTime);
        
        return (new JwtSecurityTokenHandler().WriteToken(accessToken), refreshToken);
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }

    public ClaimsPrincipal? ValidateToken(string token)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.SecretKey));

        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = key,
            ValidateIssuer = true,
            ValidIssuer = _configuration.Issuer,
            ValidateAudience = true,
            ValidAudience = _configuration.Audience,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.Zero
        };

        try
        {
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out _);
            return principal;
        }
        catch
        {
            return null;
        }
    }

    public bool ValidateClientCredentials(string clientId, string clientSecret, string clientType)
    {
        if (!_configuration.ClientSettings.TryGetValue(clientType, out var settings))
        {
            return false;
        }

        return settings.ClientId == clientId && settings.ClientSecret == clientSecret;
    }

    public async Task<bool> ValidateRefreshToken(string userId, string clientType, string refreshToken)
    {
        return await _sessionService.ValidateRefreshToken(userId, clientType, refreshToken);
    }

    public async Task RevokeRefreshToken(string userId, string clientType)
    {
        await _sessionService.RemoveUserSession(userId, clientType);
    }

    public async Task RevokeAllRefreshTokens(string userId)
    {
        await _sessionService.RemoveAllUserSessions(userId);
    }
}
