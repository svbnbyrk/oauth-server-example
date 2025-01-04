using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using OAuthServer.Models;
using OAuthServer.Models.OAuth;
using OAuthServer.Services.Interfaces;
using OpenIddict.Abstractions;

namespace OAuthServer.Services;

public class TokenService : ITokenService
{
    private readonly TokenConfiguration _configuration;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly ISessionService _sessionService;

    public TokenService(
        TokenConfiguration configuration,
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
        ISessionService sessionService)
    {
        _configuration = configuration;
        _userManager = userManager;
        _signInManager = signInManager;
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

    public async Task<TokenResponse> HandlePasswordGrantType(string username, string password, string clientId)
    {
        var user = await _userManager.FindByNameAsync(username);
        if (user == null)
        {
            throw new InvalidGrantException("The username/password couple is invalid.");
        }

        var result = await _signInManager.CheckPasswordSignInAsync(user, password, lockoutOnFailure: true);
        if (!result.Succeeded)
        {
            throw new InvalidGrantException("The username/password couple is invalid.");
        }

        var (accessToken, refreshToken) = await GenerateTokens(user, clientId);

        return CreateTokenResponse(accessToken, refreshToken, user.Scopes);
    }

    public async Task<TokenResponse> HandleRefreshTokenGrantType(ClaimsPrincipal principal, string clientId)
    {
        var userId = principal.FindFirstValue(OpenIddictConstants.Claims.Subject);
        if (string.IsNullOrEmpty(userId))
        {
            throw new InvalidGrantException("The refresh token is no longer valid.");
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new InvalidGrantException("The refresh token is no longer valid.");
        }

        if (!await _signInManager.CanSignInAsync(user))
        {
            throw new InvalidGrantException("The user is no longer allowed to sign in.");
        }

        var (accessToken, refreshToken) = await GenerateTokens(user, clientId);

        return CreateTokenResponse(accessToken, refreshToken, principal.GetScopes());
    }

    private TokenResponse CreateTokenResponse(string accessToken, string refreshToken, IEnumerable<string> scopes)
    {
        return new TokenResponse
        {
            AccessToken = accessToken,
            TokenType = "Bearer",
            ExpiresIn = 1800, // 30 minutes
            RefreshToken = refreshToken,
            Scope = string.Join(" ", scopes)
        };
    }

    public class InvalidGrantException : Exception
    {
        public InvalidGrantException(string message) : base(message) { }
    }
}
