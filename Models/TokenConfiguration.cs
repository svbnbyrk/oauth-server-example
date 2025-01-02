namespace OAuthServer.Models;

public class TokenConfiguration
{
    public required string Issuer { get; set; }
    public required string Audience { get; set; }
    public required string SecretKey { get; set; }
    public required Dictionary<string, ClientTokenSettings> ClientSettings { get; set; }
}

public class ClientTokenSettings
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public int AccessTokenLifetimeMinutes { get; set; }
    public int RefreshTokenLifetimeDays { get; set; }
    public required string[] AllowedScopes { get; set; }
}
