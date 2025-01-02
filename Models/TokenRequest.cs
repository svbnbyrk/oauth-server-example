namespace OAuthServer.Models;

public class TokenRequest
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public required string ClientType { get; set; }
    public required string Email { get; set; }
    public required string Password { get; set; }
}

public class RefreshTokenRequest
{
    public required string ClientId { get; set; }
    public required string ClientSecret { get; set; }
    public required string ClientType { get; set; }
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
}
