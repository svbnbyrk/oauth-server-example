namespace OAuthServer.Models;

public class AuthenticationResult
{
    public required string AccessToken { get; set; }
    public required string RefreshToken { get; set; }
    public required string TokenType { get; set; }
    public required IList<string> Roles { get; set; }
}
