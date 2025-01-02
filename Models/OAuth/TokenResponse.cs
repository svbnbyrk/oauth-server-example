using System.Text.Json.Serialization;

namespace OAuthServer.Models.OAuth;

/// <summary>
/// Represents the response from the token endpoint
/// </summary>
public class TokenResponse
{
    /// <summary>
    /// The access token issued by the authorization server
    /// </summary>
    [JsonPropertyName("access_token")]
    public string AccessToken { get; set; } = string.Empty;

    /// <summary>
    /// The type of the token issued
    /// </summary>
    [JsonPropertyName("token_type")]
    public string TokenType { get; set; } = "Bearer";

    /// <summary>
    /// The lifetime in seconds of the access token
    /// </summary>
    [JsonPropertyName("expires_in")]
    public int ExpiresIn { get; set; }

    /// <summary>
    /// The refresh token, which can be used to obtain new access tokens
    /// </summary>
    [JsonPropertyName("refresh_token")]
    public string? RefreshToken { get; set; }

    /// <summary>
    /// The scope of the access token
    /// </summary>
    [JsonPropertyName("scope")]
    public string Scope { get; set; } = string.Empty;
}
