using System.Text.Json.Serialization;

namespace OAuthServer.Models.OAuth;

/// <summary>
/// Represents an error response from the OAuth endpoints
/// </summary>
public class ErrorResponse
{
    /// <summary>
    /// Error code
    /// </summary>
    [JsonPropertyName("error")]
    public string Error { get; set; } = string.Empty;

    /// <summary>
    /// Human-readable description of the error
    /// </summary>
    [JsonPropertyName("error_description")]
    public string? ErrorDescription { get; set; }

    /// <summary>
    /// URI to the error documentation
    /// </summary>
    [JsonPropertyName("error_uri")]
    public string? ErrorUri { get; set; }
}
