using System.Collections.Generic;
using System.Collections.Immutable;

namespace OAuthServer.Models;

public class UserSession
{
    public string? Id { get; set; } = string.Empty;
    public string? UserId { get; set; } = string.Empty;
    public string? ClientId { get; set; } = string.Empty;
    public DateTimeOffset CreatedAt { get; set; }
    public ImmutableArray<string> Scopes { get; set; } = ImmutableArray<string>.Empty;
}
