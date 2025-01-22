using Microsoft.AspNetCore.Identity;

namespace OAuthServer.Models;

public class ApplicationUserClientRole
{
    public string UserId { get; set; } = string.Empty;
    public string RoleId { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;

    // Navigation properties
    public virtual ApplicationUser? User { get; set; }
    public virtual IdentityRole? Role { get; set; }
}
