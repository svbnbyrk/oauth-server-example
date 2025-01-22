using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace OAuthServer.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public bool IsAnonymous { get; set; }
    public string? AnonymousId { get; set; }
    public DateTime? AnonymousCreatedAt { get; set; }
    public List<string> Scopes { get; set; } = new();
    public virtual ICollection<ApplicationUserClientRole> ClientRoles { get; set; } = new List<ApplicationUserClientRole>();
}
