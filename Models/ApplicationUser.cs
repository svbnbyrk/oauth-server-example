using Microsoft.AspNetCore.Identity;
using System.Collections.Generic;

namespace OAuthServer.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public List<string> Scopes { get; set; } = new();
}
