using System.Security.Claims;
using Microsoft.AspNetCore.Identity;

namespace OAuthServer.Services.Interfaces;

public interface IIdentityClientRoleService
{
    Task<IList<string>> GetUserRolesAsync(string userId, string clientId);
    // Task<IdentityResult> AddToRoleAsync(string userId, string clientId, string roleName);
    //Task<IdentityResult> RemoveFromRoleAsync(string userId, string clientId, string roleName);
    //Task<bool> IsInRoleAsync(string userId, string clientId, string roleName);
    Task<ClaimsIdentity> GetUserClaimsIdentityAsync(string userId, string clientId);
}
