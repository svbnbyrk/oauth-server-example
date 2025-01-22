using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using OAuthServer.Data;
using OAuthServer.Models;
using OAuthServer.Services.Interfaces;
using System.Security.Claims;

namespace OAuthServer.Services;

public class IdentityClientRoleService : IIdentityClientRoleService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly ApplicationDbContext _context;

    public IdentityClientRoleService(
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole> roleManager,
        ApplicationDbContext context)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _context = context;
    }

    public async Task<IList<string>> GetUserRolesAsync(string userId, string clientId)
    {
        var clientRoles = await _context.ApplicationUserClientRoles
            .Include(cr => cr.Role)
            .Where(cr => cr.UserId == userId && cr.ClientId == clientId)
            .Select(cr => cr.Role!.Name!)
            .ToListAsync();

        return clientRoles;
    }

    // public async Task<IdentityResult> AddToRoleAsync(string userId, string clientId, string roleName)
    // {
    //     var role = await _roleManager.FindByNameAsync(roleName);
    //     if (role == null)
    //     {
    //         return IdentityResult.Failed(new IdentityError { Description = $"Role {roleName} not found." });
    //     }
    //
    //     var clientRole = new ApplicationUserClientRole
    //     {
    //         UserId = userId,
    //         RoleId = role.Id,
    //         ClientId = clientId
    //     };
    //
    //     _context.ApplicationUserClientRoles.Add(clientRole);
    //     
    //     try
    //     {
    //         await _context.SaveChangesAsync();
    //         return IdentityResult.Success;
    //     }
    //     catch (Exception ex)
    //     {
    //         return IdentityResult.Failed(new IdentityError { Description = ex.Message });
    //     }
    // }
    //
    // public async Task<IdentityResult> RemoveFromRoleAsync(string userId, string clientId, string roleName)
    // {
    //     var role = await _roleManager.FindByNameAsync(roleName);
    //     if (role == null)
    //     {
    //         return IdentityResult.Failed(new IdentityError { Description = $"Role {roleName} not found." });
    //     }
    //
    //     var clientRole = await _context.ApplicationUserClientRoles
    //         .FirstOrDefaultAsync(cr => cr.UserId == userId && cr.ClientId == clientId && cr.RoleId == role.Id);
    //
    //     if (clientRole != null)
    //     {
    //         _context.ApplicationUserClientRoles.Remove(clientRole);
    //         await _context.SaveChangesAsync();
    //     }
    //
    //     return IdentityResult.Success;
    // }
    //
    // public async Task<bool> IsInRoleAsync(string userId, string clientId, string roleName)
    // {
    //     var roles = await GetUserRolesAsync(userId, clientId);
    //     return roles.Contains(roleName);
    // }
    //
    public async Task<ClaimsIdentity> GetUserClaimsIdentityAsync(string userId, string clientId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            throw new InvalidOperationException("User not found.");
        }
    
        var roles = await GetUserRolesAsync(userId, clientId);
        var identity = new ClaimsIdentity();
    
        // Add user claims
        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, user.Id));
        identity.AddClaim(new Claim(ClaimTypes.Name, user.UserName ?? string.Empty));
        identity.AddClaim(new Claim(ClaimTypes.Email, user.Email ?? string.Empty));
        
        // Add role claims
        foreach (var role in roles)
        {
            identity.AddClaim(new Claim(ClaimTypes.Role, role));
        }
    
        // Add client ID claim
        identity.AddClaim(new Claim("client_id", clientId));
    
        return identity;
    }
}
