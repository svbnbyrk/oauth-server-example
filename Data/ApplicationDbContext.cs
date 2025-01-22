using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using OAuthServer.Models;

namespace OAuthServer.Data;

public class ApplicationDbContext : IdentityDbContext<ApplicationUser>
{
    public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
        : base(options)
    {
    }

    public DbSet<ApplicationUser> ApplicationUsers => Set<ApplicationUser>();
    public DbSet<ApplicationUserClientRole> ApplicationUserClientRoles => Set<ApplicationUserClientRole>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.Entity<ApplicationUserClientRole>()
            .HasKey(cr => new { cr.UserId, cr.RoleId, cr.ClientId });

        builder.Entity<ApplicationUserClientRole>()
            .HasOne(cr => cr.User)
            .WithMany(u => u.ClientRoles)
            .HasForeignKey(cr => cr.UserId);

        builder.Entity<ApplicationUserClientRole>()
            .HasOne(cr => cr.Role)
            .WithMany()
            .HasForeignKey(cr => cr.RoleId);
    }
}
