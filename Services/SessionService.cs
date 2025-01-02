using StackExchange.Redis;
using System.Text.Json;
using Microsoft.AspNetCore.Identity;
using OAuthServer.Models;

namespace OAuthServer.Services;

public class SessionService
{
    private readonly IConnectionMultiplexer _redis;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IDatabase _db;

    public SessionService(IConnectionMultiplexer redis, UserManager<ApplicationUser> userManager)
    {
        _redis = redis;
        _userManager = userManager;
        _db = redis.GetDatabase();
    }

    public async Task StoreUserSession(string userId, string clientType, string refreshToken, DateTime expiryTime)
    {
        var sessionInfo = new UserSessionInfo
        {
            UserId = userId,
            ClientType = clientType,
            RefreshToken = refreshToken,
            ExpiryTime = expiryTime,
            CreatedAt = DateTime.UtcNow
        };

        var key = GetSessionKey(userId, clientType);
        await _db.HashSetAsync(key, new HashEntry[]
        {
            new HashEntry("refreshToken", refreshToken),
            new HashEntry("expiryTime", expiryTime.ToString("O")),
            new HashEntry("createdAt", DateTime.UtcNow.ToString("O"))
        });

        // Set key expiration to match token expiry
        await _db.KeyExpireAsync(key, expiryTime);

        // Store session in user's active sessions set
        await _db.SetAddAsync($"user:{userId}:sessions", clientType);
    }

    public async Task<UserSessionInfo?> GetUserSession(string userId, string clientType)
    {
        var key = GetSessionKey(userId, clientType);
        var hashEntries = await _db.HashGetAllAsync(key);

        if (hashEntries.Length == 0)
            return null;

        var sessionInfo = new UserSessionInfo
        {
            UserId = userId,
            ClientType = clientType,
            RefreshToken = hashEntries.First(h => h.Name == "refreshToken").Value,
            ExpiryTime = DateTime.Parse(hashEntries.First(h => h.Name == "expiryTime").Value),
            CreatedAt = DateTime.Parse(hashEntries.First(h => h.Name == "createdAt").Value)
        };

        return sessionInfo;
    }

    public async Task<IEnumerable<string>> GetUserActiveSessions(string userId)
    {
        var sessions = await _db.SetMembersAsync($"user:{userId}:sessions");
        return sessions.Select(s => s.ToString());
    }

    public async Task RemoveUserSession(string userId, string clientType)
    {
        var key = GetSessionKey(userId, clientType);
        await _db.KeyDeleteAsync(key);
        await _db.SetRemoveAsync($"user:{userId}:sessions", clientType);
    }

    public async Task RemoveAllUserSessions(string userId)
    {
        var sessions = await GetUserActiveSessions(userId);
        foreach (var clientType in sessions)
        {
            await RemoveUserSession(userId, clientType);
        }
    }

    public async Task<bool> ValidateRefreshToken(string userId, string clientType, string refreshToken)
    {
        var session = await GetUserSession(userId, clientType);
        if (session == null)
            return false;

        return session.RefreshToken == refreshToken && session.ExpiryTime > DateTime.UtcNow;
    }

    public async Task<IEnumerable<string>> GetUserRoles(string userId)
    {
        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            return Enumerable.Empty<string>();

        return await _userManager.GetRolesAsync(user);
    }

    private static string GetSessionKey(string userId, string clientType) => $"session:{userId}:{clientType}";
}

public class UserSessionInfo
{
    public required string UserId { get; set; }
    public required string ClientType { get; set; }
    public required string RefreshToken { get; set; }
    public DateTime ExpiryTime { get; set; }
    public DateTime CreatedAt { get; set; }
}
