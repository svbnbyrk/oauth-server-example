using StackExchange.Redis;
using System.Text.Json;
using Microsoft.EntityFrameworkCore.Storage;
using Microsoft.Extensions.Options;
using OAuthServer.Models;

namespace OAuthServer.Services
{
    public interface IRedisSessionStore
    {
        Task StoreSessionAsync(string key, UserSession session, TimeSpan? expiry = null);
        Task<UserSession?> GetSessionAsync(string key);
        Task RemoveSessionAsync(string key);
        Task<IEnumerable<UserSession>> GetUserSessionsAsync(string userId);
    }

    public class RedisSessionStore : IRedisSessionStore
    {
        private readonly IConnectionMultiplexer _redis;
        private readonly StackExchange.Redis.IDatabase _db;
        private const string KeyPrefix = "session:";
        private const string UserSessionsPrefix = "user-sessions:";

        public RedisSessionStore(IConnectionMultiplexer redis)
        {
            _redis = redis;
            _db = redis.GetDatabase();
        }

        public async Task StoreSessionAsync(string key, UserSession session, TimeSpan? expiry = null)
        {
            var sessionKey = $"{KeyPrefix}{key}";
            var userSessionsKey = $"{UserSessionsPrefix}{session.UserId}";
            
            var serializedSession = JsonSerializer.Serialize(session);
            
            await Task.WhenAll(
                _db.StringSetAsync(sessionKey, serializedSession, expiry),
                _db.SetAddAsync(userSessionsKey, key)
            );
        }

        public async Task<UserSession?> GetSessionAsync(string key)
        {
            var sessionKey = $"{KeyPrefix}{key}";
            var value = await _db.StringGetAsync(sessionKey);
            
            if (!value.HasValue)
                return null;

            return JsonSerializer.Deserialize<UserSession>(value!);
        }

        public async Task RemoveSessionAsync(string key)
        {
            var sessionKey = $"{KeyPrefix}{key}";
            var session = await GetSessionAsync(key);
            
            if (session != null)
            {
                var userSessionsKey = $"{UserSessionsPrefix}{session.UserId}";
                await Task.WhenAll(
                    _db.KeyDeleteAsync(sessionKey),
                    _db.SetRemoveAsync(userSessionsKey, key)
                );
            }
        }

        public async Task<IEnumerable<UserSession>> GetUserSessionsAsync(string userId)
        {
            var userSessionsKey = $"{UserSessionsPrefix}{userId}";
            var sessionKeys = await _db.SetMembersAsync(userSessionsKey);
            
            var sessions = new List<UserSession>();
            foreach (var sessionKey in sessionKeys)
            {
                var session = await GetSessionAsync(sessionKey!);
                if (session != null)
                {
                    sessions.Add(session);
                }
            }
            
            return sessions;
        }
    }
}
