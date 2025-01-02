namespace OAuthServer.Models;

public class UserInfoResponse
{
    public string Id { get; set; }
    public string Email { get; set; }
    public string Username { get; set; }
    public bool EmailConfirmed { get; set; }
    public List<string> Roles { get; set; } = new();
}
