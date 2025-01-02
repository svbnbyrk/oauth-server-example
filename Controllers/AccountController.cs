using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OAuthServer.Models;
using OAuthServer.Services;
using System.Security.Claims;

namespace OAuthServer.Controllers;

[ApiController]
[Route("[controller]")]
public class AccountController : ControllerBase
{
    private readonly AccountService _accountService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;

    public AccountController(
        AccountService accountService, 
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager)
    {
        _accountService = accountService;
        _signInManager = signInManager;
        _userManager = userManager;
    }

    [HttpPost("token")]
    public async Task<IActionResult> GetToken([FromBody] TokenRequest request)
    {
        try
        {
            var (success, error, result) = await _accountService.AuthenticateAsync(request);
            if (!success)
            {
                return Unauthorized(error);
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while processing your request: {ex.Message}");
        }
    }

    [HttpPost("refresh-token")]
    public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenRequest request)
    {
        try
        {
            var (success, error, result) = await _accountService.RefreshTokenAsync(request);
            if (!success)
            {
                return BadRequest(error);
            }

            return Ok(result);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while processing your request: {ex.Message}");
        }
    }

    [HttpGet("sessions")]
    [Authorize]
    public async Task<IActionResult> GetActiveSessions()
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid token claims");
            }

            var sessions = await _accountService.GetUserSessionsAsync(userId);
            return Ok(sessions);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while processing your request: {ex.Message}");
        }
    }

    [HttpPost("revoke")]
    [Authorize]
    public async Task<IActionResult> RevokeSession(string clientType)
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid token claims");
            }

            await _accountService.RevokeSessionAsync(userId, clientType);
            return Ok();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while processing your request: {ex.Message}");
        }
    }

    [HttpPost("revoke-all")]
    [Authorize]
    public async Task<IActionResult> RevokeAllSessions()
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid token claims");
            }

            await _accountService.RevokeAllSessionsAsync(userId);
            return Ok();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred while processing your request: {ex.Message}");
        }
    }

    [HttpGet("login/{provider}")]
    public IActionResult ExternalLogin(
        string provider,
        string clientType,
        string? returnUrl = null)
    {
        var redirectUrl = Url.Action(
            nameof(ExternalLoginCallback),
            "Account",
            new { returnUrl, clientType });

        if (string.IsNullOrEmpty(redirectUrl))
        {
            return BadRequest("Unable to generate redirect URL");
        }

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet("callback")]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string clientType = "platform_web")
    {
        try
        {
            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                return BadRequest("Error loading external login information");
            }

            var (success, error, authResult) = await _accountService.HandleExternalLoginAsync(info, clientType);
            if (!success)
            {
                return BadRequest(error);
            }

            return BuildExternalLoginResponse(returnUrl, authResult!);
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred during external login: {ex.Message}");
        }
    }

    private IActionResult BuildExternalLoginResponse(string? returnUrl, AuthenticationResult authResult)
    {
        if (string.IsNullOrEmpty(returnUrl))
        {
            return Ok(authResult);
        }

        var queryParams = new Dictionary<string, string>
        {
            { "access_token", authResult.AccessToken },
            { "refresh_token", authResult.RefreshToken },
            { "roles", string.Join(",", authResult.Roles) }
        };

        var uriBuilder = new UriBuilder(returnUrl);
        var query = System.Web.HttpUtility.ParseQueryString(uriBuilder.Query);
        foreach (var param in queryParams)
        {
            query[param.Key] = param.Value;
        }
        uriBuilder.Query = query.ToString();

        return Redirect(uriBuilder.ToString());
    }

    [Authorize]
    [HttpPost("logout")]
    public async Task<IActionResult> Logout(string clientType)
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid token claims");
            }

            await _accountService.LogoutAsync(userId, clientType);
            return Ok();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred during logout: {ex.Message}");
        }
    }

    [HttpPost("register")]
    public async Task<IActionResult> Register([FromBody] RegistrationRequest request)
    {
        try
        {
            var (success, error) = await _accountService.RegisterAsync(request);
            if (!success)
            {
                return BadRequest(new { error });
            }

            return Ok(new { message = "Registration successful" });
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = $"An error occurred while processing your request: {ex.Message}" });
        }
    }

    [Authorize]
    [HttpGet("me")]
    public async Task<ActionResult<UserInfoResponse>> GetUserInfo()
    {
        try
        {
            var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            if (string.IsNullOrEmpty(userId))
            {
                return Unauthorized(new { error = "Invalid token" });
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
            {
                return NotFound(new { error = "User not found" });
            }

            var roles = await _userManager.GetRolesAsync(user);

            var response = new UserInfoResponse
            {
                Id = user.Id,
                Email = user.Email,
                Username = user.UserName,
                EmailConfirmed = user.EmailConfirmed,
                Roles = roles.ToList()
            };

            return Ok(response);
        }
        catch (Exception ex)
        {
            return StatusCode(500, new { error = $"An error occurred while retrieving user information: {ex.Message}" });
        }
    }
}
