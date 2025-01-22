using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OAuthServer.Models;
using OAuthServer.Services;
using OAuthServer.Services.Interfaces;
using System.Security.Claims;
using Microsoft.Extensions.Logging;

namespace OAuthServer.Controllers;

/// <summary>
/// Controller for managing user accounts and session management
/// </summary>
[ApiController]
[Route("account")]
[Produces("application/json")]
public class AccountController : ControllerBase
{
    private readonly IAccountService _accountService;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ILogger<AccountController> _logger;

    public AccountController(
        IAccountService accountService, 
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ILogger<AccountController> logger)
    {
        _accountService = accountService;
        _signInManager = signInManager;
        _userManager = userManager;
        _logger = logger;
    }

    /// <summary>
    /// Retrieves all active sessions for the authenticated user
    /// </summary>
    /// <remarks>
    /// Requires authentication. Returns a list of all active sessions across different client types.
    /// </remarks>
    /// <response code="200">Returns the list of active sessions</response>
    /// <response code="400">If the token claims are invalid</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpGet("sessions")]
    [Authorize]
    [ProducesResponseType(typeof(IEnumerable<string>), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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

    /// <summary>
    /// Revokes a specific session for the authenticated user
    /// </summary>
    /// <param name="clientType">The type of client (e.g., 'web', 'mobile')</param>
    /// <remarks>
    /// Requires authentication. Revokes all tokens associated with the specified client type.
    /// </remarks>
    /// <response code="200">If the session was successfully revoked</response>
    /// <response code="400">If the token claims are invalid</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpPost("revoke")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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

    /// <summary>
    /// Revokes all active sessions for the authenticated user
    /// </summary>
    /// <remarks>
    /// Requires authentication. Revokes all tokens across all client types.
    /// </remarks>
    /// <response code="200">If all sessions were successfully revoked</response>
    /// <response code="400">If the token claims are invalid</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpPost("revoke-all")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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

    /// <summary>
    /// Initiates external authentication with the specified provider
    /// </summary>
    /// <param name="provider">The authentication provider (e.g., 'Google', 'Facebook')</param>
    /// <param name="clientType">The type of client application</param>
    /// <param name="returnUrl">Optional URL to redirect after successful authentication</param>
    /// <remarks>
    /// Redirects to the external provider's authentication page.
    /// </remarks>
    /// <response code="302">Redirects to the external provider</response>
    /// <response code="400">If the redirect URL could not be generated</response>
    [HttpGet("login/{provider}")]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    public IActionResult ExternalLogin(
        string provider,
        string clientType,
        string? returnUrl = null)
    {
        _logger.LogInformation($"Starting external login for provider: {provider}, returnUrl: {returnUrl}");

        // Ensure we have a return URL
        if (string.IsNullOrEmpty(returnUrl))
        {
            returnUrl = "https://localhost:5251";
        }

        var redirectUrl = Url.Action(
            nameof(ExternalLoginCallback),
            "Account",
            new { returnUrl, clientType },
            Request.Scheme,
            Request.Host.Value);

        if (string.IsNullOrEmpty(redirectUrl))
        {
            _logger.LogError("Failed to generate redirect URL");
            return BadRequest("Unable to generate redirect URL");
        }

        _logger.LogInformation($"Generated redirect URL: {redirectUrl}");

        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        
        // Store the return URL in the properties
        properties.Items["returnUrl"] = returnUrl;
        
        _logger.LogInformation($"Challenging with provider: {provider}");
        return Challenge(properties, provider);
    }

    /// <summary>
    /// Handles the callback from external authentication providers
    /// </summary>
    /// <param name="returnUrl">Optional URL to redirect after successful authentication</param>
    /// <param name="clientType">The type of client application</param>
    /// <remarks>
    /// This endpoint is called by the external provider after successful authentication.
    /// If a returnUrl is provided, redirects there with tokens as query parameters.
    /// Otherwise, returns the tokens in the response body.
    /// </remarks>
    /// <response code="200">Returns the authentication result</response>
    /// <response code="302">Redirects to returnUrl with tokens if provided</response>
    /// <response code="400">If the external login information is invalid</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpGet("callback")]
    [ProducesResponseType(typeof(AuthenticationResult), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status302Found)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> ExternalLoginCallback(string? returnUrl = null, string clientType = "platform_web")
    {
        try
        {
            // Log the incoming request details
            _logger.LogInformation($"External login callback received. ReturnUrl: {returnUrl}, ClientType: {clientType}");

            var info = await _signInManager.GetExternalLoginInfoAsync();
            if (info == null)
            {
                _logger.LogError("GetExternalLoginInfoAsync returned null");
                return BadRequest("Error loading external login information. The external provider did not return the expected information.");
            }

            _logger.LogInformation($"External login info received. Provider: {info.LoginProvider}, ProviderKey: {info.ProviderKey}");
            
            // Log claims received from the external provider
            var claims = info.Principal.Claims.Select(c => $"{c.Type}: {c.Value}");
            _logger.LogInformation($"Claims received: {string.Join(", ", claims)}");

            var (success, error, authResult) = await _accountService.HandleExternalLoginAsync(info, clientType);
            if (!success)
            {
                _logger.LogError($"HandleExternalLoginAsync failed. Error: {error}");
                return BadRequest(error);
            }

            _logger.LogInformation("External login successful, building response");
            return BuildExternalLoginResponse(returnUrl, authResult!);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "An error occurred during external login callback");
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

    /// <summary>
    /// Logs out the currently authenticated user
    /// </summary>
    /// <remarks>
    /// Requires authentication. Revokes the current session's tokens.
    /// </remarks>
    /// <response code="200">If the logout was successful</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="500">If there was an internal server error</response>
    [Authorize]
    [HttpPost("logout")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> Logout()
    {
        try
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (string.IsNullOrEmpty(userId))
            {
                return BadRequest("Invalid token claims");
            }

            await _accountService.LogoutAsync(userId, "platform_web");
            return Ok();
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred during logout: {ex.Message}");
        }
    }

    /// <summary>
    /// Registers a new user
    /// </summary>
    /// <param name="request">The registration request containing user information</param>
    /// <remarks>
    /// Sample request:
    ///
    ///     POST /Account/register
    ///     {
    ///        "email": "user@example.com",
    ///        "password": "user_password",
    ///        "username": "user_username"
    ///     }
    /// </remarks>
    /// <response code="200">If the registration was successful</response>
    /// <response code="400">If the registration request is invalid</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpPost("register")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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

    /// <summary>
    /// Retrieves information about the currently authenticated user
    /// </summary>
    /// <remarks>
    /// Requires authentication. Returns user information, including roles.
    /// </remarks>
    /// <response code="200">Returns the user information</response>
    /// <response code="401">If the user is not authenticated</response>
    /// <response code="404">If the user is not found</response>
    /// <response code="500">If there was an internal server error</response>
    [Authorize]
    [HttpGet("me")]
    [ProducesResponseType(typeof(UserInfoResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status404NotFound)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
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
    // public IActionResult Login(string? returnurl)
    // {
    //     throw new NotImplementedException();
    // }
}
