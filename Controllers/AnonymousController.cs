using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using OAuthServer.Models;
using OAuthServer.Services;
using OAuthServer.Services.Interfaces;
using System.Security.Claims;

namespace OAuthServer.Controllers;

[ApiController]
[Route("anonymous")]
[Produces("application/json")]
public class AnonymousController : ControllerBase
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly IAccountService _accountService;
    private readonly ITokenService _tokenService;

    public AnonymousController(
        UserManager<ApplicationUser> userManager,
        SignInManager<ApplicationUser> signInManager,
     IAccountService accountService,
     ITokenService tokenService)
    {
        _userManager = userManager;
        _signInManager = signInManager;
        _accountService = accountService;
        _tokenService = tokenService;
    }

    /// <summary>
    /// Creates a new anonymous user and returns authentication tokens
    /// </summary>
    /// <param name="clientType">The type of client (e.g., 'web', 'mobile', 'game')</param>
    /// <response code="200">Returns the authentication tokens for the anonymous user</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpPost("create")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> CreateAnonymousUser(string clientType)
    {
        try
        {
            var anonymousId = Guid.NewGuid().ToString();
            var user = new ApplicationUser
            {
                UserName = $"anon_{anonymousId}",
                Email = $"anon_{anonymousId}@anonymous.local",
                IsAnonymous = true,
                AnonymousId = anonymousId,
                AnonymousCreatedAt = DateTime.UtcNow
            };

            var result = await _userManager.CreateAsync(user);
            if (!result.Succeeded)
            {
                return StatusCode(500, "Failed to create anonymous user");
            }

            // Sign in the user and generate tokens
            await _signInManager.SignInAsync(user, isPersistent: true);
            var authResult = await _tokenService.GenerateTokens(user, clientType);  

            return Ok(new
            {
                userId = user.Id,
                anonymousId = user.AnonymousId,
                tokens = authResult
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred: {ex.Message}");
        }
    }

    /// <summary>
    /// Links an anonymous user account to a registered account
    /// </summary>
    /// <param name="request">The link request containing the anonymous user ID and the new user credentials</param>
    /// <response code="200">Returns the updated user information and tokens</response>
    /// <response code="400">If the request is invalid or the anonymous user is not found</response>
    /// <response code="500">If there was an internal server error</response>
    [HttpPost("link")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status400BadRequest)]
    [ProducesResponseType(StatusCodes.Status500InternalServerError)]
    public async Task<IActionResult> LinkAnonymousUser([FromBody] LinkAnonymousUserRequest request)
    {
        try
        {
            // Find the anonymous user
            var anonymousUser = await _userManager.FindByIdAsync(request.AnonymousUserId);
            if (anonymousUser == null || !anonymousUser.IsAnonymous)
            {
                return BadRequest("Invalid anonymous user");
            }

            // Update the user with the new information
            anonymousUser.Email = request.Email;
            anonymousUser.UserName = request.Username;
            anonymousUser.IsAnonymous = false;

            // Update the user and set the password
            var updateResult = await _userManager.UpdateAsync(anonymousUser);
            var passwordResult = await _userManager.AddPasswordAsync(anonymousUser, request.Password);

            if (!updateResult.Succeeded || !passwordResult.Succeeded)
            {
                return StatusCode(500, "Failed to update user information");
            }

            // Generate new tokens
            var authResult = await _tokenService.GenerateTokens(anonymousUser, request.ClientType);  

            return Ok(new
            {
                userId = anonymousUser.Id,
                email = anonymousUser.Email,
                username = anonymousUser.UserName,
                tokens = authResult
            });
        }
        catch (Exception ex)
        {
            return StatusCode(500, $"An error occurred: {ex.Message}");
        }
    }
}

public class LinkAnonymousUserRequest
{
    public string AnonymousUserId { get; set; } = null!;
    public string Email { get; set; } = null!;
    public string Username { get; set; } = null!;
    public string Password { get; set; } = null!;
    public string ClientType { get; set; } = null!;
}
