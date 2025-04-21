using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server.AspNetCore;
using OAuthServer.Models;
using OAuthServer.Models.OAuth;
using OAuthServer.Services.Interfaces;
using System.Security.Claims;
using Microsoft.AspNetCore.Authentication;
using System.ComponentModel.DataAnnotations;
using System.Text.Json;
using OAuthServer.Services;
using Swashbuckle.AspNetCore.Annotations;
using System.Net.Http;
using Microsoft.Extensions.Configuration;

namespace OAuthServer.Controllers;

/// <summary>
/// OAuth 2.0 token endpoint for authentication and token management
/// </summary>
[ApiController]
[Route("connect")]
[Produces("application/json")]
[ApiExplorerSettings(GroupName = "v1")]
[Tags("Authentication")]
[SwaggerTag("OAuth 2.0 token endpoint for authentication and token management")]
public class OAuthController : Controller
{
    private readonly SignInManager<ApplicationUser> _signInManager;
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly ITokenService _tokenService;
    private readonly IAuthorizationService _authorizationService;
    private readonly IConfiguration _configuration;
    private readonly HttpClient _httpClient;
    private readonly ILogger<OAuthController> _logger;

    public OAuthController(
        SignInManager<ApplicationUser> signInManager,
        UserManager<ApplicationUser> userManager,
        ITokenService tokenService,
        IAuthorizationService authorizationService,
        IConfiguration configuration,
        HttpClient httpClient,
        ILogger<OAuthController> logger)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenService = tokenService;
        _authorizationService = authorizationService;
        _configuration = configuration;
        _httpClient = httpClient;
        _logger = logger;
    }

    /// <summary>
    /// OAuth 2.0 token endpoint for obtaining access tokens
    /// </summary>
    /// <remarks>
    /// Sample requests:
    /// 
    /// Password Grant Type:
    /// ```
    /// POST /connect/token
    /// Content-Type: application/x-www-form-urlencoded
    /// 
    /// grant_type=password
    /// &amp;username=user@example.com
    /// &amp;password=YourPassword123!
    /// &amp;client_id=postman
    /// &amp;client_secret=postman-secret
    /// &amp;scope=email profile roles
    /// ```
    /// 
    /// Authorization Code Grant Type:
    /// ```
    /// POST /connect/token
    /// Content-Type: application/x-www-form-urlencoded
    /// 
    /// grant_type=authorization_code
    /// &amp;code=authorization_code
    /// &amp;redirect_uri=https://client.example.com/callback
    /// &amp;client_id=postman
    /// &amp;client_secret=postman-secret
    /// ```
    /// 
    /// Refresh Token Grant Type:
    /// ```
    /// POST /connect/token
    /// Content-Type: application/x-www-form-urlencoded
    /// 
    /// grant_type=refresh_token
    /// &amp;refresh_token={refresh_token}
    /// &amp;client_id=postman
    /// &amp;client_secret=postman-secret
    /// ```
    /// </remarks>
    /// <response code="200">Returns the access token if valid</response>
    /// <response code="400">If the request is invalid</response>
    /// <response code="401">If the credentials are invalid</response>
    [HttpPost("token")]
    [Consumes("application/x-www-form-urlencoded")]
    [ProducesResponseType(typeof(TokenResponse), StatusCodes.Status200OK)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status400BadRequest)]
    [ProducesResponseType(typeof(ErrorResponse), StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Token()
    {
        var request = HttpContext.GetOpenIddictServerRequest() ??
            throw new InvalidOperationException("The OpenID Connect request cannot be retrieved.");

        try
        {
            if (request.IsPasswordGrantType())
            {
                var response = await _tokenService.HandlePasswordGrantType(
                    request.Username,
                    request.Password,
                    request.ClientId);

                return Ok(response);
            }
            else if (request.IsRefreshTokenGrantType())
            {
                var info = await HttpContext.AuthenticateAsync(OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
                var response = await _tokenService.HandleRefreshTokenGrantType(
                    info.Principal,
                    request.ClientId);

                return Ok(response);
            }
            else if (request.IsAuthorizationCodeGrantType())
            {
                var response = await HandleGoogleAuthorizationCodeGrantType(
                    request.Code,
                    request.RedirectUri,
                    request.ClientId,
                    request.ClientSecret);

                return Ok(response);
            }

            throw new InvalidOperationException("The specified grant type is not supported.");
        }
        catch (TokenService.InvalidGrantException ex)
        {
            var properties = new AuthenticationProperties(new Dictionary<string, string>
            {
                [OpenIddictServerAspNetCoreConstants.Properties.Error] = OpenIddictConstants.Errors.InvalidGrant,
                [OpenIddictServerAspNetCoreConstants.Properties.ErrorDescription] = ex.Message
            });

            return Forbid(properties, OpenIddictServerAspNetCoreDefaults.AuthenticationScheme);
        }
    }

    /// <summary>
    /// Handles the authorization request from clients
    /// </summary>
    /// <remarks>
    /// This endpoint initiates the authorization code flow:
    /// 1. Client redirects user here
    /// 2. User authenticates
    /// 3. User approves requested scopes
    /// 4. User is redirected back to client with auth code
    /// </remarks>
    [HttpGet("authorize")]
    [ProducesResponseType(typeof(void), StatusCodes.Status302Found)]
    public async Task<IActionResult> Authorize(
        [FromQuery] string response_type,
        [FromQuery] string client_id,
        [FromQuery] string redirect_uri,
        [FromQuery] string scope,
        [FromQuery] string state,
        [FromQuery] string? code_challenge = null,
        [FromQuery] string? code_challenge_method = null)
    {
        var request = new AuthorizationRequest
        {
            ResponseType = response_type,
            ClientId = client_id,
            RedirectUri = redirect_uri,
            Scope = scope,
            State = state,
            CodeChallenge = code_challenge,
            CodeChallengeMethod = code_challenge_method
        };

        // Store request in TempData for post-login processing
        TempData["AuthorizationRequest"] = JsonSerializer.Serialize(request);

        // If user is not authenticated, redirect to login
        if (!User.Identity?.IsAuthenticated ?? true)
        {
            return RedirectToAction("Login", "Account", new { returnUrl = Url.Action("Authorize", "OAuth", Request.QueryString.Value) });
        }

        var userId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var (success, error, redirectUri) = await _authorizationService.HandleAuthorizationRequestAsync(request, userId);

        if (!success)
        {
            return BadRequest(new { error });
        }

        return Redirect(redirectUri!);
    }

    /// <summary>
    /// Handles the Google authorization code grant type
    /// </summary>
    private async Task<ActionResult> HandleGoogleAuthorizationCodeGrantType(
        string code,
        string redirectUri,
        string clientId,
        string clientSecret)
    {
        var googleTokenUrl = "https://oauth2.googleapis.com/token";
        var googleClientId = _configuration["Authentication:Google:ClientId"];
        var googleClientSecret = _configuration["Authentication:Google:ClientSecret"];

        // Validate client credentials
        if (clientId != googleClientId || clientSecret != googleClientSecret)
            return BadRequest(new ErrorResponse { Error = "Invalid client credentials" });

        var tokenRequest = new Dictionary<string, string>
        {
            {"code", code},
            {"client_id", googleClientId},
            {"client_secret", googleClientSecret},
            {"redirect_uri", redirectUri},
            {"grant_type", "authorization_code"}
        };

        var content = new FormUrlEncodedContent(tokenRequest);
        var response = await _httpClient.PostAsync(googleTokenUrl, content);
        var responseContent = await response.Content.ReadAsStringAsync();

        if (!response.IsSuccessStatusCode)
        {
            _logger.LogError($"Google token exchange failed: {responseContent}");
             return BadRequest(new ErrorResponse { Error = "Token exchange failed" });
        }

        // Forward Google's response
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(responseContent);
        if (tokenResponse == null)
        {
            _logger.LogError("Failed to deserialize token response.");
             return BadRequest(new ErrorResponse { Error = "Token exchange failed" });
        }
        return Ok(tokenResponse);
    }

    private static IEnumerable<string> GetDestinations(Claim claim)
    {
        // Note: by default, claims are NOT automatically included in the access and identity tokens.
        // To allow OpenIddict to serialize them, you must attach them a destination, that specifies
        // whether they should be included in access tokens, in identity tokens or in both.

        switch (claim.Type)
        {
            case OpenIddictConstants.Claims.Name:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Profile))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Email:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Email))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            case OpenIddictConstants.Claims.Role:
                yield return OpenIddictConstants.Destinations.AccessToken;

                if (claim.Subject.HasScope(OpenIddictConstants.Permissions.Scopes.Roles))
                    yield return OpenIddictConstants.Destinations.IdentityToken;

                yield break;

            // Never include the security stamp in the access and identity tokens, as it's a secret value.
            case "AspNet.Identity.SecurityStamp": yield break;

            default:
                yield return OpenIddictConstants.Destinations.AccessToken;
                yield break;
        }
    }
}
