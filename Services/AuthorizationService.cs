using Microsoft.AspNetCore.Identity;
using OpenIddict.Abstractions;
using OAuthServer.Models;
using Microsoft.AspNetCore.WebUtilities;
using OAuthServer.Services.Interfaces;

namespace OAuthServer.Services;

public interface IAuthorizationService
{
    Task<(bool success, string? error, string? redirectUri)> HandleAuthorizationRequestAsync(
        AuthorizationRequest request,
        string? userId);
}

public class AuthorizationService : IAuthorizationService
{
    private readonly UserManager<ApplicationUser> _userManager;
    private readonly IOpenIddictApplicationManager _applicationManager;
    private readonly IOpenIddictAuthorizationManager _authorizationManager;
    private readonly IOpenIddictTokenManager _tokenManager;
    private readonly IAccountService _accountService;

    public AuthorizationService(
        UserManager<ApplicationUser> userManager,
        IOpenIddictApplicationManager applicationManager,
        IOpenIddictAuthorizationManager authorizationManager,
        IOpenIddictTokenManager tokenManager,
        IAccountService accountService)
    {
        _userManager = userManager;
        _applicationManager = applicationManager;
        _authorizationManager = authorizationManager;
        _tokenManager = tokenManager;
        _accountService = accountService;
    }

    public async Task<(bool success, string? error, string? redirectUri)> HandleAuthorizationRequestAsync(
        AuthorizationRequest request,
        string? userId)
    {
        // Validate response type
        if (request.ResponseType != "code")
        {
            return (false, "unsupported_response_type", null);
        }

        // Validate the client
        var application = await _applicationManager.FindByClientIdAsync(request.ClientId);
        if (application == null)
        {
            return (false, "invalid_client", null);
        }

        // Validate redirect URI
        if (!await _applicationManager.ValidateRedirectUriAsync(application, request.RedirectUri))
        {
            return (false, "invalid_redirect_uri", null);
        }

        // Validate user
        if (string.IsNullOrEmpty(userId))
        {
            return (false, "invalid_user", null);
        }

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
        {
            return (false, "invalid_user", null);
        }

        try
        {
            // Create authorization and generate authorization code
            var authorization = await _accountService.CreateAuthorizationAsync(
                userId,
                request.ClientId,
                request.Scope?.Split(' ') ?? Array.Empty<string>());

            // Generate the authorization code
            var code = await _tokenManager.CreateAsync(new OpenIddictTokenDescriptor
            {
                AuthorizationId = await _authorizationManager.GetIdAsync(authorization),
                Status = OpenIddictConstants.Statuses.Valid,
                Subject = userId,
                Type = OpenIddictConstants.ResponseTypes.Code
            });

            // Build the redirect URI
            var location = QueryHelpers.AddQueryString(request.RedirectUri, new Dictionary<string, string?>
            {
                ["code"] = code.ToString(),
                ["state"] = request.State
            });

            return (true, null, location);
        }
        catch (Exception ex)
        {
            return (false, $"server_error: {ex.Message}", null);
        }
    }
}
