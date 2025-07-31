using System.Security.Claims;
using Demo.Data;
using Demo.Models;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.EntityFrameworkCore;

namespace Demo.Middleware
{
    public class UserStatusCheckMiddleware
    {
        private readonly RequestDelegate _next;
        private readonly IServiceScopeFactory _serviceScopeFactory;
        private readonly ILogger<UserStatusCheckMiddleware> _logger;

        public UserStatusCheckMiddleware(RequestDelegate next, IServiceScopeFactory serviceScopeFactory, ILogger<UserStatusCheckMiddleware> logger)
        {
            _next = next;
            _serviceScopeFactory = serviceScopeFactory;
            _logger = logger;
        }

        public async Task InvokeAsync(HttpContext context)
        {
            // Skip check for login, register, and static files
            var path = context.Request.Path.Value?.ToLower();
            if (path == null ||
                path.Contains("/account/login") ||
                path.Contains("/account/register") ||
                path.Contains("/account/logout") ||
                path.Contains(".css") ||
                path.Contains(".js") ||
                path.Contains(".ico") ||
                path.Contains("/lib/"))
            {
                await _next(context);
                return;
            }

            // Check if user is authenticated
            if (context.User.Identity?.IsAuthenticated == true)
            {
                var userIdClaim = context.User.FindFirst(ClaimTypes.NameIdentifier);
                if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int userId))
                {
                    using var scope = _serviceScopeFactory.CreateScope();
                    var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

                    try
                    {
                        var user = await dbContext.Users.FindAsync(userId);

                        // Requirement 5: Check if user exists and isn't blocked
                        if (user == null || user.Status != UserStatus.Active)
                        {
                            _logger.LogWarning("User {UserId} is blocked or deleted, signing out", userId);
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/Account/Login?message=Your account has been blocked or deleted");
                            return;
                        }
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error checking user status for user {UserId}", userId);
                        // Continue without blocking in case of database issues
                    }
                }
            }

            await _next(context);
        }
    }

    public static class UserStatusCheckMiddlewareExtensions
    {
        public static IApplicationBuilder UseUserStatusCheck(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<UserStatusCheckMiddleware>();
        }
    }
}