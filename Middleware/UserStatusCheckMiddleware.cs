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
            // Skip check for login, register, logout, error pages, and static files
            var path = context.Request.Path.Value?.ToLower();
            if (path == null ||
                path.Contains("/account/login") ||
                path.Contains("/account/register") ||
                path.Contains("/account/logout") ||
                path.Contains("/error") ||
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

                        // Handle different scenarios
                        if (user == null)
                        {
                            // User not found in database (might have been deleted)
                            _logger.LogWarning("User {UserId} not found in database, signing out", userId);
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/Account/Login?message=Your account no longer exists. Please register again.");
                            return;
                        }

                        if (user.Status == UserStatus.Blocked)
                        {
                            // User is blocked
                            _logger.LogWarning("Blocked user {UserId} attempted to access protected resource, signing out", userId);
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/Account/Login?message=Your account has been blocked by the administrator.");
                            return;
                        }

                        if (user.Status == UserStatus.Deleted)
                        {
                            // User is marked as deleted, remove from database and sign out
                            _logger.LogWarning("Deleted user {UserId} attempted to access protected resource, removing from database and signing out", userId);
                            dbContext.Users.Remove(user);
                            await dbContext.SaveChangesAsync();
                            await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                            context.Response.Redirect("/Account/Login?message=Your account has been deleted. Please register again to create a new account.");
                            return;
                        }

                        // User is active, continue processing
                        if (user.Status == UserStatus.Active)
                        {
                            await _next(context);
                            return;
                        }

                        // Invalid status
                        _logger.LogWarning("User {UserId} has invalid status {Status}, signing out", userId, user.Status);
                        await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                        context.Response.Redirect("/Account/Login?message=Your account status is invalid. Please contact support.");
                        return;
                    }
                    catch (Exception ex)
                    {
                        _logger.LogError(ex, "Error checking user status for user {UserId}", userId);
                        // Continue without blocking in case of database issues
                        await _next(context);
                        return;
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