using Microsoft.AspNetCore.Authentication.Cookies;
using Pomelo.EntityFrameworkCore.MySql.Infrastructure;
using Demo.Data;
using Demo.Models;
using Microsoft.EntityFrameworkCore;
using System.Security.Cryptography;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddRazorPages();
builder.Services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
    .AddCookie(options =>
    {
        options.LoginPath = "/Account/Login";
        options.AccessDeniedPath = "/Account/Login";
        options.LogoutPath = "/Account/Logout";
    });

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseMySql(
        builder.Configuration.GetConnectionString("DefaultConnection"),
        new MySqlServerVersion(new Version(8, 0, 33)), // Specify your MySQL version
        mySqlOptions => mySqlOptions
            .EnableRetryOnFailure()
    ));

var app = builder.Build();

// Seed admin user (username: "admin", password: "123")
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    await context.Database.EnsureCreatedAsync();

    if (!await context.Users.AnyAsync(u => u.Email == "admin"))
    {
        var adminUser = new User
        {
            Name = "Administrator",
            Email = "admin",
            PasswordHash = HashPassword("123"),
            DateOfBirth = new DateTime(1990, 1, 1),
            MobileNumber = "1234567890",
            Gender = "Other",
            Status = UserStatus.Active,
            LastLogin = DateTime.UtcNow
        };
        context.Users.Add(adminUser);
        await context.SaveChangesAsync();
    }
}

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error");
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();
app.UseRouting();
app.UseAuthentication();
app.UseAuthorization();

// Requirement 5: Check user status before each request
app.Use(async (context, next) =>
{
    var path = context.Request.Path.Value?.ToLower();

    // Skip check for login, register, and static files
    if (path != null && (
        path.Contains("/account/login") ||
        path.Contains("/account/register") ||
        path.Contains("/account/logout") ||
        path.Contains(".css") ||
        path.Contains(".js") ||
        path.Contains(".ico") ||
        path.Contains("/lib/")))
    {
        await next();
        return;
    }

    // Check if user is authenticated and validate status
    if (context.User.Identity?.IsAuthenticated == true)
    {
        var userIdClaim = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier);
        if (userIdClaim != null && int.TryParse(userIdClaim.Value, out int userId))
        {
            using var scope = app.Services.CreateScope();
            var dbContext = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

            var user = await dbContext.Users.FindAsync(userId);

            // If user is blocked or deleted, redirect to login
            if (user == null || user.Status != UserStatus.Active)
            {
                await context.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                context.Response.Redirect("/Account/Login?message=Your account has been blocked or deleted");
                return;
            }
        }
    }

    await next();
});

app.MapRazorPages();
app.Run();

static string HashPassword(string password)
{
    using var sha256 = SHA256.Create();
    var bytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
    return Convert.ToBase64String(bytes);
}