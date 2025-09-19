using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;


var builder = WebApplication.CreateBuilder(args);

// Add services to the container.

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

app.UseHttpsRedirection();

app.UseAuthorization();

app.MapControllers();

app.Run();


// ==== Settings (keep secrets out of code in real apps) ====
var jwtIssuer = builder.Configuration["Jwt:Issuer"] ?? "https://api.example.com";
var jwtAudience = builder.Configuration["Jwt:Audience"] ?? "api-audience";
var jwtKey = builder.Configuration["Jwt:Key"] ?? "super_secret_dev_key_of_at_least_32_chars";

// ==== Auth ====
var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey));

builder.Services
    .AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = jwtIssuer,
            ValidateAudience = true,
            ValidAudience = jwtAudience,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = signingKey,
            ValidateLifetime = true,
            ClockSkew = TimeSpan.FromMinutes(2)
        };
    });

builder.Services.AddAuthorization();

// ==== Swagger (Bearer) ====
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new() { Title = "JWT Demo API", Version = "v1" });
    c.AddSecurityDefinition("Bearer", new()
    {
        Name = "Authorization",
        Type = Microsoft.OpenApi.Models.SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = Microsoft.OpenApi.Models.ParameterLocation.Header,
        Description = "Enter: Bearer {token}"
    });
    c.AddSecurityRequirement(new()
    {
        [new() { Reference = new() { Type = Microsoft.OpenApi.Models.ReferenceType.SecurityScheme, Id = "Bearer" } }] = new string[] { }
    });
});


// Issue a token (demo only)
app.MapPost("/auth/token", (UserLogin login) =>
{
    // TODO: validate user (check DB/IdP/etc.)
    if (login.Username != "alice" || login.Password != "P@ssw0rd!") return Results.Unauthorized();

    var claims = new[]
    {
        new Claim(JwtRegisteredClaimNames.Sub, login.Username),
        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
        new Claim("role", "admin"),
        new Claim("scope", "api.read api.write")
    };

    var creds = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);
    var token = new JwtSecurityToken(
        issuer: jwtIssuer,
        audience: jwtAudience,
        claims: claims,
        notBefore: DateTime.UtcNow,
        expires: DateTime.UtcNow.AddHours(1),
        signingCredentials: creds);

    var jwt = new JwtSecurityTokenHandler().WriteToken(token);
    return Results.Ok(new { access_token = jwt, token_type = "Bearer", expires_in = 3600 });
});

// Protected endpoint
app.MapGet("/secure/hello", (ClaimsPrincipal user) =>
{
    var name = user.Identity?.Name ?? user.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
    return new { message = $"Hello {name}, you are authenticated.", timeUtc = DateTime.UtcNow };
})
.RequireAuthorization();
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.Run();

record UserLogin(string Username, string Password);

