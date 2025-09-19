using Microsoft.VisualStudio.TestPlatform.TestHost;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.IdentityModel.Tokens.Jwt;
// using Microsoft.IdentityModel.Tokens;
using Xunit;

// using Microsoft.AspNetCore.Mvc.Testing;

// Ensure you have the following NuGet package installed in your test project:
// Microsoft.AspNetCore.Mvc.Testing

namespace POC.JWTTokenBasedAuthenticationAndAPISecurity.UnitTests
{
    //public class UnitTest1 : IClassFixture<WebApplicationFactory<Program>>
    //{
    //    private readonly WebApplicationFactory<Program> _factory;
    //    public JwtAuthTests(WebApplicationFactory<Program> factory) => _factory = factory;

    //    [Fact]
    //    public async Task SecureHello_ShouldReturnOk_WithValidToken()
    //    {
    //        var client = _factory.CreateClient();

    //        // Create test token matching Program.cs validation params
    //        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("super_secret_dev_key_of_at_least_32_chars"));
    //        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
    //        var token = new JwtSecurityToken(
    //            issuer: "https://api.example.com",
    //            audience: "api-audience",
    //            claims: new[] { new Claim("role", "admin"), new Claim("scope", "api.read") },
    //            expires: DateTime.UtcNow.AddMinutes(5),
    //            signingCredentials: creds);
    //        var jwt = new JwtSecurityTokenHandler().WriteToken(token);

    //        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", jwt);

    //        var res = await client.GetAsync("/secure/hello");
    //        Assert.Equal(HttpStatusCode.OK, res.StatusCode);
    //    }
   // }
}
