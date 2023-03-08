using Auth0.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace WebApp.AuthenticationTest.Service.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class HomeController : ControllerBase
    {
        private readonly IConfiguration _configuration;

        public HomeController(IConfiguration configuration)
        {
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
        }

        [Authorize(AuthenticationSchemes = OpenIdConnectDefaults.AuthenticationScheme)]
        public async Task<IActionResult> Login(string returnUrl = "/")
        {
            var authenticationProperties = new LoginAuthenticationPropertiesBuilder()
                .WithRedirectUri(returnUrl)
                .Build();

            if (User.Identity.IsAuthenticated)
                return Redirect(string.Concat("Home/", nameof(Profile)));

            return BadRequest();
        }

        [Authorize]
        [HttpGet("Profile")]
        public async Task<IActionResult> Profile()
        {
            ClaimsPrincipal currentUser = this.User;
            var currentUserName = currentUser.FindFirst(ClaimTypes.NameIdentifier).Value;

            string accessToken = await HttpContext.GetTokenAsync("access_token");
            string idToken = await HttpContext.GetTokenAsync("id_token");
            string refreshToken = await HttpContext.GetTokenAsync("refresh_token");
            string[] tokens = { User.Identity.Name, accessToken, idToken, refreshToken };
            return Ok(tokens);
            //string[] scopes = new string[] { "user.read" };
            //string accessToken = await tokenAcquisition.GetAccessTokenForUserAsync(scopes);

            //HttpClient client = new HttpClient();
            //client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", accessToken);
            //string json = await client.GetStringAsync(url);
        }

        [Authorize]
        [HttpGet("ValidateToken")]
        public async Task<IActionResult> ValidateToken()
        {
            string accessToken = await HttpContext.GetTokenAsync("access_token");

            var tokenHandler = new JwtSecurityTokenHandler();
            var key = Encoding.ASCII.GetBytes(_configuration["Jwt:Kid"]);

            tokenHandler.ValidateToken(accessToken, new TokenValidationParameters
            {
                ValidIssuer = _configuration["Jwt:Issuer"],
                IssuerSigningKey = new JsonWebKey(key.ToString()),
                ValidateAudience = false,
                ValidateIssuer = true,
                ValidateIssuerSigningKey = true,
                ValidateLifetime = false,
            }, out SecurityToken validatedtoken);

            return Ok(validatedtoken);
        }

        [Authorize]
        [HttpGet("Claims")]
        public IActionResult Claims()
        {
            IEnumerable<Claim> claims = User.Claims;

            return Ok(claims);
        }
    }
}
