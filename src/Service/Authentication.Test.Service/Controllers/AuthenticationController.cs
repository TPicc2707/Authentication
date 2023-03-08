using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.Resource;
using Microsoft.Net.Http.Headers;

namespace Authentication.Test.Service.Controllers
{
    [Route("[controller]")]
    [ApiController]
    [Authorize]
    public class AuthenticationController : ControllerBase
    {
        private readonly ILogger<AuthenticationController> _logger;
        public AuthenticationController(ILogger<AuthenticationController> logger)
        {
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        [HttpGet("SignIn")]
        public async Task<string> SignIn()
        {
            //var output = new List<string>();
            //output.Add(HttpContext.User.Identity.Name);
            //output.Add(HttpContext.User.Identity.IsAuthenticated.ToString());
            //output.AddRange(HttpContext.User.Claims.Select(x => x.Type + ": " + x.Value));

            var accessToken = string.Concat("access_token: ", await HttpContext.GetTokenAsync("access_token"));
            var idToken = string.Concat("id_token: ", await HttpContext.GetTokenAsync("id_token"));
            var refreshToken = string.Concat("refresh_token: ", await HttpContext.GetTokenAsync("refresh_token"));
            var tokens = string.Concat(accessToken, "\n", idToken, "\n", refreshToken);

            _logger.LogInformation("Authenticated User");
            return tokens;
        }
    }
}
