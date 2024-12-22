using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;

namespace CoreApi8JwtToken.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        public AuthenticationController(IConfiguration config)
        {
            _configuration = config;
        }

        [HttpPost]
        public async Task<IActionResult> GetToken(string userName, string Password)
        {
            if (userName == "1" && Password == "1")
            {
                var claims = new Claim[]
                {
                    new Claim(ClaimTypes.Email, "a@bcde.com"),
                    new Claim(ClaimTypes.Name, userName)
                };
                SymmetricSecurityKey key = new SymmetricSecurityKey(Encoding.ASCII.GetBytes(_configuration.GetValue<string>("JwtToken:secretKey")));
                JwtSecurityToken securityToken = new JwtSecurityToken(
                
                    issuer: _configuration.GetValue<string>("JwtToken:issuer"),
                    audience: _configuration.GetValue<string>("JwtToken:audience"),
                    claims: claims,
                    expires: DateTime.Now.AddMinutes(5),
                    signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature)
                );
                var token = new JwtSecurityTokenHandler().WriteToken(securityToken);
                return Ok(token);
            }
            return NotFound();
        }
    }
}
