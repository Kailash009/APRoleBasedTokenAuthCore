using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace APIRoleBasedTokenAuthCore.Models
{
    public class TokenService
    {
        private readonly IConfiguration _configuration;
        private readonly UserManager<ApplicationUser> _userManager;
        public TokenService(IConfiguration configuration, UserManager<ApplicationUser> userManager)
        {
            _configuration = configuration;
            _userManager = userManager;
        }

        public async Task<TokenModel> GenerateTokensAsync(ApplicationUser _user,string userRole)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var accessTokenExpiration = DateTime.Now.AddMinutes(15);
            var refreshTokenExpiration = DateTime.Now.AddDays(5);

            var accessToken = new JwtSecurityToken(
                issuer: _configuration["JWT:Issuer"],
                audience: _configuration["JWT:Audience"],
                claims: new List<Claim>
                {
                new Claim(ClaimTypes.NameIdentifier, _user.Id),
                new Claim(ClaimTypes.Name, _user.Email),
                new Claim(ClaimTypes.Role,userRole)
                },
                expires: accessTokenExpiration,
                signingCredentials: creds
               );
            var refreshToken = GenerateRefreshToken();
            _user.RefreshToken = refreshToken;
            _user.RefreshTokenExpiryTime = refreshTokenExpiration;
            await _userManager.UpdateAsync(_user);
            return new TokenModel
            {
                AccessToken = new JwtSecurityTokenHandler().WriteToken(accessToken),  //Short-lived, not stored in the database,used for accessing protected resources.
                RefreshToken = refreshToken    // Long-lived, stored in the database,used to obtain new access tokens.
            };
        }
        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[32];
            using (var rng = RandomNumberGenerator.Create())
            {
                rng.GetBytes(randomNumber);
                return Convert.ToBase64String(randomNumber);
            }
        }
    }
}
