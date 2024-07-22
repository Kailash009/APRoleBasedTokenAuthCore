using APIRoleBasedTokenAuthCore.Models;
using APIRoleBasedTokenAuthCore.ViewModels;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Rewrite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Query;
using Microsoft.IdentityModel.Tokens;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Text;

namespace APIRoleBasedTokenAuthCore.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AccountController : ControllerBase
    {
        ResponseMessage response = new ResponseMessage();
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly SignInManager<ApplicationUser> _signInManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly ApplicationDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly TokenService _tokenService;
        public AccountController(UserManager<ApplicationUser> userManager, SignInManager<ApplicationUser> signInManager, RoleManager<IdentityRole> roleManager, ApplicationDbContext context, IConfiguration configuration, TokenService tokenService)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _roleManager = roleManager;
            _context = context;
            _configuration = configuration;
            _tokenService = tokenService;
        }

        [HttpGet("GetAllUserRoles")]
        public async Task<ResponseMessage> GetAllUserRoles()
        {
            var userRoles = await (from user in _context.Users
                                   join userRole in _context.UserRoles on user.Id equals userRole.UserId
                                   join role in _context.Roles on userRole.RoleId equals role.Id
                                   select new UserRoleViewModel
                                   {
                                       Username = user.UserName,
                                       RoleName = role.Name
                                   }).ToListAsync();
            response.Message = "All Roles.";
            response.Data = userRoles;
            response.StatusCode = HttpStatusCode.OK;
            return response;
        }

        [HttpPost("RegisterEmployee")]
        public async Task<ResponseMessage> RegisterEmployee([FromBody] RegisterViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = new ApplicationUser { FirstName = model.FirstName, LastName = model.LastName, Age = model.Age, MobileNo = model.MobileNo, Salary = model.Salary,UserName = model.Email, Email = model.Email };
                var result = await _userManager.CreateAsync(user, model.Password);
                if (result.Succeeded)
                {
                    //await _userManager.AddToRoleAsync(user, "User"); // Don't assign Default Role User Here....
                    await _signInManager.SignInAsync(user, isPersistent: false);
                    response.Message = "Employee Details Saved SuccessFully!";
                    response.Data = user;
                    response.StatusCode = HttpStatusCode.Created;
                }
                return response;
            }
            else
            {
                response.Message = "Employee Failed!";
                response.StatusCode = HttpStatusCode.BadRequest;
                return response;
            }
        }

        [HttpPost("Login")]
        public async Task<ResponseMessage> Login([FromBody] LoginViewModel model)
        {
            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Email, model.Password, model.RememberMe, lockoutOnFailure: false);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByEmailAsync(model.Email);
                    if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
                    {
                        // Check if the user is in a specific role and redirect accordingly
                        var userRoles = await _userManager.GetRolesAsync(user);
                        var authClaims = new List<Claim>
                        {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };
                        foreach (var userRole in userRoles)
                        {
                            authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                            var token =await _tokenService.GenerateTokensAsync(user,userRole);
                            response.Message = "Token Created SuccessFully!!";
                            response.Data = token;
                            response.StatusCode = HttpStatusCode.Created;
                        }
                    }
                }
            }
            return response;
        }

        [HttpPost("RefreshToken")]
        public async Task<ResponseMessage> RefreshToken([FromBody] TokenModel tokenModel)
        {
            var principal = GetPrincipalFromExpiredToken(tokenModel.AccessToken);
            var userId = principal.Claims.First(c => c.Type == ClaimTypes.NameIdentifier).Value;
            var user = await _userManager.FindByIdAsync(userId);
            var userRoles = await _userManager.GetRolesAsync(user);
            var authClaims = new List<Claim>
                        {
                        new Claim(ClaimTypes.Name, user.UserName),
                        new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
                        };
            if (user == null || user.RefreshToken != tokenModel.RefreshToken || user.RefreshTokenExpiryTime <= DateTime.Now)
            {
                response.Message = "Can't Refresh Token!";
                response.StatusCode = HttpStatusCode.NotFound;
                return response;
            }
            foreach (var userRole in userRoles)
            {
                var newTokens = await _tokenService.GenerateTokensAsync(user,userRole);
                response.Message = "New Token Generated SuccessFully!!";
                response.Data = newTokens;
                response.StatusCode = HttpStatusCode.OK;
            }
            return response;
        }
        private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
        {
            var tokenValidationParameters = new TokenValidationParameters
            {
                ValidateAudience = false,
                ValidateIssuer = false,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Key"])),
                ValidateLifetime = false          // We check token Expiration manually
            };
            var tokenHandler = new JwtSecurityTokenHandler();
            var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
            var jwtSecurityToken = securityToken as JwtSecurityToken;
            if (jwtSecurityToken == null || !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            {
                throw new SecurityTokenException("Invalid token");
            }
            return principal;
        }

        [HttpPost("CreateRole")]
        public async Task<ResponseMessage> CreateRole([FromQuery] string roleName)
        {
            if (!await _roleManager.RoleExistsAsync(roleName))
            {
                var roleResult = await _roleManager.CreateAsync(new IdentityRole(roleName));
                if (roleResult.Succeeded)
                {
                    response.Message = $"Role {roleName} created SuccessFully!!";
                    response.Data = roleResult;
                    response.StatusCode = HttpStatusCode.Created;
                    return response;
                }
                else
                {
                    response.Message = "Failed to create role.";
                    response.Data = roleResult;
                    response.StatusCode = HttpStatusCode.NotFound;
                    return response;
                }
            }
            else
            {
                response.Message = "Role already Exist!!.";
                response.StatusCode = HttpStatusCode.BadRequest;
                return response;
            }
        }
        [HttpPost("AssignRole")]
        public async Task<ResponseMessage> AssignRole([FromQuery] string email, [FromQuery] string role)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var assign = await _userManager.AddToRoleAsync(user, role);  // Assign Role to User...
                response.Message = "Assign Role SuccessFully to the User.";
                response.Data = assign;
                response.StatusCode = HttpStatusCode.NotFound;
                return response;
            }
            else
            {
                response.Message = "User not found!!.";
                response.StatusCode = HttpStatusCode.BadRequest;
                return response;
            }
        }
    }
}
