using APIRoleBasedTokenAuthCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace APIRoleBasedTokenAuthCore.Controllers
{
    [Authorize(Roles = "User")]
    [Route("api/[controller]")]
    [ApiController]
    public class UserController : ControllerBase
    {
        ResponseMessage response = new ResponseMessage();

        [HttpGet("UserData")]
        public ResponseMessage UserData()
        {
            response.Message = "Welcome to User Page!!";
            response.StatusCode = HttpStatusCode.Found;
            return response;
        }
    }
}
