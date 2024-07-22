using APIRoleBasedTokenAuthCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace APIRoleBasedTokenAuthCore.Controllers
{
    [Authorize(Roles = "Admin")]
    [Authorize(Policy = "AdminOnly")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        ResponseMessage response = new ResponseMessage();

        [HttpGet("AdminData")]
        public ResponseMessage AdminData()
        {
            response.Message = "Welcome to Admin Page!!";
            response.StatusCode =HttpStatusCode.Found;
            return response;
        }
    }
}
