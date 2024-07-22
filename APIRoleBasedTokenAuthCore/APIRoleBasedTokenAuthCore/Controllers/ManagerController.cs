using APIRoleBasedTokenAuthCore.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Net;

namespace APIRoleBasedTokenAuthCore.Controllers
{
    [Authorize(Roles = "Manager")]
    [Route("api/[controller]")]
    [ApiController]
    public class ManagerController : ControllerBase
    {
        ResponseMessage response = new ResponseMessage();
        [HttpGet("ManagerData")]
        public ResponseMessage ManagerData()
        {
            response.Message = "Welcome to Manager Page!!";
            response.StatusCode = HttpStatusCode.Found;
            return response;
        }
    }
}
