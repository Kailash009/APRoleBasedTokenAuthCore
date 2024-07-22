using System.Net;

namespace APIRoleBasedTokenAuthCore.Models
{
    public class ResponseMessage
    {
        public string Message { get; set; }
        public object Data { get; set; }
        public HttpStatusCode StatusCode { get; set; }
    }
}
