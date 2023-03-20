using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Principal;
using System.Text;

namespace WebAPIApplication.Security
{
    public interface ITokenProvider
    {
        string CreateToken(IPrincipal principal, bool rememberMe, string audience=null);
        bool IsTokenFromTrustedAudience(HttpContext HttpContext);

    }

    public class TokenProvider : ITokenProvider
    {
        private const string AuthoritiesKey = "auth";

        private readonly SecuritySettings _securitySettings;

        private readonly JwtSecurityTokenHandler _jwtSecurityTokenHandler;

        private readonly ILogger<TokenProvider> _log;

        private SigningCredentials _key;

        private long _tokenValidityInSeconds;

        private long _tokenValidityInSecondsForRememberMe;


        public TokenProvider(ILogger<TokenProvider> log, IOptions<SecuritySettings> securitySettings)
        {
            _log = log;
            _securitySettings = securitySettings.Value;
            _jwtSecurityTokenHandler = new JwtSecurityTokenHandler();
            Init();
        }

        public string CreateToken(IPrincipal principal, bool rememberMe, string? audience=null)
        {
            var subject = CreateSubject(principal);
            var validity =
                DateTime.UtcNow.AddSeconds(rememberMe
                    ? _tokenValidityInSecondsForRememberMe
                    : _tokenValidityInSeconds);

            var tokenDescriptor = new SecurityTokenDescriptor
            {

                Subject = subject,  //ClaimIdentity
                Expires = validity,
                SigningCredentials = _key,
                Audience= audience
            };

            var token = _jwtSecurityTokenHandler.CreateToken(tokenDescriptor);
            return _jwtSecurityTokenHandler.WriteToken(token);
        }

        private void Init()
        {
            byte[] keyBytes = Encoding.UTF8.GetBytes(_securitySettings.Jwt.SecretKey);

            _key = new SigningCredentials(new SymmetricSecurityKey(keyBytes), SecurityAlgorithms.HmacSha256);
            _tokenValidityInSeconds = _securitySettings.Jwt.TokenValidityInSeconds;
            _tokenValidityInSecondsForRememberMe = _securitySettings.Jwt.TokenValidityInSecondsForRememberMe;
        }

        private static ClaimsIdentity CreateSubject(IPrincipal principal)
        {
            ClaimsIdentity claimsIdentity = new ClaimsIdentity();
            var username = principal.Identity?.Name;

            if (!string.IsNullOrEmpty(username))
            {
                claimsIdentity.AddClaim(new Claim(JwtRegisteredClaimNames.Sub, username));
            }

            var roles = GetRoles(principal);
            if (roles.Any())
            {
                foreach (var role in roles)
                {
                    claimsIdentity.AddClaim(role);
                }
            }
            return claimsIdentity;
        }

        private static IEnumerable<Claim> GetRoles(IPrincipal principal)
        {
            return principal is ClaimsPrincipal user
                ? user.FindAll(it => it.Type == ClaimTypes.Role)
                : Enumerable.Empty<Claim>();
        }

        public static IEnumerable<Claim> GetAllClaimsFromToken(HttpContext HttpContext)
        {
            try
            {
                var accessToken = HttpContext.Request.Headers["Authorization"].ToString()?.Split(' ').Last();

                var jwt = new JwtSecurityTokenHandler().ReadJwtToken(accessToken);

                return jwt.Claims;
            }
            catch (Exception e)
            {
                throw e;
                //claims = null;
            }
        }

        public bool IsTokenFromTrustedAudience(HttpContext HttpContext)
        {
            string authHeader = HttpContext.Request.Headers["Authorization"];
            string token = authHeader.Split(' ').Last();

            // Decode the JWT token to get the payload
            var handler = new JwtSecurityTokenHandler();
            var jwtToken = handler.ReadJwtToken(token);

            // Get the "aud" claim value from the payload
            var audience = jwtToken.Payload["aud"].ToString().Split(';').ToList();

           // bool areEqual = audience.SequenceEqual(_securitySettings.Jwt.ValidAudiences.Split(';').ToList()); use this if token is returned from google

            if (audience.Contains(HttpContext.Request.Host.Value))  //
            {
                return true;
            }
            else
            {
                return false;
            }
        }
    }
}
