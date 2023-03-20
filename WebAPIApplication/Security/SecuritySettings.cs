namespace WebAPIApplication.Security
{
    public class SecuritySettings
    {
        public Jwt Jwt { get; set; }
        public GoogleAuth GoogleAuth { get; set; }
        public bool EnforceHttps { get; set; }

    }

    public class Jwt
    {
        public string SecretKey { get; set; }
        public int TokenValidityInSeconds { get; set; }
        public int TokenValidityInSecondsForRememberMe { get; set; }
        public string ValidAudiences { get; set; }
    }

    public class GoogleAuth
    {
        public string ClientId { get; set; }
        public string ClientSecret { get; set; }
    }

    public class Cors
    {
        public string AllowedOrigins { get; set; }
        public string AllowedMethods { get; set; }
        public string AllowedHeaders { get; set; }
        public string ExposedHeaders { get; set; }
        public bool AllowCredentials { get; set; }
        public int MaxAge { get; set; }
    }
}
