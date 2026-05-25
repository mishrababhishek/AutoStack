namespace AutoStack.Identity.Jwt;

internal static class JwtConstants
{
    internal static class Algorithm
    {
        public const string RS256 = "RS256";
        public const string RS384 = "RS384";
        public const string RS512 = "RS512";
        public const string ES256 = "ES256";
        public const string ES384 = "ES384";
        public const string ES512 = "ES512";
        public const string HS256 = "HS256";
        public const string HS384 = "HS384";
        public const string HS512 = "HS512";
    }

    internal static class HeaderKey
    {
        public const string Algorithm = "alg";
        public const string Type = "typ";
        public const string KeyId = "kid";
    }

    internal static class ClaimType
    {
        public const string Issuer = "iss";
        public const string Subject = "sub";
        public const string Audience = "aud";
        public const string ExpirationTime = "exp";
        public const string NotBefore = "nbf";
        public const string IssuedAt = "iat";
        public const string JwtId = "jti";
    }

    internal const string TokenType = "JWT";
}