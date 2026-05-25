namespace AutoStack.Identity.Jwt;

public interface IJwtClaimsTransformer
{
    string NormalizeClaimName(string rawName) => rawName;

    void OnTokenValidated(JwtPayload payload) { }
}