using System.Text;
using System.Text.Json;

namespace AutoStack.Identity.Jwt;

public sealed class JwtValidationHelper
{
    private static readonly IJwtClaimsTransformer _noopTransformer = new NoopTransformer();

    private readonly JwtValidationOptions _options;
    private readonly IJwtVerifier _verifier;
    private readonly IJwtClaimsTransformer _transformer;
    private readonly TimeProvider _timeProvider;

    public JwtValidationHelper(JwtValidationOptions options, IJwtVerifier verifier, IJwtClaimsTransformer? transformer = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(verifier);

        _options = options;
        _verifier = verifier;
        _transformer = transformer ?? _noopTransformer;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public JwtPayload Validate(string token)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(token);

        var parts = token.Split('.');
        if (parts.Length != 3)
            throw new JwtException("Token must have exactly three dot-separated parts.");

        byte[] payloadBytes;
        byte[] signatureBytes;

        try { payloadBytes = Base64UrlDecode(parts[1]); }
        catch (Exception ex) { throw new JwtException("Token payload is not valid base64url.", ex); }

        try { signatureBytes = Base64UrlDecode(parts[2]); }
        catch (Exception ex) { throw new JwtException("Token signature is not valid base64url.", ex); }

        var signingInput = Encoding.ASCII.GetBytes($"{parts[0]}.{parts[1]}");

        if (!_verifier.Verify(signingInput, signatureBytes))
            throw new JwtException("Token signature is invalid.");

        JsonDocument payloadDoc;
        try { payloadDoc = JsonDocument.Parse(payloadBytes); }
        catch (JsonException ex) { throw new JwtException("Token payload is not valid JSON.", ex); }

        using (payloadDoc)
        {
            return ValidateClaims(payloadDoc.RootElement);
        }
    }

    private JwtPayload ValidateClaims(JsonElement root)
    {
        var issuer = GetString(root, JwtConstants.ClaimType.Issuer);
        var subject = GetString(root, JwtConstants.ClaimType.Subject);
        var jti = GetString(root, JwtConstants.ClaimType.JwtId);
        var audiences = ReadAudiences(root);
        var iat = GetUnixTime(root, JwtConstants.ClaimType.IssuedAt) ?? DateTimeOffset.MinValue;
        var exp = GetUnixTime(root, JwtConstants.ClaimType.ExpirationTime);
        var nbf = GetUnixTime(root, JwtConstants.ClaimType.NotBefore);

        var now = _timeProvider.GetUtcNow();

        if (_options.ValidateIssuer)
        {
            if (!string.Equals(issuer, _options.ValidIssuer, StringComparison.Ordinal)) throw new JwtException($"Token issuer '{issuer}' does not match expected '{_options.ValidIssuer}'.");
        }

        if (_options.ValidateAudience)
        {
            if (!audiences.Any(a => _options.ValidAudiences.Contains(a, StringComparer.Ordinal))) throw new JwtException($"Token audience '{string.Join(", ", audiences)}' is not in the list of valid audiences.");
        }

        if (_options.ValidateLifetime)
        {
            if (exp is not null && now > exp.Value.Add(_options.ClockSkew))
                throw new JwtException($"Token has expired. Expiration={exp.Value:o}, Now={now:o}.");

            if (nbf is not null && now < nbf.Value.Subtract(_options.ClockSkew))
                throw new JwtException($"Token is not yet valid. NotBefore={nbf.Value:o}, Now={now:o}.");
        }

        var extraClaims = root.EnumerateObject().Where(p => !IsRegisteredClaim(p.Name)).ToDictionary(p => _transformer.NormalizeClaimName(p.Name), p => p.Value.Clone(), StringComparer.Ordinal);

        var payload = new JwtPayload
        {
            Issuer = issuer ?? string.Empty,
            Subject = subject,
            Audiences = audiences,
            IssuedAt = iat,
            ExpiresAt = exp,
            NotBefore = nbf,
            JwtId = jti,
            Claims = extraClaims
        };

        _transformer.OnTokenValidated(payload);
        return payload;
    }

    private static IReadOnlyList<string> ReadAudiences(JsonElement root)
    {
        if (!root.TryGetProperty(JwtConstants.ClaimType.Audience, out var audEl)) return Array.Empty<string>();

        if (audEl.ValueKind == JsonValueKind.Array) return audEl.EnumerateArray().Where(a => a.ValueKind == JsonValueKind.String).Select(a => a.GetString()!).ToList().AsReadOnly();

        if (audEl.ValueKind == JsonValueKind.String)
            return new[] { audEl.GetString()! };

        return Array.Empty<string>();
    }

    private static bool IsRegisteredClaim(string name) => name is JwtConstants.ClaimType.Issuer or JwtConstants.ClaimType.Subject or JwtConstants.ClaimType.Audience or JwtConstants.ClaimType.ExpirationTime or JwtConstants.ClaimType.NotBefore or JwtConstants.ClaimType.IssuedAt or JwtConstants.ClaimType.JwtId;

    private static string? GetString(JsonElement root, string key) => root.TryGetProperty(key, out var el) && el.ValueKind == JsonValueKind.String ? el.GetString() : null;

    private static DateTimeOffset? GetUnixTime(JsonElement root, string key)
    {
        if (!root.TryGetProperty(key, out var el)) return null;
        if (el.TryGetInt64(out var seconds)) return DateTimeOffset.FromUnixTimeSeconds(seconds);
        return null;
    }

    internal static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        padded = (padded.Length % 4) switch
        {
            2 => padded + "==",
            3 => padded + "=",
            _ => padded
        };
        return Convert.FromBase64String(padded);
    }

    private sealed class NoopTransformer : IJwtClaimsTransformer { }
}



