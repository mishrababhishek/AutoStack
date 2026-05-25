using System.Text;
using System.Text.Json;

namespace AutoStack.Identity.Jwt;

public sealed class JwtIssuerHelper
{
    private readonly JwtIssuerOptions _options;
    private readonly IJwtSigner _signer;
    private readonly TimeProvider _timeProvider;

    public JwtIssuerHelper(JwtIssuerOptions options, IJwtSigner signer, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(signer);

        _options = options;
        _signer = signer;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string Issue(JwtDescriptor descriptor)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var now = descriptor.IssuedAt ?? _timeProvider.GetUtcNow();
        var expires = now.Add(_options.TokenLifetime);
        var jti = descriptor.JwtId ?? Guid.NewGuid().ToString("N");

        var headerEncoded = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(BuildHeader()));
        var payloadEncoded = Base64UrlEncode(JsonSerializer.SerializeToUtf8Bytes(BuildPayload(descriptor, now, expires, jti)));

        var signingInput = $"{headerEncoded}.{payloadEncoded}";
        var signature = _signer.Sign(Encoding.ASCII.GetBytes(signingInput));

        return $"{signingInput}.{Base64UrlEncode(signature)}";
    }

    private Dictionary<string, object> BuildHeader()
    {
        var header = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtConstants.HeaderKey.Algorithm] = _signer.Algorithm,
            [JwtConstants.HeaderKey.Type] = JwtConstants.TokenType
        };

        if (_options.KeyId is not null)
            header[JwtConstants.HeaderKey.KeyId] = _options.KeyId;

        return header;
    }

    private Dictionary<string, object> BuildPayload(JwtDescriptor descriptor, DateTimeOffset now, DateTimeOffset expires, string jti)
    {
        var payload = new Dictionary<string, object>(StringComparer.Ordinal)
        {
            [JwtConstants.ClaimType.Issuer] = _options.Issuer,
            [JwtConstants.ClaimType.Subject] = descriptor.Subject,
            [JwtConstants.ClaimType.Audience] = descriptor.Audience,
            [JwtConstants.ClaimType.IssuedAt] = now.ToUnixTimeSeconds(),
            [JwtConstants.ClaimType.ExpirationTime] = expires.ToUnixTimeSeconds(),
            [JwtConstants.ClaimType.JwtId] = jti
        };

        foreach (var (key, value) in descriptor.Claims)
            payload[key] = value;

        return payload;
    }

    internal static string Base64UrlEncode(byte[] data) => Convert.ToBase64String(data).TrimEnd('=').Replace('+', '-').Replace('/', '_');
}