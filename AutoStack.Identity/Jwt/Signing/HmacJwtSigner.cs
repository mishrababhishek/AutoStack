using System.Security.Cryptography;
using System.Text;

namespace AutoStack.Identity.Jwt.Signing;

public sealed class HmacJwtSigner : IJwtSigner, IJwtVerifier, IDisposable
{
    private readonly HMAC _hmac;
    private bool _disposed;

    public string Algorithm { get; }

    public HmacJwtSigner(byte[] secret, string algorithm = JwtConstants.Algorithm.HS256)
    {
        ArgumentNullException.ThrowIfNull(secret);
        if (secret.Length == 0)
            throw new ArgumentException("Secret must not be empty.", nameof(secret));

        (Algorithm, _hmac) = algorithm switch
        {
            JwtConstants.Algorithm.HS256 => (algorithm, (HMAC)new HMACSHA256(secret)),
            JwtConstants.Algorithm.HS384 => (algorithm, new HMACSHA384(secret)),
            JwtConstants.Algorithm.HS512 => (algorithm, new HMACSHA512(secret)),
            _ => throw new ArgumentException($"Unsupported HMAC algorithm '{algorithm}'.", nameof(algorithm))
        };
    }

    public static HmacJwtSigner FromString(string secret, string algorithm = JwtConstants.Algorithm.HS256)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(secret);
        return new HmacJwtSigner(Encoding.UTF8.GetBytes(secret), algorithm);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _hmac.ComputeHash(data);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        var expected = _hmac.ComputeHash(data);
        return CryptographicOperations.FixedTimeEquals(expected, signature);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _hmac.Dispose();
        _disposed = true;
    }
}