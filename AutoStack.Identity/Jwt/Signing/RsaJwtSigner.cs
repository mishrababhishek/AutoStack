using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoStack.Identity.Jwt.Signing;

public sealed class RsaJwtSigner : IJwtSigner, IJwtVerifier, IDisposable
{
    private readonly RSA _rsa;
    private readonly HashAlgorithmName _hashAlgorithm;
    private readonly RSASignaturePadding _padding;
    private bool _disposed;

    public string Algorithm { get; }

    public RsaJwtSigner(RSA rsa, string algorithm = JwtConstants.Algorithm.RS256)
    {
        ArgumentNullException.ThrowIfNull(rsa);

        _rsa = rsa;
        (Algorithm, _hashAlgorithm, _padding) = algorithm switch
        {
            JwtConstants.Algorithm.RS256 => (algorithm, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1),
            JwtConstants.Algorithm.RS384 => (algorithm, HashAlgorithmName.SHA384, RSASignaturePadding.Pkcs1),
            JwtConstants.Algorithm.RS512 => (algorithm, HashAlgorithmName.SHA512, RSASignaturePadding.Pkcs1),
            _ => throw new ArgumentException($"Unsupported RSA algorithm '{algorithm}'.", nameof(algorithm))
        };
    }

    public static RsaJwtSigner FromCertificate(X509Certificate2 certificate, string algorithm = JwtConstants.Algorithm.RS256)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var rsa = certificate.GetRSAPrivateKey() ?? throw new ArgumentException("Certificate does not have an RSA private key.", nameof(certificate));

        return new RsaJwtSigner(rsa, algorithm);
    }

    public static RsaJwtSigner ForVerification(X509Certificate2 certificate, string algorithm = JwtConstants.Algorithm.RS256)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var rsa = certificate.GetRSAPublicKey() ?? throw new ArgumentException("Certificate does not have an RSA public key.", nameof(certificate));

        return new RsaJwtSigner(rsa, algorithm);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _rsa.SignData(data, _hashAlgorithm, _padding);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _rsa.VerifyData(data, signature, _hashAlgorithm, _padding);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _rsa.Dispose();
        _disposed = true;
    }
}