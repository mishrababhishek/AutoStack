using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

namespace AutoStack.Identity.Jwt.Signing;

public sealed class EcdsaJwtSigner : IJwtSigner, IJwtVerifier, IDisposable
{
    private readonly ECDsa _ecdsa;
    private readonly HashAlgorithmName _hashAlgorithm;
    private bool _disposed;

    public string Algorithm { get; }

    public EcdsaJwtSigner(ECDsa ecdsa, string algorithm = JwtConstants.Algorithm.ES256)
    {
        ArgumentNullException.ThrowIfNull(ecdsa);

        _ecdsa = ecdsa;
        (Algorithm, _hashAlgorithm) = algorithm switch
        {
            JwtConstants.Algorithm.ES256 => (algorithm, HashAlgorithmName.SHA256),
            JwtConstants.Algorithm.ES384 => (algorithm, HashAlgorithmName.SHA384),
            JwtConstants.Algorithm.ES512 => (algorithm, HashAlgorithmName.SHA512),
            _ => throw new ArgumentException($"Unsupported ECDSA algorithm '{algorithm}'.", nameof(algorithm))
        };
    }

    public static EcdsaJwtSigner FromCertificate(X509Certificate2 certificate, string algorithm = JwtConstants.Algorithm.ES256)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var ecdsa = certificate.GetECDsaPrivateKey() ?? throw new ArgumentException("Certificate does not have an ECDsa private key.", nameof(certificate));

        return new EcdsaJwtSigner(ecdsa, algorithm);
    }

    public static EcdsaJwtSigner ForVerification(X509Certificate2 certificate, string algorithm = JwtConstants.Algorithm.ES256)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        var ecdsa = certificate.GetECDsaPublicKey() ?? throw new ArgumentException("Certificate does not have an ECDsa public key.", nameof(certificate));

        return new EcdsaJwtSigner(ecdsa, algorithm);
    }

    public byte[] Sign(byte[] data)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ecdsa.SignData(data, _hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public bool Verify(byte[] data, byte[] signature)
    {
        ObjectDisposedException.ThrowIf(_disposed, this);
        return _ecdsa.VerifyData(data, signature, _hashAlgorithm, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
    }

    public void Dispose()
    {
        if (_disposed) return;
        _ecdsa.Dispose();
        _disposed = true;
    }
}