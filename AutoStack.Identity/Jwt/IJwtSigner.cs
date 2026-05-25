namespace AutoStack.Identity.Jwt;

public interface IJwtSigner
{
    string Algorithm { get; }

    byte[] Sign(byte[] data);
}

public interface IJwtVerifier
{
    bool Verify(byte[] data, byte[] signature);
}

