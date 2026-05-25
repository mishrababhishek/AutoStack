using System.Security.Cryptography.X509Certificates;
using System.Xml;

namespace AutoStack.Identity.Xml.Verification;

public sealed class XmlVerificationContext
{
    public required XmlDocument Document { get; init; }

    public IReadOnlyList<X509Certificate2> TrustedRoots { get; init; } = Array.Empty<X509Certificate2>();

    public X509Certificate2? ExpectedSignerCertificate { get; init; }

    public string? SignedElementId { get; init; }

    public Dictionary<string, object> Bag { get; } = new(StringComparer.Ordinal);

    public T? GetBagValue<T>(string key) where T : class => Bag.TryGetValue(key, out var val) ? val as T : null;
}

