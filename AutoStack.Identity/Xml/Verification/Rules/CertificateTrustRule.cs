using System.Security.Cryptography.X509Certificates;

namespace AutoStack.Identity.Xml.Verification.Rules;

public sealed class CertificateTrustRule : IXmlVerificationRule
{
    private readonly X509RevocationMode _revocationMode;

    public CertificateTrustRule(X509RevocationMode revocationMode = X509RevocationMode.Online)
    {
        _revocationMode = revocationMode;
    }

    public string RuleName => "CertificateTrust";

    public Task<VerificationResult> ExecuteAsync(XmlVerificationContext context, CancellationToken cancellationToken = default)
    {
        var cert = context.GetBagValue<X509Certificate2>(SignatureVerificationRule.BagKey);

        if (cert is null)
            return Task.FromResult(VerificationResult.Fail(RuleName, $"No certificate in context bag. Ensure '{nameof(SignatureVerificationRule)}' runs first."));

        if (context.ExpectedSignerCertificate is not null)
        {
            if (!cert.Thumbprint.Equals(context.ExpectedSignerCertificate.Thumbprint, StringComparison.OrdinalIgnoreCase))
            {
                return Task.FromResult(VerificationResult.Fail(RuleName, $"Certificate thumbprint mismatch. " + $"Expected='{context.ExpectedSignerCertificate.Thumbprint}', " + $"Actual='{cert.Thumbprint}'."));
            }

            return Task.FromResult(VerificationResult.Success());
        }

        return Task.FromResult(ValidateChain(cert, context.TrustedRoots));
    }

    private VerificationResult ValidateChain(X509Certificate2 cert, IReadOnlyList<X509Certificate2> trustedRoots)
    {
        using var chain = new X509Chain();
        chain.ChainPolicy.RevocationMode = _revocationMode;
        chain.ChainPolicy.VerificationFlags = X509VerificationFlags.NoFlag;

        if (trustedRoots.Count > 0)
        {
            chain.ChainPolicy.TrustMode = X509ChainTrustMode.CustomRootTrust;
            foreach (var root in trustedRoots)
                chain.ChainPolicy.CustomTrustStore.Add(root);
        }

        var isValid = chain.Build(cert);

        if (isValid)
            return VerificationResult.Success();

        var errors = chain.ChainStatus.Select(s => $"{s.Status}: {s.StatusInformation.Trim()}").ToList();

        return VerificationResult.Fail(RuleName, $"Certificate chain validation failed for '{cert.Subject}'. " + $"Errors: {string.Join("; ", errors)}");
    }
}