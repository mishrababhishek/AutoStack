using System.Security.Cryptography.X509Certificates;

namespace AutoStack.Identity.Xml.Verification.Rules;

public sealed class CertificateExpiryRule : IXmlVerificationRule
{
    private readonly TimeProvider _timeProvider;
    public CertificateExpiryRule(TimeProvider? timeProvider = null)
    {
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public string RuleName => "CertificateExpiry";

    public Task<VerificationResult> ExecuteAsync(XmlVerificationContext context, CancellationToken cancellationToken = default)
    {
        var cert = context.GetBagValue<X509Certificate2>(SignatureVerificationRule.BagKey);

        if (cert is null)
            return Task.FromResult(VerificationResult.Fail(RuleName,
                $"No certificate in context bag. Ensure '{nameof(SignatureVerificationRule)}' runs first."));

        var now = _timeProvider.GetUtcNow().UtcDateTime;

        if (now < cert.NotBefore)
            return Task.FromResult(VerificationResult.Fail(RuleName,
                $"Certificate '{cert.Subject}' is not yet valid. NotBefore={cert.NotBefore:o}, Now={now:o}"));

        if (now > cert.NotAfter)
            return Task.FromResult(VerificationResult.Fail(RuleName,
                $"Certificate '{cert.Subject}' has expired. NotAfter={cert.NotAfter:o}, Now={now:o}"));

        return Task.FromResult(VerificationResult.Success());
    }
}


