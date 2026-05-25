using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace AutoStack.Identity.Xml.Verification.Rules;

public sealed class SignatureVerificationRule : IXmlVerificationRule
{
    public const string BagKey = "SignatureVerificationRule.SignerCertificate";

    public string RuleName => "SignatureVerification";

    public Task<VerificationResult> ExecuteAsync(XmlVerificationContext context, CancellationToken cancellationToken = default)
    {
        var signatureNodes = context.Document.GetElementsByTagName("Signature", SignedXml.XmlDsigNamespaceUrl);

        if (signatureNodes.Count == 0)
            return Task.FromResult(VerificationResult.Fail(RuleName, "Document does not contain a ds:Signature element."));

        var failures = new List<VerificationFailure>();

        foreach (XmlElement signatureNode in signatureNodes)
        {
            var result = VerifySignatureNode(context.Document, signatureNode, context);
            if (!result.IsSuccess)
                failures.AddRange(result.Failures);
        }

        return Task.FromResult(failures.Count == 0 ? VerificationResult.Success() : VerificationResult.Fail(failures.ToArray()));
    }

    private VerificationResult VerifySignatureNode(XmlDocument doc, XmlElement signatureNode, XmlVerificationContext context)
    {
        try
        {
            var signedXml = new SignedXml(doc);
            signedXml.LoadXml(signatureNode);

            var cert = ExtractCertificate(signedXml);
            if (cert is null)
                return VerificationResult.Fail(RuleName, "Could not extract certificate from ds:KeyInfo.");

            var isValid = signedXml.CheckSignature(cert, verifySignatureOnly: true);

            if (!isValid)
                return VerificationResult.Fail(RuleName, $"Signature is invalid for certificate '{cert.Subject}'.");

            context.Bag[BagKey] = cert;
            return VerificationResult.Success();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            return VerificationResult.Fail(new VerificationFailure(RuleName, $"Signature verification threw: {ex.Message}", ex));
        }
    }

    private static X509Certificate2? ExtractCertificate(SignedXml signedXml)
    {
        foreach (KeyInfoClause clause in signedXml.KeyInfo)
        {
            if (clause is KeyInfoX509Data x509Data)
            {
                if (x509Data.Certificates is not null)
                {
                    foreach (X509Certificate2 cert in x509Data.Certificates)
                        return cert;
                }
            }
        }
        return null;
    }
}

