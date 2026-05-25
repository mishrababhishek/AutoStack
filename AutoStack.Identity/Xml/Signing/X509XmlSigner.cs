using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Security.Cryptography.Xml;
using System.Xml;

namespace AutoStack.Identity.Xml.Signing;

public sealed class X509XmlSigner : IXmlSigner
{
    private readonly X509Certificate2 _certificate;

    public X509XmlSigner(X509Certificate2 certificate)
    {
        ArgumentNullException.ThrowIfNull(certificate);

        if (!certificate.HasPrivateKey)
            throw new ArgumentException(
                "Certificate must include a private key for signing.", nameof(certificate));

        _certificate = certificate;
    }

    public Task<XmlDocument> SignAsync(XmlDocument document, XmlSignatureOptions options, CancellationToken cancellationToken = default)
    {
        cancellationToken.ThrowIfCancellationRequested();

        var workingDoc = CloneDocument(document);

        var signedXml = BuildSignedXml(workingDoc, options);

        signedXml.ComputeSignature();
        var signatureElement = signedXml.GetXml();

        InsertSignature(workingDoc, signatureElement, options.InsertionMode);

        return Task.FromResult(workingDoc);
    }

    private SignedXml BuildSignedXml(XmlDocument doc, XmlSignatureOptions options)
    {
        var signedXml = new SignedXml(doc);

        signedXml.SigningKey = ResolveSigningKey();

        if (signedXml.SignedInfo == null)
            throw new NullReferenceException("SignedInfo is null after initializing SignedXml.");

        signedXml.SignedInfo.CanonicalizationMethod = options.CanonicalizationMethod;

        signedXml.SignedInfo.SignatureMethod = options.SignatureMethod ?? InferSignatureMethod(signedXml.SigningKey);

        var reference = BuildReference(doc, options);
        signedXml.AddReference(reference);

        signedXml.KeyInfo = BuildKeyInfo(options.IncludeCertificateChain);

        return signedXml;
    }

    private static Reference BuildReference(XmlDocument doc, XmlSignatureOptions options)
    {
        string uri = options.ReferenceId is not null ? $"#{options.ReferenceId}" : string.Empty;

        var reference = new Reference(uri)
        {
            DigestMethod = options.DigestMethod
        };

        reference.AddTransform(new XmlDsigEnvelopedSignatureTransform());

        reference.AddTransform(new XmlDsigExcC14NTransform());

        return reference;
    }

    private AsymmetricAlgorithm ResolveSigningKey()
    {
        var rsa = _certificate.GetRSAPrivateKey();
        if (rsa is not null)
            return rsa;

        var ecdsa = _certificate.GetECDsaPrivateKey();
        if (ecdsa is not null)
            return ecdsa;

        throw new InvalidOperationException($"Certificate key algorithm '{_certificate.GetKeyAlgorithm()}' is not supported. " + "Supported: RSA, ECDsa.");
    }

    private static string InferSignatureMethod(AsymmetricAlgorithm key) => key switch
    {
        RSA => SignedXml.XmlDsigRSASHA256Url,
        ECDsa => "http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256",
        _ => throw new NotSupportedException($"Key type '{key.GetType().Name}' not supported.")
    };

    private KeyInfo BuildKeyInfo(bool includeChain)
    {
        var keyInfo = new KeyInfo();

        if (includeChain)
        {
            using var chain = new X509Chain();
            chain.Build(_certificate);
            var data = new KeyInfoX509Data();
            foreach (var element in chain.ChainElements)
                data.AddCertificate(element.Certificate);
            keyInfo.AddClause(data);
        }
        else
        {
            keyInfo.AddClause(new KeyInfoX509Data(_certificate));
        }

        return keyInfo;
    }

    private static void InsertSignature(XmlDocument doc, XmlElement signatureElement, SignatureInsertionMode mode)
    {
        var root = doc.DocumentElement
            ?? throw new InvalidOperationException("Document has no root element.");

        switch (mode)
        {
            case SignatureInsertionMode.AppendToRoot:
                root.AppendChild(signatureElement);
                break;

            case SignatureInsertionMode.PrependToRoot:
                root.InsertBefore(signatureElement, root.FirstChild);
                break;

            case SignatureInsertionMode.AfterFirstChild:
                var firstChild = root.FirstChild;
                if (firstChild is null)
                    root.AppendChild(signatureElement);
                else
                    root.InsertAfter(signatureElement, firstChild);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, null);
        }
    }

    private static XmlDocument CloneDocument(XmlDocument source)
    {
        var clone = new XmlDocument { PreserveWhitespace = source.PreserveWhitespace };
        clone.LoadXml(source.OuterXml);
        return clone;
    }
}