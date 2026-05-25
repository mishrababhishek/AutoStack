using System.Security.Cryptography.Xml;

namespace AutoStack.Identity.Xml.Signing;

public sealed record XmlSignatureOptions
{
    public string? ReferenceId { get; init; }
    public string CanonicalizationMethod { get; init; } = SignedXml.XmlDsigExcC14NTransformUrl;
    public string DigestMethod { get; init; } = SignedXml.XmlDsigSHA256Url;

    public string? SignatureMethod { get; init; }
    public bool IncludeCertificateChain { get; init; } = false;
    public SignatureInsertionMode InsertionMode { get; init; } = SignatureInsertionMode.AppendToRoot;
}

public enum SignatureInsertionMode
{
    AppendToRoot,
    AfterFirstChild,
    PrependToRoot
}
