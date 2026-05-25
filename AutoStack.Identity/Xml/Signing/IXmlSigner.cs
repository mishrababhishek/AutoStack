using System.Xml;

namespace AutoStack.Identity.Xml.Signing;

public interface IXmlSigner
{
    Task<XmlDocument> SignAsync(XmlDocument document, XmlSignatureOptions options, CancellationToken cancellationToken = default);
}
