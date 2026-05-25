using System.Collections.ObjectModel;

namespace AutoStack.Identity.Xml;

public sealed class XmlElementNode
{
    public string LocalName { get; }
    public string? NamespaceUri { get; }
    public string? Prefix { get; }

    public ReadOnlyDictionary<string, XmlAttributeValue> Attributes { get; }
    public ReadOnlyCollection<XmlElementNode> Children { get; }
    public string? TextContent { get; }

    internal XmlElementNode(string localName, string? namespaceUri, string? prefix, Dictionary<string, XmlAttributeValue> attributes, List<XmlElementNode> children, string? textContent)
    {
        if (string.IsNullOrWhiteSpace(localName))
            throw new ArgumentException("Element local name cannot be empty.", nameof(localName));

        LocalName = localName;
        NamespaceUri = namespaceUri;
        Prefix = prefix;
        Attributes = new ReadOnlyDictionary<string, XmlAttributeValue>(attributes);
        Children = new ReadOnlyCollection<XmlElementNode>(children);
        TextContent = textContent;
    }
}

public sealed record XmlAttributeValue(string Value, string? NamespaceUri = null, string? Prefix = null);
