using System.Xml;

namespace AutoStack.Identity.Xml;

public sealed class XmlBuilder
{
    private readonly string _localName;
    private readonly string? _namespaceUri;
    private string? _prefix;
    private readonly Dictionary<string, XmlAttributeValue> _attributes = new(StringComparer.Ordinal);
    private readonly List<XmlElementNode> _children = [];
    private string? _textContent;

    private XmlBuilder(string localName, string? namespaceUri)
    {
        if (string.IsNullOrWhiteSpace(localName))
            throw new ArgumentException("Element name cannot be null or whitespace.", nameof(localName));

        _localName = localName;
        _namespaceUri = namespaceUri;
    }

    public static XmlBuilder Create(string localName, string? namespaceUri = null) => new(localName, namespaceUri);

    public XmlBuilder WithPrefix(string prefix)
    {
        _prefix = prefix;
        return this;
    }

    public XmlBuilder WithAttribute(string name, string value)
    {
        _attributes[name] = new XmlAttributeValue(value);
        return this;
    }

    public XmlBuilder WithAttribute(string name, string value, string namespaceUri, string prefix)
    {
        _attributes[name] = new XmlAttributeValue(value, namespaceUri, prefix);
        return this;
    }

    public XmlBuilder WithAttribute(string name, DateTime value) => WithAttribute(name, value.ToUniversalTime().ToString("o"));

    public XmlBuilder WithAttribute(string name, bool value) => WithAttribute(name, value ? "true" : "false");

    public XmlBuilder WithAttributeIf(bool condition, string name, string value) => condition ? WithAttribute(name, value) : this;

    public XmlBuilder WithText(string text)
    {
        _textContent = text;
        return this;
    }

    public XmlBuilder WithChild(string localName, string? namespaceUri, Action<XmlBuilder> configure)
    {
        var child = new XmlBuilder(localName, namespaceUri);
        configure(child);
        _children.Add(child.BuildNode());
        return this;
    }

    public XmlBuilder WithChild(string localName, Action<XmlBuilder> configure) => WithChild(localName, null, configure);

    public XmlBuilder WithChildIf(bool condition, string localName, string? namespaceUri, Action<XmlBuilder> configure) => condition ? WithChild(localName, namespaceUri, configure) : this;

    public XmlBuilder WithChild(XmlElementNode node)
    {
        _children.Add(node);
        return this;
    }

    public XmlBuilder WithChildren(IEnumerable<XmlElementNode> nodes)
    {
        _children.AddRange(nodes);
        return this;
    }

    public XmlElementNode BuildNode() => new(_localName, _namespaceUri, _prefix, new Dictionary<string, XmlAttributeValue>(_attributes), new List<XmlElementNode>(_children), _textContent);

    public XmlDocument BuildDocument()
    {
        var doc = new XmlDocument { PreserveWhitespace = false };
        var root = BuildNode();
        var element = CreateElement(doc, root);
        doc.AppendChild(element);
        return doc;
    }

    public string BuildString(bool indent = false)
    {
        var doc = BuildDocument();
        using var sw = new System.IO.StringWriter();
        var settings = new XmlWriterSettings
        {
            Indent = indent,
            OmitXmlDeclaration = false,
            Encoding = System.Text.Encoding.UTF8
        };
        using var xw = XmlWriter.Create(sw, settings);
        doc.Save(xw);
        return sw.ToString();
    }

    internal static XmlElement CreateElement(XmlDocument doc, XmlElementNode node)
    {
        XmlElement element = (node.NamespaceUri, node.Prefix) switch
        {
            (not null, not null) => doc.CreateElement(node.Prefix, node.LocalName, node.NamespaceUri),
            (not null, null) => doc.CreateElement(node.LocalName, node.NamespaceUri),
            _ => doc.CreateElement(node.LocalName)
        };

        foreach (var (attrName, attrVal) in node.Attributes)
        {
            XmlAttribute attr = (attrVal.NamespaceUri, attrVal.Prefix) switch
            {
                (not null, not null) => doc.CreateAttribute(attrVal.Prefix, attrName, attrVal.NamespaceUri),
                _ => doc.CreateAttribute(attrName)
            };
            attr.Value = attrVal.Value;
            element.Attributes.Append(attr);
        }

        if (node.TextContent is not null)
        {
            element.AppendChild(doc.CreateTextNode(node.TextContent));
        }
        else
        {
            foreach (var child in node.Children)
                element.AppendChild(CreateElement(doc, child));
        }

        return element;
    }
}
