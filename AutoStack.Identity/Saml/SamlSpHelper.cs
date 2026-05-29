using AutoStack.Identity.Xml;
using AutoStack.Identity.Xml.Signing;
using System.Globalization;
using System.Text;
using System.Xml;

namespace AutoStack.Identity.Saml;

public sealed class SamlSpHelper
{
    private static readonly ISamlSpProvider _noopProvider = new NoopProvider();

    private readonly SamlSpOptions _options;
    private readonly ISamlSpProvider _provider;
    private readonly TimeProvider _timeProvider;

    public SamlSpHelper(SamlSpOptions options, ISamlSpProvider? provider = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _provider = provider ?? _noopProvider;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<SamlAuthnRequest> BuildAuthnRequest(string destination, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(destination);

        var requestId = NewId();
        var issuedAt = _timeProvider.GetUtcNow();

        var builder = XmlBuilder
            .Create("AuthnRequest", SamlConstants.Ns.Protocol)
            .WithPrefix(SamlConstants.Prefix.Protocol)
            .WithAttribute("ID", requestId)
            .WithAttribute("Version", "2.0")
            .WithAttribute("IssueInstant", issuedAt.UtcDateTime)
            .WithAttribute("Destination", destination)
            .WithAttribute("AssertionConsumerServiceURL", _options.AssertionConsumerServiceUrl)
            .WithAttributeIf(_options.ForceAuthn, "ForceAuthn", "true")
            .WithChild("Issuer", SamlConstants.Ns.Assertion, b => b
                .WithPrefix(SamlConstants.Prefix.Assertion)
                .WithText(_options.EntityId))
            .WithChild("NameIDPolicy", SamlConstants.Ns.Protocol, b => b
                .WithPrefix(SamlConstants.Prefix.Protocol)
                .WithAttribute("Format", _options.NameIdFormat)
                .WithAttribute("AllowCreate", _options.AllowCreate));

        if (_options.RequestedAuthnContextClassRef is not null)
            builder.WithChild("RequestedAuthnContext", SamlConstants.Ns.Protocol, b => b
                .WithPrefix(SamlConstants.Prefix.Protocol)
                .WithAttribute("Comparison", "exact")
                .WithChild("AuthnContextClassRef", SamlConstants.Ns.Assertion, cr => cr
                    .WithPrefix(SamlConstants.Prefix.Assertion)
                    .WithText(_options.RequestedAuthnContextClassRef)));

        var doc = builder.BuildDocument();

        if (_options.Signer is not null)
        {
            var signatureOptions = new XmlSignatureOptions
            {
                ReferenceId = requestId,
                InsertionMode = SignatureInsertionMode.AfterFirstChild
            };

            doc = await _options.Signer.SignAsync(doc, signatureOptions, cancellationToken);
        }

        var xml = doc.OuterXml;

        return new SamlAuthnRequest
        {
            RequestId = requestId,
            Xml = xml,
            Base64Encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(xml)),
            IssuedAt = issuedAt
        };
    }

    public SamlResponsePayload ParseResponse(string base64Response)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(base64Response);

        string xml;
        try
        {
            xml = Encoding.UTF8.GetString(Convert.FromBase64String(base64Response));
        }
        catch (Exception ex)
        {
            throw new SamlException("SAMLResponse is not valid base64.", ex);
        }

        var doc = new XmlDocument { PreserveWhitespace = true };
        try { doc.LoadXml(xml); }
        catch (XmlException ex) { throw new SamlException("SAMLResponse contains invalid XML.", ex); }

        return ParseResponse(doc);
    }

    public SamlResponsePayload ParseResponse(XmlDocument document)
    {
        ArgumentNullException.ThrowIfNull(document);

        var ns = BuildNamespaceManager(document);

        var root = document.DocumentElement ?? throw new SamlException("Response document is empty.");

        if (root.LocalName != "Response" || root.NamespaceURI != SamlConstants.Ns.Protocol)
            throw new SamlException($"Expected samlp:Response but found '{root.NamespaceURI}:{root.LocalName}'.");

        var responseId = root.GetAttribute("ID");
        var inResponseTo = NullIfEmpty(root.GetAttribute("InResponseTo"));

        var statusCode = NullIfEmpty((document.SelectSingleNode("//samlp:StatusCode/@Value", ns) as XmlAttribute)?.Value) ?? throw new SamlException("Response is missing samlp:StatusCode/@Value.");

        var statusMessage = NullIfEmpty((document.SelectSingleNode("//samlp:StatusMessage", ns) as XmlElement)?.InnerText);

        string? nameId = null, nameIdFormat = null, sessionIndex = null;
        DateTimeOffset? notBefore = null, notOnOrAfter = null;
        var attributes = new Dictionary<string, List<string>>(StringComparer.Ordinal);

        if (statusCode == SamlConstants.StatusCode.Success)
        {
            nameId = NullIfEmpty((document.SelectSingleNode("//saml:NameID", ns) as XmlElement)?.InnerText);

            nameIdFormat = NullIfEmpty((document.SelectSingleNode("//saml:NameID/@Format", ns) as XmlAttribute)?.Value);

            sessionIndex = NullIfEmpty((document.SelectSingleNode("//saml:AuthnStatement/@SessionIndex", ns) as XmlAttribute)?.Value);

            var conditionsEl = document.SelectSingleNode("//saml:Conditions", ns) as XmlElement;
            if (conditionsEl is not null)
            {
                notBefore = ParseDateTimeOffset(conditionsEl.GetAttribute("NotBefore"));
                notOnOrAfter = ParseDateTimeOffset(conditionsEl.GetAttribute("NotOnOrAfter"));
            }

            var attrNodes = document.SelectNodes("//saml:Attribute", ns);
            if (attrNodes is not null)
            {
                foreach (XmlElement attr in attrNodes)
                {
                    var rawName = attr.GetAttribute("Name");
                    if (string.IsNullOrWhiteSpace(rawName)) continue;

                    var key = _provider.NormalizeAttributeName(rawName);
                    if (!attributes.TryGetValue(key, out var list))
                        attributes[key] = list = [];

                    foreach (XmlElement valueEl in attr.ChildNodes.OfType<XmlElement>())
                    {
                        var v = valueEl.InnerText;
                        if (!string.IsNullOrEmpty(v)) list.Add(v);
                    }
                }
            }
        }

        var payload = new SamlResponsePayload
        {
            ResponseId = responseId,
            InResponseTo = inResponseTo,
            StatusCode = statusCode,
            StatusMessage = statusMessage,
            NameId = nameId,
            NameIdFormat = nameIdFormat,
            SessionIndex = sessionIndex,
            NotBefore = notBefore,
            NotOnOrAfter = notOnOrAfter,
            Attributes = attributes.ToDictionary(kv => kv.Key, kv => (IReadOnlyList<string>)kv.Value.AsReadOnly(), StringComparer.Ordinal)
        };

        _provider.OnResponseParsed(payload);
        return payload;
    }


    private static XmlNamespaceManager BuildNamespaceManager(XmlDocument doc)
    {
        var ns = new XmlNamespaceManager(doc.NameTable);
        ns.AddNamespace("samlp", SamlConstants.Ns.Protocol);
        ns.AddNamespace("saml2p", SamlConstants.Ns.Protocol);
        ns.AddNamespace("saml", SamlConstants.Ns.Assertion);
        ns.AddNamespace("saml2", SamlConstants.Ns.Assertion);
        return ns;
    }

    private static string? NullIfEmpty(string? s) => string.IsNullOrEmpty(s) ? null : s;

    private static DateTimeOffset? ParseDateTimeOffset(string? raw)
    {
        if (string.IsNullOrEmpty(raw)) return null;
        return DateTimeOffset.TryParse(raw, null, DateTimeStyles.RoundtripKind, out var dt) ? dt : null;
    }

    private static string NewId() => $"_{Guid.NewGuid():N}";

    private sealed class NoopProvider : ISamlSpProvider { }
}


