using AutoStack.Identity.Xml;
using AutoStack.Identity.Xml.Signing;
using System.Text;
using System.Xml;

namespace AutoStack.Identity.Saml;

public sealed class SamlIdpHelper
{
    private readonly SamlIdpOptions _options;
    private readonly IXmlSigner? _signer;
    private readonly TimeProvider _timeProvider;

    public SamlIdpHelper(SamlIdpOptions options, IXmlSigner? signer = null, TimeProvider? timeProvider = null)
    {
        ArgumentNullException.ThrowIfNull(options);
        _options = options;
        _signer = signer;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<XmlDocument> BuildResponseAsync(SamlResponseDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(descriptor);

        var now = descriptor.IssuedAt ?? _timeProvider.GetUtcNow();
        var responseId = NewId();
        var assertionId = NewId();

        var assertionNode = BuildAssertion(descriptor, now, assertionId).BuildNode();

        var doc = XmlBuilder
            .Create("Response", SamlConstants.Ns.Protocol)
            .WithPrefix(SamlConstants.Prefix.Protocol)
            .WithAttribute("ID", responseId)
            .WithAttribute("Version", "2.0")
            .WithAttribute("IssueInstant", now.UtcDateTime)
            .WithAttribute("Destination", descriptor.Recipient)
            .WithAttributeIf(descriptor.InResponseTo is not null, "InResponseTo", descriptor.InResponseTo!)
            .WithChild("Issuer", SamlConstants.Ns.Assertion, b => b
                .WithPrefix(SamlConstants.Prefix.Assertion)
                .WithText(_options.EntityId))
            .WithChild("Status", SamlConstants.Ns.Protocol, b => b
                .WithPrefix(SamlConstants.Prefix.Protocol)
                .WithChild("StatusCode", SamlConstants.Ns.Protocol, sc => sc
                    .WithPrefix(SamlConstants.Prefix.Protocol)
                    .WithAttribute("Value", SamlConstants.StatusCode.Success)))
            .WithChild(assertionNode)
            .BuildDocument();

        if (_signer is not null)
        {
            doc = await _signer.SignAsync(doc, new XmlSignatureOptions
            {
                ReferenceId = assertionId,
                InsertionMode = SignatureInsertionMode.AfterFirstChild
            }, cancellationToken);
        }

        return doc;
    }

    public async Task<string> BuildResponseBase64Async(SamlResponseDescriptor descriptor, CancellationToken cancellationToken = default)
    {
        var doc = await BuildResponseAsync(descriptor, cancellationToken);
        return Convert.ToBase64String(Encoding.UTF8.GetBytes(doc.OuterXml));
    }

    private XmlBuilder BuildAssertion(SamlResponseDescriptor descriptor, DateTimeOffset now, string assertionId)
    {
        var notOnOrAfter = now.Add(_options.AssertionLifetime);
        var notBefore = now.Subtract(_options.ClockSkew);
        var nameIdFormat = descriptor.NameIdFormat ?? _options.NameIdFormat;
        var authnContextRef = descriptor.AuthnContextClassRef ?? _options.AuthnContextClassRef;

        var b = XmlBuilder
            .Create("Assertion", SamlConstants.Ns.Assertion)
            .WithPrefix(SamlConstants.Prefix.Assertion)
            .WithAttribute("ID", assertionId)
            .WithAttribute("Version", "2.0")
            .WithAttribute("IssueInstant", now.UtcDateTime)
            .WithChild("Issuer", SamlConstants.Ns.Assertion, iss => iss
                .WithPrefix(SamlConstants.Prefix.Assertion)
                .WithText(_options.EntityId))
            .WithChild("Subject", SamlConstants.Ns.Assertion, subj =>
            {
                subj.WithPrefix(SamlConstants.Prefix.Assertion)
                    .WithChild("NameID", SamlConstants.Ns.Assertion, nid => nid
                        .WithPrefix(SamlConstants.Prefix.Assertion)
                        .WithAttribute("Format", nameIdFormat)
                        .WithText(descriptor.NameId))
                    .WithChild("SubjectConfirmation", SamlConstants.Ns.Assertion, sc => sc
                        .WithPrefix(SamlConstants.Prefix.Assertion)
                        .WithAttribute("Method", SamlConstants.ConfirmationMethod.Bearer)
                        .WithChild("SubjectConfirmationData", SamlConstants.Ns.Assertion, scd =>
                        {
                            scd.WithPrefix(SamlConstants.Prefix.Assertion)
                               .WithAttribute("NotOnOrAfter", notOnOrAfter.UtcDateTime)
                               .WithAttribute("Recipient", descriptor.Recipient);

                            if (descriptor.InResponseTo is not null)
                                scd.WithAttribute("InResponseTo", descriptor.InResponseTo);
                        }));
            })
            .WithChild("Conditions", SamlConstants.Ns.Assertion, cond => cond
                .WithPrefix(SamlConstants.Prefix.Assertion)
                .WithAttribute("NotBefore", notBefore.UtcDateTime)
                .WithAttribute("NotOnOrAfter", notOnOrAfter.UtcDateTime)
                .WithChild("AudienceRestriction", SamlConstants.Ns.Assertion, ar => ar
                    .WithPrefix(SamlConstants.Prefix.Assertion)
                    .WithChild("Audience", SamlConstants.Ns.Assertion, aud => aud
                        .WithPrefix(SamlConstants.Prefix.Assertion)
                        .WithText(descriptor.SpEntityId))))
            .WithChild("AuthnStatement", SamlConstants.Ns.Assertion, authn => authn
                .WithPrefix(SamlConstants.Prefix.Assertion)
                .WithAttribute("AuthnInstant", now.UtcDateTime)
                .WithAttribute("SessionIndex", descriptor.SessionIndex)
                .WithChild("AuthnContext", SamlConstants.Ns.Assertion, ctx => ctx
                    .WithPrefix(SamlConstants.Prefix.Assertion)
                    .WithChild("AuthnContextClassRef", SamlConstants.Ns.Assertion, cr => cr
                        .WithPrefix(SamlConstants.Prefix.Assertion)
                        .WithText(authnContextRef))));

        if (descriptor.Attributes.Count > 0)
            b.WithChild("AttributeStatement", SamlConstants.Ns.Assertion, attrStmt =>
            {
                attrStmt.WithPrefix(SamlConstants.Prefix.Assertion);
                foreach (var (name, values) in descriptor.Attributes)
                    attrStmt.WithChild("Attribute", SamlConstants.Ns.Assertion, attr =>
                    {
                        attr.WithPrefix(SamlConstants.Prefix.Assertion)
                            .WithAttribute("Name", name)
                            .WithAttribute("NameFormat", SamlConstants.AttributeNameFormat);

                        foreach (var val in values)
                            attr.WithChild("AttributeValue", SamlConstants.Ns.Assertion, av =>
                                av.WithPrefix(SamlConstants.Prefix.Assertion).WithText(val));
                    });
            });

        return b;
    }

    private static string NewId() => $"_{Guid.NewGuid():N}";
}


