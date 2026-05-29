using AutoStack.Identity.Xml.Signing;

namespace AutoStack.Identity.Saml;

public sealed record SamlSpOptions
{
    public required string EntityId { get; init; }

    public required string AssertionConsumerServiceUrl { get; init; }

    public string NameIdFormat { get; init; } = SamlConstants.NameIdFormat.EmailAddress;

    public bool AllowCreate { get; init; } = true;

    public bool ForceAuthn { get; init; } = false;

    public string? RequestedAuthnContextClassRef { get; init; }
    public IXmlSigner? Signer { get; init; }
}

public sealed record SamlIdpOptions
{
    public required string EntityId { get; init; }

    public TimeSpan AssertionLifetime { get; init; } = TimeSpan.FromMinutes(5);

    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    public string NameIdFormat { get; init; } = SamlConstants.NameIdFormat.EmailAddress;

    public string AuthnContextClassRef { get; init; } = SamlConstants.AuthnContextClassRef.PasswordProtectedTransport;
}
