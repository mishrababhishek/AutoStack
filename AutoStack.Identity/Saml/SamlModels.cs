namespace AutoStack.Identity.Saml;

public sealed record SamlAuthnRequest
{
    public required string RequestId { get; init; }

    public required string Xml { get; init; }

    public required string Base64Encoded { get; init; }

    public required DateTimeOffset IssuedAt { get; init; }
}

public sealed record SamlResponsePayload
{
    public required string ResponseId { get; init; }

    public string? InResponseTo { get; init; }

    public required string StatusCode { get; init; }

    public string? StatusMessage { get; init; }

    public bool IsSuccess => StatusCode == SamlConstants.StatusCode.Success;

    public string? NameId { get; init; }

    public string? NameIdFormat { get; init; }

    public string? SessionIndex { get; init; }

    public DateTimeOffset? NotBefore { get; init; }

    public DateTimeOffset? NotOnOrAfter { get; init; }

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Attributes { get; init; } = new Dictionary<string, IReadOnlyList<string>>();
}

public sealed record SamlResponseDescriptor
{
    public required string SpEntityId { get; init; }

    public required string Recipient { get; init; }

    public string? InResponseTo { get; init; }

    public required string NameId { get; init; }

    public string? NameIdFormat { get; init; }

    public string? AuthnContextClassRef { get; init; }

    public string SessionIndex { get; init; } = $"_{Guid.NewGuid():N}";

    public IReadOnlyDictionary<string, IReadOnlyList<string>> Attributes { get; init; } = new Dictionary<string, IReadOnlyList<string>>();

    public DateTimeOffset? IssuedAt { get; init; }
}

public sealed class SamlException : Exception
{
    public SamlException(string message) : base(message) { }
    public SamlException(string message, Exception inner) : base(message, inner) { }
}



