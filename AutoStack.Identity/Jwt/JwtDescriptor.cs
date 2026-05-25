namespace AutoStack.Identity.Jwt;

public sealed record JwtDescriptor
{
    public required string Subject { get; init; }

    public required string Audience { get; init; }

    public IReadOnlyDictionary<string, object> Claims { get; init; } = new Dictionary<string, object>();

    public DateTimeOffset? IssuedAt { get; init; }

    public string? JwtId { get; init; }
}

public sealed record JwtPayload
{
    public required string Issuer { get; init; }

    public string? Subject { get; init; }

    public IReadOnlyList<string> Audiences { get; init; } = Array.Empty<string>();

    public DateTimeOffset IssuedAt { get; init; }

    public DateTimeOffset? ExpiresAt { get; init; }

    public DateTimeOffset? NotBefore { get; init; }

    public string? JwtId { get; init; }

    public IReadOnlyDictionary<string, System.Text.Json.JsonElement> Claims { get; init; } = new Dictionary<string, System.Text.Json.JsonElement>();
}