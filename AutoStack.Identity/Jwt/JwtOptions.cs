namespace AutoStack.Identity.Jwt;

public sealed record JwtIssuerOptions
{
    public required string Issuer { get; init; }

    public TimeSpan TokenLifetime { get; init; } = TimeSpan.FromHours(1);

    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    public string? KeyId { get; init; }
}

public sealed record JwtValidationOptions
{
    public required string ValidIssuer { get; init; }

    public required IReadOnlyList<string> ValidAudiences { get; init; }

    public TimeSpan ClockSkew { get; init; } = TimeSpan.FromMinutes(2);

    public bool ValidateLifetime { get; init; } = true;

    public bool ValidateIssuer { get; init; } = true;

    public bool ValidateAudience { get; init; } = true;
}