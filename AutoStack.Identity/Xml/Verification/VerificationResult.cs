namespace AutoStack.Identity.Xml.Verification;

public sealed class VerificationResult
{
    public bool IsSuccess { get; }
    public IReadOnlyList<VerificationFailure> Failures { get; }

    private VerificationResult(bool isSuccess, IReadOnlyList<VerificationFailure> failures)
    {
        IsSuccess = isSuccess;
        Failures = failures;
    }

    public static VerificationResult Success() => new(true, Array.Empty<VerificationFailure>());

    public static VerificationResult Fail(params VerificationFailure[] failures) => new(false, failures);

    public static VerificationResult Fail(string ruleName, string message) => Fail(new VerificationFailure(ruleName, message));

    public static VerificationResult Combine(IEnumerable<VerificationResult> results)
    {
        var all = results.ToList();
        var failures = all.SelectMany(r => r.Failures).ToList();
        return failures.Count == 0
            ? Success()
            : new VerificationResult(false, failures);
    }

    public override string ToString() => IsSuccess ? "OK" : $"FAILED: {string.Join("; ", Failures.Select(f => f.ToString()))}";
}

public sealed record VerificationFailure(string RuleName, string Message, Exception? Exception = null)
{
    public override string ToString() => $"[{RuleName}] {Message}";
}

