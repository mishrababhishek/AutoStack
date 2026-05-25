namespace AutoStack.Identity.Xml.Verification;

public sealed class XmlVerificationPipeline
{
    private readonly IReadOnlyList<IXmlVerificationRule> _rules;

    public bool FailFast { get; init; }

    internal XmlVerificationPipeline(IReadOnlyList<IXmlVerificationRule> rules)
    {
        _rules = rules;
    }

    public async Task<VerificationResult> VerifyAsync(XmlVerificationContext context, CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(context);

        var failures = new List<VerificationFailure>();

        foreach (var rule in _rules)
        {
            cancellationToken.ThrowIfCancellationRequested();

            VerificationResult result;
            try
            {
                result = await rule.ExecuteAsync(context, cancellationToken).ConfigureAwait(false);
            }
            catch (OperationCanceledException)
            {
                throw;
            }
            catch (Exception ex)
            {
                result = VerificationResult.Fail(new VerificationFailure(rule.RuleName, $"Rule threw an unhandled exception: {ex.Message}", ex));
            }

            if (!result.IsSuccess)
            {
                failures.AddRange(result.Failures);

                if (FailFast)
                    return VerificationResult.Fail(failures.ToArray());
            }
        }

        return failures.Count == 0 ? VerificationResult.Success() : VerificationResult.Fail(failures.ToArray());
    }
}

public sealed class XmlVerificationPipelineBuilder
{
    private readonly List<IXmlVerificationRule> _rules = [];
    private bool _failFast;

    public static XmlVerificationPipelineBuilder Create() => new();

    public XmlVerificationPipelineBuilder AddRule(IXmlVerificationRule rule)
    {
        ArgumentNullException.ThrowIfNull(rule);
        _rules.Add(rule);
        return this;
    }

    public XmlVerificationPipelineBuilder AddRules(IEnumerable<IXmlVerificationRule> rules)
    {
        foreach (var rule in rules)
            AddRule(rule);
        return this;
    }

    public XmlVerificationPipelineBuilder WithFailFast(bool failFast = true)
    {
        _failFast = failFast;
        return this;
    }

    public XmlVerificationPipeline Build() => new(_rules.AsReadOnly()) { FailFast = _failFast };
}


