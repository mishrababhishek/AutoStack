namespace AutoStack.Identity.Xml.Verification;

public interface IXmlVerificationRule
{
    string RuleName { get; }

    Task<VerificationResult> ExecuteAsync(XmlVerificationContext context, CancellationToken cancellationToken = default);
}
