namespace AutoStack.Identity.Saml;

public interface ISamlSpProvider
{
    string NormalizeAttributeName(string rawName) => rawName;

    void OnResponseParsed(SamlResponsePayload payload) { }
}