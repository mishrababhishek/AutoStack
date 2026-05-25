namespace AutoStack.Identity.Saml;

internal static class SamlConstants
{
    internal static class Ns
    {
        public const string Protocol = "urn:oasis:names:tc:SAML:2.0:protocol";
        public const string Assertion = "urn:oasis:names:tc:SAML:2.0:assertion";
    }

    internal static class Prefix
    {
        public const string Protocol = "samlp";
        public const string Assertion = "saml";
    }

    internal static class NameIdFormat
    {
        public const string EmailAddress = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress";
        public const string Transient = "urn:oasis:names:tc:SAML:2.0:nameid-format:transient";
        public const string Persistent = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent";
        public const string Unspecified = "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified";
        public const string X509Subject = "urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName";
    }

    internal static class StatusCode
    {
        public const string Success = "urn:oasis:names:tc:SAML:2.0:status:Success";
        public const string Requester = "urn:oasis:names:tc:SAML:2.0:status:Requester";
        public const string Responder = "urn:oasis:names:tc:SAML:2.0:status:Responder";
    }

    internal static class ConfirmationMethod
    {
        public const string Bearer = "urn:oasis:names:tc:SAML:2.0:cm:bearer";
    }

    internal static class AuthnContextClassRef
    {
        public const string PasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport";
        public const string Password = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password";
        public const string Unspecified = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified";
    }

    internal const string AttributeNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:basic";
}


