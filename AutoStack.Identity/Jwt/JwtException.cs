namespace AutoStack.Identity.Jwt;

public sealed class JwtException : Exception
{
    public JwtException(string message) : base(message) { }
    public JwtException(string message, Exception inner) : base(message, inner) { }
}