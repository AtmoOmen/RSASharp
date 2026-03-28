namespace RSASharp.Algorithms;

public readonly record struct RSASignatureAlgorithm
{
    internal RSASignatureAlgorithm(bool isPSS, RSAHashAlgorithm hashAlgorithm, string canonicalName)
    {
        IsPSS         = isPSS;
        HashAlgorithm = hashAlgorithm;
        CanonicalName = canonicalName;
    }

    public string CanonicalName { get; }

    public string HashName => HashAlgorithm.DisplayName;

    public bool UsesPSS => IsPSS;

    internal bool IsPSS { get; }

    internal RSAHashAlgorithm HashAlgorithm { get; }

    public static RSASignatureAlgorithm CreatePKCS1(string hashName) =>
        RSAAlgorithmParser.ParseSignature($"PKCS1+{hashName}");

    public static RSASignatureAlgorithm CreatePSS(string hashName) =>
        RSAAlgorithmParser.ParseSignature($"PSS+{hashName}");

    public static RSASignatureAlgorithm Parse(string value) =>
        RSAAlgorithmParser.ParseSignature(value);

    public static bool TryParse(string? value, out RSASignatureAlgorithm algorithm) =>
        RSAAlgorithmParser.TryParseSignature(value, out algorithm);

    public override string ToString() =>
        CanonicalName;

    internal void EnsureInitialized()
    {
        if (string.IsNullOrWhiteSpace(CanonicalName))
            throw new InvalidOperationException("RSA 签名算法尚未初始化。");
    }
}
