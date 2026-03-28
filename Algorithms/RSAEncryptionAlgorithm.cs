namespace RSASharp.Algorithms;

public readonly record struct RSAEncryptionAlgorithm
{
    internal RSAEncryptionAlgorithm(RSAEncryptionPaddingKind kind, RSAHashAlgorithm hashAlgorithm, string canonicalName)
    {
        Kind          = kind;
        HashAlgorithm = hashAlgorithm;
        CanonicalName = canonicalName;
    }

    public static RSAEncryptionAlgorithm PKCS1 { get; } = RSAAlgorithmParser.ParseEncryption("PKCS1");

    public static RSAEncryptionAlgorithm NoPadding { get; } = RSAAlgorithmParser.ParseEncryption("NO");

    public string CanonicalName { get; }

    public string? HashName =>
        Kind == RSAEncryptionPaddingKind.OAEP ? HashAlgorithm.DisplayName : null;

    internal RSAEncryptionPaddingKind Kind { get; }

    internal RSAHashAlgorithm HashAlgorithm { get; }

    public static RSAEncryptionAlgorithm CreateOAEP(string hashName) =>
        RSAAlgorithmParser.ParseEncryption($"OAEP+{hashName}");

    public static RSAEncryptionAlgorithm Parse(string value) =>
        RSAAlgorithmParser.ParseEncryption(value);

    public static bool TryParse(string? value, out RSAEncryptionAlgorithm algorithm) =>
        RSAAlgorithmParser.TryParseEncryption(value, out algorithm);

    public override string ToString() =>
        CanonicalName;

    internal void EnsureInitialized()
    {
        if (string.IsNullOrWhiteSpace(CanonicalName))
            throw new InvalidOperationException("RSA 加密算法尚未初始化。");
    }
}
