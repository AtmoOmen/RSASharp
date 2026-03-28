using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace RSASharp.Algorithms;

internal static partial class RSAAlgorithmParser
{
    internal static RSAEncryptionAlgorithm ParseEncryption(string? value)
    {
        var normalizedValue = NormalizeToken(value);

        if (string.IsNullOrEmpty(normalizedValue) || normalizedValue is "RSA" or "PKCS" or "PKCS1")
            return new RSAEncryptionAlgorithm(RSAEncryptionPaddingKind.PKCS1, default, "PKCS1");

        if (normalizedValue is "RAW" or "NO" || string.Equals(normalizedValue, "RSA/ECB/NOPADDING", StringComparison.OrdinalIgnoreCase))
            return new RSAEncryptionAlgorithm(RSAEncryptionPaddingKind.NoPadding, default, "NO");

        if (normalizedValue is "OAEP" or "RSA/ECB/OAEPPADDING")
            normalizedValue = "OAEP+SHA1";

        if (normalizedValue.StartsWith("OAEP+", StringComparison.OrdinalIgnoreCase))
        {
            var hashAlgorithm = ParseHashAlgorithm(normalizedValue[5..]);
            return new RSAEncryptionAlgorithm(RSAEncryptionPaddingKind.OAEP, hashAlgorithm, $"OAEP+{hashAlgorithm.DisplayName}");
        }

        if (string.Equals(normalizedValue, "RSA/ECB/PKCS1PADDING", StringComparison.OrdinalIgnoreCase))
            return new RSAEncryptionAlgorithm(RSAEncryptionPaddingKind.PKCS1, default, "PKCS1");

        var oaepMatch = EncryptionOAEPPaddingPattern().Match(normalizedValue);

        if (oaepMatch.Success)
        {
            var hashAlgorithm = ParseHashAlgorithm(oaepMatch.Groups[1].Value);
            return new RSAEncryptionAlgorithm(RSAEncryptionPaddingKind.OAEP, hashAlgorithm, $"OAEP+{hashAlgorithm.DisplayName}");
        }

        throw new InvalidOperationException($"无法识别 RSA 加密算法：{value}");
    }

    internal static RSASignatureAlgorithm ParseSignature(string? value)
    {
        var normalizedValue = NormalizeToken(value);
        if (string.IsNullOrEmpty(normalizedValue))
            throw new InvalidOperationException("RSA 签名算法不能为空。");

        if (string.Equals(normalizedValue, "RSASSA-PSS", StringComparison.OrdinalIgnoreCase))
            normalizedValue = "PSS+SHA1";

        if (normalizedValue.StartsWith("PSS+", StringComparison.OrdinalIgnoreCase))
        {
            var hashAlgorithm = ParseHashAlgorithm(normalizedValue[4..]);
            return new RSASignatureAlgorithm(true, hashAlgorithm, $"PSS+{hashAlgorithm.DisplayName}");
        }

        if (normalizedValue.StartsWith("PKCS1+", StringComparison.OrdinalIgnoreCase))
        {
            var hashAlgorithm = ParseHashAlgorithm(normalizedValue[6..]);
            return new RSASignatureAlgorithm(false, hashAlgorithm, $"PKCS1+{hashAlgorithm.DisplayName}");
        }

        var signatureMatch = SignaturePattern().Match(normalizedValue);

        if (signatureMatch.Success)
        {
            var hashAlgorithm = ParseHashAlgorithm(signatureMatch.Groups[1].Value);
            var isPSS         = !string.IsNullOrEmpty(signatureMatch.Groups[2].Value);
            return new RSASignatureAlgorithm(isPSS, hashAlgorithm, $"{(isPSS ? "PSS" : "PKCS1")}+{hashAlgorithm.DisplayName}");
        }

        var fallbackHashAlgorithm = ParseHashAlgorithm(normalizedValue);
        return new RSASignatureAlgorithm(false, fallbackHashAlgorithm, $"PKCS1+{fallbackHashAlgorithm.DisplayName}");
    }

    internal static bool TryParseEncryption(string? value, out RSAEncryptionAlgorithm algorithm)
    {
        try
        {
            algorithm = ParseEncryption(value);
            return true;
        }
        catch
        {
            algorithm = default;
            return false;
        }
    }

    internal static bool TryParseSignature(string? value, out RSASignatureAlgorithm algorithm)
    {
        try
        {
            algorithm = ParseSignature(value);
            return true;
        }
        catch
        {
            algorithm = default;
            return false;
        }
    }

    internal static RSAEncryptionPadding CreateEncryptionPadding(RSAEncryptionAlgorithm algorithm)
    {
        algorithm.EnsureInitialized();

        if (algorithm.Kind == RSAEncryptionPaddingKind.NoPadding)
            throw new InvalidOperationException("NoPadding 需要走手动运算路径。");

        if (algorithm.Kind == RSAEncryptionPaddingKind.PKCS1)
            return RSAEncryptionPadding.Pkcs1;

        EnsureHashSupported(algorithm.HashAlgorithm);
        return RSAEncryptionPadding.CreateOaep(new HashAlgorithmName(algorithm.HashAlgorithm.RuntimeName));
    }

    internal static RSASignaturePadding CreateSignaturePadding(RSASignatureAlgorithm algorithm)
    {
        algorithm.EnsureInitialized();
        EnsureHashSupported(algorithm.HashAlgorithm);
        return algorithm.IsPSS ? RSASignaturePadding.Pss : RSASignaturePadding.Pkcs1;
    }

    internal static HashAlgorithmName CreateHashAlgorithmName(RSASignatureAlgorithm algorithm)
    {
        algorithm.EnsureInitialized();
        EnsureHashSupported(algorithm.HashAlgorithm);
        return new HashAlgorithmName(algorithm.HashAlgorithm.RuntimeName);
    }

    internal static void EnsureHashSupported(RSAHashAlgorithm algorithm)
    {
        if (string.IsNullOrWhiteSpace(algorithm.RuntimeName))
            return;

        try
        {
            using var _ = IncrementalHash.CreateHash(new HashAlgorithmName(algorithm.RuntimeName));
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new NotSupportedException($"当前运行时不支持 {algorithm.DisplayName} 摘要算法。", ex);
        }
    }

    private static RSAHashAlgorithm ParseHashAlgorithm(string value)
    {
        var normalizedValue = NormalizeToken(value)
                              .Replace('_', '-')
                              .Replace(" ", string.Empty)
                              .ToUpperInvariant();

        return normalizedValue switch
        {
            "MD5"                         => new RSAHashAlgorithm("MD5",         "MD5",        128),
            "SHA1" or "SHA-1"             => new RSAHashAlgorithm("SHA1",        "SHA1",       160),
            "SHA224" or "SHA-224"         => new RSAHashAlgorithm("SHA224",      "SHA224",     224),
            "SHA256" or "SHA-256"         => new RSAHashAlgorithm("SHA256",      "SHA256",     256),
            "SHA384" or "SHA-384"         => new RSAHashAlgorithm("SHA384",      "SHA384",     384),
            "SHA512" or "SHA-512"         => new RSAHashAlgorithm("SHA512",      "SHA512",     512),
            "SHA512/224" or "SHA-512/224" => new RSAHashAlgorithm("SHA-512/224", "SHA512/224", 224),
            "SHA512/256" or "SHA-512/256" => new RSAHashAlgorithm("SHA-512/256", "SHA512/256", 256),
            "SHA3-224"                    => new RSAHashAlgorithm("SHA3-224",    "SHA3-224",   224),
            "SHA3-256"                    => new RSAHashAlgorithm("SHA3-256",    "SHA3-256",   256),
            "SHA3-384"                    => new RSAHashAlgorithm("SHA3-384",    "SHA3-384",   384),
            "SHA3-512"                    => new RSAHashAlgorithm("SHA3-512",    "SHA3-512",   512),
            _                             => throw new InvalidOperationException($"无法识别摘要算法：{value}")
        };
    }

    private static string NormalizeToken(string? value) =>
        value?.Trim() ?? string.Empty;

    [GeneratedRegex("^RSA/.+/OAEPWITH(.+)ANDMGF1PADDING$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex EncryptionOAEPPaddingPattern();

    [GeneratedRegex("^(.+)WITHRSA(?:/(PSS))?$", RegexOptions.IgnoreCase | RegexOptions.CultureInvariant)]
    private static partial Regex SignaturePattern();
}
