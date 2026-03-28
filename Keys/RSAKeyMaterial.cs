using System.Security.Cryptography;
using RSASharp.Formats;
using RSASharp.Internal;

namespace RSASharp.Keys;

public sealed class RSAKeyMaterial
{
    private readonly byte[]? dp;
    private readonly byte[]? dq;
    private readonly byte[]? inverseQ;
    private readonly byte[]  modulus;
    private readonly byte[]? p;
    private readonly byte[]? privateExponent;
    private readonly byte[]  publicExponent;
    private readonly byte[]? q;

    private RSAKeyMaterial
    (
        byte[]  modulus,
        byte[]  publicExponent,
        byte[]? privateExponent,
        byte[]? p,
        byte[]? q,
        byte[]? dp,
        byte[]? dq,
        byte[]? inverseQ
    )
    {
        this.modulus        = CloneRequired(modulus,        nameof(modulus));
        this.publicExponent = CloneRequired(publicExponent, nameof(publicExponent));

        if (privateExponent is null)
            return;

        var halfKeyLength = this.modulus.Length / 2;

        this.privateExponent = RSAKeyMath.PadLeft(privateExponent,                                this.modulus.Length);
        this.p               = RSAKeyMath.PadLeft(RequirePrivatePart(p,        nameof(p)),        halfKeyLength);
        this.q               = RSAKeyMath.PadLeft(RequirePrivatePart(q,        nameof(q)),        halfKeyLength);
        this.dp              = RSAKeyMath.PadLeft(RequirePrivatePart(dp,       nameof(dp)),       halfKeyLength);
        this.dq              = RSAKeyMath.PadLeft(RequirePrivatePart(dq,       nameof(dq)),       halfKeyLength);
        this.inverseQ        = RSAKeyMath.PadLeft(RequirePrivatePart(inverseQ, nameof(inverseQ)), halfKeyLength);
    }

    public int KeySize => modulus.Length * 8;

    public bool HasPrivateKey => privateExponent is not null;

    internal int KeySizeInBytes => modulus.Length;

    internal ReadOnlySpan<byte> ModulusSpan => modulus;

    internal ReadOnlySpan<byte> PublicExponentSpan => publicExponent;

    internal ReadOnlySpan<byte> PrivateExponentSpan =>
        privateExponent ?? throw new InvalidOperationException("当前密钥不包含私钥，无法执行该操作。");

    internal ReadOnlySpan<byte> PSpan =>
        p ?? throw new InvalidOperationException("当前密钥缺少私钥参数 P。");

    internal ReadOnlySpan<byte> QSpan =>
        q ?? throw new InvalidOperationException("当前密钥缺少私钥参数 Q。");

    internal ReadOnlySpan<byte> DPSpan =>
        dp ?? throw new InvalidOperationException("当前密钥缺少私钥参数 DP。");

    internal ReadOnlySpan<byte> DQSpan =>
        dq ?? throw new InvalidOperationException("当前密钥缺少私钥参数 DQ。");

    internal ReadOnlySpan<byte> InverseQSpan =>
        inverseQ ?? throw new InvalidOperationException("当前密钥缺少私钥参数 InverseQ。");

    public static RSAKeyMaterial Generate(int keySize)
    {
        ArgumentOutOfRangeException.ThrowIfNegativeOrZero(keySize);

        using var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return CreateFromRSA(rsa);
    }

    public static RSAKeyMaterial ImportPEM(string keyText) =>
        PEMKeyReader.Read(keyText);

    public static RSAKeyMaterial ImportXML(string keyText) =>
        XMLKeyReader.Read(keyText);

    public string ExportPEM(RSAKeyContainerFormat format = RSAKeyContainerFormat.PKCS8, bool publicOnly = false) =>
        RSAKeyExporter.ExportPEM(this, format, publicOnly);

    public byte[] ExportDER(RSAKeyContainerFormat format = RSAKeyContainerFormat.PKCS8, bool publicOnly = false) =>
        RSAKeyExporter.ExportDER(this, format, publicOnly);

    public string ExportXML(bool publicOnly = false) =>
        XMLKeyWriter.Write(this, publicOnly);

    public RSAKeyMaterial ToPublicKey() =>
        new(modulus, publicExponent, null, null, null, null, null, null);

    internal RSA CreateRSA(bool publicOnly = false)
    {
        var rsa = RSA.Create();
        ImportParameters(rsa, publicOnly);
        return rsa;
    }

    internal void EnsurePrivateKey()
    {
        if (!HasPrivateKey)
            throw new InvalidOperationException("当前密钥不包含私钥，无法执行该操作。");
    }

    internal static RSAKeyMaterial CreateFromComponents
    (
        byte[]  modulus,
        byte[]  publicExponent,
        byte[]? privateExponent,
        byte[]? p,
        byte[]? q,
        byte[]? dp,
        byte[]? dq,
        byte[]? inverseQ
    )
    {
        if (privateExponent is null)
            return new RSAKeyMaterial(modulus, publicExponent, null, null, null, null, null, null);

        var hasCompletePrivateParts = p is not null && q is not null && dp is not null && dq is not null && inverseQ is not null;
        if (hasCompletePrivateParts)
            return new RSAKeyMaterial(modulus, publicExponent, privateExponent, p, q, dp, dq, inverseQ);

        var derivedParts = RSAKeyMath.DerivePrivateParts(modulus, publicExponent, privateExponent);
        return new RSAKeyMaterial(modulus, publicExponent, privateExponent, derivedParts.P, derivedParts.Q, derivedParts.DP, derivedParts.DQ, derivedParts.InverseQ);
    }

    internal static RSAKeyMaterial CreateFromRSA(RSA rsa, bool publicOnly = false)
    {
        ArgumentNullException.ThrowIfNull(rsa);

        var parameters = publicOnly
                             ? rsa.ExportParameters(false)
                             : TryExportPrivateParameters(rsa) ?? rsa.ExportParameters(false);

        return CreateFromComponents
        (
            parameters.Modulus  ?? throw new CryptographicException("RSA 密钥缺少模数。"),
            parameters.Exponent ?? throw new CryptographicException("RSA 密钥缺少公钥指数。"),
            parameters.D,
            parameters.P,
            parameters.Q,
            parameters.DP,
            parameters.DQ,
            parameters.InverseQ
        );
    }

    private void ImportParameters(RSA rsa, bool publicOnly)
    {
        ArgumentNullException.ThrowIfNull(rsa);

        var parameters = new RSAParameters
        {
            Modulus  = [.. modulus],
            Exponent = [.. publicExponent]
        };

        if (!publicOnly && privateExponent is not null)
        {
            parameters.D        = [.. PrivateExponentSpan];
            parameters.P        = [.. PSpan];
            parameters.Q        = [.. QSpan];
            parameters.DP       = [.. DPSpan];
            parameters.DQ       = [.. DQSpan];
            parameters.InverseQ = [.. InverseQSpan];
        }

        rsa.ImportParameters(parameters);
    }

    private static RSAParameters? TryExportPrivateParameters(RSA rsa)
    {
        try
        {
            return rsa.ExportParameters(true);
        }
        catch (CryptographicException)
        {
            return null;
        }
    }

    private static byte[] CloneRequired(byte[]? bytes, string paramName) =>
        bytes is null or { Length: 0 }
            ? throw new ArgumentException($"{paramName} 不能为空。", paramName)
            : [.. bytes];

    private static byte[] RequirePrivatePart(byte[]? bytes, string paramName) =>
        bytes is null or { Length: 0 }
            ? throw new ArgumentException($"私钥参数 {paramName} 不能为空。", paramName)
            : [.. bytes];
}
