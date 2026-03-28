using RSASharp.Keys;

namespace RSASharp.Formats;

internal static class RSAKeyExporter
{
    internal static string ExportPEM(RSAKeyMaterial keyMaterial, RSAKeyContainerFormat format, bool publicOnly)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);

        using var rsa              = keyMaterial.CreateRSA(publicOnly || !keyMaterial.HasPrivateKey);
        var       exportPublicOnly = publicOnly || !keyMaterial.HasPrivateKey;

        return (format, exportPublicOnly) switch
        {
            (RSAKeyContainerFormat.PKCS1, true)  => rsa.ExportRSAPublicKeyPem(),
            (RSAKeyContainerFormat.PKCS1, false) => rsa.ExportRSAPrivateKeyPem(),
            (RSAKeyContainerFormat.PKCS8, true)  => rsa.ExportSubjectPublicKeyInfoPem(),
            (RSAKeyContainerFormat.PKCS8, false) => rsa.ExportPkcs8PrivateKeyPem(),
            _                                    => throw new ArgumentOutOfRangeException(nameof(format), format, "不支持的密钥导出格式。")
        };
    }

    internal static byte[] ExportDER(RSAKeyMaterial keyMaterial, RSAKeyContainerFormat format, bool publicOnly)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);

        using var rsa              = keyMaterial.CreateRSA(publicOnly || !keyMaterial.HasPrivateKey);
        var       exportPublicOnly = publicOnly || !keyMaterial.HasPrivateKey;

        return (format, exportPublicOnly) switch
        {
            (RSAKeyContainerFormat.PKCS1, true)  => rsa.ExportRSAPublicKey(),
            (RSAKeyContainerFormat.PKCS1, false) => rsa.ExportRSAPrivateKey(),
            (RSAKeyContainerFormat.PKCS8, true)  => rsa.ExportSubjectPublicKeyInfo(),
            (RSAKeyContainerFormat.PKCS8, false) => rsa.ExportPkcs8PrivateKey(),
            _                                    => throw new ArgumentOutOfRangeException(nameof(format), format, "不支持的密钥导出格式。")
        };
    }
}
