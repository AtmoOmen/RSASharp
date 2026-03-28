using System.Security.Cryptography;
using RSASharp.Keys;

namespace RSASharp.Formats;

internal static class PEMKeyReader
{
    internal static RSAKeyMaterial Read(string keyText)
    {
        if (string.IsNullOrWhiteSpace(keyText))
            throw new FormatException("PEM 内容不能为空。");

        using var rsa = RSA.Create();

        try
        {
            rsa.ImportFromPem(keyText);
        }
        catch (Exception ex) when (ex is ArgumentException or CryptographicException)
        {
            throw new FormatException("PEM 内容无效。", ex);
        }

        return RSAKeyMaterial.CreateFromRSA(rsa);
    }
}
