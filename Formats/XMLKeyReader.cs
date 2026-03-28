using System.Xml.Linq;
using RSASharp.Keys;

namespace RSASharp.Formats;

internal static class XMLKeyReader
{
    internal static RSAKeyMaterial Read(string keyText)
    {
        if (string.IsNullOrWhiteSpace(keyText))
            throw new FormatException("XML 内容不能为空。");

        XElement root;

        try
        {
            root = XElement.Parse(keyText);
        }
        catch (Exception ex)
        {
            throw new FormatException("XML 内容无效。", ex);
        }

        if (!string.Equals(root.Name.LocalName, "RSAKeyValue", StringComparison.Ordinal))
            throw new FormatException("XML 根节点必须是 RSAKeyValue。");

        var modulus         = ReadRequired(root, "Modulus");
        var publicExponent  = ReadRequired(root, "Exponent");
        var privateExponent = ReadOptional(root, "D");
        var p               = ReadOptional(root, "P");
        var q               = ReadOptional(root, "Q");
        var dp              = ReadOptional(root, "DP");
        var dq              = ReadOptional(root, "DQ");
        var inverseQ        = ReadOptional(root, "InverseQ");

        return RSAKeyMaterial.CreateFromComponents(modulus, publicExponent, privateExponent, p, q, dp, dq, inverseQ);
    }

    private static byte[] ReadRequired(XElement root, string name)
    {
        var element = root.Element(name);
        if (element is null || string.IsNullOrWhiteSpace(element.Value))
            throw new FormatException($"XML 缺少 {name}。");

        try
        {
            return Convert.FromBase64String(element.Value);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"XML 中的 {name} 不是有效的 Base64。", ex);
        }
    }

    private static byte[]? ReadOptional(XElement root, string name)
    {
        var element = root.Element(name);
        if (element is null || string.IsNullOrWhiteSpace(element.Value))
            return null;

        try
        {
            return Convert.FromBase64String(element.Value);
        }
        catch (FormatException ex)
        {
            throw new FormatException($"XML 中的 {name} 不是有效的 Base64。", ex);
        }
    }
}
