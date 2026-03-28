using System.Xml.Linq;
using RSASharp.Keys;

namespace RSASharp.Formats;

internal static class XMLKeyWriter
{
    internal static string Write(RSAKeyMaterial keyMaterial, bool publicOnly)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);

        var exportPublicOnly = publicOnly || !keyMaterial.HasPrivateKey;
        var root = new XElement
        (
            "RSAKeyValue",
            new XElement("Modulus",  Convert.ToBase64String(keyMaterial.ModulusSpan)),
            new XElement("Exponent", Convert.ToBase64String(keyMaterial.PublicExponentSpan))
        );

        if (!exportPublicOnly)
        {
            root.Add(new XElement("P",        Convert.ToBase64String(keyMaterial.PSpan)));
            root.Add(new XElement("Q",        Convert.ToBase64String(keyMaterial.QSpan)));
            root.Add(new XElement("DP",       Convert.ToBase64String(keyMaterial.DPSpan)));
            root.Add(new XElement("DQ",       Convert.ToBase64String(keyMaterial.DQSpan)));
            root.Add(new XElement("InverseQ", Convert.ToBase64String(keyMaterial.InverseQSpan)));
            root.Add(new XElement("D",        Convert.ToBase64String(keyMaterial.PrivateExponentSpan)));
        }

        return root.ToString(SaveOptions.DisableFormatting);
    }
}
