using System.Buffers;
using System.Numerics;
using System.Security.Cryptography;
using RSASharp.Algorithms;
using RSASharp.Internal;
using RSASharp.Keys;

namespace RSASharp.Cryptography;

public static class RSACryptography
{
    public static byte[] Encrypt(RSAKeyMaterial keyMaterial, RSAEncryptionAlgorithm algorithm, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        algorithm.EnsureInitialized();

        if (data.IsEmpty)
            return [];

        var keySizeInBytes   = keyMaterial.KeySizeInBytes;
        var inputBlockLength = GetEncryptionInputBlockLength(algorithm, keySizeInBytes);

        using var rsa = keyMaterial.CreateRSA(true);

        return algorithm.Kind == RSAEncryptionPaddingKind.NoPadding
                   ? ProcessBlocks
                   (
                       data,
                       inputBlockLength,
                       GetBlockCount(data.Length, inputBlockLength) * keySizeInBytes,
                       block => TransformWithoutPadding(keyMaterial, true, block, keySizeInBytes)
                   )
                   : ProcessBlocks
                   (
                       data,
                       inputBlockLength,
                       GetBlockCount(data.Length, inputBlockLength) * keySizeInBytes,
                       block => EncryptWithPadding(rsa, algorithm, block, keySizeInBytes)
                   );
    }

    public static byte[] Decrypt(RSAKeyMaterial keyMaterial, RSAEncryptionAlgorithm algorithm, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        algorithm.EnsureInitialized();
        keyMaterial.EnsurePrivateKey();

        if (data.IsEmpty)
            return [];

        var keySizeInBytes = keyMaterial.KeySizeInBytes;
        if (data.Length % keySizeInBytes != 0)
            throw new CryptographicException("密文块长度不正确。");

        using var rsa = keyMaterial.CreateRSA();

        return algorithm.Kind == RSAEncryptionPaddingKind.NoPadding
                   ? ProcessBlocks(data, keySizeInBytes, data.Length, block => TransformWithoutPadding(keyMaterial, false, block, keySizeInBytes))
                   : ProcessBlocks(data, keySizeInBytes, data.Length, block => DecryptWithPadding(rsa, algorithm, block, keySizeInBytes));
    }

    public static byte[] DecryptFromBase64(RSAKeyMaterial keyMaterial, RSAEncryptionAlgorithm algorithm, string cipherText)
    {
        if (string.IsNullOrWhiteSpace(cipherText))
            return [];

        try
        {
            return Decrypt(keyMaterial, algorithm, Convert.FromBase64String(cipherText));
        }
        catch (FormatException ex)
        {
            throw new FormatException("密文不是有效的 Base64 内容。", ex);
        }
    }

    public static byte[] Sign(RSAKeyMaterial keyMaterial, RSASignatureAlgorithm algorithm, ReadOnlySpan<byte> data)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        algorithm.EnsureInitialized();
        keyMaterial.EnsurePrivateKey();

        if (data.IsEmpty)
            return [];

        using var rsa = keyMaterial.CreateRSA();
        return rsa.SignData(data, RSAAlgorithmParser.CreateHashAlgorithmName(algorithm), RSAAlgorithmParser.CreateSignaturePadding(algorithm));
    }

    public static bool Verify(RSAKeyMaterial keyMaterial, RSASignatureAlgorithm algorithm, ReadOnlySpan<byte> data, ReadOnlySpan<byte> signature)
    {
        ArgumentNullException.ThrowIfNull(keyMaterial);
        algorithm.EnsureInitialized();

        if (signature.IsEmpty)
            return false;

        using var rsa = keyMaterial.CreateRSA(true);
        return rsa.VerifyData(data, signature, RSAAlgorithmParser.CreateHashAlgorithmName(algorithm), RSAAlgorithmParser.CreateSignaturePadding(algorithm));
    }

    private static int GetEncryptionInputBlockLength(RSAEncryptionAlgorithm algorithm, int keySizeInBytes)
    {
        var inputBlockLength = algorithm.Kind switch
        {
            RSAEncryptionPaddingKind.NoPadding => keySizeInBytes,
            RSAEncryptionPaddingKind.PKCS1     => keySizeInBytes - 11,
            RSAEncryptionPaddingKind.OAEP      => keySizeInBytes - (algorithm.HashAlgorithm.BitLength / 8 * 2 + 2),
            _                                  => throw new InvalidOperationException("未知的 RSA 加密算法。")
        };

        if (inputBlockLength < 1)
            throw new InvalidOperationException($"RSA[{algorithm.CanonicalName}] 的密钥位数过小，无法完成当前操作。");

        return inputBlockLength;
    }

    private static byte[] EncryptWithPadding(RSA rsa, RSAEncryptionAlgorithm algorithm, ReadOnlySpan<byte> block, int keySizeInBytes)
    {
        var destination = GC.AllocateUninitializedArray<byte>(keySizeInBytes);
        if (!rsa.TryEncrypt(block, destination, RSAAlgorithmParser.CreateEncryptionPadding(algorithm), out var bytesWritten))
            throw new CryptographicException("RSA 加密失败。");

        return bytesWritten == destination.Length ? destination : destination[..bytesWritten];
    }

    private static byte[] DecryptWithPadding(RSA rsa, RSAEncryptionAlgorithm algorithm, ReadOnlySpan<byte> block, int keySizeInBytes)
    {
        var rentedBuffer = ArrayPool<byte>.Shared.Rent(keySizeInBytes);

        try
        {
            if (!rsa.TryDecrypt(block, rentedBuffer, RSAAlgorithmParser.CreateEncryptionPadding(algorithm), out var bytesWritten))
                throw new CryptographicException("RSA 解密失败。");

            return [.. rentedBuffer.AsSpan(0, bytesWritten)];
        }
        finally
        {
            rentedBuffer.AsSpan(0, keySizeInBytes).Clear();
            ArrayPool<byte>.Shared.Return(rentedBuffer);
        }
    }

    private static byte[] TransformWithoutPadding(RSAKeyMaterial keyMaterial, bool isEncrypt, ReadOnlySpan<byte> block, int blockLength)
    {
        var paddedBlock = ArrayPool<byte>.Shared.Rent(blockLength);

        try
        {
            var paddedSpan = paddedBlock.AsSpan(0, blockLength);
            paddedSpan.Clear();
            block.CopyTo(paddedSpan[(blockLength - block.Length)..]);

            var modulus  = RSAKeyMath.ReadBigEndianInteger(keyMaterial.ModulusSpan);
            var exponent = RSAKeyMath.ReadBigEndianInteger(isEncrypt ? keyMaterial.PublicExponentSpan : keyMaterial.PrivateExponentSpan);
            var value    = RSAKeyMath.ReadBigEndianInteger(paddedSpan);
            var result   = RSAKeyMath.WriteBigEndianInteger(BigInteger.ModPow(value, exponent, modulus));

            return isEncrypt ? RSAKeyMath.PadLeft(result, blockLength) : TrimLeadingZeros(result);
        }
        finally
        {
            paddedBlock.AsSpan(0, blockLength).Clear();
            ArrayPool<byte>.Shared.Return(paddedBlock);
        }
    }

    private static byte[] ProcessBlocks(ReadOnlySpan<byte> data, int sourceBlockLength, int estimatedLength, Func<ReadOnlySpan<byte>, byte[]> transform)
    {
        var writer = estimatedLength > 0 ? new ArrayBufferWriter<byte>(estimatedLength) : new ArrayBufferWriter<byte>();

        for (var offset = 0; offset < data.Length; offset += sourceBlockLength)
        {
            var blockLength = Math.Min(sourceBlockLength, data.Length - offset);
            var result      = transform(data.Slice(offset, blockLength));
            Append(writer, result);
        }

        return writer.WrittenSpan.ToArray();
    }

    private static int GetBlockCount(int totalLength, int blockLength) =>
        totalLength == 0 ? 0 : (totalLength + blockLength - 1) / blockLength;

    private static void Append(ArrayBufferWriter<byte> writer, ReadOnlySpan<byte> bytes)
    {
        var destination = writer.GetSpan(bytes.Length);
        bytes.CopyTo(destination);
        writer.Advance(bytes.Length);
    }

    private static byte[] TrimLeadingZeros(ReadOnlySpan<byte> value)
    {
        var index = 0;
        while (index < value.Length && value[index] == 0)
            index++;

        return index == 0 ? [.. value] : [.. value[index..]];
    }
}
