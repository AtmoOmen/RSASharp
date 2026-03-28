using System.Diagnostics;
using System.Numerics;

namespace RSASharp.Internal;

internal static class RSAKeyMath
{
    private const int FACTORIZATION_TIMEOUT_MILLISECONDS = 3_000;

    internal static byte[] PadLeft(ReadOnlySpan<byte> bytes, int length)
    {
        ArgumentOutOfRangeException.ThrowIfNegative(length);

        if (bytes.Length >= length)
            return [.. bytes];

        var result = GC.AllocateUninitializedArray<byte>(length);
        bytes.CopyTo(result.AsSpan(length - bytes.Length));
        return result;
    }

    internal static BigInteger ReadBigEndianInteger(ReadOnlySpan<byte> bytes) =>
        new(bytes, true, true);

    internal static byte[] WriteBigEndianInteger(BigInteger value) =>
        value.ToByteArray(true, true);

    internal static (byte[] P, byte[] Q, byte[] DP, byte[] DQ, byte[] InverseQ) DerivePrivateParts
    (
        ReadOnlySpan<byte> modulus,
        ReadOnlySpan<byte> publicExponent,
        ReadOnlySpan<byte> privateExponent
    )
    {
        var modulusValue         = ReadBigEndianInteger(modulus);
        var publicExponentValue  = ReadBigEndianInteger(publicExponent);
        var privateExponentValue = ReadBigEndianInteger(privateExponent);
        var pValue               = FindFactor(publicExponentValue, privateExponentValue, modulusValue);
        var qValue               = modulusValue / pValue;

        if (pValue > qValue)
            (pValue, qValue) = (qValue, pValue);

        var dpValue       = privateExponentValue % (pValue - BigInteger.One);
        var dqValue       = privateExponentValue % (qValue - BigInteger.One);
        var inverseQValue = ComputeModInverse(qValue, pValue);
        var halfKeyLength = modulus.Length / 2;

        return
            (
                PadLeft(WriteBigEndianInteger(pValue),        halfKeyLength),
                PadLeft(WriteBigEndianInteger(qValue),        halfKeyLength),
                PadLeft(WriteBigEndianInteger(dpValue),       halfKeyLength),
                PadLeft(WriteBigEndianInteger(dqValue),       halfKeyLength),
                PadLeft(WriteBigEndianInteger(inverseQValue), halfKeyLength)
            );
    }

    private static BigInteger FindFactor(BigInteger publicExponent, BigInteger privateExponent, BigInteger modulus)
    {
        var exponentProductMinusOne = publicExponent * privateExponent - BigInteger.One;
        var s                       = 0;
        var t                       = exponentProductMinusOne;

        while (t.IsEven)
        {
            t >>= 1;
            s++;
        }

        var stopwatch = Stopwatch.StartNew();

        for (var a = 2;; a++)
        {
            if (a % 10 == 0 && stopwatch.ElapsedMilliseconds > FACTORIZATION_TIMEOUT_MILLISECONDS)
                throw new TimeoutException("反推 RSA 质因数超时。");

            var value = BigInteger.ModPow(a, t, modulus);

            for (var i = 0; i < s; i++)
            {
                if (value == BigInteger.One || value == modulus - BigInteger.One)
                    break;

                var squared = value * value % modulus;
                if (squared == BigInteger.One)
                    return BigInteger.GreatestCommonDivisor(value - BigInteger.One, modulus);

                value = squared;
            }
        }
    }

    private static BigInteger ComputeModInverse(BigInteger value, BigInteger modulus)
    {
        var originalModulus = modulus;
        var x0              = BigInteger.Zero;
        var x1              = BigInteger.One;

        while (value > BigInteger.One)
        {
            var quotient = value / modulus;

            (value, modulus) = (modulus, value % modulus);
            (x0, x1)         = (x1 - quotient * x0, x0);
        }

        return x1 < BigInteger.Zero ? x1 + originalModulus : x1;
    }
}
