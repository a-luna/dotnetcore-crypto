namespace AaronLuna.Crypto
{
    using System.Security.Cryptography;

    public static class CryptoRandom
    {
        public static byte[] GetRandomBytes(int length)
        {
            var bytes = new byte[length];
            using (var random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(bytes);
            }

            return bytes;
        }
    }
}
