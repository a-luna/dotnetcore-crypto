namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Security.Cryptography;

    using SHA3;

    public static class CryptoHashers
    {
        public static byte[] CalculateFileDigest(string filePath, HashAlgorithmType hashAlgorithm, byte[] key)
        {
            switch (hashAlgorithm)
            {
                case HashAlgorithmType.HMAC_MD5:
                    return HashFile_HMAC_MD5(filePath, key);

                case HashAlgorithmType.HMAC_SHA1:
                    return HashFile_HMAC_SHA1(filePath, key);

                case HashAlgorithmType.HMAC_SHA256:
                    return HashFile_HMAC_SHA256(filePath, key);

                case HashAlgorithmType.HMAC_SHA384:
                    return HashFile_HMAC_SHA384(filePath, key);

                case HashAlgorithmType.HMAC_SHA512:
                    return HashFile_HMAC_SHA512(filePath, key);

                case HashAlgorithmType.SHA2_256:
                    return HashFile_SHA2_256(filePath, key);

                case HashAlgorithmType.SHA2_384:
                    return HashFile_SHA2_384(filePath, key);

                case HashAlgorithmType.SHA2_512:
                    return HashFile_SHA2_512(filePath, key);

                case HashAlgorithmType.SHA3_256:
                    return HashFile_SHA3_256(filePath);

                case HashAlgorithmType.SHA3_384:
                    return HashFile_SHA3_384(filePath);

                case HashAlgorithmType.SHA3_512:
                    return HashFile_SHA3_512(filePath);

                default:
                    throw new NotSupportedException($"Hash algorithm {nameof(hashAlgorithm)} is not supported");
            }
        }

        static byte[] HashFile_HMAC_MD5(string filePath, byte[] key)
        {
            byte[] md5;
            using (var hmac = new HMACMD5(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                md5 = hmac.ComputeHash(fs);
            }

            return md5;
        }

        static byte[] HashFile_HMAC_SHA1(string filePath, byte[] key)
        {
            byte[] md5;
            using (var hmac = new HMACSHA1(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                md5 = hmac.ComputeHash(fs);
            }

            return md5;
        }

        static byte[] HashFile_HMAC_SHA256(string filePath, byte[] key)
        {
            byte[] md5;
            using (var hmac = new HMACSHA256(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                md5 = hmac.ComputeHash(fs);
            }

            return md5;
        }

        static byte[] HashFile_HMAC_SHA384(string filePath, byte[] key)
        {
            byte[] md5;
            using (var hmac = new HMACSHA384(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                md5 = hmac.ComputeHash(fs);
            }

            return md5;
        }

        static byte[] HashFile_HMAC_SHA512(string filePath, byte[] key)
        {
            byte[] md5;
            using (var hmac = new HMACSHA512(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                md5 = hmac.ComputeHash(fs);
            }

            return md5;
        }

        static byte[] HashFile_SHA2_256(string filePath, byte[] key)
        {
            byte[] sha256;
            using (var sha = new HMACSHA256(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha256 = sha.ComputeHash(fs);
            }

            return sha256;
        }

        static byte[] HashFile_SHA2_384(string filePath, byte[] key)
        {
            byte[] sha384;
            using (var sha = new HMACSHA384(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha384 = sha.ComputeHash(fs);
            }

            return sha384;
        }

        static byte[] HashFile_SHA2_512(string filePath, byte[] key)
        {
            byte[] sha512;
            using (var sha = new HMACSHA512(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha512 = sha.ComputeHash(fs);
            }

            return sha512;
        }

        static byte[] HashFile_SHA3_256(string filePath)
        {
            var sha3 = Sha3Permutation.Sha3_256();
            var fileBytes = File.ReadAllBytes(filePath);
            return sha3.Process(fileBytes, 256, fileBytes.Length);
        }

        static byte[] HashFile_SHA3_384(string filePath)
        {
            var sha3 = Sha3Permutation.Sha3_384();
            var fileBytes = File.ReadAllBytes(filePath);
            return sha3.Process(fileBytes, 384, fileBytes.Length);
        }

        static byte[] HashFile_SHA3_512(string filePath)
        {
            var sha3 = Sha3Permutation.Sha3_512();
            var fileBytes = File.ReadAllBytes(filePath);
            return sha3.Process(fileBytes, 512, fileBytes.Length);
        }
    }
}
