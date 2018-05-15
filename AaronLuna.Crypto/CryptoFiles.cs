using AaronLuna.Crypto.SHA3;

namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using static System.Convert;

    using Common.Result;

    public static class CryptoFiles
    {
        public static async Task<Result<EncryptedFileInfo>> EncryptFileAsync(string filePath, string publicRsaKeyXmlFilePath, HashAlgorithmType hashAlgorithm=HashAlgorithmType.SHA2_256)
        {
            var folderPath = Path.GetDirectoryName(filePath);
            var encryptedFileName = $"{Path.GetFileName(filePath)}.encrypted";
            var infoXmlFilePath = Path.Combine(folderPath, $"{encryptedFileName}.xml");
            EncryptedFileInfo infoXml;

            try
            {
                infoXml = await Task.Factory.StartNew(() => Encrypt(filePath, publicRsaKeyXmlFilePath, hashAlgorithm));
            }
            catch (FileNotFoundException ex)
            {
                return Result.Fail<EncryptedFileInfo>($"{ex.Message} {ex.GetType()}");
            }

            var serializationResult = EncryptedFileInfo.Serialize(infoXml, infoXmlFilePath);
            if (serializationResult.Failure)
            {
                return Result.Fail<EncryptedFileInfo>("Error occurred serializing encrypted file info to XML.");
            }

            return Result.Ok(infoXml);
        }

        public static async Task<Result> DecryptFileAsync(string encryptedFilePath, EncryptedFileInfo infoXml, string privateRsaKeyXmlFilePath)
        {
            Result decryptResult;
            try
            {
                decryptResult = await Task.Factory.StartNew(() => Decrypt(encryptedFilePath, infoXml, privateRsaKeyXmlFilePath));
            }
            catch (Exception ex)
            {
                return Result.Fail($"{ex.Message} {ex.GetType()}");
            }

            return decryptResult;
        }

        static EncryptedFileInfo Encrypt(string filePath, string publicRsaKeyXmlFilePath, HashAlgorithmType hashAlgorithm)
        {
            var folderPath = Path.GetDirectoryName(filePath);
            var fileName = Path.GetFileName(filePath);
            var encryptedFileName = $"{fileName}.encrypted";
            var encryptedFilePath = Path.Combine(folderPath, encryptedFileName);

            var signatureKey = GetRandomBytes(64);
            var encryptionKey = GetRandomBytes(16);
            var encryptionIv = GetRandomBytes(16);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 128;
                using (var encryptor = aes.CreateEncryptor(encryptionKey, encryptionIv))
                using (var fsInput = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var fsEncrypted = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var cs = new CryptoStream(fsEncrypted, encryptor, CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }

            var encryptedFileSignature = CalculateFileManifest(encryptedFilePath, hashAlgorithm, signatureKey);
            var publicRsaKey = ReadRsaKeyXmlFromFile(publicRsaKeyXmlFilePath);

            return CreateInfoXml(
                fileName,
                encryptedFileName,
                encryptedFileSignature,
                signatureKey,
                hashAlgorithm,
                encryptionKey,
                encryptionIv,
                publicRsaKey);
        }

        static string ReadRsaKeyXmlFromFile(string rsaXmlFilePath)
        {
            string rsaKey;
            using (var sr = File.OpenText(rsaXmlFilePath))
            {
                rsaKey = sr.ReadToEnd();
            }

            return rsaKey;
        }

        static byte[] GetRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(bytes);
            }

            return bytes;
        }

        static byte[] CalculateFileManifest(string filePath, HashAlgorithmType hashAlgorithm, byte[] key)
        {
            byte[] encryptedFileSignature = new byte[256];
            switch (hashAlgorithm)
            {
                case HashAlgorithmType.SHA2_256:
                    return CalculateSha2_256(filePath, key);

                case HashAlgorithmType.SHA2_384:
                    return CalculateSha2_384(filePath, key);

                case HashAlgorithmType.SHA2_512:
                    return CalculateSha2_512(filePath, key);

                case HashAlgorithmType.SHA3_256:
                    return CalculateSha3_256(filePath, key);

                case HashAlgorithmType.SHA3_384:
                    return CalculateSha3_384(filePath, key);

                case HashAlgorithmType.SHA3_512:
                    return CalculateSha3_512(filePath, key);

                default:
                    return encryptedFileSignature;
            }
        }

        static byte[] CalculateSha2_256(string filePath, byte[] key)
        {
            byte[] sha256;
            using (var sha = new HMACSHA256(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha256 = sha.ComputeHash(fs);
            }

            return sha256;
        }

        static byte[] CalculateSha2_384(string filePath, byte[] key)
        {
            byte[] sha384;
            using (var sha = new HMACSHA384(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha384 = sha.ComputeHash(fs);
            }

            return sha384;
        }

        static byte[] CalculateSha2_512(string filePath, byte[] key)
        {
            byte[] sha512;
            using (var sha = new HMACSHA512(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha512 = sha.ComputeHash(fs);
            }

            return sha512;
        }

        static byte[] CalculateSha3_256(string filePath, byte[] key)
        {
            var sha3 = Sha3Permutation.Sha3_256();
            var fileBytes = File.ReadAllBytes(filePath);
            var sha256 = sha3.Process(fileBytes, 256, fileBytes.Length);

            return sha256;
        }

        static byte[] CalculateSha3_384(string filePath, byte[] key)
        {
            var sha3 = Sha3Permutation.Sha3_384();
            var fileBytes = File.ReadAllBytes(filePath);
            var sha384 = sha3.Process(fileBytes, 384, fileBytes.Length);

            return sha384;
        }

        static byte[] CalculateSha3_512(string filePath, byte[] key)
        {
            var sha3 = Sha3Permutation.Sha3_512();
            var fileBytes = File.ReadAllBytes(filePath);
            var sha512 = sha3.Process(fileBytes, 512, fileBytes.Length);

            return sha512;
        }

        static EncryptedFileInfo CreateInfoXml(
            string fileName,
            string encryptedFileName,
            byte[] signature,
            byte[] signatureKey,
            HashAlgorithmType hashAlgorithm,
            byte[] encryptionKey,
            byte[] encryptionIv,
            string rsaKey)
        {
            var fileEncryptionAlgorithmType = CipherAlgorithmType.Aes128;
            var encryptedAesKey = ToBase64String(EncryptBytesRsa(encryptionKey, rsaKey));
            var encryptedAesIv = ToBase64String(EncryptBytesRsa(encryptionIv, rsaKey));
            var fileManifestKeyEncryptionAlgorithmType = ExchangeAlgorithmType.RsaKeyX;
            var encryptedFileManifest = ToBase64String(signature);
            var encryptedFileManifestKey = ToBase64String(EncryptBytesRsa(signatureKey, rsaKey));

            var encryptedFileInfo = new EncryptedFileInfo
            {
                FileName = fileName,
                EncryptedFileName = encryptedFileName,
                FileEncryptionAlgorithmType = fileEncryptionAlgorithmType,
                EncryptedAesKey = encryptedAesKey,
                EncryptedAesIv = encryptedAesIv,
                FileManifestHashAlgorithmType = hashAlgorithm,
                EncryptedFileManifest = encryptedFileManifest,
                FileManifestKeyEncryptionAlgorithmType = fileManifestKeyEncryptionAlgorithmType,
                EncryptedFileManifestKey = encryptedFileManifestKey
            };

            return encryptedFileInfo;
        }

        static byte[] EncryptBytesRsa(byte[] bytes, string publicRsaKeyXml)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                RsaKeyExtensions.FromXmlString(rsa, publicRsaKeyXml);
                encrypted = rsa.Encrypt(bytes, true);
            }

            return encrypted;
        }

        static byte[] DecryptBytesRsa(byte[] bytes, string privateRsaKeyXml)
        {
            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                RsaKeyExtensions.FromXmlString(rsa, privateRsaKeyXml);
                decrypted = rsa.Decrypt(bytes, true);
            }

            return decrypted;
        }

        static Result Decrypt(string encryptedFilePath, EncryptedFileInfo infoXml, string privateRsaKeyXmlFilePath)
        {
            var folderPath = Path.GetDirectoryName(encryptedFilePath);
            var privateRsaKey = ReadRsaKeyXmlFromFile(privateRsaKeyXmlFilePath);
            var fileName = infoXml.FileName;
            var filePath = Path.Combine(folderPath, fileName);

            var aesKey = DecryptBytesRsa(FromBase64String(infoXml.EncryptedAesKey), privateRsaKey);
            var aesIv = DecryptBytesRsa(FromBase64String(infoXml.EncryptedAesIv), privateRsaKey);

            var hashAlgorithm = infoXml.FileManifestHashAlgorithmType;
            var signatureKey = DecryptBytesRsa(FromBase64String(infoXml.EncryptedFileManifestKey), privateRsaKey);
            var signatureCalculated = ToBase64String(CalculateFileManifest(encryptedFilePath, hashAlgorithm, signatureKey));
            var signatureFromXmlFile = infoXml.EncryptedFileManifest;

            if (signatureFromXmlFile != signatureCalculated)
            {
                return Result.Fail(
                    "File manifest calculated for the encrypted file does not match the value in the XML doc. File may have been modified, aborting decryption operation.");
            }

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 128;
                aes.Key = aesKey;
                aes.IV = aesIv;
                var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (var fsPlain = File.Open(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var fsEncrypted = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var cs = new CryptoStream(fsPlain, decryptor, CryptoStreamMode.Write))
                {
                    fsEncrypted.CopyTo(cs);
                }
            }

            return Result.Ok();
        }
    }
}
