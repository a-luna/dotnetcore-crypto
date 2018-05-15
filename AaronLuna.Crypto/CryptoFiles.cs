namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Threading.Tasks;

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

            var encryptedFileSignature = CryptoHashers.CalculateFileDigest(encryptedFilePath, hashAlgorithm, signatureKey);
            var publicRsaKey = CryptoKeys.ReadRsaXmlKeyFromFile(publicRsaKeyXmlFilePath);

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
        
        static byte[] GetRandomBytes(int length)
        {
            byte[] bytes = new byte[length];
            using (RNGCryptoServiceProvider random = new RNGCryptoServiceProvider())
            {
                random.GetBytes(bytes);
            }

            return bytes;
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
            var encryptedAesKey = Convert.ToBase64String(EncryptBytesRsa(encryptionKey, rsaKey));
            var encryptedAesIv = Convert.ToBase64String(EncryptBytesRsa(encryptionIv, rsaKey));
            var encryptedFileManifest = Convert.ToBase64String(signature);
            var encryptedFileManifestKey = Convert.ToBase64String(EncryptBytesRsa(signatureKey, rsaKey));

            return new EncryptedFileInfo
            {
                FileName = fileName,
                EncryptedFileName = encryptedFileName,
                FileEncryptionAlgorithmType = CipherAlgorithmType.Aes128,
                EncryptedAesKey = encryptedAesKey,
                EncryptedAesIv = encryptedAesIv,
                FileManifestHashAlgorithmType = hashAlgorithm,
                EncryptedFileManifest = encryptedFileManifest,
                FileManifestKeyEncryptionAlgorithmType = ExchangeAlgorithmType.RsaKeyX,
                EncryptedFileManifestKey = encryptedFileManifestKey
            };
        }

        static byte[] EncryptBytesRsa(byte[] bytes, string publicRsaKeyXml)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXml(publicRsaKeyXml);
                encrypted = rsa.Encrypt(bytes, true);
            }

            return encrypted;
        }

        static byte[] DecryptBytesRsa(byte[] bytes, string privateRsaKeyXml)
        {
            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXml(privateRsaKeyXml);
                decrypted = rsa.Decrypt(bytes, true);
            }

            return decrypted;
        }

        static Result Decrypt(string encryptedFilePath, EncryptedFileInfo infoXml, string privateRsaKeyXmlFilePath)
        {
            var folderPath = Path.GetDirectoryName(encryptedFilePath);
            var filePath = Path.Combine(folderPath, infoXml.FileName);

            var privateRsaKey = CryptoKeys.ReadRsaXmlKeyFromFile(privateRsaKeyXmlFilePath);
            var aesKey = DecryptBytesRsa(Convert.FromBase64String(infoXml.EncryptedAesKey), privateRsaKey);
            var aesIv = DecryptBytesRsa(Convert.FromBase64String(infoXml.EncryptedAesIv), privateRsaKey);
            
            var signatureKey = DecryptBytesRsa(Convert.FromBase64String(infoXml.EncryptedFileManifestKey), privateRsaKey);
            var signatureCalculated = Convert.ToBase64String(CryptoHashers.CalculateFileDigest(encryptedFilePath, infoXml.FileManifestHashAlgorithmType, signatureKey));
            var signatureTransmitted = infoXml.EncryptedFileManifest;

            if (signatureTransmitted != signatureCalculated)
            {
                return Result.Fail(
                    "File manifest calculated for the encrypted file does not match the value in the XML doc. File may have been modified, aborting decryption operation.");
            }

            using (var aes = new AesCryptoServiceProvider {KeySize = 128, Key = aesKey, IV = aesIv })
            using (var decryptor = aes.CreateDecryptor())
            using (var fsPlain = File.Open(filePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var fsEncrypted = File.Open(encryptedFilePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var cs = new CryptoStream(fsPlain, decryptor, CryptoStreamMode.Write))
            {
                fsEncrypted.CopyTo(cs);
            }

            return Result.Ok();
        }
    }
}
