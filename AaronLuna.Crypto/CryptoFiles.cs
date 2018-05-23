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
        public static async Task<Result<EncryptedFileInfo>> EncryptFileAsync(
            string filePath,
            string publicKeyXmlFilePath,
            HashAlgorithmType hashAlgorithm = HashAlgorithmType.SHA2_256)
        {
            var folderPath = Path.GetDirectoryName(filePath);
            var encryptedFileName = $"{Path.GetFileName(filePath)}.encrypted";
            var infoXmlFilePath = Path.Combine(folderPath, $"{encryptedFileName}.xml");

            EncryptedFileInfo infoXml;
            try
            {
                var publicKeyXml = CryptoKeys.ReadXmlKeyFromFile(publicKeyXmlFilePath);
                infoXml = await Task.Factory.StartNew(() => Encrypt(filePath, publicKeyXml, hashAlgorithm));
            }
            catch (FileNotFoundException ex)
            {
                return Result.Fail<EncryptedFileInfo>($"{ex.Message} {ex.GetType()}");
            }

            var serializationResult = EncryptedFileInfo.SaveToFile(infoXml, infoXmlFilePath);

            return serializationResult.Success
                ? Result.Ok(infoXml)
                : Result.Fail<EncryptedFileInfo>("Error occurred serializing encrypted file info to XML.");
        }

        public static async Task<Result> DecryptFileAsync(
            string encryptedFilePath,
            string privateKeyXmlFilePath,
            string encryptedFileInfoXmlFilePath)
        {
            Result decryptResult;
            try
            {
                var deserializationResult = EncryptedFileInfo.ReadFromFile(encryptedFileInfoXmlFilePath);
                if (deserializationResult.Failure)
                {
                    return Result.Fail(
                        "An error occurred reading the encryption info XML file, unable to continue decrypting file.");
                }

                var encryptionInfoXml = deserializationResult.Value;
                var privateKeyXml = CryptoKeys.ReadXmlKeyFromFile(privateKeyXmlFilePath);

                decryptResult = await Task.Factory.StartNew(() => Decrypt(encryptedFilePath, encryptionInfoXml, privateKeyXml));
            }
            catch (Exception ex)
            {
                return Result.Fail($"{ex.Message} {ex.GetType()}");
            }

            return decryptResult;
        }

        static EncryptedFileInfo Encrypt(string filePath, string publicKeyXml, HashAlgorithmType hashAlgorithm)
        {
            var folderPath = Path.GetDirectoryName(filePath);
            var fileName = Path.GetFileName(filePath);
            var encryptedFileName = $"{fileName}.encrypted";
            var encryptedFilePath = Path.Combine(folderPath, encryptedFileName);

            var signatureKey = CryptoRandom.GetRandomBytes(64);
            var encryptionKey = CryptoRandom.GetRandomBytes(16);
            var encryptionIv = CryptoRandom.GetRandomBytes(16);

            using (var aes = new AesCryptoServiceProvider { KeySize = 128, Key = encryptionKey, IV = encryptionIv })
            using (var encryptor = aes.CreateEncryptor())
            using (var fsInput = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            using (var fsEncrypted = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
            using (var cs = new CryptoStream(fsEncrypted, encryptor, CryptoStreamMode.Write))
            {
                fsInput.CopyTo(cs);
            }

            var encryptedAesKey = Convert.ToBase64String(EncryptBytesRsa(encryptionKey, publicKeyXml));
            var encryptedAesIv = Convert.ToBase64String(EncryptBytesRsa(encryptionIv, publicKeyXml));

            var encryptedFileDigestKey = Convert.ToBase64String(EncryptBytesRsa(signatureKey, publicKeyXml));
            var encryptedFileDigestBytes = CryptoHashers.CalculateFileDigest(encryptedFilePath, hashAlgorithm, signatureKey);
            var encryptedFileDigest = Convert.ToBase64String(encryptedFileDigestBytes);

            return new EncryptedFileInfo
            {
                FileName = fileName,
                EncryptedFileName = encryptedFileName,
                FileEncryptionAlgorithmType = CipherAlgorithmType.Aes128,
                EncryptedAesKey = encryptedAesKey,
                EncryptedAesIv = encryptedAesIv,
                FileDigestHashAlgorithmType = hashAlgorithm,
                EncryptedFileDigest = encryptedFileDigest,
                FileDigestKeyEncryptionAlgorithmType = ExchangeAlgorithmType.RsaKeyX,
                EncryptedFileDigestKey = encryptedFileDigestKey
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

        static Result Decrypt(string encryptedFilePath, EncryptedFileInfo encryptionInfoXml, string privateKeyXml)
        {
            var folderPath = Path.GetDirectoryName(encryptedFilePath);
            var filePath = Path.Combine(folderPath, encryptionInfoXml.FileName);

            var aesKey = DecryptBytesRsa(Convert.FromBase64String(encryptionInfoXml.EncryptedAesKey), privateKeyXml);
            var aesIv = DecryptBytesRsa(Convert.FromBase64String(encryptionInfoXml.EncryptedAesIv), privateKeyXml);

            var signatureKey = DecryptBytesRsa(Convert.FromBase64String(encryptionInfoXml.EncryptedFileDigestKey), privateKeyXml);
            var signatureCalculated = Convert.ToBase64String(CryptoHashers.CalculateFileDigest(encryptedFilePath, encryptionInfoXml.FileDigestHashAlgorithmType, signatureKey));
            var signatureTransmitted = encryptionInfoXml.EncryptedFileDigest;

            if (signatureTransmitted != signatureCalculated)
            {
                return Result.Fail(
                    "File manifest calculated for the encrypted file does not match the value in the XML doc. File may have been modified, aborting decryption operation.");
            }

            using (var aes = new AesCryptoServiceProvider { KeySize = 128, Key = aesKey, IV = aesIv })
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
