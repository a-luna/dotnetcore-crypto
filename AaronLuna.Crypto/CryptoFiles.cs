namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Linq;
    using System.Security.Authentication;
    using System.Security.Cryptography;
    using System.Threading.Tasks;
    using System.Xml.Linq;
    using System.Xml.XPath;
    using static System.Convert;

    using Common.Result;

    public static class CryptoFiles
    {
        public static async Task<Result> EncryptFileAsync(string filePath, string publicRsaKeyXmlFilePath)
        {
            try
            {
                await Task.Factory.StartNew(() => Encrypt(filePath, publicRsaKeyXmlFilePath));
            }
            catch (Exception ex)
            {
                return Result.Fail($"{ex.Message} {ex.GetType()}");
            }

            return Result.Ok();
        }

        public static async Task<Result> DecryptFileAsync(string infoXmlFilePath, string privateRsaKeyXmlFilePath)
        {
            Result decryptResult;
            try
            {
                decryptResult = await Task.Factory.StartNew(() => Decrypt(infoXmlFilePath, privateRsaKeyXmlFilePath));

            }
            catch (Exception ex)
            {
                return Result.Fail($"{ex.Message} {ex.GetType()}");
            }

            return decryptResult;
        }

        static void Encrypt(string filePath, string publicRsaKeyXmlFilePath)
        {
            var folderPath = Path.GetDirectoryName(filePath);
            var fileName = Path.GetFileName(filePath);
            var encryptedFileName = $"{fileName}.encrypted";
            var encryptedFilePath = Path.Combine(folderPath, encryptedFileName);
            var infoXmlFilePath = Path.Combine(folderPath, $"{fileName}.info.xml");

            var signatureKey = GetRandomBytes(64);
            var encryptionKey = GetRandomBytes(16);
            var encryptionIv = GetRandomBytes(16);

            using (var aes = new AesCryptoServiceProvider())
            {
                aes.KeySize = 128;
                aes.Key = encryptionKey;
                aes.IV = encryptionIv;

                using (var encryptor = aes.CreateEncryptor(aes.Key, aes.IV))
                using (var fsInput = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
                using (var fsEncrypted = File.Open(encryptedFilePath, FileMode.Create, FileAccess.Write, FileShare.None))
                using (var cs = new CryptoStream(fsEncrypted, encryptor, CryptoStreamMode.Write))
                {
                    fsInput.CopyTo(cs);
                }
            }

            var encryptedFileSignature = CalculateSha256(encryptedFilePath, signatureKey);
            var publicRsaKey = ReadRsaKeyXmlFromFile(publicRsaKeyXmlFilePath);

            CreateInfoXml(
                fileName,
                encryptedFileName,
                encryptedFileSignature,
                signatureKey,
                encryptionKey,
                encryptionIv,
                publicRsaKey,
                infoXmlFilePath);
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

        static byte[] CalculateSha256(string filePath, byte[] key)
        {
            byte[] sha256;
            using (var sha = new HMACSHA256(key))
            using (var fs = File.Open(filePath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                sha256 = sha.ComputeHash(fs);
            }

            return sha256;
        }

        static void CreateInfoXml(
            string fileName,
            string encryptedFileName,
            byte[] signature,
            byte[] signatureKey,
            byte[] encryptionKey,
            byte[] encryptionIv,
            string rsaKey,
            string manifestFilePath)
        {
            var testFolder = @"C:\Users\aaronluna\source\repos\dotnetcore-crypto\AaronLuna.Crypto.Test\TestFiles\CryptoFilesTestFixture";
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
                FileManifestHashAlgorithmType = "SHA2_256",
                EncryptedFileManifest = encryptedFileManifest,
                FileManifestKeyEncryptionAlgorithmType = fileManifestKeyEncryptionAlgorithmType,
                EncryptedFileManifestKey = encryptedFileManifestKey
            };

            EncryptedFileInfo.Serialize(encryptedFileInfo, Path.Combine(testFolder, $"{fileName}.encrypted.pdf.xml"));

            var template = "<DataInfo>" +
                              $"<FileName>{fileName}</FileName>" +
                              $"<EncryptedFileName>{encryptedFileName}</EncryptedFileName>" +
                              "<DataEncryption algorithm='AES128'>" +
                              "<AESEncryptedKeyValue>" +
                              "<Key/>" +
                              "<IV/>" +
                              "</AESEncryptedKeyValue>" +
                              "</DataEncryption>" +
                              "<DataSignature algorithm='HMACSHA256'>" +
                              "<Value />" +
                              "<EncryptedKey />" +
                              "<KeyEncryption algorithm='RSA2048'>" +
                              "</KeyEncryption>" +
                              "</DataSignature>" +
                              "</DataInfo>";

            var doc = XDocument.Parse(template);

            doc.Descendants("DataEncryption")
                .Single().Descendants("AESEncryptedKeyValue")
                .Single().Descendants("Key")
                .Single().Value = encryptedAesKey;

            doc.Descendants("DataEncryption")
                .Single().Descendants("AESEncryptedKeyValue")
                .Single().Descendants("IV")
                .Single().Value = encryptedAesIv;

            doc.Descendants("DataSignature")
                .Single().Descendants("Value")
                .Single().Value = encryptedFileManifest;

            doc.Descendants("DataSignature")
                .Single().Descendants("EncryptedKey")
                .Single().Value = encryptedFileManifestKey;

            doc.Save(manifestFilePath);
        }

        static byte[] EncryptBytesRsa(byte[] bytes, string publicRsaKeyXml)
        {
            byte[] encrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(publicRsaKeyXml);
                encrypted = rsa.Encrypt(bytes, true);
            }

            return encrypted;
        }

        static byte[] DecryptBytesRsa(byte[] bytes, string privateRsaKeyXml)
        {
            byte[] decrypted;
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                rsa.FromXmlString(privateRsaKeyXml);
                decrypted = rsa.Decrypt(bytes, true);
            }

            return decrypted;
        }

        static Result Decrypt(string infoXmlFilePath, string privateRsaKeyXmlFilePath)
        {
            var testFolder = @"C:\Users\aaronluna\source\repos\dotnetcore-crypto\AaronLuna.Crypto.Test\TestFiles\CryptoFilesTestFixture";
            var encryptedFileInfo = EncryptedFileInfo.Deserialize(Path.Combine(testFolder, "Usage.pdf.encrypted.xml"));

            var folderPath = Path.GetDirectoryName(infoXmlFilePath);
            var privateRsaKey = ReadRsaKeyXmlFromFile(privateRsaKeyXmlFilePath);

            var xmlDoc = XDocument.Load(infoXmlFilePath);
            var fileName = xmlDoc.Root.XPathSelectElement("./FileName").Value;
            var filePath = Path.Combine(folderPath, fileName);

            var encryptedFileName = xmlDoc.Root.XPathSelectElement("./EncryptedFileName").Value;
            var encryptedFilePath = Path.Combine(folderPath, encryptedFileName);

            var aesKeyElement = xmlDoc.Root.XPathSelectElement("./DataEncryption/AESEncryptedKeyValue/Key");
            var aesKey = DecryptBytesRsa(FromBase64String(aesKeyElement.Value), privateRsaKey);

            var aesIvElement = xmlDoc.Root.XPathSelectElement("./DataEncryption/AESEncryptedKeyValue/IV");
            var aesIv = DecryptBytesRsa(FromBase64String(aesIvElement.Value), privateRsaKey);

            var dataSignatureElement = xmlDoc.Root.XPathSelectElement("./DataSignature/Value");
            var encryptedFileSignatureFromFileBytes = FromBase64String(dataSignatureElement.Value);
            var encryptedFileSignatureFromFileString = dataSignatureElement.Value;

            var dataSigEncryptedKeyElement = xmlDoc.Root.XPathSelectElement("./DataSignature/EncryptedKey");
            var signatureKey = DecryptBytesRsa(FromBase64String(dataSigEncryptedKeyElement.Value), privateRsaKey);

            var encryptedFileSignatureCalculatedBytes = CalculateSha256(encryptedFilePath, signatureKey);
            var encryptedFileSignatureCalculatedString = ToBase64String(encryptedFileSignatureCalculatedBytes);
            
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
