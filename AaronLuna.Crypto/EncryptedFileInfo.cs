namespace AaronLuna.Crypto
{
    using System;
    using System.IO;
    using System.Security.Authentication;
    using System.Xml.Serialization;

    using Common.Result;

    public class EncryptedFileInfo
    {
        public string FileName { get; set; }
        public string EncryptedFileName { get; set; }

        public CipherAlgorithmType FileEncryptionAlgorithmType { get; set; }
        public string EncryptedAesKey { get; set; }
        public string EncryptedAesIv { get; set; }

        public HashAlgorithmType FileDigestHashAlgorithmType { get; set; }
        public string EncryptedFileDigest { get; set; }

        public ExchangeAlgorithmType FileDigestKeyEncryptionAlgorithmType { get; set; }
        public string EncryptedFileDigestKey { get; set; }

        public static Result Serialize(EncryptedFileInfo fileInfo, string filePath)
        {
            try
            {
                var serializer = new XmlSerializer(typeof(EncryptedFileInfo));
                using (var writer = new StreamWriter(filePath))
                {
                    serializer.Serialize(writer, fileInfo);
                }
            }
            catch (FileNotFoundException ex)
            {
                return Result.Fail<EncryptedFileInfo>($"{ex.Message} ({ex.GetType()})");
            }

            return Result.Ok();
        }

        public static Result<EncryptedFileInfo> Deserialize(string filePath)
        {
            EncryptedFileInfo fileInfo;
            try
            {
                var deserializer = new XmlSerializer(typeof(EncryptedFileInfo));
                using (var reader = new StreamReader(filePath))
                {
                    fileInfo = (EncryptedFileInfo)deserializer.Deserialize(reader);
                }
            }
            catch (Exception ex)
            {
                return Result.Fail<EncryptedFileInfo>($"{ex.Message} ({ex.GetType()})");
            }

            return Result.Ok(fileInfo);
        }
    }
}
