namespace AaronLuna.Crypto
{
    using System;
    using System.Security.Cryptography;
    using System.Xml;

    static class RsaKeyExtensions
    {
        public static void FromXmlString(this RSA rsa, string xmlString)
        {
            RSAParameters parameters = new RSAParameters();
            XmlDocument xmlDoc = new XmlDocument();
            xmlDoc.LoadXml(xmlString);

            if (xmlDoc.DocumentElement.Name.Equals("RSAKeyValue"))
            {
                foreach (XmlNode node in xmlDoc.DocumentElement.ChildNodes)
                {
                    switch (node.Name)
                    {
                        case "Modulus": parameters.Modulus = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Exponent": parameters.Exponent = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "P": parameters.P = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "Q": parameters.Q = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DP": parameters.DP = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "DQ": parameters.DQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "InverseQ": parameters.InverseQ = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                        case "D": parameters.D = (string.IsNullOrEmpty(node.InnerText) ? null : Convert.FromBase64String(node.InnerText)); break;
                    }
                }
            }
            else
            {
                throw new Exception("Invalid XML RSA key.");
            }

            rsa.ImportParameters(parameters);
        }

        public static string ToXmlString(this RSA rsa, bool includePrivateParameters)
        {
            RSAParameters parameters = rsa.ExportParameters(includePrivateParameters);

            var modulus = parameters.Modulus != null
                ? Convert.ToBase64String(parameters.Modulus)
                : null;

            var exponent = parameters.Exponent != null
                ? Convert.ToBase64String(parameters.Exponent)
                : null;

            var p = parameters.P != null
                ? Convert.ToBase64String(parameters.P)
                : null;

            var q = parameters.Q != null
                ? Convert.ToBase64String(parameters.Q)
                : null;

            var dp = parameters.DP != null
                ? Convert.ToBase64String(parameters.DP)
                : null;

            var dq = parameters.DQ != null
                ? Convert.ToBase64String(parameters.DQ)
                : null;

            var inverseQ = parameters.InverseQ != null
                ? Convert.ToBase64String(parameters.InverseQ)
                : null;

            var d = parameters.D != null
                ? Convert.ToBase64String(parameters.D)
                : null;

            return
                $"<RSAKeyValue><Modulus>{modulus}</Modulus><Exponent>{exponent}</Exponent><P>{p}</P><Q>{q}</Q><DP>{dp}</DP><DQ>{dq}</DQ><InverseQ>{inverseQ}</InverseQ><D>{d}</D></RSAKeyValue>";
        }
    }
}
