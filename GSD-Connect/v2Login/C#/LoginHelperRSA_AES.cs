using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using System.Xml;

namespace GSD.REST_Lib
{
    internal class LoginHelperRSA_AES
    {
        private static RSA _rsaKeyPair = null;
        private static readonly object _lock = new object();

        public static void GenerateRSAKeyPair()
        {
            lock (_lock)
            {
                if (_rsaKeyPair == null)
                {
                    _rsaKeyPair = RSA.Create(4096);
                }
            }
        }

        public static string GetBase64PublicKey()
        {
            GenerateRSAKeyPair();
            byte[] publicKeyBytes = _rsaKeyPair.ExportSubjectPublicKeyInfo();
            string base64PublicKey = Convert.ToBase64String(publicKeyBytes);

            return "-----BEGIN PUBLIC KEY-----\n" +
                   InsertLineBreaks(base64PublicKey) +
                   "-----END PUBLIC KEY-----\n";
        }

        private static string InsertLineBreaks(string base64Key)
        {
            StringBuilder formattedKey = new StringBuilder();
            for (int i = 0; i < base64Key.Length; i += 64)
            {
                formattedKey.Append(base64Key.Substring(i, Math.Min(64, base64Key.Length - i))).Append("\n");
            }
            return formattedKey.ToString();
        }

        public static string EncryptRequest(string json, string publicKeyPem)
        {
            string publicKeyPEM = publicKeyPem.Replace("-----BEGIN PUBLIC KEY-----", "")
                                              .Replace("-----END PUBLIC KEY-----", "")
                                              .Replace("\n", "")
                                              .Replace("\r", "");
            byte[] publicKeyBytes = Convert.FromBase64String(publicKeyPEM);
            RSA clientRsa = RSA.Create();
            clientRsa.ImportSubjectPublicKeyInfo(publicKeyBytes, out _);

            using Aes aes = Aes.Create();
            aes.GenerateKey();
            byte[] responseAesKey = aes.Key;
            byte[] encryptedResponse = EncryptAES(Encoding.UTF8.GetBytes(json), responseAesKey);
            byte[] encryptedResponseAesKey = clientRsa.Encrypt(responseAesKey, RSAEncryptionPadding.OaepSHA256);

            // Base64-kodiert json erstellen
            GetBase64PublicKey();
            return $"{{\"aesKey\":\"{Convert.ToBase64String(encryptedResponseAesKey)}\",\"data\":\"{Convert.ToBase64String(encryptedResponse)}\",\"publicKey\":\"{Convert.ToBase64String(_rsaKeyPair.ExportSubjectPublicKeyInfo())}\"}}";
        }

        public static string DecryptResponse(string encryptedResponse)
        {
            string[] parts = encryptedResponse.Split('|');
            if (parts.Length != 2)
                throw new Exception("Invalid Response");
            // encryptedJson["aesKey"] und ["data"] müssen vorhanden sein
            byte[] encryptedAesKey = Convert.FromBase64String(parts[0]);
            byte[] encryptedData = Convert.FromBase64String(parts[1]);

            byte[] aesKey;
            try
            {
                aesKey = _rsaKeyPair.Decrypt(encryptedAesKey, RSAEncryptionPadding.OaepSHA256);
            }
            catch (Exception e)
            {
                throw new Exception("error in AES-Key");
            }
            try
            {
                string decryptedLogin = DecryptAES(encryptedData, aesKey);
                return decryptedLogin;
            }
            catch (Exception e)
            {
                throw new Exception("error in encrypted data");
            }
        }

        // AES-Verschlüsselung mit IV
        static byte[] EncryptAES(byte[] data, byte[] key)
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.GenerateIV();
            using var encryptor = aes.CreateEncryptor();
            byte[] encrypted = encryptor.TransformFinalBlock(data, 0, data.Length);
            return aes.IV.Concat(encrypted).ToArray();
        }

        // AES-Entschlüsselung
        static string DecryptAES(byte[] data, byte[] key)
        {
            using Aes aes = Aes.Create();
            aes.Key = key;
            aes.IV = data.Take(16).ToArray();
            using var decryptor = aes.CreateDecryptor();
            byte[] decrypted = decryptor.TransformFinalBlock(data, 16, data.Length - 16);
            return Encoding.UTF8.GetString(decrypted);
        }
    }
}