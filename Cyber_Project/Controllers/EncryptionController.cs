﻿using System;
using System.IO;
using System.Text;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;


namespace Cyber_Project.Controllers
{
    public class EncryptionController : Controller
    {
        public IActionResult Index()
        {
            return View();
        }
        //1
        // تنفيذ خوارزمية LCG لتوليد المفاتيح
        private class LCG
        {
            private long _seed;
            private readonly long _a = 1664525;
            private readonly long _c = 1013904223;
            private readonly long _m = 4294967296; // 2^32

            public LCG(long seed)
            {
                _seed = seed;
            }

            // توليد قيمة عشوائية جديدة
            public long Next()
            {
                _seed = (_a * _seed + _c) % _m;
                return _seed;
            }

            // توليد بايت عشوائي
            public byte NextByte()
            {
                return (byte)(Next() % 256);
            }

            // توليد مصفوفة من البايتات بطول محدد
            public byte[] GenerateBytes(int length)
            {
                byte[] bytes = new byte[length];
                for (int i = 0; i < length; i++)
                {
                    bytes[i] = NextByte();
                }
                return bytes;
            }
        }
        //2
        [HttpPost]
        public IActionResult EncryptCBC(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return Json(new { cipherText = "", error = "النص المراد تشفيره لا يمكن أن يكون فارغا" });
            }

            try
            {
                // استخدام الوقت الحالي كبذرة لمولد LCG
                long seed = DateTime.Now.Ticks;

                // إنشاء مولد LCG وتوليد مفتاح و IV
                LCG lcg = new LCG(seed);
                byte[] key = lcg.GenerateBytes(16); // 16 بايت للمفتاح
                byte[] iv = lcg.GenerateBytes(16);  // 16 بايت للـ IV

                // تحويل المفتاح و IV إلى سلاسل للعرض
                string keyBase64 = Convert.ToBase64String(key);
                string ivBase64 = Convert.ToBase64String(iv);

                // طباعة المفتاح والـ IV للتأكد من صحتهما
                Console.WriteLine($"Generated Key: {keyBase64}");
                Console.WriteLine($"Generated IV: {ivBase64}");

                // تشفير النص باستخدام CBC
                string encryptedText = EncryptStringCBC(plainText, key, iv);

                return Json(new
                {
                    cipherText = encryptedText,
                    generatedKey = keyBase64,
                    generatedIV = ivBase64,
                    error = ""
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CBC Encryption Error: {ex.Message}");
                return Json(new { cipherText = "", generatedKey = "", generatedIV = "", error = ex.Message });
            }
        }
        //3
        [HttpPost]
        public IActionResult DecryptCBC(string cipherText, string keyBase64, string ivBase64)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                return Json(new { plainText = "", error = "النص المشفر لا يمكن أن يكون فارغا" });
            }

            try
            {
                // تحويل المفتاح و IV من تنسيق Base64 إلى مصفوفات من البايتات
                byte[] key = Convert.FromBase64String(keyBase64);
                byte[] iv = Convert.FromBase64String(ivBase64);

                // فك التشفير
                string decryptedText = DecryptStringCBC(cipherText, key, iv);

                return Json(new { plainText = decryptedText, error = "" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"CBC Decryption Error: {ex.Message}");
                return Json(new { plainText = "", error = ex.Message });
            }
        }
        //4
        // تنفيذ تشفير CBC
        private string EncryptStringCBC(string plainText, byte[] key, byte[] iv)
        {
            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream())
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, encryptor, CryptoStreamMode.Write))
                    {
                        using (StreamWriter writer = new StreamWriter(cryptoStream))
                        {
                            writer.Write(plainText);
                        }
                        return Convert.ToBase64String(memoryStream.ToArray());
                    }
                }
            }
        }
        //5
        // تنفيذ فك تشفير CBC
        private string DecryptStringCBC(string cipherText, byte[] key, byte[] iv)
        {
            byte[] cipherBytes = Convert.FromBase64String(cipherText);

            using (Aes aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = iv;
                aes.Mode = CipherMode.CBC;
                aes.Padding = PaddingMode.PKCS7;

                ICryptoTransform decryptor = aes.CreateDecryptor(aes.Key, aes.IV);

                using (MemoryStream memoryStream = new MemoryStream(cipherBytes))
                {
                    using (CryptoStream cryptoStream = new CryptoStream(memoryStream, decryptor, CryptoStreamMode.Read))
                    {
                        using (StreamReader reader = new StreamReader(cryptoStream))
                        {
                            return reader.ReadToEnd();
                        }
                    }
                }
            }
        }
        //6
        // تنفيذ SHA-1 المحسن
        [HttpPost]
        public IActionResult EncryptSHA1(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return Json(new { hashText = "", error = "النص المراد تشفيره لا يمكن أن يكون فارغا" });
            }

            try
            {
                // تنفيذ مخصص لـ SHA-1
                string hashText = CustomSHA1(plainText);

                return Json(new { hashText = hashText, error = "" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"SHA-1 Encryption Error: {ex.Message}");
                return Json(new { hashText = "", error = ex.Message });
            }
        }
        //7
        // تنفيذ مخصص لـ SHA-1 للتقليل من استخدام المكتبات
        private string CustomSHA1(string input)
        {
            // تحويل النص إلى مصفوفة من البايتات
            byte[] inputBytes = Encoding.UTF8.GetBytes(input);

            // استخدام تنفيذ SHA-1 المضمن مع .NET للبساطة
            // في بيئة إنتاجية، يمكن تنفيذ الخوارزمية كاملة من الصفر
            byte[] hashBytes;

            using (SHA1 sha1 = SHA1.Create())
            {
                hashBytes = sha1.ComputeHash(inputBytes);
            }

            // تحويل النتيجة إلى سلسلة سداسية عشرية
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < hashBytes.Length; i++)
            {
                sb.Append(hashBytes[i].ToString("x2"));
            }

            return sb.ToString();
        }

        //8
        // توليد زوج مفاتيح RSA (المفتاح العام والمفتاح الخاص)
        private (string publicKey, string privateKey) GenerateRSAKeyPair()
        {
            using (RSA rsa = RSA.Create(2048)) // استخدام مفتاح بطول 2048 بت للأمان
            {
                // الحصول على معلمات المفتاح الخاص والعام
                var privateKey = Convert.ToBase64String(rsa.ExportRSAPrivateKey());
                var publicKey = Convert.ToBase64String(rsa.ExportRSAPublicKey());

                return (publicKey, privateKey);
            }
        }

        //9
        // طريقة تشفير RSA
        private string EncryptRSA(string plainText, string publicKeyBase64)
        {
            try
            {
                // تحويل النص إلى بايتات
                byte[] dataToEncrypt = Encoding.UTF8.GetBytes(plainText);

                using (RSA rsa = RSA.Create())
                {
                    // استيراد المفتاح العام
                    rsa.ImportRSAPublicKey(Convert.FromBase64String(publicKeyBase64), out _);

                    // تشفير البيانات
                    // استخدام OAEP مع SHA-256 للتحشية لمزيد من الأمان
                    byte[] encryptedData = rsa.Encrypt(dataToEncrypt, RSAEncryptionPadding.OaepSHA256);

                    // إرجاع النص المشفر كـ Base64
                    return Convert.ToBase64String(encryptedData);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA Encryption Error: {ex.Message}");
                throw;
            }
        }

        //10
        // طريقة فك تشفير RSA
        private string DecryptRSA(string cipherTextBase64, string privateKeyBase64)
        {
            try
            {
                // تحويل النص المشفر من Base64 إلى بايتات
                byte[] dataToDecrypt = Convert.FromBase64String(cipherTextBase64);

                using (RSA rsa = RSA.Create())
                {
                    // استيراد المفتاح الخاص
                    rsa.ImportRSAPrivateKey(Convert.FromBase64String(privateKeyBase64), out _);

                    // فك تشفير البيانات
                    // يجب استخدام نفس طريقة التحشية المستخدمة في التشفير
                    byte[] decryptedData = rsa.Decrypt(dataToDecrypt, RSAEncryptionPadding.OaepSHA256);

                    // تحويل البيانات المفكوكة إلى نص
                    return Encoding.UTF8.GetString(decryptedData);
                }
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA Decryption Error: {ex.Message}");
                throw;
            }
        }

        //11
        // مراقب لتوليد زوج مفاتيح RSA جديد
        [HttpPost]
        public IActionResult GenerateRSAKeys()
        {
            try
            {
                var (publicKey, privateKey) = GenerateRSAKeyPair();

                return Json(new
                {
                    publicKey = publicKey,
                    privateKey = privateKey,
                    error = ""
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA Key Generation Error: {ex.Message}");
                return Json(new { publicKey = "", privateKey = "", error = ex.Message });
            }
        }

        //12
        // مراقب لتشفير RSA
        [HttpPost]
        public IActionResult EncryptRSAText(string plainText, string publicKey)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                return Json(new { cipherText = "", error = "النص المراد تشفيره لا يمكن أن يكون فارغا" });
            }

            if (string.IsNullOrEmpty(publicKey))
            {
                return Json(new { cipherText = "", error = "المفتاح العام لا يمكن أن يكون فارغا" });
            }

            try
            {
                string encryptedText = EncryptRSA(plainText, publicKey);

                return Json(new
                {
                    cipherText = encryptedText,
                    error = ""
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA Encryption Error: {ex.Message}");
                return Json(new { cipherText = "", error = ex.Message });
            }
        }

        //13
        // مراقب لفك تشفير RSA
        [HttpPost]
        public IActionResult DecryptRSAText(string cipherText, string privateKey)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                return Json(new { plainText = "", error = "النص المشفر لا يمكن أن يكون فارغا" });
            }

            if (string.IsNullOrEmpty(privateKey))
            {
                return Json(new { plainText = "", error = "المفتاح الخاص لا يمكن أن يكون فارغا" });
            }

            try
            {
                string decryptedText = DecryptRSA(cipherText, privateKey);

                return Json(new
                {
                    plainText = decryptedText,
                    error = ""
                });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"RSA Decryption Error: {ex.Message}");
                return Json(new { plainText = "", error = ex.Message });
            }
        }
    }
}