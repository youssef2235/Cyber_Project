
using System.Text;
using Microsoft.AspNetCore.Mvc;


namespace Cyber_Project.Controllers
{
    public class EncryptionController : Controller
    {
        private const long a = 1664525;
        private const long c = 1013904223;
        private const long m = 4294967296; // 2^32

        // Default seed and block size
        private const int DefaultBlockSize = 16; // 16 bytes = 128 bits

        public IActionResult Index()
        {
            return View();
        }

        [HttpPost]
        public IActionResult Encrypt(string plainText, long seed)
        {
            if (string.IsNullOrEmpty(plainText))
            {
                TempData["ErrorMessage"] = "النص المراد تشفيره لا يمكن أن يكون فارغاً";
                return RedirectToAction("Index");
            }

            // Generate encryption key using LCG
            byte[] key = GenerateKeyFromLCG(seed, DefaultBlockSize);

            // Generate IV (could be random, but using a fixed one derived from seed for simplicity)
            byte[] iv = GenerateIVFromSeed(seed, DefaultBlockSize);

            // Encrypt using CBC mode
            byte[] cipherBytes = EncryptCBC(Encoding.UTF8.GetBytes(plainText), key, iv);

            // Convert to Base64 for display
            string cipherText = Convert.ToBase64String(cipherBytes);

            // Convert key and IV to hex strings for display
            string keyHex = BitConverter.ToString(key).Replace("-", "");
            string ivHex = BitConverter.ToString(iv).Replace("-", "");

            ViewBag.CipherText = cipherText;
            ViewBag.PlainText = plainText;
            ViewBag.Seed = seed;
            ViewBag.Key = keyHex;
            ViewBag.IV = ivHex;

            return View("Result");
        }

        [HttpPost]
        public IActionResult Decrypt(string cipherText, long seed)
        {
            if (string.IsNullOrEmpty(cipherText))
            {
                TempData["ErrorMessage"] = "النص المشفر لا يمكن أن يكون فارغاً";
                return RedirectToAction("Index");
            }

            try
            {
                // Generate the same key using LCG with the same seed
                byte[] key = GenerateKeyFromLCG(seed, DefaultBlockSize);

                // Generate the same IV from seed
                byte[] iv = GenerateIVFromSeed(seed, DefaultBlockSize);

                // Convert from Base64
                byte[] cipherBytes = Convert.FromBase64String(cipherText);

                // Decrypt using CBC mode
                byte[] plainBytes = DecryptCBC(cipherBytes, key, iv);

                // Convert back to string
                string plainText = Encoding.UTF8.GetString(plainBytes);

                // Convert key and IV to hex strings for display
                string keyHex = BitConverter.ToString(key).Replace("-", "");
                string ivHex = BitConverter.ToString(iv).Replace("-", "");

                ViewBag.PlainText = plainText;
                ViewBag.CipherText = cipherText;
                ViewBag.Seed = seed;
                ViewBag.Key = keyHex;
                ViewBag.IV = ivHex;

                return View("Result");
            }
            catch (Exception ex)
            {
                TempData["ErrorMessage"] = $"خطأ في فك التشفير: {ex.Message}";
                return RedirectToAction("Index");
            }
        }

        private byte[] GenerateKeyFromLCG(long seed, int keyLength)
        {
            byte[] key = new byte[keyLength];
            long currentValue = seed;

            for (int i = 0; i < keyLength; i++)
            {
                // Generate next value using LCG formula: X_n+1 = (a * X_n + c) mod m
                currentValue = (a * currentValue + c) % m;

                // Take the least significant byte
                key[i] = (byte)(currentValue & 0xFF);
            }

            return key;
        }

        private byte[] GenerateIVFromSeed(long seed, int ivLength)
        {
            // Use a different starting point for IV generation to avoid key/IV correlation
            long ivSeed = (seed ^ 0xFFFFFFFF) % m;
            return GenerateKeyFromLCG(ivSeed, ivLength);
        }

        private byte[] EncryptCBC(byte[] plainBytes, byte[] key, byte[] iv)
        {
            int blockSize = key.Length;

            // Pad the plaintext to a multiple of the block size using PKCS#7 padding
            int paddingSize = blockSize - (plainBytes.Length % blockSize);
            byte[] paddedPlaintext = new byte[plainBytes.Length + paddingSize];
            Array.Copy(plainBytes, 0, paddedPlaintext, 0, plainBytes.Length);

            // PKCS#7 padding: fill with the padding size value
            for (int i = 0; i < paddingSize; i++)
            {
                paddedPlaintext[plainBytes.Length + i] = (byte)paddingSize;
            }

            // Initialize the result array: IV + ciphertext
            byte[] result = new byte[iv.Length + paddedPlaintext.Length];
            Array.Copy(iv, 0, result, 0, iv.Length);

            byte[] previousBlock = new byte[blockSize];
            Array.Copy(iv, 0, previousBlock, 0, blockSize);

            // Process each block
            for (int blockStart = 0; blockStart < paddedPlaintext.Length; blockStart += blockSize)
            {
                byte[] currentBlock = new byte[blockSize];
                Array.Copy(paddedPlaintext, blockStart, currentBlock, 0, blockSize);

                // XOR with previous ciphertext block (or IV for first block)
                for (int i = 0; i < blockSize; i++)
                {
                    currentBlock[i] ^= previousBlock[i];
                }

                // Encrypt the block using our simple XOR cipher with the key
                byte[] encryptedBlock = SimpleEncrypt(currentBlock, key);

                // Store in result
                Array.Copy(encryptedBlock, 0, result, iv.Length + blockStart, blockSize);

                // Update previous block for next iteration
                Array.Copy(encryptedBlock, 0, previousBlock, 0, blockSize);
            }

            return result;
        }

        private byte[] DecryptCBC(byte[] cipherBytes, byte[] key, byte[] iv)
        {
            int blockSize = key.Length;

            // Extract IV from beginning of ciphertext
            byte[] extractedIV = new byte[blockSize];
            Array.Copy(cipherBytes, 0, extractedIV, 0, blockSize);

            // Skip IV in ciphertext
            int cipherTextLength = cipherBytes.Length - blockSize;
            byte[] actualCipherText = new byte[cipherTextLength];
            Array.Copy(cipherBytes, blockSize, actualCipherText, 0, cipherTextLength);

            byte[] plaintext = new byte[cipherTextLength];
            byte[] previousBlock = new byte[blockSize];
            Array.Copy(extractedIV, 0, previousBlock, 0, blockSize);

            // Process each block
            for (int blockStart = 0; blockStart < cipherTextLength; blockStart += blockSize)
            {
                byte[] currentBlock = new byte[blockSize];
                Array.Copy(actualCipherText, blockStart, currentBlock, 0, blockSize);

                // Decrypt block
                byte[] decryptedBlock = SimpleDecrypt(currentBlock, key);

                // XOR with previous ciphertext block (or IV for first block)
                for (int i = 0; i < blockSize; i++)
                {
                    decryptedBlock[i] ^= previousBlock[i];
                }

                // Store in result
                Array.Copy(decryptedBlock, 0, plaintext, blockStart, blockSize);

                // Update previous block for next iteration
                Array.Copy(currentBlock, 0, previousBlock, 0, blockSize);
            }

            // Remove PKCS#7 padding
            int paddingSize = plaintext[plaintext.Length - 1];
            if (paddingSize > 0 && paddingSize <= blockSize)
            {
                // Verify padding is valid
                bool validPadding = true;
                for (int i = plaintext.Length - paddingSize; i < plaintext.Length; i++)
                {
                    if (plaintext[i] != paddingSize)
                    {
                        validPadding = false;
                        break;
                    }
                }

                if (validPadding)
                {
                    byte[] unpaddedPlaintext = new byte[plaintext.Length - paddingSize];
                    Array.Copy(plaintext, 0, unpaddedPlaintext, 0, unpaddedPlaintext.Length);
                    return unpaddedPlaintext;
                }
            }

            // If padding is invalid, return the plaintext without removing padding
            return plaintext;
        }

        // Simple XOR cipher with key rotation
        private byte[] SimpleEncrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                // XOR with key byte, rotating through the key
                result[i] = (byte)(data[i] ^ key[i % key.Length]);

                // Add additional mixing for more security
                result[i] = (byte)((result[i] << 3) | (result[i] >> 5));
            }

            return result;
        }

        // Simple XOR cipher with key rotation (decryption)
        private byte[] SimpleDecrypt(byte[] data, byte[] key)
        {
            byte[] result = new byte[data.Length];

            for (int i = 0; i < data.Length; i++)
            {
                // Reverse the additional mixing
                byte unmixed = (byte)((data[i] >> 3) | (data[i] << 5));

                // XOR with key byte, rotating through the key
                result[i] = (byte)(unmixed ^ key[i % key.Length]);
            }

            return result;
        }

    }
}
