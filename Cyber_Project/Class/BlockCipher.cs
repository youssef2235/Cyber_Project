namespace Cyber_Project.Class
{
    public class BlockCipher
    {
        private byte[] _key;

        public BlockCipher(byte[] key)
        {
            _key = key;
        }

        public byte[] Encrypt(byte[] data)
        {
            byte[] cipherText = new byte[data.Length];
            byte[] iv = new byte[16]; // تحديد طول IV

            for (int i = 0; i < data.Length; i++)
            {
                byte keyByte = _key[i % _key.Length];
                cipherText[i] = (byte)(data[i] ^ keyByte);
            }

            return cipherText;
        }

        public byte[] Decrypt(byte[] cipherText)
        {
            return Encrypt(cipherText); // XOR معكوس التشفير
        }
    }
}
