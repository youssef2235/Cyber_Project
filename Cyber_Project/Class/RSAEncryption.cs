using System.Security.Cryptography;
using System.Text;

namespace Cyber_Project.Class
{
    public class RSAEncryption
    {
        private RSACryptoServiceProvider _rsa;

        public RSAEncryption()
        {
            _rsa = new RSACryptoServiceProvider();
        }

        public string PublicKey => _rsa.ToXmlString(false);
        public string PrivateKey => _rsa.ToXmlString(true);

        public byte[] Encrypt(string data)
        {
            return _rsa.Encrypt(Encoding.UTF8.GetBytes(data), false);
        }

        public string Decrypt(byte[] cipherText)
        {
            byte[] decryptedBytes = _rsa.Decrypt(cipherText, false);
            return Encoding.UTF8.GetString(decryptedBytes);
        }
    }
}
