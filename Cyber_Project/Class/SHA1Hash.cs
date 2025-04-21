using System.Security.Cryptography;
using System.Text;

namespace Cyber_Project.Class
{
    public class SHA1Hash
    {
        public string ComputeHash(string input)
        {
            using (SHA1 sha1 = SHA1.Create())
            {
                byte[] hashBytes = sha1.ComputeHash(Encoding.UTF8.GetBytes(input));
                return BitConverter.ToString(hashBytes).Replace("-", "").ToLower();
            }
        }
    }
}
