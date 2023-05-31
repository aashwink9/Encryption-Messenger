/**
File: Cipher.cs
Project: Messenger
Author: Aashwin Katiyar
Email: ak2577@rit.edu

Description: This file contains all the relevant classes and methods for RSA Encryption/Decryption.
It also contains some utility classes that assist in the RSA.
**/

using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Newtonsoft.Json;


namespace RSAEncDec
{
    /// <summary>
    /// Class <c>KeyGen</c> is a private class that contains all the operations related to
    /// Key generation and encoding/decoding the keys.
    /// </summary>
    class KeyGen
    {
        /// <summary>
        /// A helper method that calculates 20% of the size for the byte array for p in Prime Generation.
        /// It then keeps incrementing the 20% size till it is a multiple of 8. Finally, it adds that
        /// obtained value to the size of p.
        /// </summary>
        /// <param name="bits">The number of bits inputted by the user (have to be a multiple of 8 and greater than 32)</param>
        /// <returns>
        /// The new calculated size for p.
        /// </returns>
        private int calcTwentyPercent(int bits) {
            int pLen = (bits / 2);
            int twentyPLen = (int)Math.Floor(pLen * 0.2);

            int count = 1;
            while (twentyPLen % 8 != 0) {
                twentyPLen += count;
            }
            
            return (pLen + twentyPLen) / 8;
        }

       
        /// <summary>
        /// A helper method that Generates prime numbers from cryptographically strong number randomizer.
        /// </summary>
        /// <param name="bits">The number of bits inputted by the user (have to be a multiple of 8 and greater than 32)</param>
        /// <returns>
        /// A BigInteger[] array that contains 3 values: p, q, and e (in that order).
        /// </returns>
        public BigInteger[] GeneratePrimes(int bits)
        {
            int pLen = calcTwentyPercent(bits);
            int totalByteSize = bits / 8;

            byte[] pbyte = new byte[pLen];
            byte[] qbyte = new byte[totalByteSize - pLen];
            byte[] ebyte = new byte[4];

            BigInteger[] primes = new BigInteger[3];

            while (primes.Contains(0))
            {
                RandomNumberGenerator rand = RandomNumberGenerator.Create();
                rand.GetNonZeroBytes(pbyte);
                rand.GetNonZeroBytes(qbyte);
                rand.GetNonZeroBytes(ebyte);

                BigInteger p = new BigInteger(pbyte);
                BigInteger q = new BigInteger(qbyte);
                BigInteger e = new BigInteger(ebyte);

                p = BigInteger.Abs(p);
                q = BigInteger.Abs(q);
                e = BigInteger.Abs(e);

                if (p.isProbablyPrime() && primes[0] == 0) primes[0] = p;
                if (q.isProbablyPrime() && primes[1] == 0) primes[1] = q;
                if (e.isProbablyPrime() && primes[2] == 0) primes[2] = e;
            }
            return primes;
        }

        /// <summary>
        /// Another helper method that calls the generated prime numbers from GeneratePrimes() and performs
        /// operations on them to generate values that form the private and public keys for the user.
        /// </summary>
        /// <param name="bits">The number of bits inputted by the user (have to be a multiple of 8 and greater than 32)</param>
        /// <returns>
        /// A BigInteger[] array that contains 3 values: n, d, and e (in that order).
        /// </returns>
        private BigInteger[] RSAGen(int bits)
        {
            BigInteger[] primes = GeneratePrimes(bits);

            BigInteger p = primes[0];
            BigInteger q = primes[1];
            BigInteger e = primes[2];

            BigInteger n = p * q;
            BigInteger r = (p - 1) * (q - 1);
            BigInteger d = CipherUtils.modInverse(e, r);

            BigInteger[] nde = { n, d, e };
            return nde;
        }

        /// <summary>
        /// This method calls in the RSAGen() method to extract the three values for Private and Public
        /// Key generation. It then calls in the encodeKey() to encode the keys into Base64 encoded string.
        /// </summary>
        /// <param name="bits">The number of bits inputted by the user (have to be a multiple of 8 and greater than 32)</param>
        /// <returns>
        /// A string[] array that returns the Private key and Public key (in that order).
        /// </returns>
        protected string[] GenKeys(int bits)
        {
            BigInteger[] generatedVals = RSAGen(bits);
            BigInteger n = generatedVals[0];
            BigInteger d = generatedVals[1];
            BigInteger e = generatedVals[2];

            // ----------------- PRIVATE KEY GENERATION ------------------------------- //
            string PrivateKeyStr64 = encodeKey(d, n);

            // ----------------- PUBLIC KEY GENERATION ------------------------------- //
            string PublicKeyStr64 = encodeKey(e, n);

            string[] encodedKeys = { PrivateKeyStr64, PublicKeyStr64 };
            return encodedKeys;
        }

        /// <summary>
        /// This method performs the encoding of two values into the corresponding private and public keys.
        /// Since the operations for encoding the key are same for both public and private keys, it uses an
        /// arbitary variable k to account for either d or e, depending on private key or public key.
        /// </summary>
        /// <param name="k">The arbitrary BigInteger value that can either be d, or e.</param>
        /// <param name="n">The common n BigInteger value that pairs up with the k to form an encoded key.</param>
        /// <returns>
        /// A Base64 encoded string which is either going to be a public key or a private key.
        /// </returns>
        private string encodeKey(BigInteger k, BigInteger n)
        {
            int kSize = k.GetByteCount();
            byte[] kSizeBytes = BitConverter.GetBytes(kSize);   // To be filled in Base64 Array
            if (BitConverter.IsLittleEndian) kSizeBytes = kSizeBytes.Reverse().ToArray();
            byte[] K = k.ToByteArray();   // To be filled in Base64 Array

            int nSize = n.GetByteCount();
            byte[] nSizeBytes = BitConverter.GetBytes(nSize);   // To be filled in Base64 Array
            if (BitConverter.IsLittleEndian) nSizeBytes = nSizeBytes.Reverse().ToArray();
            byte[] N = n.ToByteArray();   // To be filled in Base64 Array

            int KeySize = 8 + kSize + nSize;
            byte[] KeyBytes = new byte[KeySize];

            kSizeBytes.CopyTo(KeyBytes, 0);
            K.CopyTo(KeyBytes, 4);

            nSizeBytes.CopyTo(KeyBytes, 4 + kSize);
            N.CopyTo(KeyBytes, 4 + kSize + 4);

            string KeyStr64 = Convert.ToBase64String(KeyBytes);
            return KeyStr64;
        }

        /// <summary>
        /// This method performs the decoding of a Base64 encoded string, which is either a public key or a private key.
        /// </summary>
        /// <param name="keyString">The Base64 encoded string representing either a public or a private key</param>
        /// <returns>
        /// A BigInteger[] array which contains two values: k and n. k is interchangable for d and e.
        /// </returns>
        protected BigInteger[] decodeKey(string keyString)
        {
            byte[] KeyBytes = Convert.FromBase64String(keyString);

            // Finding size of the R byte to read.
            byte[] kBytes = new byte[4];
            Array.Copy(KeyBytes, 0, kBytes, 0, 4);    // Fill the kBytes Array
            if (BitConverter.IsLittleEndian) kBytes = kBytes.Reverse().ToArray();
            int kSize = BitConverter.ToInt32(kBytes);

            // Reading kSize bytes after 4
            byte[] Kbytes = new byte[kSize];
            Array.Copy(KeyBytes, 4, Kbytes, 0, kSize);   // Fill the Kbytes Array

            // Finding size of N byte to read
            byte[] nBytes = new byte[4];
            Array.Copy(KeyBytes, 4 + kSize, nBytes, 0, 4);
            if (BitConverter.IsLittleEndian) nBytes = nBytes.Reverse().ToArray();
            int nSize = BitConverter.ToInt32(nBytes);

            // Reading nSize bytes after 4 + 4 + kSize
            byte[] Nbytes = new byte[nSize];
            Array.Copy(KeyBytes, 4 + kSize + 4, Nbytes, 0, nSize);   // Fill the Nbytes Array

            BigInteger k = new BigInteger(Kbytes);
            BigInteger n = new BigInteger(Nbytes);

            BigInteger[] decodedKey = { k, n };
            return decodedKey;
        }
    }

    /// <summary>
    /// Class <c>KeyOps</c> is an inheriting class from KeyGen which contains the Encryption and
    /// Decryption algorithms to accordingly encrypt or decrypt a plaintext message using compatible keys.
    /// </summary>
    class KeyOps : KeyGen
    {
        /// <summary>
        /// This method performs Encryption on a plaintext message using a public key.
        /// </summary>
        /// <param name="message">The plaintext string message to be encoded</param>
        /// <param name="pubKey">The Public key to use for enrypting the plaintext</param>
        /// <returns>
        /// A Base64 encoded string that contains the encrypted message. 
        /// </returns>
        public string EncryptData(string message, string pubKey)
        {
            BigInteger[] getPubKey = decodeKey(pubKey);
            BigInteger e = getPubKey[0];                        // ENCRYPTION PARAMETER
            BigInteger n = getPubKey[1];                        // ENCRYPTION PARAMETER

            byte[] mBytes = Encoding.ASCII.GetBytes(message);
            BigInteger mNum = new BigInteger(mBytes);           // ENCRYPTION PARAMETER

            BigInteger mEncNum = BigInteger.ModPow(mNum, e, n);

            if(mEncNum >= n) return "LONG_MSG";

            string EncryptedMssg = Convert.ToBase64String(mEncNum.ToByteArray());
            return EncryptedMssg;
        }

        /// <summary>
        /// This method performs Decryption on a Base64 encoded, encrypted message using
        /// a private key that corresponds to the public key.
        /// </summary>
        /// <param name="EncryptedMessage">The encrypted Base64 encoded message to be Decrypted</param>
        /// <param name="privKey">The Private key to use for decrypting the plaintext</param>
        /// <returns>
        /// A plain string value that was the original message which was encrypted.
        /// </returns>
        public string DecryptData(string EncryptedMessage, string privKey)
        {
            BigInteger[] getPrivKey = decodeKey(privKey);
            BigInteger d = getPrivKey[0];  // DECRYPTION PARAMETER
            BigInteger n = getPrivKey[1];  // DECRYPTION PARAMETER

            byte[] mBytes = Convert.FromBase64String(EncryptedMessage);
            BigInteger mNum = new BigInteger(mBytes);    // DECRYPTION PARAMETER
            BigInteger mDecNum = BigInteger.ModPow(mNum, d, n);
            byte[] mDecBytes = mDecNum.ToByteArray();
            string DecryptedMessage = Encoding.ASCII.GetString(mDecBytes);

            return DecryptedMessage;
        }
        
        /// <summary>
        /// This method calls in the GenKeys method to generate random public and private keys and then
        /// writes those keys into "private.key" and "public.key" files, containing a json format 
        /// of email(s) and key.
        /// </summary>
        /// <param name="bits">The number of bits inputted by the user (have to be a multiple of 8 and greater than 32)</param>
        public void MakeAndWriteKeys(int bits)
        {
            string[] generatedKeys = GenKeys(bits);
            string privKey = generatedKeys[0];
            string pubKey = generatedKeys[1];

            PrivJson privateObj = new PrivJson();
            PubJson publicObj = new PubJson();

            privateObj.key = privKey;
            publicObj.key = pubKey;

            string privJson = JsonConvert.SerializeObject(privateObj);
            string pubJson = JsonConvert.SerializeObject(publicObj);

            string PubPath = Directory.GetCurrentDirectory() + "\\public.key";
            string PrivPath = Directory.GetCurrentDirectory() + "\\private.key";

            File.WriteAllText(PubPath, pubJson);
            File.WriteAllText(PrivPath, privJson);
        }
    }

    /// <summary>
    /// Class <c>CipherUtils</c> is a static class that contains some useful utilities for RSA.
    /// </summary>
    public static class CipherUtils
    {
        /// <summary>
        /// A utility static method that evaluates the Mod Inverse of two BigInteger values.
        /// </summary>
        /// <param name="val">The first value for the operation.</param>
        /// <param name="k">The second value for the operation.</param>
        /// <returns>
        /// the result BigInteger number from the mod inverse operation.
        /// </returns>
        public static BigInteger modInverse(BigInteger a, BigInteger n)
        {
            BigInteger i = n, v = 0, d = 1;
            while (a > 0)
            {
                BigInteger t = i / a, x = a;
                a = i % x;
                i = x;
                x = d;
                d = v - t * x;
                v = x;
            }
            v %= n;
            if (v < 0) v = (v + n) % n;
            return v;
        }

        /// <summary>
        /// A utility static method that uses the Miller-Rabin algorithm to evaluate a very 
        /// large random number and check whether it is Probably prime or not.
        /// </summary>
        /// <param name="val">The BigInteger Object to be determined for its primality.</param>
        /// <param name="k">The number of witnesses (default to 10) for evaluating the number.</param>
        /// <returns>
        /// true if the number is a prime, false if the number is not a prime.
        /// </returns>
        public static Boolean isProbablyPrime(this BigInteger val, int k = 10)
        {
            if (val % 2 == 0) return false;
            if (val <= 2) return false;
            if (k <= 0) k = 10;

            BigInteger d = val - 1;
            int s = 0;

            while (d % 2 == 0)
            {
                d /= 2;
                s += 1;
            }

            Byte[] b = new Byte[val.ToByteArray().LongLength];
            BigInteger a;

            for (int i = 0; i < k; i++)
            {
                do
                {
                    var gen = new Random();
                    gen.NextBytes(b);
                    a = new BigInteger(b);
                } while (a < 2 || a >= val - 2);

                BigInteger x = BigInteger.ModPow(a, d, val);
                if (x == 1 || x == val - 1) continue;

                for (int r = 1; r < s; r++)
                {
                    x = BigInteger.ModPow(x, 2, val);
                    if (x == 1) return false;
                    if (x == val - 1) break;
                }

                if (x != val - 1) return false;
            }

            return true;
        }
    }
}