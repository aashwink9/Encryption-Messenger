/**
File: ServerOps.cs
Project: Messenger
Author: Aashwin Katiyar
Email: ak2577@rit.edu

Description: This file contains classes related to the Network aspect of the project. It contains
the methods for making GET and PUT requests to and from the server to receive/send data and then
calls the classes from Cipher.cs and JsonClasses.cs. to assist.
**/


using System.Text;
using Newtonsoft.Json;
using RSAEncDec;


namespace ServerSide
{
    /// <summary>
    /// Class <c>ServerEncDec</c> is a network focused class that contains async methods for
    /// making GET and PUT requests to the server.
    /// </summary>
    class ServerEncDec
    {
        // HttpClient is intended to be instantiated once per application, rather than per-use. See Remarks.
        static readonly HttpClient client = new HttpClient();

        /// <summary>
        /// This generic method makes a GET request to the supplied uri and returns the string response.
        /// </summary>
        /// <param name="uri">The uri to be made the request to</param>
        /// <returns>
        /// A promise of the response string.
        /// </returns>
        private static async Task<string> RequestKeyData(string uri)
        {
            try
            {
                string responseBody = await client.GetStringAsync(uri);
                return responseBody;
            }
            catch (HttpRequestException)
            {
                Console.WriteLine("Error in fetching values");
                return "HTTP_ERROR";
            }
        }

        /// <summary>
        /// This generic method makes a PUT request to the supplied uri with the supplied json serialized data.
        /// </summary>
        /// <param name="uri">The uri to be made the request to</param>
        /// <param name="jsonData">The JSON serialized string to be PUT to the server</param>
        private static async Task PutKeyData(string uri, string jsonData)
        {
            try
            {
                var content = new StringContent(jsonData, Encoding.UTF8, "application/json");
                await client.PutAsync(uri, content);
            }
            catch (HttpRequestException) { Console.WriteLine("Error sending values"); }
        }

        /// <summary>
        /// This method makes a GET request to the server to extract a public key for a user.
        /// </summary>
        /// <param name="email">The associated email for the user to extract the key from</param>
        public async Task getKey(string email)  // WORKS
        {
            string genUri = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
            string PubKeyJsonStr = await RequestKeyData(genUri);

            if (PubKeyJsonStr.Length < 5) Console.WriteLine("Email does not exist");
            else
            {
                StoreUserKey(email, PubKeyJsonStr);
                Console.WriteLine("Key Stored");
            }
        }

        /// <summary>
        /// This method makes a PUT request to the server to send a public key for the user email.
        /// </summary>
        /// <param name="email">The associated email for the user to send the key for.</param>
        public async Task sendKey(string email)  // WORKS
        {
            PubJson? PubKeyObj = GetPubKeyFile("public.key");
            if (PubKeyObj != null)
            {
                PubKeyObj.email = email;
                string serPubJson = JsonConvert.SerializeObject(PubKeyObj);
                string genUri = $"http://kayrun.cs.rit.edu:5000/Key/{email}";
                await PutKeyData(genUri, serPubJson);
                UpdatePrivEmail(email);
                Console.WriteLine("Key Saved");
            }
        }

        /// <summary>
        /// This method calls in the encryption algorithm and encrypts the plaintext message supplied and then
        /// PUTS that message onto the server.
        /// </summary>
        /// <param name="email">The associated email for the user to send the encrypted message for.</param>
        /// <param name="plaintext">The plaintext message that will be encrypted and sent to the server.</param>
        public async Task sendMsg(string email, string plaintext)
        {
            string userFile = email + ".key";
            PubJson? userExistsObj = GetPubKeyFile(userFile);

            if (userExistsObj != null && userExistsObj.key != null && userExistsObj.email != null)
            {
                string userPubKey = userExistsObj.key;
                KeyOps ko = new KeyOps();
                SendMsgJson msgJsonObj = new SendMsgJson();
                string EncryptedMsg = ko.EncryptData(plaintext, userPubKey);
                
                if (EncryptedMsg != "LONG_MSG"){
                    msgJsonObj.email = email;
                    msgJsonObj.content = EncryptedMsg;
                    string encSerMsgJson = JsonConvert.SerializeObject(msgJsonObj);
                    string genUri = $"http://kayrun.cs.rit.edu:5000/Message/{email}";
                    await PutKeyData(genUri, encSerMsgJson);
                    Console.WriteLine("Message written");
                }
                else {
                    Console.WriteLine("Error: Message too long, please try again.");
                }
            }

            else
            {
                Console.WriteLine("Unable to encrypt: The Public Key for this user was not found.");
            }
        }
         
        /// <summary>
        /// This method extracs the message from the server and decrypts it, if the receiver has the private key
        /// associated for it.
        /// </summary>
        /// <param name="email">The associated email for the user (typically self) to get the encrypted message with the key.</param>
        public async Task getMsg(string email)
        {
            string path = Directory.GetCurrentDirectory() + "\\private.key";
            if (File.Exists(path))
            {
                string PrivKeyJsonStr = File.ReadAllText(path);
                try
                {
                    PrivJson? PrivUserObj = JsonConvert.DeserializeObject<PrivJson>(PrivKeyJsonStr);
                    if (PrivUserObj != null && PrivUserObj.key != null)
                    {
                        if (PrivUserObj.email.Contains(email))
                        {
                            string genUri = $"http://kayrun.cs.rit.edu:5000/Message/{email}";
                            string MsgJsonStr = await RequestKeyData(genUri);
                            if (MsgJsonStr != "HTTP_ERROR")
                            {
                                GetMsgJson? getMsgObj = JsonConvert.DeserializeObject<GetMsgJson>(MsgJsonStr);
                                if (getMsgObj != null && getMsgObj.email != null && getMsgObj.content != null)
                                {
                                    if (getMsgObj.email == email)
                                    {
                                        string EncodedMsg = getMsgObj.content;
                                        string PrivKey = PrivUserObj.key;
                                        KeyOps ko = new KeyOps();
                                        string decryptedMsg = ko.DecryptData(EncodedMsg, PrivKey);
                                        Console.WriteLine(decryptedMsg);
                                    }
                                    else
                                    {
                                        Console.WriteLine("Error: Email mismatch between fetched data and the email provided.");
                                    }
                                }
                                else
                                {
                                    Console.WriteLine("Error: One or more fields in the deserealized json was null.");
                                }
                            }
                            else
                            {
                                Console.WriteLine("Error: The HTTP server returned an Error Response.");
                            }
                        }
                        else
                        {
                            Console.WriteLine("Error: Cannot decode the message. The private key is " +
                            "incompatible with the encrypted message.");
                        }
                    }
                }
                catch (Exception e) when (e is JsonReaderException ||
            e is JsonSerializationException || e is JsonWriterException)
                {
                    Console.WriteLine("Error in Json Serialization/Deserialization, please make sure the " +
                                      "data and file name are in the correct format.");
                }
            }
            else
            {
                Console.WriteLine("Error: The private.key file was not found.");
            }
        }

        /// <summary>
        /// This helper method querys the current directory for either the public.key file or a user's public key file
        /// and then serializes the json content of that file into a Json Object and returns it.
        /// </summary>
        /// <param name="name">The name (with the extension) of the file to query.</param>
        /// <returns>
        /// A PubJson class which represents a json object for public key with email.
        /// </returns>
        private PubJson? GetPubKeyFile(string name)
        {
            string path = Directory.GetCurrentDirectory() + $"\\{name}";
            if (File.Exists(path))
            {
                string PubKeyJsonStr = File.ReadAllText(path);
                try
                {
                    PubJson? PubObj = JsonConvert.DeserializeObject<PubJson>(PubKeyJsonStr);
                    if (PubObj != null && PubObj.key != null) return PubObj;
                    else
                    {
                        Console.WriteLine("The json object or a key was found to be null.");
                        return null;
                    }
                }
                catch (Exception e) when (e is JsonReaderException ||
                       e is JsonSerializationException || e is JsonWriterException)
                {
                    Console.WriteLine("Error in Json Serialization/Deserialization, please make sure the " +
                                      "data and file name are in the correct format.");
                    return null;
                }
            }
            else
            {
                Console.WriteLine("Error: private.key file not found.");
                return null;
            }
        }

        /// <summary>
        /// This helper method updates the private.key file with an email for when the user makes a
        /// sendKey request with the email. It gets updated with that email supplied.
        /// </summary>
        /// <param name="email">The email supplied in the getKey request</param>
        private void UpdatePrivEmail(string email)
        {
            string path = Directory.GetCurrentDirectory() + "\\private.key";
            if (File.Exists(path))
            {
                string PrivKeyJsonStr = File.ReadAllText(path);

                try
                {
                    PrivJson? PrivObj = JsonConvert.DeserializeObject<PrivJson>(PrivKeyJsonStr);
                    if (PrivObj != null && PrivObj.key != null)
                    {
                        if (!PrivObj.email.Contains(email))
                        {
                            string[] newEmails = PrivObj.email.Append(email).ToArray();
                            PrivObj.email = newEmails;
                            string PrivSerJson = JsonConvert.SerializeObject(PrivObj);
                            File.WriteAllText(path, PrivSerJson);
                        }
                    }
                    else
                    {
                        Console.WriteLine("Error in updating private.key: Json deserialized Object or key " +
                        "was found to be null.");
                    }
                }
                catch (Exception e) when (e is JsonReaderException ||
            e is JsonSerializationException || e is JsonWriterException)
                {
                    Console.WriteLine("Error in Json Serialization/Deserialization, please make sure the " +
                                      "data and file name are in the correct format.");
                }
            }
            else
            {
                Console.WriteLine("Error in updating private.key: The private key was not found. Please " +
                "generate the keys using keyGen first and try again.");
            }
        }

        /// <summary>
        /// This helper method stores a user's email and public key in json format in the file format 'email'.key
        /// </summary>
        /// <param name="email">The email to store the json key file for.</param>
        /// <param name="rawContent">The stringified json content received from the server for getKey.</param>
        public void StoreUserKey(string email, string rawContent)
        {
            try
            {
                PubJson? userObj = JsonConvert.DeserializeObject<PubJson>(rawContent);
                if (userObj != null && userObj.email != null && userObj.key != null)
                {
                    if (userObj.email == email)
                    {
                        string userFile = email + ".key";
                        string userSerJson = JsonConvert.SerializeObject(userObj);
                        string userPath = Directory.GetCurrentDirectory() + $"\\{userFile}";
                        File.WriteAllText(userPath, userSerJson);
                    }
                    else
                    {
                        Console.WriteLine("Error: User email mismatch.");
                    }
                }
                else
                {
                    Console.WriteLine("Error: The user email or key was found to be null.");
                }
            }
            catch (Exception e) when (e is JsonReaderException ||
            e is JsonSerializationException || e is JsonWriterException)
            {
                Console.WriteLine("Error in Json Serialization/Deserialization, please make sure the " +
                                  "data and file name are in the correct format.");
            }
        }
    }
}
