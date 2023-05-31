/**
File: Program.cs
Project: Messenger
Author: Aashwin Katiyar
Email: ak2577@rit.edu

Description: This project is concerned with Network Security and on securely sending
and receiving messages through a server. It uses the RSA encryption/decryption algorithm
to generate a public and a private key for a user. It then makes verious HTTP requests to
perform CRUD operations for keys and messages, while also utilizing the encryption/decryption.
**/

using RSAEncDec;
using ServerSide;

namespace MessengerSpace
{
    /// <summary>
    /// Class <c>Main</c> is the main class the calls all contained methods
    /// as well as other classes to perform the command line CRUD Operations.
    /// </summary>
    class MessengerMain
    {
        /// <summary>
        /// The Main method that calls everything and enforces the conditions for the command
        /// line arguments and runs the operations asynchronously.
        /// </summary>
        public static async Task Main(string[] args)
        {
            string USAGE = "USAGE: dotnet run <option> <other arguments>\n" +
            "keyGen <keySize>: Generate a public and private key from specified bits and store them locally.\n" +
            "sendKey <email>: Send a generated public to the server for an associated email.\n" +
            "getKey <email>: Get a public key for an associated email.\n" + 
            "sendMsg <email> <plaintext>: Send an encrypted message to the server addressed to the supplied email.\n" +
            "getMsg <email>: Get an encrypted message from the server for the associated email.";
            ServerEncDec sed = new ServerEncDec();

            if (args.Length == 2)
            {
                if (args[0] == "keyGen")
                {
                    KeyOps ko = new KeyOps();
                    if (int.TryParse(args[1], out int inBits))
                    {
                        if (inBits >= 32 && inBits % 8 == 0)
                        {
                            ko.MakeAndWriteKeys(inBits);
                        }
                    }
                }
                else if (args[0] == "sendKey")
                {
                    string email = args[1];
                    await sed.sendKey(email);
                }

                else if (args[0] == "getKey")
                {
                    string email = args[1];
                    await sed.getKey(email);
                }

                else if (args[0] == "getMsg")
                {
                    string email = args[1];
                    await sed.getMsg(email);
                }

                else
                {
                    Console.WriteLine($"Error: Invalid arguments.\n{USAGE}");
                }
            }

            else if (args.Length == 3 && args[0] == "sendMsg")
            {
                string email = args[1];
                string message = args[2];
                await sed.sendMsg(email, message);
            }

            else
            {
                Console.WriteLine($"Error: Invalid number of arguments.\n{USAGE}");
            }
        }
    }
}
