/**
File: JsonClasses.cs
Project: Messenger
Author: Aashwin Katiyar
Email: ak2577@rit.edu

Description: This file contains all of the classes that represent a JSON object, for serialization and
deserialization.
**/


/// <summary>
/// Class <c>PrivJson</c> is a class that represents the Private Key JSON to be written to private.key 
/// </summary>    
class PrivJson
{
    public string[] email = {};
    public string? key = null;
}

/// <summary>
/// Class <c>PubJson</c> is a class that represents the Public Key JSON to be written to public.key 
/// </summary>      
class PubJson
{
    public string? email = null;
    public string? key = null;
}

/// <summary>
/// Class <c>SendMsgJson</c> represents the JSON for sending an encrypted message to the server for an email.
/// </summary> 
class SendMsgJson
{
    public string? email = null;
    public string? content = null;
}

/// <summary>
/// Class <c>GetMsgJson</c> represents the JSON for receiving an encrypted message to the server for an email.
/// </summary>  
class GetMsgJson
{
    public string? email = null;
    public string? content = null;
    public string? messageTime = null;
}
