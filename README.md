# btc-crypto

Build
-----

    $ mvn install

Get your public key
------ 
    $ java -jar btc-crypto.jar 

Get encrypted text
-----
      $ java -jar btc-crypto.jar "recipient_public_key" "message"

Regenerate your public key
-----
      $ rm mnemonic 
      $ java -jar btc-crypto.jar 


If you get following exception you:
    
    ava.security.NoSuchAlgorithmException: Cannot find any provider supporting AES/CBC/PKCS7PADDING

you have to make commands from article

https://deveshsharma.info/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/

