# btc-crypto

Build
-----

    $ mvn install

Get your public key
------ 
    $ java -jar btc-crypto.jar
    
    Your public key: eQo3RaiwVzjiMgUPZ9rcE36GYHVkXeCoZy8sn7cSctWZ


Get encrypted text
-----
      $ java -jar btc-crypto.jar "recipient_public_key" "message"
      
      Your encr text: JEAJHELy8i4uLVhUYXSnKi9jCoxdenpdu6yW1VHjeMtdFett1


Regenerate your public key
-----
      $ rm mnemonic 
      $ java -jar btc-crypto.jar 
      
      Your public key: eQo3RaiwVzjiMgUPZ9rcE36GYHVkXeCoZy8sn7cSctWZ
      


If you get following exception you:
    
    ava.security.NoSuchAlgorithmException: Cannot find any provider supporting AES/CBC/PKCS7PADDING

you have to make commands from article

https://deveshsharma.info/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/

