# btc-crypto

Build
-----

    $ mvn install

Get your public key
------ 
    $ java -jar btc-crypto.jar
    
    Your public key: vVyKui9osVyjH4HjRJYFa9gNxPvxnh87X9BkFk1zeDGE


Get encrypted text
-----
      $ java -jar btc-crypto.jar "recipient_public_key" "message"
      
      Example:
      $ java -jar btc-crypto.jar "ipkDWsv5oeK2pLDoPkqay8KxtmjuTmXRkevTBc1Ds4Cp" "hello world"
      
      Your encr text: 2hww3nTCkXGX1ThdwJuEK4QXU4YvdWCoLgLAKQ8bnoedRbyxHG


Regenerate your public key
-----
      $ rm mnemonic 
      $ java -jar btc-crypto.jar 
      
      Your public key: eQo3RaiwVzjiMgUPZ9rcE36GYHVkXeCoZy8sn7cSctWZ
      


If you get following exception you:
    
    ava.security.NoSuchAlgorithmException: Cannot find any provider supporting AES/CBC/PKCS7PADDING

you have to make commands from article

https://deveshsharma.info/2012/10/09/fixing-java-security-invalidkeyexception-illegal-key-size-exception/

