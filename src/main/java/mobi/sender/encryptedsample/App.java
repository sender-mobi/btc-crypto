package mobi.sender.encryptedsample;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import java.security.Security;

public class App{

    static {
        Security.addProvider(new BouncyCastleProvider());
    }
    public static void main( String[] args ) throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        LWallet wallet = LWallet.getInstance();
        System.out.println( "Your public key: " +wallet.getMyRootPubKey());
        String text = wallet.encrypt(wallet.pubKeyFromString(args[0]), args[1]);
        System.out.println( "Your encr text: " +text);
    }
}
