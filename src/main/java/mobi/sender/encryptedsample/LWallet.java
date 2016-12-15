package mobi.sender.encryptedsample;

import org.bitcoinj.core.Base58;
import org.bitcoinj.core.NetworkParameters;
import org.bitcoinj.core.Utils;
import org.bitcoinj.core.Wallet;
import org.bitcoinj.crypto.DeterministicKey;
import org.bitcoinj.crypto.HDKeyDerivation;
import org.bitcoinj.params.MainNetParams;
import org.bitcoinj.wallet.DeterministicSeed;
import org.bitcoinj.wallet.KeyChainGroup;
import org.bouncycastle.crypto.params.ECDomainParameters;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.provider.JCEECPrivateKey;
import org.bouncycastle.jce.provider.JCEECPublicKey;
import org.bouncycastle.jce.spec.ECNamedCurveParameterSpec;
import org.bouncycastle.jce.spec.ECNamedCurveSpec;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.spec.ECPrivateKeySpec;
import org.bouncycastle.math.ec.ECPoint;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Security;

/**
 * Created by artem on 13.12.16.
 */
public class LWallet extends Wallet {

    private static LWallet instance;
    public static final String PROP_MNEMONIC = "mnemonic";
    public static final String PROP_CREATED = "created";
    private static final NetworkParameters params = MainNetParams.get();
    private DeterministicKey rootKey;
//    private android.content.Context ctx;
    private LWallet(NetworkParameters params) {
    super(params);
}

    private LWallet(NetworkParameters params, KeyChainGroup keyChainGroup) {
        super(params, keyChainGroup);
    }


    public static synchronized LWallet getInstance() throws Exception {
//        rootKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        String mnemonicData =  readMnemonic();

        if (mnemonicData==null) {
            instance = new LWallet(params);
            DeterministicSeed seed = instance.getKeyChainSeed();
            String newMnemonic = Utils.join(seed.getMnemonicCode());
            FileOutputStream out = new FileOutputStream("mnemonic");
            out.write(newMnemonic.getBytes());
            out.write("\n".getBytes());
            out.write(String.valueOf(seed.getCreationTimeSeconds()).getBytes());
            out.close();
            instance.rootKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
        } else {
            try {
                String mnemonicArray [] = mnemonicData.split("\n");

                KeyChainGroup keyChainGroup =new KeyChainGroup(params, new DeterministicSeed(mnemonicArray[0], null, "", Long.valueOf(mnemonicArray[1])));
                instance = new LWallet(params, keyChainGroup);
                DeterministicSeed seed = instance.getKeyChainSeed();
                instance.rootKey = HDKeyDerivation.createMasterPrivateKey(seed.getSeedBytes());
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        return instance;
    }


    public static String readMnemonic() throws Exception {
        try {

            BufferedReader br = new BufferedReader(new FileReader("mnemonic"));
            try {
                StringBuilder sb = new StringBuilder();
                String line = br.readLine();

                while (line != null) {
                    sb.append(line);
                    sb.append(System.lineSeparator());
                    line = br.readLine();
                }
                return sb.toString();
            } finally {
                br.close();
            }
        }catch (FileNotFoundException e){
            System.err.println("no mnemonic");
            return null;
        }
    }

    public String getMyRootPubKey() {
        if (rootKey != null) {
            byte[] pubKey = rootKey.getPubKey();
            return Base58.encode(pubKey);
        }
        return null;
    }
    public String decrypt(ECPublicKey key, String s) throws Exception {
        ECPrivateKey privateKey = getMyPrivateKey();
        byte[] encbuf = Base58.decode(s);
        int tagLength = 4;
        byte[] c = slice(encbuf, 0, encbuf.length - tagLength);
        byte[] d = slice(encbuf, encbuf.length - tagLength, encbuf.length);
        byte[] kKem = kEkM(key, privateKey);
        byte[] ke = slice(kKem, 0, 32);
        byte[] km = slice(kKem, 32, 64);
        byte[] dd = hmacSha256(c, km);
        byte[] d2 = slice(dd, 0, 4); // shortTag
        for (int i = 0; i < d.length; i++) {
            if (d[i] != d2[i]) throw new Exception("Invalid checksum, key: " + key + ", s:" + s);
        }
        byte[] decrypted = decryptAesCBC(ke, c);
        return new String(decrypted);
    }

    public static byte[] hmacSha256(byte[] msg, byte[] keyB) {
        try {
            SecretKeySpec key = new SecretKeySpec(keyB, "HmacSHA256");
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(key);
            return mac.doFinal(msg);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }


    public ECPrivateKey getMyPrivateKey() throws Exception {
        if (rootKey == null) {
            return null;
        }
        BigInteger privKey = rootKey.getPrivKey();
        ECDomainParameters parameters = getDParams();
        ECPrivateKeySpec spec = new ECPrivateKeySpec(privKey, new ECParameterSpec(parameters.getCurve(), parameters.getG(), parameters.getN()));
        return new JCEECPrivateKey("ECIES", spec);
    }


    private ECDomainParameters getDParams() {
        ECNamedCurveParameterSpec ecParams = ECNamedCurveTable.getParameterSpec("secp256k1");
        return new ECDomainParameters(ecParams.getCurve(), ecParams.getG(), ecParams.getN(), ecParams.getH());
    }

    public static byte[] decryptAesCBC(byte[] key, byte[] value) throws Exception {
        byte[] initV = slice(value, 0, 16);
        byte[] data = slice(value, 16, value.length);
        IvParameterSpec iv = new IvParameterSpec(initV);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");
        Security.addProvider(new BouncyCastleProvider());
//        Security.insertProviderAt(new org.spongycastle.jce.provider.BouncyCastleProvider(), 1);

        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");
        cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
        return cipher.doFinal(data);
    }

    public static byte[] slice(byte[] in, int start, int end) {
        int len = end - start;
        byte[] out = new byte[len];
        System.arraycopy(in, start, out, 0, len);
        return out;
    }


    public static byte[] kEkM(ECPublicKey publicKey, ECPrivateKey privateKey) {
        BigInteger d = privateKey.getD();
        ECPoint q = publicKey.getQ();
        ECPoint p = q.multiply(d);
        BigInteger x = p.getX().toBigInteger();
        byte[] s = getUnsignedBytes(x, 32);
        return sha512(s, 64);
    }
    public static byte[] sha512(byte[] bytes, int digestLength) {
        MessageDigest sha512;
        try {
            sha512 = MessageDigest.getInstance("SHA-512");
            byte[] sum = sha512.digest(bytes);
            return copyOf(sum, digestLength);
        } catch (NoSuchAlgorithmException e) {
            throw new RuntimeException("NoSuchAlgorithmException occurred in DigestSHA512.sha512()", e);
        }

    }

    public static byte[] copyOf(byte[] from, int length) {
        byte[] result = new byte[length];
        System.arraycopy(from, 0, result, 0, length);
        return result;
    }

    public static byte[] getUnsignedBytes(BigInteger number, int length) {
        byte[] value = number.toByteArray();

        if (value.length > length + 1) {
            throw new IllegalArgumentException
                    ("The given BigInteger does not fit into a byte array with the given length: " + value.length
                            + " > " + length);
        }

        byte[] result = new byte[length];

        int i = value.length == length + 1 ? 1 : 0;
        for (; i < value.length; i++) {
            result[i + length - value.length] = value[i];
        }
        return result;
    }
    public ECPublicKey pubKeyFromString(String s) {
        try {
            ECDomainParameters parameters = getDParams();
            byte[] f = Base58.decode(s);
            ECPublicKeyParameters params = new ECPublicKeyParameters(parameters.getCurve().decodePoint(f), parameters);
            ECNamedCurveSpec spec = new ECNamedCurveSpec("secp256k1", parameters.getCurve(), parameters.getG(), parameters.getN(), parameters.getH());
            return new JCEECPublicKey("ECIES", params, spec);
        } catch (Exception e) {
            e.printStackTrace();
        }
        return null;
    }

    public String encrypt(ECPublicKey key, String s) throws Exception {
        ECPrivateKey privateKey = getMyPrivateKey();
        byte[] ivbuf0 = hmacSha256(s.getBytes("ASCII"), privateKey.getEncoded());
        byte[] ivbuf = slice(ivbuf0, 0, 16);
        byte[] kKem = kEkM(key, privateKey);
        byte[] ke = slice(kKem, 0, 32);
        byte[] km = slice(kKem, 32, 64);
        byte[] c = encryptAesCBC(ke, ivbuf, s.getBytes());
        byte[] dd = hmacSha256(c, km);
        byte[] tag = slice(dd, 0, 4); // short
        byte[][] encbuf = new byte[][]{c, tag};
        byte[] bytes = concatByteArrays(encbuf);
        return Base58.encode(bytes);
    }

    public static byte[] encryptAesCBC(byte[] key, byte[] initV, byte[] value) throws Exception {
        IvParameterSpec iv = new IvParameterSpec(initV);
        SecretKeySpec skeySpec = new SecretKeySpec(key, "AES");


        Security.addProvider(new BouncyCastleProvider());
        // "BC" is the name of the BouncyCastle provider
//        KeyGenerator keyGen = KeyGenerator.getInstance("DES", "BC");
//        keyGen.init(new SecureRandom());
//
//        SecretKey key1 = keyGen.generateKey();






        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS7PADDING");
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, iv);
        byte[] rez = cipher.doFinal(value);
        byte[][] out = new byte[][]{initV, rez};
        return concatByteArrays(out);
    }
    public static byte[] concatByteArrays(byte[][] arrs) {
        int alLen = 0;
        for (byte[] e : arrs) {
            alLen += e.length;
        }
        byte[] d = new byte[alLen];
        int endPos = 0;
        for (byte[] e : arrs) {
            System.arraycopy(e, 0, d, endPos, e.length);
            endPos += e.length;
        }
        return d;
    }




}
