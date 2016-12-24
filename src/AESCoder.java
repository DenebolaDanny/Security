import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Denebola on 2016/11/24.
 */
public class AESCoder {

    public static Key toKey(String b) throws Exception  {
        SecretKey secretKey = new SecretKeySpec(CodeType.s2b(b),"AES");
        return (secretKey);
    }

    public static String decrypt(String data,String key) throws Exception {
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,k);
        byte[] rawData = cipher.doFinal(CodeType.s2b(data));
        return new String(rawData);
    }

    public static String encrypt(String data,String key) throws Exception {
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,k);
        byte[] cryptText = cipher.doFinal(data.getBytes());
        return CodeType.b2s(cryptText);
    }

    public static String initKey() throws  Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128); //128/192/256
        SecretKey secretKey = keyGenerator.generateKey();
        byte[] key = secretKey.getEncoded();
        return CodeType.b2s(key);
    }
}
