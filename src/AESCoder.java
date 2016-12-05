import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;

/**
 * Created by Denebola on 2016/11/24.
 */
public class AESCoder {

    public static Key toKey(byte[] b){
        SecretKey secretKey = new SecretKeySpec(b,"AES");
        return (secretKey);
    }

    public static byte[] decrypt(byte[] data,byte[] key) throws Exception {
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE,k);
        return (cipher.doFinal(data));
    }

    public static byte[] encrypt(byte[] data,byte[] key) throws Exception {
        Key k = toKey(key);
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE,k);
        return (cipher.doFinal(data));
    }

    public static byte[] initKey() throws  Exception{
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(128);
        SecretKey secretKey = keyGenerator.generateKey();
        return secretKey.getEncoded();
    }
}
