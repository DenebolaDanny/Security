import javax.crypto.Cipher;
import java.security.*;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Created by kevindanny on 2016/11/30.
 */
public class RSACoder  {
    /**
     * 私钥解密
     * @param data 待解密数据
     * @param key 私钥
     * @return 解密数据
     * @throws Exception
     */
    public static String decryptByPrivateKey(String data,String key)throws Exception{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(CodeType.s2b(key)); //获取私钥
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PrivateKey privateKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);   //生成私钥
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  //对数据解密
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        return new String(cipher.doFinal(CodeType.s2b(data)));
    }

    /**
     * 加密数据
     * @param data 待加密数据
     * @param key 公钥
     * @return 加密数据
     * @throws Exception
     */
    public static String encryptByPublicKey(String data,String key)throws Exception{
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(CodeType.s2b(key));    //取得公钥
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey publicKey = keyFactory.generatePublic(x509EncodedKeySpec);
        Cipher cipher = Cipher.getInstance(keyFactory.getAlgorithm());  //加密数据
        cipher.init(Cipher.ENCRYPT_MODE,publicKey);
        return CodeType.b2s(cipher.doFinal(data.getBytes()));
    }

    /**
     * 取得私钥
     * @param keyMap 秘钥Map
     * @return 私钥
     * @throws Exception
     */
    public static String getPrivateKey(Map<String,String> keyMap)throws Exception{
        String key = keyMap.get("private");
        return key;
    }

    /**
     * 取得公钥
     * @param keyMap 秘钥Map
     * @return 公钥
     * @throws Exception
     */
    public static String getPublicKey(Map<String,String> keyMap)throws Exception{
        String key = keyMap.get("public");
        return key;
    }

    /**
     * 初始化秘钥
     * @return 秘钥Map
     * @throws Exception
     */
    public static Map<String,String> initKey() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");    //实例化秘钥对生成器
        keyPairGenerator.initialize(1024);   //秘钥对生成器初始化
        KeyPair keyPair = keyPairGenerator.generateKeyPair();   //生成秘钥对
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic(); //获取公钥
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate(); //获取私钥
        Map<String,String> keyMap = new HashMap<>(2);   //存入map
        keyMap.put("private",CodeType.b2s(privateKey.getEncoded()));
        keyMap.put("public",CodeType.b2s(publicKey.getEncoded()));
        return keyMap;
    }
}
