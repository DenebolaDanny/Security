import java.security.*;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by kevindanny on 2016/12/6.
 */
public class RSASign {
    /**
     *  签名
     * @param data 待签名数据
     * @param privateKey 私钥
     * @return byte[] 数字签名
     * @throws Exception
     */
    public static String sign(String data,String privateKey) throws Exception{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(CodeType.s2b(privateKey));  //转换私钥
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");   //实例化秘钥工厂
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);    //取得私钥
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(priKey); // 初始化Signture
        signature.update(data.getBytes());     //更新
        return CodeType.b2s(signature.sign());    //签名
    }

    /**
     * 校验
     * @param data 待校验数据
     * @param publickey 公钥
     * @param sign 数字签名
     * @return 校验成功判断
     * @throws Exception
     */
    public static boolean vertify(String data, String publickey,String sign) throws Exception{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(CodeType.s2b(publickey)); //转换公钥材料
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  //实例化工厂
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  // 生成公钥
        Signature signature = Signature.getInstance("MD5withRSA");  //实例化Signature
        signature.initVerify(pubKey);
        signature.update(data.getBytes());
        return signature.verify(CodeType.s2b(sign));

    }

    /**
     * 取得私钥
     * @param keyMap 密钥map
     * @return 私钥
     * @throws Exception
     */
    public static String getPrivateKey(Map<String,String> keyMap) throws Exception{
        String key =  keyMap.get("Private Key");
        return key;
    }

    /**
     * 取得公钥
     * @param keyMap 密钥map
     * @return 公钥
     * @throws Exception
     */
    public static String getPublicKey(Map<String,String> keyMap)throws Exception{
        String key = keyMap.get("Public Key");
        return key;
    }

    /**
     * 初始化密钥
     * @return 密钥map
     * @throws Exception
     */
    public static Map<String,String> initKey() throws Exception{
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(1024);
        KeyPair keyPair=keyPairGenerator.generateKeyPair();
        RSAPublicKey publicKey = (RSAPublicKey)keyPair.getPublic();
        RSAPrivateKey privateKey = (RSAPrivateKey)keyPair.getPrivate();
        Map<String,String> keyMap = new HashMap<>(2);
        keyMap.put("Public Key",CodeType.b2s(publicKey.getEncoded()));
        keyMap.put("Private Key",CodeType.b2s(privateKey.getEncoded()));
        return keyMap;
    }
}

