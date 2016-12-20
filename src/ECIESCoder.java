import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import javax.crypto.Cipher;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by kevindanny on 2016/12/13.
 */
public class ECIESCoder {

//    public static Map<byte[],byte[]> map = new HashMap<>(2);
public static Map<String,String> map = new HashMap<>(2);
    /**
     * 初始化密钥
     * 公私钥对存入map
     *
     * @return 公钥
     * @throws Exception
     */
    @org.junit.Test
    public static String initKey() throws Exception {
        Map<byte[], byte[]> keyMap = new HashMap<byte[], byte[]>();
        byte[] publicKey = null;
        byte[] privateKey = null;

        Security.addProvider(new BouncyCastleProvider());
        //生成公私钥
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);

        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        //公钥
        ECPublicKey ecPublicKey = (ECPublicKey) keyPair.getPublic();
        //私钥
        ECPrivateKey ecPrivateKey = (ECPrivateKey) keyPair.getPrivate();

        publicKey = ecPublicKey.getEncoded();
        privateKey = ecPrivateKey.getEncoded();


        ECIESCoder.map.put(CodeType.b2s(publicKey),CodeType.b2s(privateKey));  //<公钥，私钥>放入秘钥池
//        ECIESCoder.map.put("private",new BASE64Encoder().encodeBuffer(privateKey));  //<公钥，私钥>放入秘钥池
        return CodeType.b2s(publicKey);
//        return publicKey;
    }

    /**
     * 用公钥加密
     *
     * @param data 待加密数据
     * @param  pubKey)  公钥
     * @return 密文字节流
     * @throws Exception
     */
    public static String encrypt(String data, String pubKey) throws Exception {
        byte[] cipherText = null;
//        转换公钥
        byte[] key=CodeType.s2b(pubKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance("ECDH");
//        生成公钥
        PublicKey publicKey = factory.generatePublic(spec);
//        加密
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherText = cipher.doFinal(data.getBytes());
        return CodeType.b2s(cipherText);
    }

    /**
     * 用私钥解密
     *
     * @param strData 待解秘数据
     * @param priKey  私钥
     * @return 原文字节流
     * @throws Exception
     */
    public static String decrypt(String strData, String priKey) throws Exception {
        byte[] transData = null;
        byte[] data=CodeType.s2b(strData);
        byte[] key=CodeType.s2b(priKey);
//        转换私钥
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance("ECDH");
//        生层私钥
        PrivateKey privateKey = factory.generatePrivate(spec);
//        解密
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        transData = cipher.doFinal(data);

        return new String(transData);
    }
}
