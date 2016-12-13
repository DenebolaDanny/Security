import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

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

    public static Map<byte[],byte[]> map = new HashMap<>(2);
    /**
     * 初始化密钥
     * 公私钥对存入map
     *
     * @return 公钥
     * @throws Exception
     */
    @org.junit.Test
    public static byte[] initKey() throws Exception {
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

//        System.out.println("公钥\n" + new BASE64Encoder().encode(publicKey));
//        System.out.println("\n私钥\n" + new BASE64Encoder().encode(privateKey));

        ECIESCoder.map.put(publicKey, privateKey);  //<公钥，私钥>放入秘钥池
        return publicKey;
    }

    /**
     * 用公钥加密
     *
     * @param data 待加密数据
     * @param key  公钥
     * @return 密文字节流
     * @throws Exception
     */
    public static byte[] encrypt(byte[] data, byte[] key) throws Exception {
        byte[] cipherText = null;
//        转换公钥
        X509EncodedKeySpec spec = new X509EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance("ECDH");
//        生成公钥
        PublicKey publicKey = factory.generatePublic(spec);
//        System.out.println("\n重新生成的公钥：\n"+ new BASE64Encoder().encode(publicKey.getEncoded()));
//        加密
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        cipherText = cipher.doFinal(data);
        return cipherText;
    }

    /**
     * 用私钥解密
     *
     * @param data 待解秘数据
     * @param key  私钥
     * @return 原文字节流
     * @throws Exception
     */
    public static byte[] decrypt(byte[] data, byte[] key) throws Exception {
        byte[] transData = null;
//        转换私钥
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(key);
        KeyFactory factory = KeyFactory.getInstance("ECDH");
//        生层私钥
        PrivateKey privateKey = factory.generatePrivate(spec);
//        System.out.println("\n重新生成的私钥：\n"+ new BASE64Encoder().encode(privateKey.getEncoded()));
//        解密
        Cipher cipher = Cipher.getInstance("ECIES", BouncyCastleProvider.PROVIDER_NAME);
        cipher.init(Cipher.DECRYPT_MODE,privateKey);
        transData = cipher.doFinal(data);

        return transData;
    }
}
