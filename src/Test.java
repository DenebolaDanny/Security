import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.util.encoders.Base64;
import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

import java.util.Map;

/**
 * Created by kevindanny on 2016/12/13.
 */
public class Test {
    /**
     * AES对称加密测试
     *
     * @throws Exception
     */
    @org.junit.Test
    public void AEStest() throws Exception {
        String data = "11111111111111AES";
        String key = AESCoder.initKey();
        System.out.println("密钥：" + key);

        data = AESCoder.encrypt(data, key);
        System.out.println("加密后：" + data);

        data = AESCoder.decrypt(data, key);
        data = new String(data);
        System.out.println("解密后：" + data);
    }

    /**
     * RSA签名测试
     *
     * @throws Exception
     */
    @org.junit.Test
    public void RSASignTest() throws Exception {
        String privateKey;
        String publicKey;

        Map<String, String> keyMap = RSASign.initKey();
        privateKey = RSASign.getPrivateKey(keyMap);
        publicKey = RSASign.getPublicKey(keyMap);
        System.out.println("私钥：\n" + privateKey);
        System.out.println("公钥：\n" + publicKey);

        String test = "这是要签名的一句话。";
        String sign = RSASign.sign(test, privateKey);
        System.out.println("签名：\n" + sign);
        System.out.println("状态：\n" + RSASign.vertify(test, publicKey, sign));
    }

    /**
     * RSA加密测试
     *
     * @throws Exception
     */
    @org.junit.Test
    public void RSATest() throws Exception {
        String privateKey;
        String publicKey;
        Map<String, String> keyMap = RSACoder.initKey();
        privateKey = RSACoder.getPrivateKey(keyMap);
        publicKey = RSACoder.getPublicKey(keyMap);
        System.out.println("公钥：\n" + publicKey);
        System.out.println("私钥：\n" + privateKey);

        String data = "这里这里在这里";
        System.out.println("原始数据：" + data);
        String encodeData = RSACoder.encryptByPublicKey(data, publicKey);
        System.out.println("加密后：\n" + encodeData);
        String decodeData = RSACoder.decryptByPrivateKey(encodeData, privateKey);
        System.out.println("解密后：\n" + decodeData);
        System.out.println("解密后数据：\n" + decodeData);
    }

    /**
     * ECIES加密测试
     *
     * @throws Exception
     */
    @org.junit.Test
    public void ECIESTest() throws Exception {
        String test = "一定要成功！";

        String publicKey = ECIESCoder.initKey();
        String cryptData = ECIESCoder.encrypt(test, publicKey);
        String privateKey = ECIESCoder.map.get(publicKey);
        String rawData = ECIESCoder.decrypt(cryptData, privateKey);
        System.out.println("原始数据：\n" + test);
        System.out.println("加密数据：\n" + cryptData);
        System.out.println("私钥：\n" + privateKey);
        System.out.println("公钥：\n" + publicKey);
        System.out.println("解密后数据：\n" + rawData);
    }

    @org.junit.Test
    public void DSATest() throws Exception {
        String str = "DSA数字签名";
        DSACoder dsaCoder = new DSACoder();
        dsaCoder.init();
        String sign = dsaCoder.sign(str, dsaCoder.getPrivateKey());
        boolean status = dsaCoder.vertify(str, dsaCoder.getPublicKey(), sign);
        System.out.println("公钥：\n" + dsaCoder.getPublicKey());
        System.out.println("私钥：\n" + dsaCoder.getPrivateKey());
        System.out.println("签名：\n" + sign);
        System.out.println("状态\n" + status);
    }

    @org.junit.Test
    public void ECDSATest() throws Exception {
        String str = "ECDSA数字签名";
        ECDSACoder ecdsaCoder = new ECDSACoder();
        ecdsaCoder.init();
        String sign = ecdsaCoder.sign(str, ecdsaCoder.getPrivateKey());
        boolean status = ecdsaCoder.vertify(str, ecdsaCoder.getPublicKey(), sign);
        System.out.println("公钥：\n" + ecdsaCoder.getPublicKey());
        System.out.println("私钥：\n" + ecdsaCoder.getPrivateKey());
        System.out.println("签名：\n" + sign);
        System.out.println("状态\n" + status);
    }
}
