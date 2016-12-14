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
     * @throws Exception
     */
    @org.junit.Test
    public void AEStest() throws Exception{
        String data="11111111111111AES";
        byte[] byteData=data.getBytes();
        byte[] key = AESCoder.initKey();
        System.out.println("密钥："+ new BASE64Encoder().encode(key));

        byteData = AESCoder.encrypt(byteData,key);
        System.out.println("加密后："+new BASE64Encoder().encode(byteData));

        byteData = AESCoder.decrypt(byteData,key);
        data = new String(byteData);
        System.out.println("解密后："+data);
    }

    /**
     * RSA签名测试
     * @throws Exception
     */
    @org.junit.Test
    public void RSASignTest()throws Exception{
         byte[] privateKey;
         byte[] publicKey;

        Map<String,Object> keyMap = RSASign.initKey();
        privateKey = RSASign.getPrivateKey(keyMap);
        publicKey=RSASign.getPublicKey(keyMap);
        System.out.println("私钥：\n"+ new BASE64Encoder().encode(privateKey));
        System.out.println("公钥：\n"+new BASE64Encoder().encode(publicKey));

        String test = "这是要签名的一句话。";
        byte[] byteTest=test.getBytes();
        byte[] sign = RSASign.sign(byteTest,privateKey);
        System.out.println("签名：\n"+new BASE64Encoder().encode(sign));
        System.out.println("状态：\n"+RSASign.vertify(byteTest,publicKey,sign));
    }

    /**
     * RSA加密测试
     * @throws Exception
     */
    @org.junit.Test
    public void RSATest() throws Exception{
        byte[] privateKey;
        byte[] publicKey;
        Map<String,Object> keyMap = RSACoder.initKey();
        privateKey = RSACoder.getPrivateKey(keyMap);
        publicKey=RSACoder.getPublicKey(keyMap);
        System.out.println("公钥：\n"+ new BASE64Encoder().encode(publicKey));
        System.out.println("私钥：\n"+ new BASE64Encoder().encode(privateKey));

        String string="待加密数据";
        byte[] data = string.getBytes();
        System.out.println("原始数据："+string);
        byte[] encodeData = RSACoder.encryptByPublicKey(data,publicKey);
        System.out.println("加密后：\n"+ new BASE64Encoder().encode(encodeData));
        byte[] decodeData = RSACoder.decryptByPrivateKey(encodeData,privateKey);
        System.out.println("解密后：\n"+new BASE64Encoder().encode(decodeData));
        System.out.println("解密后数据：\n"+new String(decodeData));
    }

    /**
     * ECIES加密测试
     * @throws Exception
     */
    @org.junit.Test
    public void ECIESTest()throws Exception{
        String test="一定要成功！";

        String publicKey=ECIESCoder.initKey();
        String cryptData = ECIESCoder.encrypt(test,publicKey);
        String privateKey=ECIESCoder.map.get(publicKey);
        byte[] rawData = ECIESCoder.decrypt(cryptData,privateKey);
        System.out.println("原始数据：\n"+test);
        System.out.println("加密数据：\n"+cryptData);
        System.out.println("私钥：\n"+ privateKey);
        System.out.println("公钥：\n"+ publicKey);
        System.out.println("解密后数据：\n"+new String(rawData));
    }


}
