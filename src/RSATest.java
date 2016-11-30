import com.sun.xml.internal.org.jvnet.staxex.Base64Data;
import sun.misc.BASE64Encoder;

import java.util.*;

/**
 * Created by kevindanny on 2016/11/30.
 */
public class RSATest {
    private byte[] privateKey;
    private byte[] publicKey;

    /**
     * 初始化秘钥
     * @throws Exception
     */
    public void initKey()throws Exception{
        Map<String,Object> keyMap = RSACoder.initKey();
        privateKey = RSACoder.getPrivateKey(keyMap);
        publicKey=RSACoder.getPublicKey(keyMap);
        System.out.println("公钥：\n"+ new BASE64Encoder().encode(publicKey));
        System.out.println("私钥：\n"+ new BASE64Encoder().encode(privateKey));
    }

    public void test()throws Exception{
        String string="待加密数据";
        byte[] data = string.getBytes();
        System.out.println("原始数据："+string);
        byte[] encodeData = RSACoder.encryptByPublicKey(data,publicKey);
        System.out.println("加密后：\n"+ new BASE64Encoder().encode(encodeData));
         byte[] decodeData = RSACoder.decryptByPrivateKey(encodeData,privateKey);
        System.out.println("解密后：\n"+new BASE64Encoder().encode(decodeData));
        System.out.println("解密后数据：\n"+new String(decodeData));
    }
}
