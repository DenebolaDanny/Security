import sun.misc.BASE64Encoder;

import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

/**
 * Created by Denebola on 2016/12/6.
 */
public class RSASignTest {
    private byte[] privateKey;
    private byte[] publicKey;

    public void initKey() throws Exception{
        Map<String,Object> keyMap = RSASign.initKey();
        privateKey = RSASign.getPrivateKey(keyMap);
        publicKey=RSASign.getPublicKey(keyMap);
        System.out.println("私钥：\n"+ new BASE64Encoder().encode(privateKey));
        System.out.println("公钥：\n"+new BASE64Encoder().encode(publicKey));
    }

    public void sign() throws Exception{
        String test = "这是要签名的一句话。";
        byte[] byteTest=test.getBytes();
        byte[] sign = RSASign.sign(byteTest,privateKey);
        System.out.println("签名：\n"+new BASE64Encoder().encode(sign));
        System.out.println("状态：\n"+RSASign.vertify(byteTest,publicKey,sign));
    }
}
