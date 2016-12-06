import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

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
    public static byte[] sign(byte[] data,byte[] privateKey) throws Exception{
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKey);  //转换私钥
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");   //实例化秘钥工厂
        PrivateKey priKey = keyFactory.generatePrivate(pkcs8EncodedKeySpec);    //取得私钥
        Signature signature = Signature.getInstance("MD5withRSA");
        signature.initSign(priKey); // 初始化Signture
        signature.update(data);     //更新
        return signature.sign();    //签名
    }

    /**
     * 校验
     * @param data 待校验数据
     * @param publickey 公钥
     * @param sign 数字签名
     * @return 校验成功判断
     * @throws Exception
     */
    public static boolean vertify(byte[] data, byte[] publickey,byte[] sign) throws Exception{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(publickey); //转换公钥材料
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");  //实例化工厂
        PublicKey pubKey = keyFactory.generatePublic(keySpec);  // 生成公钥
        Signature signature = Signature.getInstance("MD5withRSA");  //实例化Signature
        signature.initVerify(pubKey);
        signature.update(data);
        return signature.verify(sign);

    }
}

