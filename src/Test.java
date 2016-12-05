import sun.misc.BASE64Encoder;

/**
 * Created by Denebola on 2016/11/24.
 */
public class Test {
    public void AESTest() throws Exception{
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
}
