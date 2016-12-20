import sun.misc.BASE64Decoder;
import sun.misc.BASE64Encoder;

/**
 * Created by Denebola on 2016/12/19.
 */
public class CodeType {
    public static String b2s(byte[] b){
        return new BASE64Encoder().encodeBuffer(b);
    }

    public static byte[] s2b(String str) throws Exception{
        return new BASE64Decoder().decodeBuffer(str);
    }
}
