import java.security.*;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

/**
 * Created by Denebola on 2016/12/24.
 */
public class DSACoder  {
    private byte[] privateKey;
    private byte[] publicKey;

    public String getPrivateKey() {
        return CodeType.b2s(privateKey);
    }

    public String getPublicKey() {
        return CodeType.b2s(publicKey);
    }

    public void init() throws Exception{
        KeyPairGenerator keygen = KeyPairGenerator.getInstance("DSA");
        keygen.initialize(1024,new SecureRandom());
        KeyPair keys = keygen.generateKeyPair();
        DSAPublicKey publicKey = (DSAPublicKey)keys.getPublic();
        DSAPrivateKey privateKey = (DSAPrivateKey)keys.getPrivate();

        this.privateKey = privateKey.getEncoded();
        this.publicKey = publicKey.getEncoded();
    }

    public String sign(String data,String privateKey) throws Exception{
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(CodeType.s2b(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PrivateKey priKey = keyFactory.generatePrivate(encodedKeySpec);

        Signature signature = Signature.getInstance("SHA1withDSA");

        signature.initSign(priKey);

        signature.update(data.getBytes());

        return CodeType.b2s(signature.sign());
    }

    public boolean vertify(String data,String publicKey,String sign) throws Exception{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(CodeType.s2b(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("DSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA1withDSA");

        signature.initVerify(pubKey);
        signature.update(data.getBytes());

        return signature.verify(CodeType.s2b(sign));
    }
}
