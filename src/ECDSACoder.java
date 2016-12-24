import org.bouncycastle.jce.interfaces.ECPrivateKey;
import org.bouncycastle.jce.interfaces.ECPublicKey;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;

/**
 * Created by Denebola on 2016/12/24.
 */
public class ECDSACoder {
    private byte[] privateKey;
    private byte[] publicKey;

    public String getPrivateKey() {
        return CodeType.b2s(privateKey);
    }

    public String getPublicKey() {
        return CodeType.b2s(publicKey);
    }

    public void init() throws Exception{
        Security.addProvider(new BouncyCastleProvider());
        BigInteger p = new BigInteger(
                "883423532389192164791648750360308885314476597252960362792450860609699839"
        );
        ECFieldFp ecFieldFp = new ECFieldFp(p);
        BigInteger a=new BigInteger(
          "7fffffffffffffffffffffff7fffffffffff8000000000007ffffffffffc",16
        );
        BigInteger b = new BigInteger
                ("6b016c3bdcf18941d0d654921475ca71a9db2fb27d1d37796185c2942c0a",16);
        EllipticCurve ellipticcurve = new EllipticCurve(ecFieldFp, a, b);
        BigInteger x = new BigInteger
                ("110282003749548856476348533541186204577905061504881242240149511594420911");
        BigInteger y = new BigInteger
                ("869078407435509378747351873793058868500210384946040694651368759217025454");
        ECPoint g = new ECPoint(x, y);
        BigInteger n = new BigInteger("883423532389192164791648750360308884807550341691627752275345424702807307");
        ECParameterSpec ecParameterSpec = new ECParameterSpec (ellipticcurve,g, n, 1);

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA");
        kpg.initialize(ecParameterSpec, new SecureRandom());

        KeyPair keypair = kpg.generateKeyPair();
        ECPublicKey publicKey = (ECPublicKey) keypair.getPublic();
        ECPrivateKey privateKey = (ECPrivateKey)keypair.getPrivate();

        this.privateKey=privateKey.getEncoded();

        this.publicKey = publicKey.getEncoded();
    }

    public String sign(String data,String privateKey) throws Exception{
        PKCS8EncodedKeySpec encodedKeySpec = new PKCS8EncodedKeySpec(CodeType.s2b(privateKey));
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        PrivateKey priKey = keyFactory.generatePrivate(encodedKeySpec);

        Signature signature = Signature.getInstance("SHA256withECDSA");

        signature.initSign(priKey);

        signature.update(data.getBytes());

        return CodeType.b2s(signature.sign());
    }

    public boolean vertify(String data,String publicKey,String sign) throws Exception{
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(CodeType.s2b(publicKey));
        KeyFactory keyFactory = KeyFactory.getInstance("ECDSA");
        PublicKey pubKey = keyFactory.generatePublic(keySpec);
        Signature signature = Signature.getInstance("SHA256withECDSA");

        signature.initVerify(pubKey);
        signature.update(data.getBytes());

        return signature.verify(CodeType.s2b(sign));
    }
}
