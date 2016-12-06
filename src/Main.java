public class Main {

    public static void main(String[] args) throws Exception{
//        RSATest rsaTest = new RSATest();
//        rsaTest.initKey();
//        rsaTest.test();

        RSASignTest rst = new RSASignTest();
        rst.initKey();
        rst.sign();
    }
}
