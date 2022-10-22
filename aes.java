package aesalgorithmkel1;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

public class AES {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        System.out.print("Masukan Key(16 bit): ");
        String key = scanner.nextLine();
        System.out.print("Masukan Plain :");
        String plain = scanner.nextLine();
        try {
            String cipher = doEcnrypt(plain, key);
            System.out.println(cipher);
            plain = doDecrypt(cipher, key);
            System.out.println(plain);
        }
        catch (Exception e) {
            System.err.println(e.toString());
        }

    }
    private static String doEcnrypt(String pesan, String kunci) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(kunci.getBytes(), "AES");
        byte[] bIv = new byte[16];
        SecureRandom.getInstanceStrong().nextBytes(bIv);
        IvParameterSpec inSpec = new IvParameterSpec(bIv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.ENCRYPT_MODE, keySpec, inSpec);
        byte[] bEn = c.doFinal(pesan.getBytes());
        String strEnc = Base64.getEncoder().encodeToString(bEn);
        String strIv = Base64.getEncoder().encodeToString(bIv);
        return strIv + " : " + strEnc;
    }
    private static String doDecrypt(String cipher, String kunci) throws Exception {
        SecretKeySpec keySpec = new SecretKeySpec(kunci.getBytes(), "AES");
        String[] pair = cipher.split(" : ");
        byte[] bIv = Base64.getDecoder().decode(pair[0]);
        byte[] bEn = Base64.getDecoder().decode(pair[1]);
        IvParameterSpec inSpec = new IvParameterSpec(bIv);
        Cipher c = Cipher.getInstance("AES/CBC/PKCS5Padding");
        c.init(Cipher.DECRYPT_MODE, keySpec, inSpec);
        byte[] bDec = c.doFinal(bEn);
        return new String(bDec);
    }
}
