import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class AES {

  public static byte[] encrypt(String plainText, byte[] encryptionKey, String IV) throws Exception {
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");
    cipher.init(Cipher.ENCRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return cipher.doFinal(plainText.getBytes("UTF-8"));
  }

  public static String decrypt(byte[] cipherText, byte[] encryptionKey, String IV) throws Exception{
    Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "SunJCE");
    SecretKeySpec key = new SecretKeySpec(encryptionKey, "AES");
    cipher.init(Cipher.DECRYPT_MODE, key,new IvParameterSpec(IV.getBytes("UTF-8")));
    return new String(cipher.doFinal(cipherText),"UTF-8");
  }
  
}