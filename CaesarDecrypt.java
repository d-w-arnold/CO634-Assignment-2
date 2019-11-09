import java.io.File;
import java.io.IOException;

/**
 * Decryption of ciphertext encode with a Caesar Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class CaesarDecrypt extends Decrypt
{
    public CaesarDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
    }

    public String decrypt()
    {
        int charAlphaLen = charAlphabet.length;
        String decryptedPlaintext = "";
        // For all possible values of k.
        for (int k = 0; k < charAlphaLen; k++) {
            String plaintext = "";
            // For every single character in the ciphertext.
            for (int j = 0; j < ciphertext.length(); j++) {
                int c = findIndex(charAlphabet, ciphertext.charAt(j));
                plaintext += charAlphabet[(charAlphaLen + (c - k)) % charAlphaLen];
            }
            // If the tess??.txt file contains the decrypted plaintext with a given k value,
            // it must be the correct decryption.
            if (tess.contains(plaintext)) {
                System.out.println("Caesar Cipher\n");
                System.out.println("Decrypted: " + plaintext);
                System.out.println("Key: " + k);
                decryptedPlaintext = plaintext;
            }
        }
        return decryptedPlaintext;
    }
}
