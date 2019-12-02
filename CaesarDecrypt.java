import java.io.File;
import java.io.IOException;

/**
 * Decryption of ciphertext encoded with a Caesar Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class CaesarDecrypt extends Decrypt
{
    private String pt;

    public CaesarDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
    }

    public String decrypt()
    {
        int charAlphaLen = charAlphabet.length;
        // For all possible characters in the character alphabet.
        for (int i = 0; i < charAlphaLen; i++) {
            String plaintext = "";
            // For every single character in the ciphertext.
            for (int j = 0; j < ciphertext.length(); j++) {
                int c = findIndex(charAlphabet, ciphertext.charAt(j));
                plaintext += charAlphabet[(charAlphaLen + (c - i)) % charAlphaLen];
            }
            // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
            if (tess.contains(plaintext)) {
                System.out.println(getExercise(cipherFile) + ": Caesar Cipher");
                System.out.println("Decrypted: " + plaintext);
                System.out.println("Key: " + charAlphabet[i]);
                System.out.println();
                pt = plaintext;
            }
        }
        return pt;
    }
}
