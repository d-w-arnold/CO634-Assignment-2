import java.io.File;
import java.io.IOException;

/**
 * Decryption of ciphertext encoded with a Vigenere Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class VigenereDecrypt extends Decrypt
{
    public VigenereDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
    }

    /**
     * Decrypt with a provided key.
     */
    public String decrypt(String key)
    {
        String decryptedPlaintext = "";
        char[] keyCharacters = key.toCharArray();
        int charAlphaLen = charAlphabet.length;
        int i = 0;
        // For each character in the cipher text.
        for (char character : ciphertext.toCharArray()) {
            // The value of the character in the cipher text.
            int a = findIndex(charAlphabet, character);
            // The value of the character in the provided key.
            int b = findIndex(charAlphabet, keyCharacters[(i % key.length())]);
            decryptedPlaintext += charAlphabet[(charAlphaLen + (a - b)) % charAlphaLen];
            i++;
        }
        // If the tess??.txt file contains the decrypted plaintext,
        // it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println(getExercise(cipherFile) + ": Vigenere Cipher");
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Key: " + key);
            System.out.println();
        }
        return decryptedPlaintext;
    }

    /**
     * Decrypt with an unknown key which is an arbitary sequence of letters.
     *
     * @param len Length of the unknown key.
     */
    public String decrypt(int len)
    {


        return "";
    }
}
