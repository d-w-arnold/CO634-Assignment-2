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
    private String pt;
    private boolean plaintextFound;

    public VigenereDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.plaintextFound = false;
    }

    /**
     * Decrypt with a provided key.
     */
    public String decrypt(String key)
    {
        decryptPrivate(key);
        return pt;
    }

    /**
     * Decrypt with an unknown key which is an arbitary sequence of letters.
     * @param keyLen Length of the unknown key.
     */
    public String decrypt(int keyLen)
    {
        checkAllKeys(charAlphabet, keyLen);
        if (plaintextFound) {
            return pt;
        } else {
            return "";
        }
    }

    // The method that tries all decryption keys of a given length k.
    // It is mainly a wrapper over recursive function checkAllKeysRec()
    private void checkAllKeys(char[] set, int k)
    {
        checkAllKeysRec(set, "", set.length, k);
    }

    // The main recursive method to try decryption with all possible strings of length k.
    private void checkAllKeysRec(char[] set, String prefix, int n, int k)
    {
        // Base case: k is 0, print prefix
        if (k != 0) {
            // One by one add all characters from set and recursively call for k equals to k-1
            for (int i = 0; i < n; ++i) {
                // Next character of input added
                String newPrefix = prefix + set[i];
                // k is decreased, because we have added a new character
                checkAllKeysRec(set, newPrefix, n, k - 1);
            }
        } else {
            System.out.println(prefix);
            decryptPrivate(prefix);
            if (tess.contains(pt)) {
                // We've found our plaintext.
                return;
            }
        }
    }

    private void decryptPrivate(String key)
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
        pt = decryptedPlaintext;
    }
}
