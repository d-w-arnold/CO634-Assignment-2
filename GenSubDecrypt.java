import javafx.util.Pair;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.Comparator;

/**
 * Decryption of ciphertext encoded with a General Substitution Cipher.
 *
 * @author David W. Arnold
 * @version 09/11/2019
 */
public class GenSubDecrypt extends Decrypt
{
    final private ArrayList<Character> ENGLISH_FREQUENCY_ORDER = new ArrayList<Character>()
    {{
        add('|');
        add('E');
        add('T');
        add('A');
        add('O');
        add('I');
        add('N');
        add('S');
        add('H');
        add('R');
        add('D');
        add('L');
        add('C');
        add('U');
        add('M');
        add('W');
        add('F');
        add('G');
        add('Y');
        add('P');
        add('B');
        add('V');
        add('K');
        add('J');
        add('X');
        add('Q');
        add('Z');
    }};
    private String pt;

    public GenSubDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
    }

    /**
     * Decrypt a General Substitution Cipher.
     */
    public String decrypt()
    {
        System.out.println(getExercise(cipherFile) + ": General Substitution Cipher");
        // Key: Character in charAlphabet
        // Value: Occurrences of a given character in ciphertext
        ArrayList<Pair<Character, Integer>> characterCounts = new ArrayList<>();
        // For each character in charAlphabet
        // characterCounts for number of occurrences for each character
        for (char charAlpha : charAlphabet) {
            int totalOccurrences = 0;
            for (char charCipher : ciphertext.toCharArray()) {
                if (charAlpha == charCipher) {
                    totalOccurrences++;
                }
            }
            characterCounts.add(new Pair<>(charAlpha, totalOccurrences));
        }
        // Sort characterCounts into descending order for count
        characterCounts.sort(new Comparator<Pair<Character, Integer>>() {
            @Override
            public int compare(Pair<Character, Integer> o1, Pair<Character, Integer> o2) {
                if (o1.getValue() > o2.getValue()) {
                    return -1;
                } else if (o1.getValue().equals(o2.getValue())) {
                    return 0; // You can change this to make it then look at the
                    //words alphabetical order
                } else {
                    return 1;
                }
            }
        });
        // Generate String representation of character mappings
        // Key: letter in ciphertext
        // Value: most likely mapped letter based on frequency of occurrence
        ArrayList<Pair<Character, Character>> mappedLetters = new ArrayList<>();
        for (int i = 0; i < characterCounts.size(); i++) {
            mappedLetters.add(new Pair<>(characterCounts.get(i).getKey(), ENGLISH_FREQUENCY_ORDER.get(i)));
        }
        // Generate mapped letters String
        String mappedString = "";
        for (char sw : charAlphabet) {
            for (Pair<Character, Character> pair : mappedLetters) {
                if (pair.getValue() == sw) {
                    mappedString += pair.getKey();
                }
            }
        }
        // Using mappedChars generate plaintext
        String decryptedPlaintext = "";
        for (char ctChar : ciphertext.toCharArray()) {
            for (Pair<Character, Character> pair : mappedLetters) {

                if (pair.getKey() == ctChar) {

                    decryptedPlaintext += pair.getValue();

                }
            }
        }
        // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
        if (tess.contains(decryptedPlaintext)) {
            System.out.println("Decrypted: " + decryptedPlaintext);
            System.out.println("Character Alphabet: " + String.valueOf(charAlphabet));
            System.out.println("Character Mappings: " + "");
            System.out.println();
            pt = decryptedPlaintext;
        }
        return pt;
    }
}
