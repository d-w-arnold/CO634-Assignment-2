import javafx.util.Pair;
import java.io.File;
import java.io.IOException;
import java.util.*;

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
        // Generate mappedLetters String for decryption
        String mappedString = "";
        for (int i = 0; i < characterCounts.size(); i++) {
            mappedString += characterCounts.get(i).getKey();
        }
        System.out.println();
        // Try all permutations of mappedString
        String decryptedPlaintext = "";
        Set<String> oldSet = null;
        int count = 0;
        for (int i = 1; i < mappedString.length(); i++) {
            Set<String> set = permute(mappedString.substring(mappedString.length() - i));
            for (String s : set) {
                if (oldSet == null || !oldSet.contains(s.substring(s.length() - (i - 1)))) {
                    String permuMappedString = mappedString.substring(0, mappedString.length() - i) + s;
                    // Generate permutation of mappedLetters according to the permutation of mappedString
                    HashMap<Character, Character> permuMappedLetters = new HashMap<>();
                    char[] pMS = permuMappedString.toCharArray();
                    for (int j = 0; j < pMS.length; j++) {
                        permuMappedLetters.put(pMS[j], ENGLISH_FREQUENCY_ORDER.get(j));
                    }
                    // Generate decrypted plaintext from permutation of mapped
                    decryptedPlaintext = "";
                    for (char ctChar : ciphertext.toCharArray()) {
                        char newCtChar = permuMappedLetters.get(ctChar);
                        decryptedPlaintext += newCtChar;
                    }
                    // If the tess??.txt file contains the decrypted plaintext, it must be the correct decryption.
                    if (tess.contains(decryptedPlaintext)) {
                        System.out.println("Decrypted: " + decryptedPlaintext);
                        System.out.println("Character Alphabet: " + String.valueOf(charAlphabet));
                        System.out.println("Character Mappings: " + permuMappedLetters);
                        System.out.println("Count Iterations: " + count);
                        System.out.println();
                        pt = decryptedPlaintext;
                        return pt;
                    } else {
                        System.out.println("Not: " + permuMappedString);
                        count++;
                    }
                }
            }
            oldSet = set;
        }
        return pt;
    }

    // For a given string, return a set of all possible strings made byt the chars of the provided string.
    private static Set<String> permute(String chars)
    {
        // Use sets to eliminate semantic duplicates (aab is still aab even if you switch the two 'a's)
        // Switch to HashSet for better performance
        Set<String> set = new TreeSet<>();

        // Termination condition: only 1 permutation for a string of length 1
        if (chars.length() == 1) {
            set.add(chars);
        }
        else {
            // Give each character a chance to be the first in the permuted string
            for (int i = 0; i<chars.length(); i++)
            {
                // Remove the character at index i from the string
                String pre = chars.substring(0, i);
                String post = chars.substring(i + 1);
                String remaining = pre + post;

                // Recurse to find all the permutations of the remaining chars
                for (String permutation : permute(remaining))
                {
                    // Concatenate the first character with the permutations of the remaining chars
                    set.add(chars.charAt(i) + permutation);
                }
            }
        }
        return set;
    }
}
