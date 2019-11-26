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
    final private ArrayList<String> ENGLISH_ONE_LETTER_WORDS = new ArrayList<String>()
    {{
        add("A");
        add("I");
    }};
    final private ArrayList<String> ENGLISH_TWO_LETTER_WORDS = new ArrayList<String>()
    {{
        add("OF");
        add("TO");
        add("IN");
        add("IT");
        add("IS");
        add("BE");
        add("AS");
        add("AT");
        add("SO");
        add("WE");
        add("HE");
        add("BY");
        add("OR");
        add("ON");
        add("DO");
        add("IF");
        add("ME");
        add("MY");
        add("UP");
        add("AN");
        add("GO");
        add("NO");
        add("US");
        add("AM");
    }};
    final private ArrayList<String> ENGLISH_THREE_LETTER_WORDS = new ArrayList<String>()
    {{
        add("THE");
        add("AND");
        add("FOR");
        add("ARE");
        add("BUT");
        add("NOT");
        add("YOU");
        add("ALL");
        add("ANY");
        add("CAN");
        add("HAD");
        add("HER");
        add("WAS");
        add("ONE");
        add("OUR");
        add("OUT");
        add("DAY");
        add("GET");
        add("HAS");
        add("HIM");
        add("HIS");
        add("HOW");
        add("MAN");
        add("NEW");
        add("NOW");
        add("OLD");
        add("SEE");
        add("TWO");
        add("WAY");
        add("WHO");
        add("BOY");
        add("DID");
        add("ITS");
        add("LET");
        add("PUT");
        add("SAY");
        add("SHE");
        add("TOO");
        add("USE");
    }};
    final private ArrayList<String> ENGLISH_FOUR_LETTER_WORDS = new ArrayList<String>()
    {{
        add("THAT");
        add("WITH");
        add("HAVE");
        add("THIS");
        add("WILL");
        add("YOUR");
        add("FROM");
        add("THEY");
        add("KNOW");
        add("WANT");
        add("BEEN");
        add("GOOD");
        add("MUCH");
        add("SOME");
        add("TIME");
    }};
    private String pt;
    // Key: letter in ciphertext, Value: most likely mapped letter based on frequency of occurrence
    ArrayList<Pair<Character, Character>> mappedLetters;
    private ArrayList<Pair<String, ArrayList<String>>> mostSimilaritiesForEachWord;
    private ArrayList<Pair<String, ArrayList<ArrayList<Pair<Character, Character>>>>> mostSimilaritiesForEachWordMappings;
    HashMap<Character, Character> mappedLetters2;

    public GenSubDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.mappedLetters = new ArrayList<>();
        this.mostSimilaritiesForEachWord = new ArrayList<>();
        this.mostSimilaritiesForEachWordMappings = new ArrayList<>();
        this.mappedLetters2 = new HashMap<>();
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
        characterCounts.sort(new Comparator<Pair<Character, Integer>>()
        {
            @Override
            public int compare(Pair<Character, Integer> o1, Pair<Character, Integer> o2)
            {
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
        for (int i = 0; i < characterCounts.size(); i++) {
            mappedLetters.add(new Pair<>(characterCounts.get(i).getKey(), ENGLISH_FREQUENCY_ORDER.get(i)));
        }
        // Generate mappedLetters String for decryption
        String mappedString = "";
        for (int i = 0; i < characterCounts.size(); i++) {
            mappedString += characterCounts.get(i).getKey();
        }
        // Generate decrypted plaintext from mappedLetters
        String decryptedPlaintext = "";
        for (char ctChar : ciphertext.toCharArray()) {
            for (int i = 0; i < mappedLetters.size(); i++) {
                if (mappedLetters.get(i).getKey() == ctChar) {
                    decryptedPlaintext += mappedLetters.get(i).getValue();
                }
            }
        }
        // Separate decrypted plaintext into potential words separated by '|'
        String[] separated = decryptedPlaintext.split("\\|");
        ArrayList<String> potentialWords = new ArrayList<>(Arrays.asList(separated));
        // Check for any english words which already exist
        setExistingWordsToLowerCase(potentialWords);
        // Populate mostSimilaritiesForEachWord
        for (int i = 1; i <= 4; i++) {
            for (int j = 0; j < potentialWords.size(); j++) {
                String potentialWord = potentialWords.get(j);
                if (potentialWord.length() == i) { // 1 letter words, then 2, then 3, then 4
                    mostSimilarWord(potentialWord);
                }
            }
        }
        // Remove duplicates from mostSimilaritiesForEachWord
        mostSimilaritiesForEachWord = removeDuplicates(mostSimilaritiesForEachWord);
        // Populate mostSimilaritiesForEachWordMappings
        for (int i = 0; i < mostSimilaritiesForEachWord.size(); i++) {
            Pair<String, ArrayList<String>> mostSimilaritiesForAWord = mostSimilaritiesForEachWord.get(i);
            if (mostSimilaritiesForAWord.getKey().length() == 1) { // 1 letter word
                String letterBeingMapped = mostSimilaritiesForAWord.getKey();
                ArrayList<String> newLetterMappings = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (int j = 0; j < mostSimilaritiesForAWord.getValue().size(); j++) {
                    int finalJ = j;
                    tmpArray.add(new ArrayList<Pair<Character, Character>>(){{add(new Pair<>(letterBeingMapped.charAt(0), newLetterMappings.get(finalJ).charAt(0)));}});
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(letterBeingMapped, new ArrayList<>(tmpArray)));
            } else { // 2, 3 and 4 letter words
                char[] wordBeingMapped = mostSimilaritiesForAWord.getKey().toCharArray();
                ArrayList<String> newLetterMappings = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (int j = 0; j < newLetterMappings.size(); j++) {
                    ArrayList<Pair<Character, Character>> singleArray = new ArrayList<>(); // All mappings for PE => BE
                    char[] wordBeingMappedTo = newLetterMappings.get(j).toCharArray();
                    for (int k = 0; k < wordBeingMapped.length; k++) {
                        System.out.println();
                        if (wordBeingMapped[k] != wordBeingMappedTo[k]) {
                            singleArray.add(new Pair<>(wordBeingMapped[k], wordBeingMappedTo[k]));
                        }
                    }
                    tmpArray.add(singleArray);
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(mostSimilaritiesForAWord.getKey(), new ArrayList<>(tmpArray)));
            }
        }
        System.out.println();
        // Start work out actual letter mappings, mappedLetters2
        boolean succesfulPath = false;
        while (!succesfulPath) {
            HashMap<Character, Character> tmpMappedLetters2 = new HashMap<>();
            for (int i = 0; i < mostSimilaritiesForEachWordMappings.size(); i++) {
                System.out.println();
            }
        }
        System.out.println();
        return pt;
    }

    // Any words already existing of length 1, 2 or 3 in potentialWords, set toLowerCase.
    private void setExistingWordsToLowerCase(ArrayList<String> potentialWords)
    {
        for (int i = 1; i <= 4; i++) {
            for (int j = 0; j < potentialWords.size(); j++) {
                if (i == 1) {
                    if (ENGLISH_ONE_LETTER_WORDS.contains(potentialWords.get(j))) {
                        String lowerCaseTmp = potentialWords.get(j).toLowerCase();
                        potentialWords.set(j, lowerCaseTmp);
                        for (int k = 0; k < lowerCaseTmp.length(); k++) {
                            mappedLetters2.put(Character.toUpperCase(lowerCaseTmp.charAt(k)), Character.toUpperCase(lowerCaseTmp.charAt(k)));
                        }
                    }
                } else if (i == 2) {
                    if (ENGLISH_TWO_LETTER_WORDS.contains(potentialWords.get(j).toUpperCase())) {
                        String lowerCaseTmp = potentialWords.get(j).toLowerCase();
                        potentialWords.set(j, lowerCaseTmp);
                        for (int k = 0; k < lowerCaseTmp.length(); k++) {
                            mappedLetters2.put(Character.toUpperCase(lowerCaseTmp.charAt(k)), Character.toUpperCase(lowerCaseTmp.charAt(k)));
                        }
                    }
                } else if (i == 3) {
                    if (ENGLISH_THREE_LETTER_WORDS.contains(potentialWords.get(j).toUpperCase())) {
                        String lowerCaseTmp = potentialWords.get(j).toLowerCase();
                        potentialWords.set(j, lowerCaseTmp);
                        for (int k = 0; k < lowerCaseTmp.length(); k++) {
                            mappedLetters2.put(Character.toUpperCase(lowerCaseTmp.charAt(k)), Character.toUpperCase(lowerCaseTmp.charAt(k)));
                        }
                    }
                } else if (i == 4) {
                    if (ENGLISH_FOUR_LETTER_WORDS.contains(potentialWords.get(j).toUpperCase())) {
                        String lowerCaseTmp = potentialWords.get(j).toLowerCase();
                        potentialWords.set(j, lowerCaseTmp);
                        for (int k = 0; k < lowerCaseTmp.length(); k++) {
                            mappedLetters2.put(Character.toUpperCase(lowerCaseTmp.charAt(k)), Character.toUpperCase(lowerCaseTmp.charAt(k)));
                        }
                    }
                }
            }
        }
    }

    // Function to remove duplicates from an ArrayList.
    public <T> ArrayList<T> removeDuplicates(ArrayList<T> list)
    {
        // Create a new ArrayList
        ArrayList<T> newList = new ArrayList<>();
        // Traverse through the first list
        for (T element : list) {
            // If this element is not present in newList then add it
            if (!newList.contains(element)) {
                newList.add(element);
            }
        }
        return newList;
    }

    // For a given word, returns the most similar word in ENGLISH_?_LETTER_WORDS.
    private void mostSimilarWord(String possibleWord)
    {
        if (possibleWord.length() == 1) {
            mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, ENGLISH_ONE_LETTER_WORDS));
        } else if (possibleWord.length() == 2) {
            // If the word is lowerCase already, its an english word - keep
            if (!allLowerCase(possibleWord)) {
                HashMap<String, Double> similarities = new HashMap<>();
                for (int i = 0; i < ENGLISH_TWO_LETTER_WORDS.size(); i++) {
                    String word = ENGLISH_TWO_LETTER_WORDS.get(i);
                    similarities.put(word, similarity(possibleWord, word));
                }
                genMostSimilarities(possibleWord, similarities);
            }
        } else if (possibleWord.length() == 3) {
            // If the word is lowerCase already, its an english word - keep
            if (!allLowerCase(possibleWord)) {
                HashMap<String, Double> similarities = new HashMap<>();
                for (int i = 0; i < ENGLISH_THREE_LETTER_WORDS.size(); i++) {
                    String word = ENGLISH_THREE_LETTER_WORDS.get(i);
                    similarities.put(word, similarity(possibleWord, word));
                }
                genMostSimilarities(possibleWord, similarities);
            }
        } else if (possibleWord.length() == 4) {
            // If the word is lowerCase already, its an english word - keep
            if (!allLowerCase(possibleWord)) {
                HashMap<String, Double> similarities = new HashMap<>();
                for (int i = 0; i < ENGLISH_FOUR_LETTER_WORDS.size(); i++) {
                    String word = ENGLISH_FOUR_LETTER_WORDS.get(i);
                    similarities.put(word, similarity(possibleWord, word));
                }
                genMostSimilarities(possibleWord, similarities);
            }
        }
    }

    // Checks to see is all characters in a string are all lower case.
    private boolean allLowerCase(String str)
    {
        boolean allLowerCase = true;
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            if (!Character.isLowerCase(charArray[i])) {
                return false;
            }
        }
        return allLowerCase;
    }

    // Populate mostSimilaritiesForEachWord.
    private void genMostSimilarities(String possibleWord, HashMap<String, Double> similarities)
    {
        double mostSimilarPerc = similarities.entrySet().stream().max((entry1, entry2) -> entry1.getValue().compareTo(entry2.getValue())).get().getValue();
        ArrayList<String> mostSimilarities = new ArrayList<>();
        for (Map.Entry<String, Double> entry : similarities.entrySet()) {
            if (entry.getValue().equals(mostSimilarPerc)) {
                mostSimilarities.add(entry.getKey());
            }
        }
        mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, mostSimilarities));
    }

    // Calculates the similarity (a number within 0 and 1) between two strings.
    private double similarity(String s1, String s2)
    {
        String longer = s1, shorter = s2;
        if (s1.length() < s2.length()) { // longer should always have greater length
            longer = s2;
            shorter = s1;
        }
        int longerLength = longer.length();
        if (longerLength == 0) {
            return 1.0; // both strings are zero length
        }
        return (longerLength - editDistance(longer, shorter)) / (double) longerLength;

    }

    // Example implementation of the Levenshtein Edit Distance.
    private int editDistance(String s1, String s2)
    {
        s1 = s1.toLowerCase();
        s2 = s2.toLowerCase();

        int[] costs = new int[s2.length() + 1];
        for (int i = 0; i <= s1.length(); i++) {
            int lastValue = i;
            for (int j = 0; j <= s2.length(); j++) {
                if (i == 0) {
                    costs[j] = j;
                } else {
                    if (j > 0) {
                        int newValue = costs[j - 1];
                        if (s1.charAt(i - 1) != s2.charAt(j - 1))
                            newValue = Math.min(Math.min(newValue, lastValue),
                                    costs[j]) + 1;
                        costs[j - 1] = lastValue;
                        lastValue = newValue;
                    }
                }
            }
            if (i > 0) {
                costs[s2.length()] = lastValue;
            }
        }
        return costs[s2.length()];
    }

    // Replace all letters of certain char in each potential word with its corresponding mapping in mappedLetters2.
    private void replaceLetter(char ch, ArrayList<String> potentialWords, HashMap<Character, Character> mappedLetters2)
    {
        for (int i = 0; i < potentialWords.size(); i++) {
            char[] potentialWordChars = potentialWords.get(i).toCharArray();
            for (int j = 0; j < potentialWordChars.length; j++) {
                if (potentialWordChars[j] == ch) {
                    potentialWordChars[j] = Character.toLowerCase(mappedLetters2.get(ch));
                }
            }
            potentialWords.set(i, String.valueOf(potentialWordChars));
        }
    }
}
