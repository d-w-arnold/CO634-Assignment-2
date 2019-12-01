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
    final private ArrayList<String> ENGLISH_DIGRAPHS = new ArrayList<String>()
    {{
        add("TH");
        add("ER");
        add("ON");
        add("AN");
        add("RE");
        add("HE");
        add("IN");
        add("ED");
        add("ND");
        add("HA");
        add("AT");
        add("EN");
        add("ES");
        add("OF");
        add("OR");
        add("NT");
        add("EA");
        add("TI");
        add("TO");
        add("IT");
        add("ST");
        add("IO");
        add("LE");
        add("IS");
        add("OU");
        add("AR");
        add("AS");
        add("DE");
        add("RT");
        add("VE");
    }};
    final private ArrayList<String> ENGLISH_TRIGRAPHS = new ArrayList<String>()
    {{
        add("THE");
        add("AND");
        add("THA");
        add("ENT");
        add("ION");
        add("TIO");
        add("FOR");
        add("NDE");
        add("HAS");
        add("NCE");
        add("EDT");
        add("TIS");
        add("OFT");
        add("STH");
        add("MEN");
    }};
    // Key: letter in ciphertext, Value: most likely mapped letter based on frequency of occurrence
    ArrayList<Pair<Character, Character>> mappedLetters;
    LinkedHashMap<Character, Character> mappedLetters2;
    LinkedHashMap<Character, Character> mappedLetters2DuplicateKeyValue;
    private String pt;
    private ArrayList<Pair<String, ArrayList<String>>> mostSimilaritiesForEachWord;
    private ArrayList<Pair<String, ArrayList<ArrayList<Pair<Character, Character>>>>> mostSimilaritiesForEachWordMappings;

    public GenSubDecrypt(File tessFile, File cipherFile) throws IOException
    {
        super(tessFile, cipherFile);
        this.pt = "";
        this.mappedLetters = new ArrayList<>();
        this.mostSimilaritiesForEachWord = new ArrayList<>();
        this.mostSimilaritiesForEachWordMappings = new ArrayList<>();
        this.mappedLetters2 = new LinkedHashMap<>();
        this.mappedLetters2DuplicateKeyValue = new LinkedHashMap<Character, Character>()
        {{
            put('|', '|');
        }};
    }

    /**
     * Decrypt a General Substitution Cipher.
     */
    public String decrypt()
    {
        System.out.println(getExercise(cipherFile) + ": General Substitution Cipher");
        // Generate characterCounts containing count of each letter from charAlphabet in the ciphertext
        ArrayList<Pair<Character, Integer>> characterCounts = new ArrayList<>();
        genCharacterCounts(ciphertext, characterCounts);
        // Sort characterCounts into descending order for count
        characterCounts.sort((o1, o2) -> {
            if (o1.getValue() > o2.getValue()) {
                return -1;
            } else if (o1.getValue().equals(o2.getValue())) {
                return 0;
            } else {
                return 1;
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
        pt = decryptedPlaintext;

        // Generate mappedLetter2 and mappedLetter2DuplicateKeyValue using most common 1, 2, 3 and 4 letter words
        // Separate decrypted plaintext into potential words separated by '|'
        String[] separated = pt.split("\\|");
        ArrayList<String> potentialWords = new ArrayList<>(Arrays.asList(separated));
        // Any English words found will be removed (hEr, add R=R to mappedLetters2)
        // Populate mostSimilaritiesForEachWord
        popMostSimilaritiesForEachWord(containsEnglishWords(potentialWords));
        // Remove duplicates from mostSimilaritiesForEachWord
        mostSimilaritiesForEachWord = removeDuplicates(mostSimilaritiesForEachWord);
        // Populate mostSimilaritiesForEachWordMappings
        popMostSimilaritiesForEachWordMappings();
        // TODO Add handling for if there are 2x one letter words, not just 1x (R = [[R=A], [R=I]])
        for (int i = 0; i < mostSimilaritiesForEachWordMappings.size(); ) {
            // Exit clauses
            if (mostSimilaritiesForEachWordMappings.get(i).getValue().isEmpty()) {
                mostSimilaritiesForEachWord.remove(i);
                mostSimilaritiesForEachWordMappings.remove(i);
                continue;
            }
            ArrayList<Pair<Character, Character>> newLetterMappings = mostSimilaritiesForEachWordMappings.get(i).getValue().get(0);
            if (newLetterMappings.isEmpty() && (mostSimilaritiesForEachWord.get(i).getValue().get(0)).equals(mostSimilaritiesForEachWord.get(i).getKey().toUpperCase())) {
                char[] keyCA = mostSimilaritiesForEachWordMappings.get(i).getKey().toCharArray();
                for (char c : keyCA) {
                    if (Character.isUpperCase(c)) {
                        mappedLetters2.put(c, c);
                    }
                }
                mostSimilaritiesForEachWord.remove(i);
                mostSimilaritiesForEachWordMappings.remove(i);
                continue;
            }
            // Added [R=A] to mappedLetters2
            boolean forceContinue = false;
            for (int j = 0; j < newLetterMappings.size(); j++) {
                Pair<Character, Character> pair = newLetterMappings.get(j);
                if (!mappedLetters2.containsKey(pair.getKey()) && !mappedLetters2.containsValue(pair.getValue())) {
                    mappedLetters2.put(pair.getKey(), pair.getValue());
                } else {
                    mostSimilaritiesForEachWord.remove(i);
                    mostSimilaritiesForEachWordMappings.remove(i);
                    forceContinue = true;
                }
            }
            if (forceContinue) {
                continue;
            }
            // Populate mostSimilaritiesForEachWord
            popMostSimilaritiesForEachWord(genNewPotentialWords());
            // Populate mostSimilaritiesForEachWordMappings
            popMostSimilaritiesForEachWordMappings();
            // Remove from mappedLetters2 where key and value are equal - necessary and could contain incorrect mappings Y => Y
            for (char charAlpha : charAlphabet) {
                if (mappedLetters2.containsKey(charAlpha) && mappedLetters2.get(charAlpha).equals(charAlpha)) {
                    mappedLetters2.remove(charAlpha);
                    mappedLetters2DuplicateKeyValue.put(charAlpha, charAlpha);
                }
            }
            i = 0;
        }
        // Remove from mappedLetters2 where mappedLetters2DuplicateKeyValue containsKey of value
        for (char charAlpha : charAlphabet) {
            if (mappedLetters2.containsKey(charAlpha) && mappedLetters2DuplicateKeyValue.containsKey(mappedLetters2.get(charAlpha))) {
                mappedLetters2.remove(charAlpha);
            }
        }
        // Combine mappedLetters2 and mappedLetters2DuplicateKeyValues
        mappedLetters2.putAll(mappedLetters2DuplicateKeyValue);

        // Generate mappedString2
        String mappedString2 = "";
        char[] mappedStringCA = mappedString.toCharArray();
        for (int i = 0; i < mappedStringCA.length; i++) {
            char letter = mappedStringCA[i];
            if (mappedLetters2.containsKey(letter)) {
                mappedString2 += mappedLetters2.get(letter);
            } else {
                mappedString2 += letter;
            }
        }
        // Generate new decrypted plaintext from mappedLetters2
        String decryptedPlaintext2 = "";
        for (char ptChar : pt.toCharArray()) {
            if (mappedLetters2.containsKey(ptChar)) {
                decryptedPlaintext2 += Character.toLowerCase(mappedLetters2.get(ptChar));
            } else {
                decryptedPlaintext2 += ptChar;
            }
        }
        pt = decryptedPlaintext2;

        // Generate extendedMappedLetters, containing what the remaining letters not featuring in mappedLetters2 could be
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCounts = new ArrayList<>();
        genCharacterCounts(mappedString2, mappedString2CharacterCounts);
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsWithoutMappedLetters2Keys = new ArrayList<>();
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsAsZero = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCounts) {
            if (!mappedLetters2.containsKey(pair.getKey())) {
                mappedString2CharacterCountsWithoutMappedLetters2Keys.add(pair);
            }
            if (pair.getValue() == 0) {
                mappedString2CharacterCountsAsZero.add(pair);
            }
        }
        ArrayList<Pair<Character, Integer>> mappedString2CharacterCountsAsOne = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCountsWithoutMappedLetters2Keys) {
            if (pair.getValue() == 1) {
                mappedString2CharacterCountsAsOne.add(pair);
            }
        }
        ArrayList<Character> zeroLetters = new ArrayList<>();
        ArrayList<Character> oneLetters = new ArrayList<>();
        ArrayList<ArrayList<Character>> permuZeros = new ArrayList<>();
        ArrayList<ArrayList<Character>> permuOnes = new ArrayList<>();
        for (Pair<Character, Integer> pair : mappedString2CharacterCountsWithoutMappedLetters2Keys) {
            if (pair.getValue() == 2) {
                zeroLetters.add(pair.getKey());
                ArrayList<Character> tmp = new ArrayList<>();
                for (Pair<Character, Integer> zeroPair : mappedString2CharacterCountsAsZero) {
                    tmp.add(zeroPair.getKey());
                }
                permuZeros = listPermutations(tmp);
            } else if (pair.getValue() == 1) {
                oneLetters.add(pair.getKey());
                ArrayList<Character> tmp = new ArrayList<>();
                for (Pair<Character, Integer> onePair : mappedString2CharacterCountsAsOne) {
                    tmp.add(onePair.getKey());
                }
                permuOnes = listPermutations(tmp);
            }
        }

        // TODO Try each mapping in extendedMappedLetters2,
        //  choose mapping for each letter which rears a decrypted plaintext with the most
        //  digraphs, trigraphs, most common doubles occurrences

        // Generate zeroLetterMappings
        ArrayList<HashMap<Character, Character>> zeroLetterMappings = new ArrayList<>();
        for (int i = 0; i < permuZeros.size(); i++) {
            HashMap<Character, Character> tmpHM = new HashMap<>();
            ArrayList<Character> aPermu = permuZeros.get(i);
            for (int j = 0; j < aPermu.size(); j++) {
                tmpHM.put(zeroLetters.get(j), aPermu.get(j));
            }
            zeroLetterMappings.add(tmpHM);
        }

        // Generate oneLetterMappings
        ArrayList<HashMap<Character, Character>> oneLetterMappings = new ArrayList<>();
        for (int i = 0; i < permuOnes.size(); i++) {
            HashMap<Character, Character> tmpHM = new HashMap<>();
            ArrayList<Character> aPermu = permuOnes.get(i);
            for (int j = 0; j < aPermu.size(); j++) {
                tmpHM.put(oneLetters.get(j), aPermu.get(j));
            }
            oneLetterMappings.add(tmpHM);
        }

        HashMap<Character, Character> extendedMappedLetters2 = new HashMap<>();
        // Try each combination of zeroLetterMappings and oneLetterMappings
        // TODO Change this to check for digraphs and trigraphs occurences,
        //  most occurrences means the most likely combination of zeroLetterMappings and oneLetterMappings
        //  to give the extendedMappedLetters2.
        for (HashMap<Character, Character> zeroHM : zeroLetterMappings) {
            for (HashMap<Character, Character> oneHM : oneLetterMappings) {
                HashMap<Character, Character> tmpHM = new HashMap<Character, Character>()
                {{
                    putAll(zeroHM);
                    putAll(oneHM);
                }};
                String tmpPT = pt;
                String newTmpPT = "";
                for (char tmpPTChar : tmpPT.toCharArray()) {
                    if (Character.isUpperCase(tmpPTChar) && tmpHM.containsKey(tmpPTChar)) {
                        newTmpPT += tmpHM.get(tmpPTChar);
                    } else {
                        newTmpPT += tmpPTChar;
                    }
                }
                if (tess.contains(newTmpPT.toUpperCase())) {
                    extendedMappedLetters2.putAll(tmpHM);
                    pt = newTmpPT.toUpperCase();
                    System.out.println("Decrypted: " + pt);
                    String charAlphabetString = "";
                    for (char charAlpha : charAlphabet) {
                        charAlphabetString += charAlpha;
                    }
                    System.out.println("Character Alphabet: " + charAlphabetString);
                    HashMap<Character, Character> fullMappedLetters = new HashMap<Character, Character>()
                    {{
                        putAll(mappedLetters2);
                        putAll(extendedMappedLetters2);
                    }};
                    String finalMappedString = "";
                    for (char mappedStringChar : mappedString.toCharArray()) {
                        finalMappedString += fullMappedLetters.get(mappedStringChar);
                    }
                    System.out.println("Character Mappings: " + finalMappedString);
                    System.out.println();
                    return pt;
                }
            }
        }
        return "";
    }

    private ArrayList<ArrayList<Character>> listPermutations(ArrayList<Character> list)
    {
        if (list.size() == 0) {
            ArrayList<ArrayList<Character>> result = new ArrayList<>();
            result.add(new ArrayList<>());
            return result;
        }
        ArrayList<ArrayList<Character>> returnMe = new ArrayList<>();
        char firstElement = list.remove(0);
        ArrayList<ArrayList<Character>> recursiveReturn = listPermutations(list);
        for (List<Character> li : recursiveReturn) {
            for (int index = 0; index <= li.size(); index++) {
                ArrayList<Character> temp = new ArrayList<>(li);
                temp.add(index, firstElement);
                returnMe.add(temp);
            }

        }
        return returnMe;
    }

    private void genCharacterCounts(String mappedString2, ArrayList<Pair<Character, Integer>> mappedString2CharacterCounts)
    {
        for (char charAlpha : charAlphabet) {
            int totalOccurrences = 0;
            for (char mappedString2Char : mappedString2.toCharArray()) {
                if (charAlpha == mappedString2Char) {
                    totalOccurrences++;
                }
            }
            mappedString2CharacterCounts.add(new Pair<>(charAlpha, totalOccurrences));
        }
    }

    // Gen newPotential Words, using new letter mapping such as [R=A]
    private ArrayList<String> genNewPotentialWords()
    {
        // Alter all keys in mostSimilaritiesForEachWord
        ArrayList<String> newPotentialWords = new ArrayList<>();
        for (int j = 0; j < mostSimilaritiesForEachWord.size(); j++) {
            char[] aWordCA = mostSimilaritiesForEachWord.get(j).getKey().toCharArray();
            String newWord = "";
            for (int k = 0; k < aWordCA.length; k++) {
                if (mappedLetters2.containsKey(aWordCA[k])) {
                    newWord += Character.toLowerCase(mappedLetters2.get(aWordCA[k]));
                } else {
                    newWord += aWordCA[k];
                }
            }
            if (!allLowerCase(newWord)) {
                newPotentialWords.add(newWord);
            }
        }
        return newPotentialWords;
    }

    // Returns new potential words and adds to mappedLetters2 any letter used in an english word
    private ArrayList<String> containsEnglishWords(ArrayList<String> potentialWords)
    {
        ArrayList<String> nonEnglishPotentialWords = new ArrayList<>();
        for (int i = 0; i < potentialWords.size(); i++) {
            String aWord = potentialWords.get(i);
            if (aWord.length() == 1) {
                if (ENGLISH_ONE_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    mappedLetters2DuplicateKeyValue.put(Character.toUpperCase(aWord.charAt(0)), Character.toUpperCase(aWord.charAt(0)));
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 2) {
                if (ENGLISH_TWO_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (int j = 0; j < aWordCA.length; j++) {
                        if (Character.isUpperCase(aWordCA[j])) {
                            mappedLetters2DuplicateKeyValue.put(aWordCA[j], aWordCA[j]);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 3) {
                if (ENGLISH_THREE_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (int j = 0; j < aWordCA.length; j++) {
                        if (Character.isUpperCase(aWordCA[j])) {
                            mappedLetters2DuplicateKeyValue.put(aWordCA[j], aWordCA[j]);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            } else if (aWord.length() == 4) {
                if (ENGLISH_FOUR_LETTER_WORDS.contains(aWord.toUpperCase())) {
                    char[] aWordCA = aWord.toCharArray();
                    for (int j = 0; j < aWordCA.length; j++) {
                        if (Character.isUpperCase(aWordCA[j])) {
                            mappedLetters2DuplicateKeyValue.put(aWordCA[j], aWordCA[j]);
                        }
                    }
                } else {
                    nonEnglishPotentialWords.add(aWord);
                }
            }
        }
        return nonEnglishPotentialWords;
    }

    // Populate mostSimilaritiesForEachWord
    private void popMostSimilaritiesForEachWord(ArrayList<String> potentialWords)
    {
        mostSimilaritiesForEachWord.clear();
        for (int i = 1; i <= 4; i++) { // 1 letter words, then 2, then 3, then 4
            for (int j = 0; j < potentialWords.size(); j++) {
                String potentialWord = potentialWords.get(j);
                if (potentialWord.length() == i) { // 1 letter words, then 2, then 3, then 4
                    mostSimilarWord(potentialWord);
                }
            }
        }
    }

    private void popMostSimilaritiesForEachWordMappings()
    {
        mostSimilaritiesForEachWordMappings.clear();
        for (int i = 0; i < mostSimilaritiesForEachWord.size(); i++) {
            Pair<String, ArrayList<String>> mostSimilaritiesForAWord = mostSimilaritiesForEachWord.get(i);
            if (mostSimilaritiesForAWord.getKey().length() == 1) { // 1 letter word
                String letterBeingMapped = mostSimilaritiesForAWord.getKey();
                ArrayList<String> newLetterMappings = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (int j = 0; j < mostSimilaritiesForAWord.getValue().size(); j++) {
                    int finalJ = j;
                    tmpArray.add(new ArrayList<Pair<Character, Character>>()
                    {{
                        add(new Pair<>(letterBeingMapped.charAt(0), newLetterMappings.get(finalJ).charAt(0)));
                    }});
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(letterBeingMapped, new ArrayList<>(tmpArray)));
            } else { // 2, 3 and 4 letter words
                char[] wordBeingMapped = mostSimilaritiesForAWord.getKey().toCharArray();
                ArrayList<String> aWord = mostSimilaritiesForAWord.getValue();
                ArrayList<ArrayList<Pair<Character, Character>>> tmpArray = new ArrayList<>();
                for (int j = 0; j < aWord.size(); j++) {
                    ArrayList<Pair<Character, Character>> singleArray = new ArrayList<>(); // All mappings for PE => BE
                    char[] wordBeingMappedTo = aWord.get(j).toCharArray();
                    for (int k = 0; k < wordBeingMapped.length; k++) {
                        if (wordBeingMapped[k] != wordBeingMappedTo[k] && Character.isUpperCase(wordBeingMapped[k])) {
                            singleArray.add(new Pair<>(wordBeingMapped[k], wordBeingMappedTo[k]));
                        }
                    }
                    // Check if singleArray keys and values are unique
                    if (singleArray.size() > 1) {
                        HashMap<Character, Character> tmpMap = new HashMap<>();
                        for (int k = 0; k < singleArray.size(); k++) {
                            tmpMap.put(singleArray.get(k).getKey(), singleArray.get(k).getValue());
                        }
                        // [E = L, E = N] - do not add to tmpArray
                        if (tmpMap.size() < singleArray.size()) {
                            continue;
                        }
                        // [E = L, N = L] - do not add to tmpArray
                        Set<Character> values = new HashSet<>(tmpMap.values());
                        if (values.size() == singleArray.size()) {
                            tmpArray.add(singleArray);
                        }
                    } else {
                        tmpArray.add(singleArray);
                    }
                }
                mostSimilaritiesForEachWordMappings.add(new Pair<>(mostSimilaritiesForAWord.getKey(), new ArrayList<>(tmpArray)));
            }
        }
    }

    // Function to remove duplicates from an ArrayList.
    private <T> ArrayList<T> removeDuplicates(ArrayList<T> list)
    {
        ArrayList<T> newList = new ArrayList<>();
        for (T element : list) {
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
            if (!ENGLISH_ONE_LETTER_WORDS.contains(possibleWord.toUpperCase())) {
                mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, ENGLISH_ONE_LETTER_WORDS));
            } else {
                mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, new ArrayList<>()));
            }
        } else if (possibleWord.length() == 2) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (int i = 0; i < ENGLISH_TWO_LETTER_WORDS.size(); i++) {
                String word = ENGLISH_TWO_LETTER_WORDS.get(i);
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        } else if (possibleWord.length() == 3) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (int i = 0; i < ENGLISH_THREE_LETTER_WORDS.size(); i++) {
                String word = ENGLISH_THREE_LETTER_WORDS.get(i);
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        } else if (possibleWord.length() == 4) {
            LinkedHashMap<String, Double> similarities = new LinkedHashMap<>();
            for (int i = 0; i < ENGLISH_FOUR_LETTER_WORDS.size(); i++) {
                String word = ENGLISH_FOUR_LETTER_WORDS.get(i);
                similarities.put(word, similarity(possibleWord.toUpperCase(), word));
            }
            genMostSimilarities(possibleWord, similarities);
        }
    }

    // Checks to see is all characters in a string are all lower case.
    private boolean allLowerCase(String str)
    {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            if (!Character.isLowerCase(charArray[i])) {
                return false;
            }
        }
        return true;
    }

    // Checks to see is all characters in a string are all upper case.
    private boolean allUpperCase(String str)
    {
        char[] charArray = str.toCharArray();
        for (int i = 0; i < charArray.length; i++) {
            if (!Character.isUpperCase(charArray[i])) {
                return false;
            }
        }
        return true;
    }

    // Populate mostSimilaritiesForEachWord.
    private void genMostSimilarities(String possibleWord, LinkedHashMap<String, Double> similarities)
    {
        ArrayList<String> sortedSimilarWords = new ArrayList<>(sortByValue(similarities));
        if (!allUpperCase(possibleWord)) {
            // Generate indexes of possibleWord which need checking due to being lowerCase
            ArrayList<Integer> lowerCaseIndexes = new ArrayList<>();
            char[] possibleWordCA = possibleWord.toCharArray();
            for (int i = 0; i < possibleWordCA.length; i++) {
                if (Character.isLowerCase(possibleWordCA[i])) {
                    lowerCaseIndexes.add(i);
                }
            }
            // Generate newSortedList based on indexes of lowerCase letters in possibleWord
            ArrayList<String> newSortedList = new ArrayList<>();
            for (int i = 0; i < sortedSimilarWords.size(); i++) {
                boolean toAdd = true;
                for (Integer index : lowerCaseIndexes) {
                    String possibleWordLetter = possibleWord.substring(index, index + 1);
                    String sortedSimilarWordLetter = sortedSimilarWords.get(i).substring(index, index + 1);
                    if (!possibleWordLetter.toUpperCase().equals(sortedSimilarWordLetter)) {
                        toAdd = false;
                        break;
                    }
                }
                if (toAdd) {
                    newSortedList.add(sortedSimilarWords.get(i));
                }
            }
            mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, newSortedList));
        } else {
            mostSimilaritiesForEachWord.add(new Pair<>(possibleWord, sortedSimilarWords));
        }
    }

    // Sort HashMap by values
    private Set<String> sortByValue(LinkedHashMap<String, Double> hm)
    {
        //LinkedHashMap preserve the ordering of elements in which they are inserted
        LinkedHashMap<String, Double> reverseSortedMap = new LinkedHashMap<>();
        //Use Comparator.reverseOrder() for reverse ordering
        hm.entrySet().stream().sorted(Map.Entry.comparingByValue(Comparator.reverseOrder())).forEachOrdered(x -> reverseSortedMap.put(x.getKey(), x.getValue()));
        return reverseSortedMap.keySet();
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
}
