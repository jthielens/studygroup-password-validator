package com.sodiumcow.password;

import java.util.EnumMap;
import java.util.Map;

/**
 * Reduces the java.lang.Character Unicode types to the conventional
 * groupings as they apply to password policies.
 * @author john
 */
public enum CharacterType {
    CONTROL, SPACE, DIGIT, UPPER, LOWER, SPECIAL;

    /**
     * Returns the CharacterType mapped from java.lang.Character types.
     * @param c the character
     * @return its CharacterType
     */
    public static CharacterType of(char c) {
        switch (Character.getType(c)) {
        case Character.DECIMAL_DIGIT_NUMBER:    // 0-9
            return DIGIT;
        case Character.UPPERCASE_LETTER:        // A-Z
            return UPPER;
        case Character.LOWERCASE_LETTER:        // a-z
            return LOWER;
        case Character.START_PUNCTUATION:       // ([{
        case Character.END_PUNCTUATION:         // )]}
        case Character.DASH_PUNCTUATION:        // -
        case Character.CONNECTOR_PUNCTUATION:   // _
        case Character.OTHER_PUNCTUATION:       // !"#%&'*,./:;?@\
        case Character.CURRENCY_SYMBOL:         // $
        case Character.MATH_SYMBOL:             // +<=>|~
        case Character.MODIFIER_SYMBOL:         // ^`
            return SPECIAL;
        case Character.SPACE_SEPARATOR:         // <space>
            return SPACE;
        default:
            return CONTROL;
        }
    }

    /**
     * Returns a Map of CharacterType counts for a String.
     * @param s the String to inspect
     * @return the counts collected by CharacterType
     */
    public static Map<CharacterType,Integer> of(String s) {
        EnumMap<CharacterType,Integer> counts = new EnumMap<CharacterType, Integer>(CharacterType.class);
        for (CharacterType t : CharacterType.values()) {
            counts.put(t,  0);
        }
        for (char c : s.toCharArray()) {
            CharacterType t = of(c);
            counts.put(t, counts.get(t)+1);
        }
        return counts;
    }
}