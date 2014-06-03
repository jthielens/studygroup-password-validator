package com.sodiumcow.password;

import java.util.Date;
import java.util.EnumMap;
import java.util.EnumSet;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sodiumcow.password.PasswordRules.PasswordMatcher.Result;

public class PasswordRules {

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

    /* Java Bean Hell -- sorry, just can't do this anymore */
    private int     minLength  = 0;
    private int     minUpper   = 0;
    private int     minLower   = 0;
    private int     minDigit   = 0;
    private int     minSpecial = 0;
    private int     minUnique  = 0;  // number of unique passwords before reuse
    private int     maxAge     = -1; // days before password change required
    private boolean noUser     = false;

    public int     getMinPasswordLength()              { return minLength;             }
    public int     getMinNumUpperCaseChars()           { return minUpper;              }
    public int     getMinNumLowerCaseChars()           { return minLower;              }
    public boolean getRequireMixedCase()               { return minUpper+minLower > 0; }
    public int     getMinNumNumericChars()             { return minDigit;              }
    public boolean getRequireNumericChars()            { return minDigit>0;            }
    public int     getMinNumSpecialChars()             { return minSpecial;            }
    public boolean getRequireSpecialChars()            { return minSpecial>0;          }
    public int     getNumberofPasswordsBeforeRepeats() { return minUnique;             }
    public boolean getPreventPasswordRepeats()         { return minUnique>0;           }
    public int     getNumberofDaysUntilExpiration()    { return maxAge;                }
    public boolean getExpirePasswords()                { return maxAge>0;              }
    public boolean getRestrictUserNameInPassword()     { return noUser;                }
    
    public PasswordRules setMinPasswordLength             (int minLength ) { this.minLength  = minLength ; return this; }
    public PasswordRules setMinNumUpperCaseChars          (int minUpper  ) { this.minUpper   = minUpper  ; return this; }
    public PasswordRules setMinNumLowerCaseChars          (int minLower  ) { this.minLower   = minLower  ; return this; }
    public PasswordRules setMinNumNumericChars            (int minDigit  ) { this.minDigit   = minDigit  ; return this; }
    public PasswordRules setMinNumSpecialChars            (int minSpecial) { this.minSpecial = minSpecial; return this; }
    public PasswordRules setNumberOfPasswordsBeforeRepeats(int minUnique ) { this.minUnique  = minUnique ; return this; }
    public PasswordRules setNumberOfDaysUntilExpiration   (int maxAge    ) { this.maxAge     = maxAge    ; return this; }
    public PasswordRules setRestrictUserNameInPassword    (boolean noUser) { this.noUser     = noUser    ; return this; }

    /**
     * Returns a canonical parse-able serialization of the rules.
     */
    @Override
    public String toString() {
        StringBuilder sb = new StringBuilder();
        if (getMinPasswordLength()>0)        sb.append("length>=") .append(getMinPasswordLength())             .append(' ');
        if (getMinNumUpperCaseChars()>0)     sb.append("upper>=")  .append(getMinNumUpperCaseChars())          .append(' ');
        if (getMinNumLowerCaseChars()>0)     sb.append("lower>=")  .append(getMinNumLowerCaseChars())          .append(' ');
        if (getMinNumNumericChars()>0)       sb.append("digit>=")  .append(getMinNumNumericChars())            .append(' ');
        if (getMinNumSpecialChars()>0)       sb.append("special>=").append(getMinNumSpecialChars())            .append(' ');
        if (getExpirePasswords())            sb.append("age<=")    .append(getNumberofDaysUntilExpiration())   .append(' ');
        if (getPreventPasswordRepeats())     sb.append("repeat>=") .append(getNumberofPasswordsBeforeRepeats()).append(' ');
        if (getRestrictUserNameInPassword()) sb.append("!user")                                                .append(' ');
        if (sb.length()>0) sb.setLength(sb.length()-1); // truncate final spurious ' '
        return sb.toString();
    }

    /**
     * Default constructor: all checks reset to no check.
     */
    public PasswordRules() {
        // just use the defaults
    }

    /**
     * A clause in the specification is:
     *    [!]word[op number]
     * where op is <= or >=.  Capture groups set up for
     *    1:! or nothing
     *    2:the word
     *    3:the first character of op, or nothing
     *    4:the number, or nothing
     */
    private static final Pattern CLAUSE =
        Pattern.compile("(?i)\\s*(!)?\\s*(\\w+)\\s*(?:([><])=\\s*(\\d+)\\s*)?");
    /**
     * Parsing constructor: parses a string for constraint tokens as follows:
     * <ul>
     * <li>length>=number     sets the getMinPasswordLength constraint
     * <li>upper>=number      sets the getMinNumUpperCaseChars constraint
     * <li>lower>=number      sets the getMinNumLowerCaseChars constraint
     * <li>digit>=number      sets the getMinNumNumericChars constraint
     * <li>special>=number    sets the getMinNumSpecialChars constraint
     * <li>age<=number        sets the getNumberOfDaysUntilExpiration constraint
     * <li>repeat>=number     sets the getNumberOfPasswordsBeforeRepeats constraint
     * <li>!user              sets the getRestrictUserNameInPassword constraint
     * </ul>
     * @param spec the string to parse
     * @throws IllegalArgumentException in case of parsing error
     */
    public PasswordRules(String spec) {
        if (spec!=null) {
            Matcher m   = CLAUSE.matcher(spec);
            int     i   = 0;
            String  err = "parsing error";
            while (m.find() && m.start()==i) {
                boolean bang    = m.group(1) != null;
                String  id      = m.group(2);
                boolean limited = m.group(3) != null;
                char    ineq    = limited ? m.group(3).charAt(0) : 'x';
                int     limit   = limited ? Integer.valueOf(m.group(4)) : -1;
                if (id.equalsIgnoreCase("user")) {
                    if (!bang || ineq!='x') { err = "!user expected"          ; break; }
                    noUser = true;
                } else if (id.equalsIgnoreCase("age")) {
                    if ( bang || ineq!='<') { err = "age<=number expected"    ; break; }
                    maxAge = limit;
                } else if (id.equalsIgnoreCase("length")) {
                    if ( bang || ineq!='>') { err = "length>=number expected" ; break; }
                    minLength = limit;
                } else if (id.equalsIgnoreCase("upper")) {
                    if ( bang || ineq!='>') { err = "upper>=number expected"  ; break; }
                    minUpper = limit;
                } else if (id.equalsIgnoreCase("lower")) {
                    if ( bang || ineq!='>') { err = "lower>=number expected"  ; break; }
                    minLower = limit;
                } else if (id.equalsIgnoreCase("digit")) {
                    if ( bang || ineq!='>') { err = "digit>=number expected"  ; break; }
                    minDigit = limit;
                } else if (id.equalsIgnoreCase("special")) {
                    if ( bang || ineq!='>') { err = "special>=number expected"; break; }
                    minSpecial = limit;
                } else if (id.equalsIgnoreCase("repeat")) {
                    if ( bang || ineq!='>') { err = "repeat>=number expected" ; break; }
                    minUnique = limit;
                } else {
                    /* otherwise */         { err = "unrecognized token";       break; }
                }
                i = m.end();
            }
            if (i<spec.length()) {
                // we didn't make it cleanly to the end
                throw new IllegalArgumentException(err+": "+spec.substring(0,i)+"-->"+spec.substring(i));
            }
        }
    }

    public interface PasswordMatcher {
        public enum Result { MATCH, NO_MATCH, NO_GENERATION; }
        /**
         * Checks a password against historical values or hashes.  Generation
         * 0 means the current password, 1 means the previous, and so on.  If
         * no history is available, NO_GENERATION is the appropriate Result.
         * @param password the new proposed password
         * @param generation how many generations back to match
         * @return MATCH or NO_MATCH, or NO_GENERATION if history is exhausted
         */
        Result matches(String password, int generation);
    }

    public enum PasswordConstraint {
        LENGTH_CONSTRAINT,
        UPPERCASE_CONSTRAINT,
        LOWERCASE_CONSTRAINT,
        DIGIT_CONSTRAINT,
        SPECIAL_CONSTRAINT,
        REUSE_CONSTRAINT,
        AGE_CONSTRAINT,
        USERSUBSTRING_CONSTRAINT;
    }

    /**
     * Analyzes a proposed password against the rules and returns a set of constraints
     * that the new password violates.  If the password is ok, the empty set
     * {@code EnumSet.noneOf(PasswordConstraint.class)} is returned.
     * <p>
     * Note that {@code user} and {@code matcher} may be null, which effectively
     * disables checking for the associated constraints (for example, if the
     * user string is generated in some way, or if no password history is available).
     * <p>
     * Note also that expiration (AGE_CONSTRAINT) is handled separately since checking
     * if a password needs to be changed happens at a separate time from checking that
     * the new proposed password passes validation.
     * 
     * @param password the new password
     * @param user the username (required to check USERSUBSTRING_CONSTRAINT)
     * @param matcher a password history matcher (required to check REUSE_CONSTRAINT)
     * @return an {@code EnumSet} of violated constraints
     */
    public EnumSet<PasswordConstraint> getContentViolations(String password, String user, PasswordMatcher matcher) {
        EnumSet<PasswordConstraint> violations = EnumSet.noneOf(PasswordConstraint.class);
        if (minUpper+minLower+minDigit+minSpecial > 0) {
            // need to count characters
            Map<CharacterType,Integer> counts = CharacterType.of(password);
            if (counts.get(CharacterType.UPPER  ) < minUpper) {
                violations.add(PasswordConstraint.UPPERCASE_CONSTRAINT);
            }
            if (counts.get(CharacterType.LOWER  ) < minLower) {
                violations.add(PasswordConstraint.LOWERCASE_CONSTRAINT);
            }
            if (counts.get(CharacterType.DIGIT  ) < minDigit) {
                violations.add(PasswordConstraint.DIGIT_CONSTRAINT);
            }
            if (counts.get(CharacterType.SPECIAL) < minSpecial) {
                violations.add(PasswordConstraint.SPECIAL_CONSTRAINT);
            }
        }
        if (password.length() < minLength) {
            violations.add(PasswordConstraint.LENGTH_CONSTRAINT);
        }
        if (noUser && user!=null && password.toLowerCase().indexOf(user.toLowerCase())>=0) {
            violations.add(PasswordConstraint.USERSUBSTRING_CONSTRAINT);
        }
        if (minUnique>0 && matcher!=null) {
            Result result=Result.NO_GENERATION;
            for (int g=0;
                 g<minUnique && (result=matcher.matches(password, g))==Result.NO_MATCH;
                 g++);
            if (result==Result.MATCH) {
                violations.add(PasswordConstraint.REUSE_CONSTRAINT);
            }
        }
        return violations;
    }

    /**
     * Checks the last changed {@code Date} of an existing password against
     * the AGE_CONSTRAINT in the PasswordRules.
     * @param lastChanged
     * @return true if the constraint is enabled and lastChanged is tooOld
     */
    public boolean tooOld(Date lastChanged) {
        if (getExpirePasswords()) {
            long now  = System.currentTimeMillis();
            long last = lastChanged.getTime();
            return now-last > maxAge * 1000 * 60 * 60 * 24; // 1000 millis/sec * 60 sec/min * 60 min/hour * 24 hour/day
        }
        return false;
    }
}