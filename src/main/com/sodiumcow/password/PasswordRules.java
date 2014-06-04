package com.sodiumcow.password;

import static com.sodiumcow.password.PasswordConstraint.LENGTH_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.UPPERCASE_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.LOWERCASE_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.DIGIT_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.SPECIAL_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.REUSE_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.USERSUBSTRING_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.AGE_CONSTRAINT;
import static com.sodiumcow.password.PasswordConstraint.ENABLED;
import static com.sodiumcow.password.PasswordConstraint.DISABLED;

import java.util.Date;
import java.util.EnumMap;
import java.util.EnumSet;

public class PasswordRules {

    private EnumMap<PasswordConstraint,Integer> constraints = new EnumMap<PasswordConstraint,Integer>(PasswordConstraint.class);

    public int get(PasswordConstraint constraint) {
        return constraints.get(constraint);
    }

    public PasswordRules set(PasswordConstraint constraint, int value) {
        constraints.put(constraint, value);
        return this;
    }

    // legacy method emulation
    public int     getMinPasswordLength()              { return get(LENGTH_CONSTRAINT   ); }
    public int     getMinNumUpperCaseChars()           { return get(UPPERCASE_CONSTRAINT); }
    public int     getMinNumLowerCaseChars()           { return get(LOWERCASE_CONSTRAINT); }
    public int     getMinNumNumericChars()             { return get(DIGIT_CONSTRAINT    ); }
    public int     getMinNumSpecialChars()             { return get(SPECIAL_CONSTRAINT  ); }
    public int     getNumberofPasswordsBeforeRepeats() { return get(REUSE_CONSTRAINT    ); } 
    public int     getNumberofDaysUntilExpiration()    { return get(AGE_CONSTRAINT      ); }

    public boolean getExpirePasswords()                { return AGE_CONSTRAINT          .enabled(constraints); }
    public boolean getRestrictUserNameInPassword()     { return USERSUBSTRING_CONSTRAINT.enabled(constraints); }
    public boolean getRequireMixedCase()               { return LOWERCASE_CONSTRAINT    .enabled(constraints)
                                                             || UPPERCASE_CONSTRAINT    .enabled(constraints); }
    public boolean getRequireNumericChars()            { return DIGIT_CONSTRAINT        .enabled(constraints); }
    public boolean getRequireSpecialChars()            { return SPECIAL_CONSTRAINT      .enabled(constraints); }
    public boolean getPreventPasswordRepeats()         { return REUSE_CONSTRAINT        .enabled(constraints); }

    public PasswordRules setMinPasswordLength             (int minLength ) { return set(LENGTH_CONSTRAINT,    minLength);  }
    public PasswordRules setMinNumUpperCaseChars          (int minUpper  ) { return set(UPPERCASE_CONSTRAINT, minUpper);   }
    public PasswordRules setMinNumLowerCaseChars          (int minLower  ) { return set(LOWERCASE_CONSTRAINT, minLower);   }
    public PasswordRules setMinNumNumericChars            (int minDigit  ) { return set(DIGIT_CONSTRAINT,     minDigit);   }
    public PasswordRules setMinNumSpecialChars            (int minSpecial) { return set(SPECIAL_CONSTRAINT,   minSpecial); }
    public PasswordRules setNumberOfPasswordsBeforeRepeats(int minUnique ) { return set(REUSE_CONSTRAINT,     minUnique);  }
    public PasswordRules setRestrictUserNameInPassword    (boolean noUser) { return set(USERSUBSTRING_CONSTRAINT,
                                                                              noUser?ENABLED:DISABLED); }
    public PasswordRules setNumberOfDaysUntilExpiration   (int maxAge    ) { return set(AGE_CONSTRAINT,       maxAge);     }

    /**
     * Returns a canonical parse-able serialization of the rules.
     */
    @Override
    public String toString() {
        return PasswordConstraint.format(constraints);
    }

    /**
     * Default constructor: all checks reset to no check.
     */
    public PasswordRules() {
        // just use the defaults: null means DISABLED
    }

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
        constraints.putAll(PasswordConstraint.parse(spec));
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
        EnumSet<PasswordConstraint>    violations = EnumSet.noneOf(PasswordConstraint.class);
        EnumMap<CharacterType,Integer> counts     = new EnumMap<CharacterType,Integer>(CharacterType.class);
        for (PasswordConstraint constraint : PasswordConstraint.values()) {
            if (constraint.enabled(constraints) &&
                !constraint.validate(constraints, password, counts, user, matcher)) {
                violations.add(constraint);
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
        if (AGE_CONSTRAINT.enabled(constraints)) {
            long now  = System.currentTimeMillis();
            long last = lastChanged.getTime();
            // 1000 millis/sec * 60 sec/min * 60 min/hour * 24 hour/day
            return now-last > constraints.get(AGE_CONSTRAINT) * 1000 * 60 * 60 * 24;
        }
        return false;
    }
}