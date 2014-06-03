package com.sodiumcow.password;

import static org.junit.Assert.*;

import java.util.Date;
import java.util.EnumSet;
import java.util.Map;

import org.junit.Test;

import com.sodiumcow.password.PasswordRules.CharacterType;
import com.sodiumcow.password.PasswordRules.PasswordConstraint;

public class PasswordRulesTest {

    @Test
    public final void testPasswordRulesParserErrors() {
        // test when we get to invalid input
        try {
            new PasswordRules("declaration of independence");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("unrecognized token"));
        }
        try {
            new PasswordRules("length>=2 length<=4");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("length>=number expected"));
        }
        try {
            new PasswordRules("     .      ");
            fail();
        } catch (IllegalArgumentException e) {
            assertTrue(e.getMessage().startsWith("parsing error"));
        }
    }

    @Test
    public final void testPasswordRulesStrings() {
        assertTrue((new PasswordRules("length>=2").toString().equals("length>=2")));
        assertTrue((new PasswordRules("!user repeat>=1 age<=90 special>=2 digit>=3 lower>=4 upper>=5 length>=99")
                   .toString().equals("length>=99 upper>=5 lower>=4 digit>=3 special>=2 age<=90 repeat>=1 !user")));
    }

    @Test
    public final void testPasswordRulesParseDefaults() {
        assertTrue((new PasswordRules("repeat>=0 special>=0 digit>=0 lower>=0 upper>=0 length>=0")
                   .toString().isEmpty()));
    }

    @Test
    public final void testPasswordRulesDefaults() {
        PasswordRules defaults = new PasswordRules();
        assertFalse(defaults.getPreventPasswordRepeats()     ||
                    defaults.getRequireMixedCase()           ||
                    defaults.getRequireNumericChars()        ||
                    defaults.getRequireSpecialChars()        ||
                    defaults.getRestrictUserNameInPassword() ||
                    defaults.getExpirePasswords());
    }

    @Test
    public final void testCharacterType() {
        char[] test = new char[128];
        for (int i=0; i<test.length; i++) {
            test[i] = (char)i;
        }
        Map<CharacterType,Integer> counts = CharacterType.of(new String(test));
        assertTrue(counts.get(CharacterType.CONTROL)==33);
        assertTrue(counts.get(CharacterType.SPACE  )== 1);
        assertTrue(counts.get(CharacterType.DIGIT  )==10);
        assertTrue(counts.get(CharacterType.UPPER  )==26);
        assertTrue(counts.get(CharacterType.LOWER  )==26);
        assertTrue(counts.get(CharacterType.SPECIAL)==32);
    }

    @Test
    public final void testValidation() {
        PasswordRules test = new PasswordRules("special>=1 digit>=2 upper>=3 lower>=4 length>=10");
        assertEquals(test.getContentViolations(" ", null, null),
                     EnumSet.of(PasswordConstraint.SPECIAL_CONSTRAINT,
                                PasswordConstraint.DIGIT_CONSTRAINT,
                                PasswordConstraint.UPPERCASE_CONSTRAINT,
                                PasswordConstraint.LOWERCASE_CONSTRAINT,
                                PasswordConstraint.LENGTH_CONSTRAINT));
        assertEquals(test.getContentViolations("!99AAAbbbb", null, null),
                     EnumSet.noneOf(PasswordConstraint.class));
    }

    @Test
    public final void testUserValidation() {
        PasswordRules test = new PasswordRules("!user");
        assertEquals(test.getContentViolations("hidetheuserinhere", "User", null),
                     EnumSet.of(PasswordConstraint.USERSUBSTRING_CONSTRAINT));
        assertEquals(test.getContentViolations("!99AAAbbbb", "User", null),
                     EnumSet.noneOf(PasswordConstraint.class));
    }

    @Test
    public final void testReuseValidation() {
        PasswordRules test = new PasswordRules("repeat>=3");
        assertEquals(test.getContentViolations("password", null,
                                               new PasswordRules.PasswordMatcher() {
                                                   public Result matches(String password, int generation) {
                                                       return generation==2 ? Result.MATCH : Result.NO_MATCH; }
                                               }),
                     EnumSet.of(PasswordConstraint.REUSE_CONSTRAINT));
        assertEquals(test.getContentViolations("password", null,
                                               new PasswordRules.PasswordMatcher() {
                                                   public Result matches(String password, int generation) {
                                                       return generation==3 ? Result.MATCH : Result.NO_MATCH; }
                                               }),
                     EnumSet.noneOf(PasswordConstraint.class));
        assertEquals(test.getContentViolations("password", null,
                                               new PasswordRules.PasswordMatcher() {
                                                   public Result matches(String password, int generation) {
                                                       return Result.NO_GENERATION; }
                                               }),
                     EnumSet.noneOf(PasswordConstraint.class));
    }

    @Test
    public final void testExpiration() {
        PasswordRules test = new PasswordRules("age<=3");
        long now = System.currentTimeMillis();
        assertTrue(test.tooOld(new Date(now-7*86400000L)));
        assertTrue(test.tooOld(new Date(now-3*86400000L-1)));
        assertFalse(test.tooOld(new Date(now)));
        test.setNumberOfDaysUntilExpiration(-1);
        assertFalse(test.tooOld(new Date(now-7*86400000L)));
        assertFalse(test.tooOld(new Date(now)));
    }
}
