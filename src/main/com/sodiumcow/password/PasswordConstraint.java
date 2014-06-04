package com.sodiumcow.password;

import java.util.EnumMap;
import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.sodiumcow.password.PasswordRules.PasswordMatcher;
import com.sodiumcow.password.PasswordRules.PasswordMatcher.Result;

public enum PasswordConstraint {
    LENGTH_CONSTRAINT (Type.MIN, "length") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            return password.length()>=constraints.get(this);
        }
    },
    UPPERCASE_CONSTRAINT (Type.MIN, "upper") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            synchronized (counts) {
                if (counts.isEmpty()) {
                    counts.putAll(CharacterType.of(password));
                }
            }
            return counts.get(CharacterType.UPPER)>=constraints.get(this);
        }
    },
    LOWERCASE_CONSTRAINT (Type.MIN, "lower") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            synchronized (counts) {
                if (counts.isEmpty()) {
                    counts.putAll(CharacterType.of(password));
                }
            }
            return counts.get(CharacterType.LOWER)>=constraints.get(this);
        }
    },
    DIGIT_CONSTRAINT (Type.MIN, "digit") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            synchronized (counts) {
                if (counts.isEmpty()) {
                    counts.putAll(CharacterType.of(password));
                }
            }
            return counts.get(CharacterType.DIGIT)>=constraints.get(this);
        }
    },
    SPECIAL_CONSTRAINT (Type.MIN, "special") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            synchronized (counts) {
                if (counts.isEmpty()) {
                    counts.putAll(CharacterType.of(password));
                }
            }
            return counts.get(CharacterType.SPECIAL)>=constraints.get(this);
        }
    },
    AGE_CONSTRAINT (Type.MAX, "age"),
    REUSE_CONSTRAINT (Type.MIN, "repeat") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            Result result=Result.NO_GENERATION;
            int    minUnique = constraints.get(this);
            for (int g=0;
                 g<minUnique && (result=matcher.matches(password, g))==Result.NO_MATCH;
                 g++);
            return result!=Result.MATCH;
        }
    },
    USERSUBSTRING_CONSTRAINT (Type.PROHIBIT, "user") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            return !enabled(constraints) ||
                   password.toLowerCase().indexOf(user.toLowerCase()) < 0;
        }
    };

    public enum Type { MIN, MAX, REQUIRE, PROHIBIT; }

    public static final int MIN_DEFAULT = 0;
    public static final int MAX_DEFAULT = -1;
    public static final int ENABLED     = 1; // for REQUIRE/PROHIBIT
    public static final int DISABLED    = 0; // default for REQUIRE/PROHIBIT

    public final Type    type;
    public final String  id;

    private PasswordConstraint(Type type, String id) {
        this.type  = type;
        this.id    = id;
    }

    public boolean validate(Map<PasswordConstraint,Integer> constraints,
                            String                          password,
                            Map<CharacterType,Integer>      counts,
                            String                          user,
                            PasswordMatcher                 matcher) {
        return true; // @Override this if there is something to check
    }

    private static final HashMap<String,PasswordConstraint> index = new HashMap<String,PasswordConstraint>();
    static {
        for (PasswordConstraint c : PasswordConstraint.values()) {
            index.put(c.id.toLowerCase(), c);
        }
    }

    public static PasswordConstraint of(String id) {
        return index.get(id.toLowerCase());
    }

    public int getDefault() {
        switch (type) {
        case MIN:      return MIN_DEFAULT;
        case MAX:      return MAX_DEFAULT;
        case REQUIRE:
        case PROHIBIT: return DISABLED;
        default:       return 0; // can't happen, but shuts up the compiler
        }
    }

    public boolean enabled(Integer value) {
        return value!=null && value!=getDefault();
    }

    public boolean enabled(Map<PasswordConstraint,Integer> constraints) {
        return enabled(constraints.get(this));
    }

    public static String format(EnumMap<PasswordConstraint,Integer>constraints) {
        StringBuilder sb = new StringBuilder();
        for (PasswordConstraint c : PasswordConstraint.values()) {
            if (c.enabled(constraints)) {
                switch (c.type) {
                case MIN:      sb.append(c.id).append(">=").append(constraints.get(c)); break;
                case MAX:      sb.append(c.id).append("<=").append(constraints.get(c)); break;
                case REQUIRE:  sb.append(c.id);                                         break;
                case PROHIBIT: sb.append('!').append(c.id);                             break;
                }
                sb.append(' ');
            }
        }
        if (sb.length()>0) sb.setLength(sb.length()-1); // remove extra trailing ' '
        return sb.toString();
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
    public static EnumMap<PasswordConstraint,Integer> parse (String spec) {
        EnumMap<PasswordConstraint,Integer>map = new EnumMap<PasswordConstraint,Integer>(PasswordConstraint.class);
        if (spec!=null) {
            Matcher m   = CLAUSE.matcher(spec);
            int     i   = 0;
            String  err = null;
            while (err==null && m.find() && m.start()==i) {
                boolean            bang       = m.group(1) != null;
                PasswordConstraint constraint = of(m.group(2));
                boolean            limited    = m.group(3) != null;
                char               ineq       = limited ? m.group(3).charAt(0) : 'x';
                int                limit      = limited ? Integer.valueOf(m.group(4)) : -1;
                if (constraint==null) {
                    err = "unrecognized token";
                } else {
                    switch(constraint.type) {
                    case MIN:
                        if (bang || ineq!='>') {
                            err = constraint.id+">=number expected";
                        }
                        map.put(constraint, limit);
                        break;
                    case MAX:
                        if (bang || ineq!='<') {
                            err = constraint.id+"<=number expected";
                        }
                        map.put(constraint, limit);
                        break;
                    case REQUIRE:
                        if (bang || ineq!='x') {
                            err = constraint.id+" expected";
                        }
                        map.put(constraint, ENABLED);
                        break;
                    case PROHIBIT:
                        if (!bang || ineq!='x') {
                            err = "!"+constraint.id+" expected";
                        }
                        map.put(constraint, ENABLED);
                        break;
                    }
                }
                i = m.end();
            }
            if (i<spec.length() || err!=null) {
                // we didn't make it cleanly to the end
                if (err==null) err="parsing error";
                throw new IllegalArgumentException(err+": "+spec.substring(0,i)+"-->"+spec.substring(i));
            }
        }
        return map;
    }
}