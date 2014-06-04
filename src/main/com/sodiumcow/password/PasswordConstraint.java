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
    AGE_CONSTRAINT (Type.MAX, "age") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            return true;  // AGE_CONSTRAINT does not apply in the validation context
        }
    },
    USERSUBSTRING_CONSTRAINT (Type.PROHIBIT, "user") {
        @Override
        public boolean validate(Map<PasswordConstraint,Integer> constraints, String password, Map<CharacterType,Integer>counts, String user, PasswordMatcher matcher) {
            return !enabled(constraints.get(this)) ||
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

    public abstract boolean validate(Map<PasswordConstraint,Integer> constraints,
                                     String                          password,
                                     Map<CharacterType,Integer>      counts,
                                     String                          user,
                                     PasswordMatcher                 matcher);

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

    public boolean enabled(int value) {
        return value != getDefault();
    }

    public StringBuffer append(StringBuffer sb, int value) {
        if (enabled(value)) {
            switch (type) {
            case MIN:      sb.append(id).append(">=").append(value); break;
            case MAX:      sb.append(id).append("<=").append(value); break;
            case REQUIRE:  sb.append(id);                            break;
            case PROHIBIT: sb.append('!').append(id);                break;
            }
        }
        return sb;
    }

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
                    err = "recognized token";
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
            if (i<spec.length()) {
                // we didn't make it cleanly to the end
                if (err==null) err="parsing error";
                throw new IllegalArgumentException(err+": "+spec.substring(0,i)+"-->"+spec.substring(i));
            }
        }
        return map;
    }
}