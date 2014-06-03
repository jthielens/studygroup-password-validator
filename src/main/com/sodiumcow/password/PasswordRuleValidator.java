package com.sodiumcow.password;

import java.util.Date;

public class PasswordRuleValidator {
    String username = null;
    
    String newPassword = null;
    String confirmPassword = null;
    boolean passwordChanged = false;
    boolean shortMessage = false;

    LocalUserMailbox localUserMailbox = null;

    String errorMessage = null;
    
    PackageText rbTxt = null;
    
    public PasswordRuleValidator(String username) {   
      this.username = username;
    }

    public PasswordRuleValidator(String username, String newPassword, String confirmPassword, LocalUserMailbox localUserMailbox, 
                                 boolean passwordChanged, boolean shortMessage) {
      this.username = username;
      this.newPassword = newPassword;
      this.confirmPassword = confirmPassword;
      this.localUserMailbox = localUserMailbox;
      this.passwordChanged = passwordChanged;
      this.shortMessage = shortMessage;
      rbTxt = new LexBeanBeanText("PasswordRuleValidator");
    }

    // Allow overriding of the resource file text
    public void setPackageText(PackageText rbTxt) {
      this.rbTxt = rbTxt;
    }
    
    public String getErrorMessage() {
      return this.errorMessage;
    }

    public boolean verifyPassword() {
      boolean success = true;
      if (newPassword == null || newPassword.trim().length() == 0) {
        errorMessage = rbTxt.getText("BlankPasswordError");
        success = false;
      } else if (confirmPassword == null || confirmPassword.trim().length() == 0) {
        errorMessage = rbTxt.getText("ConfirmPasswordEntry");
        success = false;
      } else if (!newPassword.equals(confirmPassword)){
        errorMessage = rbTxt.getText("PasswordsMustMatch") + " \n" +
                       rbTxt.getText("EnterPasswordsAgain");
        success = false;      
      } else if (passwordChanged && (this.localUserMailbox != null) &&
                 this.localUserMailbox.isEnforcePasswordPolicy()) {
        errorMessage = this.localUserMailbox.checkAgainstPreviousPasswords(newPassword, this.shortMessage);
        if (errorMessage != null)
          success = false;
        else {
          //System.out.println("PasswordRuleValidator - enforcing password policy...");
          PasswordRules passwordRules = (PasswordRules)this.localUserMailbox.getPasswordRules();        
          errorMessage = verifyPassword(username, newPassword, passwordRules);
          if (errorMessage != null) {
            if (this.shortMessage)
              errorMessage = rbTxt.getText("NotPasswordPolicy");
            success = false;
          }
        }
      }    
      return success;
    }
    
    // Here's where the established rules will be checked
    // e.g., password length, at least one digit/character
    // mixed case, etc.
    
    static int UPPERCASE = 0;
    static int LOWERCASE = 1;
    static int NUMERIC = 2;
    static int SPECIAL = 3;
    
    public String verifyPassword(String username, String password, 
                                 PasswordRules passwordRules) {                   
      if (username == null)
         username = "";
       
       if ((password.length() < passwordRules.getMinPasswordLength()) ||
            (passwordRules.getRestrictUserNameInPassword() && 
             password.toLowerCase().indexOf(username.toLowerCase()) >= 0) ||
            (passwordRules.getRequireMixedCase() && 
              (countChars(password, UPPERCASE) < passwordRules.getMinNumUpperCaseChars())) ||
            (passwordRules.getRequireMixedCase() && 
              (countChars(password, LOWERCASE) < passwordRules.getMinNumLowerCaseChars())) ||
            (passwordRules.getRequireNumericChars() && 
              (countChars(password, NUMERIC) < passwordRules.getMinNumNumericChars())) ||
            (passwordRules.getRequireSpecialChars() && 
              (countChars(password, SPECIAL) < passwordRules.getMinNumSpecialChars())) ) { 

         return getPasswordRulesReminderMessage(passwordRules);
             
       } else     
         return null;
    }
     
    public static boolean isPasswordExpired(Date created, PasswordRules passwordRules){
      boolean expired = false;
      if (passwordRules.getExpirePasswords()){
        long interval = LexBean.ONE_DAY * passwordRules.getNumberofDaysUntilExpiration();
        long elapsed = System.currentTimeMillis() - created.getTime();
        expired = elapsed >= interval;
      }
      
      return expired;
    }
     
    private static int countChars(String string, int type) {
      int count = 0;
      char[] pwChars = string.toCharArray();
      for (int i=0; i < pwChars.length; i++) {
        int thisChar = (int)pwChars[i];
        if (type == UPPERCASE && 
            thisChar >= 65 && thisChar <= 90) {
          count++;
        } else if (type == LOWERCASE && 
            thisChar >= 97 && thisChar <= 122) {
          count++;
        } else if (type == NUMERIC &&
            thisChar >= 48 && thisChar <= 57) {
          count++;
        } else if (type == SPECIAL &&
                   ((thisChar >= 33 && thisChar <= 47) ||
                    (thisChar >= 58 && thisChar <= 64) ||
                    (thisChar >= 92 && thisChar <= 96) ||
                    (thisChar == 126))) {
          count++;
        }
      }
      return count;
    }
    
    private String getPasswordRulesReminderMessage(PasswordRules passwordRules) {
      String rulesString = rbTxt.getText("ForSecurity") + ":\n"   + 
                           rbTxt.getText("MinimumPassword") + " " + 
                           passwordRules.getMinPasswordLength() + " " + 
                           rbTxt.getText("CharacterLength") + ".\n";
      
      if (passwordRules.getRestrictUserNameInPassword()) 
        rulesString += "   " + rbTxt.getText("CannotBeUsername") + "\n";
      
      if (passwordRules.getRequireMixedCase()) {
        rulesString += "   " + rbTxt.getText("MustBeMixedCase") + 
                       " " + passwordRules.getMinNumUpperCaseChars();
        rulesString += " " + rbTxt.getText("UppercaseAnd") + " " + 
                       passwordRules.getMinNumLowerCaseChars() + " " + 
                       rbTxt.getText("Lowercase") + " ";
        if (passwordRules.getMinNumUpperCaseChars() == 1 && passwordRules.getMinNumLowerCaseChars() == 1)
          rulesString += rbTxt.getText("Character");
        else
          rulesString += rbTxt.getText("Characters");
        rulesString += ".   \n";
      }
      if (passwordRules.getRequireNumericChars()) {
        rulesString += "   " + rbTxt.getText("MinimumChars") + " " + 
                       passwordRules.getMinNumNumericChars() + " " + 
                       rbTxt.getText("Numeric") + " ";
        if (passwordRules.getMinNumNumericChars() == 1)
          rulesString += rbTxt.getText("Character");
        else  
          rulesString += rbTxt.getText("Characters");
        rulesString += ".\n";
      }
      
      if (passwordRules.getRequireSpecialChars()) {
        rulesString += "   " + rbTxt.getText("MinimumChars") + " " + 
                       passwordRules.getMinNumSpecialChars() + " " + 
                       rbTxt.getText("Special") + " ";
        
        if (passwordRules.getMinNumSpecialChars() == 1)
          rulesString += rbTxt.getText("Character");
        else  
          rulesString += rbTxt.getText("Characters");
        rulesString += ", " + rbTxt.getText("ForExample") + "," + " !@#$%^&*, etc.,\n   " + 
                       rbTxt.getText("CannotContainSpace") + ".\n";
      } 
      rulesString += "\n";
      return rulesString;
    }
}
