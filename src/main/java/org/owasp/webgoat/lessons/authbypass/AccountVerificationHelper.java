/*
 * This file is part of WebGoat, an Open Web Application Security Project utility. For details, please see http://www.owasp.org/
 *
 * Copyright (c) 2002 - 2019 Bruce Mayhew
 *
 * This program is free software; you can redistribute it and/or modify it under the terms of the
 * GNU General Public License as published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without
 * even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with this program; if
 * not, write to the Free Software Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 *
 * Getting Source ==============
 *
 * Source for this application is maintained at https://github.com/WebGoat/WebGoat, a repository for free software projects.
 */

package org.owasp.webgoat.lessons.authbypass;

import java.util.HashMap;
import java.util.Map;

/** Created by appsec on 7/18/17. */
public class AccountVerificationHelper {

  // simulating database storage of verification credentials
  private static final Integer VERIFYUSERID = 1223445;
  private static final Map<String, String> userSecQuestions = new HashMap<>();
  private static final String SECQ0 = "secQuestion0";
  private static final String SECQ1 = "secQuestion1";

  static {
    userSecQuestions.put(SECQ0, "Dr. Watson");
    userSecQuestions.put(SECQ1, "Baker Street");
  }

  private static final Map<Integer, Map> secQuestionStore = new HashMap<>();

  static {
    secQuestionStore.put(VERIFYUSERID, userSecQuestions);
  }

  // end 'data store set up'

  // this is to aid feedback in the attack process and is not intended to be part of the
  // 'vulnerable' code
  public boolean didUserLikelylCheat(HashMap<String, String> submittedAnswers) {
    boolean likely = false;

    if (submittedAnswers.size() == secQuestionStore.get(VERIFYUSERID).size()) {
      likely = true;
    }

    if ((submittedAnswers.containsKey(SECQ0)
            && submittedAnswers
                .get(SECQ0)
                .equals(secQuestionStore.get(VERIFYUSERID).get(SECQ0)))
        && (submittedAnswers.containsKey(SECQ1)
            && submittedAnswers
                .get(SECQ1)
                .equals(secQuestionStore.get(VERIFYUSERID).get(SECQ1)))) {
      likely = true;
    } else {
      likely = false;
    }

    return likely;
  }

  // end of cheating check ... the method below is the one of real interest. Can you find the flaw?

  public boolean verifyAccount(Integer userId, HashMap<String, String> submittedQuestions) {
    // short circuit if no questions are submitted
    if (submittedQuestions.entrySet().size() != secQuestionStore.get(VERIFYUSERID).size()) {
      return false;
    }

    if (submittedQuestions.containsKey(SECQ0)
        && !submittedQuestions
            .get(SECQ0)
            .equals(secQuestionStore.get(VERIFYUSERID).get(SECQ0))) {
      return false;
    }

    if (submittedQuestions.containsKey(SECQ1)
        && !submittedQuestions
            .get(SECQ1)
            .equals(secQuestionStore.get(VERIFYUSERID).get(SECQ1))) {
      return false;
    }

    // else
    return true;
  }
}
