package org.owasp.webgoat;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.owasp.webgoat.lessons.challenges.SolutionConstants.PASSWORD;
import static org.owasp.webgoat.lessons.challenges.challenge7.Assignment7.ADMIN_PASSWORD_LINK;

import io.restassured.RestAssured;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import org.assertj.core.api.Assertions;
import org.junit.jupiter.api.Test;
import org.springframework.http.HttpStatus;

public class ChallengeIntegrationTest extends IntegrationTest {

  @Test
  void testChallenge1() {
    startLesson("Challenge1");

    byte[] resultBytes =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(url("challenge/logo"))
            .then()
            .statusCode(200)
            .extract()
            .asByteArray();

    String pincode = new String(Arrays.copyOfRange(resultBytes, 81216, 81220));
    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("username", "admin");
    params.put("password", PASSWORD.replace("1234", pincode));

    // checkAssignment(url("challenge/1"), params, true);
    String result =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .formParams(params)
            .post(url("challenge/1"))
            .then()
            .statusCode(200)
            .extract()
            .asString();

    String flag = result.substring(result.indexOf("flag") + 6, result.indexOf("flag") + 42);
    params.clear();
    params.put("flag", flag);
    // checkAssignment(url("challenge/flag"), params, true);

    // checkResults("/challenge/1");

    List<String> capturefFlags =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(url("scoreboard-data"))
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .get("find { it.username == \"" + this.getUser() + "\" }.flagsCaptured");
    // assertTrue(capturefFlags.contains("Admin lost password"));
  }

  @Test
  void testChallenge5() {
    startLesson("Challenge5");

    Map<String, Object> params = new HashMap<>();
    params.clear();
    params.put("username_login", "Larry");
    params.put("password_login", "1' or '1'='1");

    String result =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .formParams(params)
            .post(url("challenge/5"))
            .then()
            .statusCode(200)
            .extract()
            .asString();

    String flag = result.substring(result.indexOf("flag") + 6, result.indexOf("flag") + 42);
    params.clear();
    params.put("flag", flag);
    checkAssignment(url("challenge/flag"), params, true);

    checkResults("/challenge/5");

    List<String> capturefFlags =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(url("scoreboard-data"))
            .then()
            .statusCode(200)
            .extract()
            .jsonPath()
            .get("find { it.username == \"" + this.getUser() + "\" }.flagsCaptured");
    assertTrue(capturefFlags.contains("Without password"));
  }

  @Test
  void testChallenge7() {
    startLesson("Challenge7");
    cleanMailbox();

    // One should first be able to download git.zip from WebGoat
    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .get(url("challenge/7/.git"))
        .then()
        .statusCode(200)
        .extract()
        .asString();

    // Should send an email to WebWolf inbox this should give a hint to the link being static
    RestAssured.given()
        .when()
        .relaxedHTTPSValidation()
        .cookie("JSESSIONID", getWebGoatCookie())
        .formParams("email", getUser() + "@webgoat.org")
        .post(url("challenge/7"))
        .then()
        .statusCode(200)
        .extract()
        .asString();

    // Check whether email has been received
    var responseBody =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("WEBWOLFSESSION", getWebWolfCookie())
            .get(webWolfUrl("mail"))
            .then()
            .extract()
            .response()
            .getBody()
            .asString();
    Assertions.assertThat(responseBody).contains("Hi, you requested a password reset link");

    // Call reset link with admin link
    /* String result =
        RestAssured.given()
            .when()
            .relaxedHTTPSValidation()
            .cookie("JSESSIONID", getWebGoatCookie())
            .get(url("challenge/7/reset-password/{link}"), ADMIN_PASSWORD_LINK)
            .then()
            .statusCode(HttpStatus.ACCEPTED.value())
            .extract()
            .asString();

    String flag = result.substring(result.indexOf("flag") + 6, result.indexOf("flag") + 42);
    checkAssignment(url("challenge/flag"), Map.of("flag", flag), true); */
  }
}
