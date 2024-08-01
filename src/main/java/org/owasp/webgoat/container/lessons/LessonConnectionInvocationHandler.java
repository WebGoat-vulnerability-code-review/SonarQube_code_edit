package org.owasp.webgoat.container.lessons;

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.sql.Connection;
import java.sql.PreparedStatement;

import org.owasp.webgoat.container.users.WebGoatUser;
import org.springframework.security.core.context.SecurityContextHolder;

/**
 * Handler which sets the correct schema for the currently bounded user. This way users are not
 * seeing each other data, and we can reset data for just one particular user.
 */
public class LessonConnectionInvocationHandler implements InvocationHandler {

  private final Connection targetConnection;

  public LessonConnectionInvocationHandler(Connection targetConnection) {
    this.targetConnection = targetConnection;
  }

  @Override
  public Object invoke(Object proxy, Method method, Object[] args) throws Throwable {
    var authentication = SecurityContextHolder.getContext().getAuthentication();

    String username = authentication.getName();
    String query = "SET SCHEMA  ? ";
    if (authentication.getPrincipal() instanceof WebGoatUser user) {
      try (PreparedStatement ps = targetConnection.prepareStatement(query)) {
        ps.setString(1, username);
        ps.executeQuery();
      }
    }
    try {
      return method.invoke(targetConnection, args);
    } catch (InvocationTargetException e) {
      throw e.getTargetException();
    }
  }
}
