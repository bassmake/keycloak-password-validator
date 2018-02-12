package sk.bsmk.keycloak.passwordvalidator.tools;

import org.apache.commons.io.IOUtils;
import org.jboss.logging.Logger;


import javax.ws.rs.client.ClientRequestContext;
import javax.ws.rs.client.ClientResponseContext;
import javax.ws.rs.client.ClientResponseFilter;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.Collections;
import java.util.Map;

public class LoggingFilter implements ClientResponseFilter {

  private static final Logger log = Logger.getLogger(LoggingFilter.class);

  @Override
  public void filter(ClientRequestContext requestContext, ClientResponseContext responseContext)
    throws IOException {

    if (log.isInfoEnabled()) {
      log.infof(
        "\r\nRequest: %s %s %s\r\nHeaders: %s\r\nResponse: %s %s",
        requestContext.getMethod(),
        requestContext.getUri(),
        sanitize(requestContext.getEntity()),
        requestContext.getStringHeaders(),
        responseContext.getStatus(),
        content(responseContext));
    }
  }

  private String content(ClientResponseContext responseContext) throws IOException {
    final InputStream entityStream = responseContext.getEntityStream();
    if (entityStream == null) {
      return "";
    }
    final byte[] bytes = IOUtils.toByteArray(entityStream);
    responseContext.setEntityStream(new ByteArrayInputStream(bytes));
    return new String(bytes, StandardCharsets.UTF_8);
  }

  @SuppressWarnings("unchecked")
  private static String sanitize(Object entity) {
    if (entity == null) {
      return "";
    }
    if (entity instanceof Map) {
      final Map map = (Map) entity;
      if (map.containsKey("password")) {
        map.put("password", Collections.singletonList("***"));
      }
      return map.toString();
    }
    return entity.toString();
  }
}
