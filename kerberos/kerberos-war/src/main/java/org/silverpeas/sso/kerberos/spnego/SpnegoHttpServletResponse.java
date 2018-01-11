/*
 * Copyright (C) 2000 - 2018 Silverpeas
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as
 * published by the Free Software Foundation, either version 3 of the
 * License, or (at your option) any later version.
 *
 * As a special exception to the terms and conditions of version 3.0 of
 * the GPL, you may redistribute this Program in connection with Free/Libre
 * Open Source Software ("FLOSS") applications as described in Silverpeas's
 * FLOSS exception.  You should have received a copy of the text describing
 * the FLOSS exception, and it is also available here:
 * "https://www.silverpeas.org/legal/floss_exception.html"
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

package org.silverpeas.sso.kerberos.spnego;

import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpServletResponseWrapper;
import java.io.IOException;

/**
 * Class adds capability to track/determine if the HTTP Status
 * code has been set.
 * <p/>
 * <p>
 * Also allows the ability to set the content length to zero
 * and flush the buffer immediately after setting the HTTP
 * Status code.
 * </p>
 * @author Darwin V. Felix
 */
public final class SpnegoHttpServletResponse extends HttpServletResponseWrapper {

  private transient boolean statusSet = false;

  /**
   * @param response
   */
  public SpnegoHttpServletResponse(final HttpServletResponse response) {
    super(response);
  }

  /**
   * Tells if setStatus has been called.
   * @return true if HTTP Status code has been set
   */
  public boolean isStatusSet() {
    return this.statusSet;
  }

  @Override
  public void setStatus(final int status) {
    super.setStatus(status);
    this.statusSet = true;
  }

  /**
   * Sets the HTTP Status Code and optionally set the the content
   * length to zero and flush the buffer.
   * @param status http status code
   * @param immediate set to true to set content len to zero and flush
   * @throws IOException
   * @see #setStatus(int)
   */
  public void setStatus(final int status, final boolean immediate) throws IOException {
    setStatus(status);
    if (immediate) {
      setContentLength(0);
      flushBuffer();
    }
  }
}
