<%--
  ~ Copyright (C) 2000 - 2019 Silverpeas
  ~
  ~ This program is free software: you can redistribute it and/or modify
  ~ it under the terms of the GNU Affero General Public License as
  ~ published by the Free Software Foundation, either version 3 of the
  ~ License, or (at your option) any later version.
  ~
  ~ As a special exception to the terms and conditions of version 3.0 of
  ~ the GPL, you may redistribute this Program in connection with Free/Libre
  ~ Open Source Software ("FLOSS") applications as described in Silverpeas's
  ~ FLOSS exception.  You should have received a copy of the text describing
  ~ the FLOSS exception, and it is also available here:
  ~ "https://www.silverpeas.org/legal/floss_exception.html"
  ~
  ~ This program is distributed in the hope that it will be useful,
  ~ but WITHOUT ANY WARRANTY; without even the implied warranty of
  ~ MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  ~ GNU Affero General Public License for more details.
  ~
  ~ You should have received a copy of the GNU Affero General Public License
  ~ along with this program.  If not, see <http://www.gnu.org/licenses/>.
  --%>

<%@page contentType="text/html; charset=UTF-8" pageEncoding="UTF-8" %>
<%@ taglib uri="http://java.sun.com/jsp/jstl/core" prefix="c" %>
<%@ taglib uri="http://www.silverpeas.com/tld/viewGenerator" prefix="view" %>
<c:url var="negoUrl" value="/sso/kerberos/nego"/>
<c:url var="negoErrorUrl" value="/Login">
  <c:param name="ErrorCode" value="Error_SsoNotAllowed"/>
</c:url>

<view:sp-page>
<view:sp-head-part noLookAndFeel="true">
  <view:includePlugin name="jquery"/>
  <script type="text/javascript">
    jQuery.ajax({url:'${negoUrl}?pre-auth=true',type:'GET',dataType:'text',cache:false,success:function(){location.href='${negoUrl}';},error:function(){location.href='${negoErrorUrl}';}});
  </script>
</view:sp-head-part>
<view:sp-body-part>
</view:sp-body-part>
</view:sp-page>
