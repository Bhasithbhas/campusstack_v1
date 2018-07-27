<%@page contentType="text/html" pageEncoding="UTF-8"%>
<!DOCTYPE html>
<head>
        <title>JSP Page</title>
    </head>
    <body>  
         <%
             if(session.getAttribute("login")!=null)
{
   response.sendRedirect("JSP/Welcome/welcomePage.jsp");
}
             else{
                 response.sendRedirect("CommonJSP/signin.jsp");
             }
         %>
    </body>
</html>