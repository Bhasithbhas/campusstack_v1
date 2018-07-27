package CAMPS.Admin;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.URL;
import java.net.URLConnection;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;
import org.json.JSONObject;

public class gSignIn extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        HttpSession session = request.getSession(true);
        try (PrintWriter out = response.getWriter()) {
            try {
                // get code
                String code = request.getParameter("code");
                // format parameters to post
                String urlParameters = "code="
                        + code
                        + "&client_id=<client_id>"
                        + "&client_secret=<client secret>"
                        + "&redirect_uri=http://localhost:8084/CampusStack/gSignIn"
                        + "&grant_type=authorization_code";

                //post parameters
                URL url = new URL("https://accounts.google.com/o/oauth2/token");
                URLConnection urlConn = url.openConnection();
                urlConn.setDoOutput(true);
                OutputStreamWriter writer = new OutputStreamWriter(
                        urlConn.getOutputStream());
                writer.write(urlParameters);
                writer.flush();

                //get output in outputString 
                String line, outputString = "";
                BufferedReader reader = new BufferedReader(new InputStreamReader(
                        urlConn.getInputStream()));
                while ((line = reader.readLine()) != null) {
                    outputString += line;
                }
                //out.println(outputString);

                //get Access Token 
                JSONObject json = new JSONObject(outputString);
                String access_token = json.get("access_token").toString();
                //out.println(access_token);

                //get User Info 
                url = new URL(
                        "https://www.googleapis.com/oauth2/v1/userinfo?access_token="
                        + access_token);
                urlConn = url.openConnection();
                outputString = "";
                reader = new BufferedReader(new InputStreamReader(
                        urlConn.getInputStream()));
                while ((line = reader.readLine()) != null) {
                    outputString += line;
                }
                //out.println(outputString);
                 json = json = new JSONObject(outputString);
                session.setAttribute("gkey", json.get("email").toString());
                response.sendRedirect("checkLogin");
                writer.close();
                reader.close();
            } catch (Exception e) {
                out.println(e);
            }
        }
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }// </editor-fold>

}
