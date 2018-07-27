package CAMPS.Admin;

import CAMPS.Common.escapeSpecialChars;
import java.io.IOException;
import java.io.PrintWriter;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import CAMPS.Connect.DBConnect;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.ResourceBundle;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.http.HttpSession;

public class authentication extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        HttpSession ses = request.getSession(true);
        PrintWriter out = response.getWriter();
        DBConnect db = new DBConnect();
        try {
            request.getServletContext().setAttribute("hostname", (Object) (request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath() + "/"));
            db.getConnection();
            escapeSpecialChars objesc = new escapeSpecialChars();
            ResourceBundle rb = ResourceBundle.getBundle("CAMPS.Admin.Psalt");
            String uname = null;
            boolean Admin = false;
            String ip = request.getHeader("X-FORWARDED-FOR");
            request.getHeader("VIA");
            String ipAddress = request.getHeader("X-FORWARDED-FOR");
            if (ipAddress == null) {
                ipAddress = request.getRemoteAddr();
            }
            ip = ipAddress;
            String status = "";
            String gkey = (String) ses.getAttribute("gkey");
            if (gkey != null) {
                db.read("SELECT um.user_id,um.roles,um.user_name,um.status,NOW() lastlogin,CASE WHEN um.staff_id IS NOT NULL THEN 'Staff' WHEN stu.student_id IS NOT NULL THEN 'Student' WHEN mr.student_id IS NOT NULL THEN 'Parent' END ss_det ,IF(um.staff_id IS NOT NULL,sm.staff_id,stu.student_id) staff_id,IF(um.staff_id IS NOT NULL,CONCAT(sm.first_name,' ',sm.middle_name,' ',sm.last_name),CONCAT(stu.first_name,' ',stu.middle_name,' ',stu.last_name)) staff_name FROM admin.user_master um LEFT JOIN camps.staff_master sm ON um.staff_id=sm.staff_id LEFT JOIN camps.student_master stu ON stu.student_id=um.student_id LEFT JOIN camps.master_relation mr ON mr.student_id=um.student_id WHERE stu.institute_email_id='"+gkey+"' OR sm.institute_email_id='"+gkey+"' OR mr.email_id='"+gkey+"' ");
            } else {
                db.read("SELECT um.user_id,um.roles,um.user_name,um.status,now() lastlogin,IF(um.staff_id IS NOT NULL,'Staff','Student') ss_det ,IF(um.staff_id IS NOT NULL,sm.staff_id,stu.student_id) staff_id,IF(um.staff_id IS NOT NULL,CONCAT(sm.first_name,' ',sm.middle_name,' ',sm.last_name),CONCAT(stu.first_name,' ',stu.middle_name,' ',stu.last_name)) staff_name FROM admin.user_master um LEFT JOIN camps.staff_master sm ON um.staff_id=sm.staff_id LEFT JOIN camps.student_master stu ON stu.student_id=um.student_id WHERE um.user_name='" + objesc.escapeSpecialChar(request.getParameter("uname")) + "'");
            }
            if (db.rs.first()) {
                if (db.rs.getRow() == 1) {
                    status = "1";
                    ses.setAttribute("login", db.rs.getString("user_id"));
                    ses.setAttribute("roles", db.rs.getString("roles"));
                    ses.setAttribute("user_id", db.rs.getString("user_id"));
                    ses.setAttribute("lastlogintime", db.rs.getString("lastlogin"));
                    ses.setAttribute("OTPstatus", "0");
                    ses.setAttribute("user_name", db.rs.getString("staff_name"));
                    ses.setAttribute("ss_id", db.rs.getString("staff_id"));
                    ses.setAttribute("depId", "Test");
                    ses.setAttribute("email", "Test");
                    ses.setAttribute("uType", db.rs.getString("ss_det"));
                    db.read1("SELECT StartUpPage,role_name FROM admin.role_master WHERE role_id IN (" + db.rs.getString("roles") + ") ORDER BY startuppage DESC");
                    ArrayList<String> rolename = new ArrayList<String>();
                    while (db.rs1.next()) {
                        rolename.add(db.rs1.getString("role_name"));
                    }
                    if (db.rs1.first() && db.rs.getInt("status") == 1) {
                        String startpage = db.rs1.getString("StartUpPage");                       
                        if (startpage != null && !startpage.isEmpty()) {
                            response.sendRedirect(startpage);
                        } else {
                            response.sendRedirect("JSP/Welcome/welcomePage.jsp");
                        }
                    } else if (db.rs.getInt("status") == 2) {
                        response.sendRedirect("JSP/Welcome/reset_passwd.jsp");
                    } else {
                        response.sendRedirect("JSP/Welcome/welcomePage.jsp");
                    }
                }
            } else {
                status = "0";
                response.sendRedirect(this.getServletContext().getAttribute("hostname").toString() + "CommonJSP/signin.jsp?er_c=0");

            }
            if (gkey != null) {
                db.insert("INSERT INTO admin.authentication_log VALUES('" + ip + "',NOW(),'" + gkey + "','" + status + "');");
            } else if (!Admin) {
                db.insert("INSERT INTO admin.authentication_log VALUES('" + ip + "',NOW(),'" + uname + "','" + status + "');");
            } else if (Admin) {
                ses.setAttribute("OTPstatus", "1");
                db.insert("INSERT INTO admin.authentication_log VALUES('" + ip + "',NOW(),'" + uname + "','99');");
            } else {
                db.insert("INSERT INTO admin.authentication_log VALUES('" + ip + "',NOW(),'" + uname + "','98');");
            }

        } catch (SQLException e) {
            out.print(e);
        } catch (Exception e) {
        } finally {
            try {
                out.close();
                db.closeConnection();
            } catch (SQLException ex) {
                Logger.getLogger(authentication.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    protected void doGet(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        //this.processRequest(request, response);
    }

    protected void doPost(HttpServletRequest request, HttpServletResponse response) throws ServletException, IOException {
        this.processRequest(request, response);
    }

    public String getServletInfo() {
        return "Short description";
    }
}
