package CAMPS.Admin;

import CAMPS.Connect.DBConnect;
import java.io.IOException;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.FilterConfig;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;

public class authorizationFilter implements Filter {

    private FilterConfig filterConfig = null;

    public authorizationFilter() {
    }

    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException, ServletException {
        DBConnect db = new DBConnect();
        try {
            HttpSession session = ((HttpServletRequest) request).getSession();
            HttpServletRequest req = (HttpServletRequest) request;
            HttpServletResponse res = (HttpServletResponse) response;
            String url = null,url1=null;
            if (req.getQueryString() != null) {
                url = req.getServletPath() + "?" + req.getQueryString();
            } else {
                url = req.getServletPath();
            }
             url1 = req.getServletPath();
            String hostname = req.getScheme() + "://" + req.getServerName() + ":" + req.getServerPort() + req.getContextPath() + "/";
            boolean allowedRequest = false;
            boolean reRirect = false;
            if (url.contains("welcomePage.jsp")) {
                allowedRequest = true;
            }
             else if (!allowedRequest) {
                if (session.getAttribute("login") == null || session.getAttribute("login") == "false") {
                    res.sendRedirect(hostname + "index.jsp");
                    reRirect = true;
                }
                String roleid = null;
                if (session.getAttribute("roles") != null) {
                    roleid = session.getAttribute("roles").toString();
                }
                db.getConnection();
                db.read1("SELECT * FROM admin.role_resource_mapping rrm INNER JOIN admin.resource_master rm ON FIND_IN_SET(rm.id,rrm.menuId) AND rrm.roleid IN (" + roleid + ") AND rm.link ='" + url.substring(1) + "'");
                if (db.rs1.first()) {
                    if(db.rs1.getString("critical").equalsIgnoreCase("1") && "0".equalsIgnoreCase(session.getAttribute("OTPstatus").toString())){
                         res.sendRedirect(hostname + "JSP/Welcome/otp_verification.jsp");
                         reRirect = true;
                    }
                    db.insert("INSERT INTO admin.authorization_log VALUES(page,'" + url1.substring(1) + "',NOW(),'Authorized','" + session.getAttribute("userId").toString() + "','" + session.getAttribute("roleNames") + "');");
                   
                } else {
                    if (req.getHeader("Referer") == null) {
                        db.insert("INSERT INTO admin.authorization_log VALUES(page,'" + url1.substring(1) + "',NOW(),'Not  Authorized','" + session.getAttribute("userId").toString() + "','" + session.getAttribute("roleNames") + "');");
                        res.sendRedirect(hostname + "JSP/Welcome/welcomePage.jsp?error_code=0");
                        reRirect = true;
                    } else {
                        db.insert("INSERT INTO admin.authorization_log VALUES('" + req.getHeader("Referer") + "','" + url1.substring(1) + "',NOW(),'AJAX','" + session.getAttribute("userId").toString() + "','" + session.getAttribute("roleNames") + "');");
                    }
                }
            }
            if (!reRirect) {
               chain.doFilter(request, response);
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        } finally {
            try {
                db.closeConnection();
            } catch (SQLException ex) {
                Logger.getLogger(authorizationFilter.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }

    public FilterConfig getFilterConfig() {
        return (this.filterConfig);
    }

    public void setFilterConfig(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public void destroy() {
    }

    public void init(FilterConfig filterConfig) {
        this.filterConfig = filterConfig;
    }

    public void log(String msg) {
        filterConfig.getServletContext().log(msg);
    }
}
