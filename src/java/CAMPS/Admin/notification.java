package CAMPS.Admin;

import CAMPS.Connect.DBConnect;
import java.io.IOException;
import java.io.PrintWriter;
import java.sql.SQLException;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import javax.servlet.http.HttpSession;


public class notification extends HttpServlet {

    protected void processRequest(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        response.setContentType("text/html;charset=UTF-8");
        try (PrintWriter out = response.getWriter()) {
            HttpSession ses = request.getSession(); 
            DBConnect db = new DBConnect();
            String data = "", nm_id = "";
            int count = 0,flag=0;
            try {
                db.getConnection();
                db.read("SELECT nm.nm_id,nm.nm_title,nm.nm_desc,nm.nm_link,nm.trigger_type,nq.query,nm.trigger_type,CONCAT('\"title\":\"',nm.nm_title,'\",\"msg\":\"',nm.nm_desc,'\",\"url\":\"',nm.nm_link,'\"') DATA,nm.trigger_type FROM camps.notification_master nm LEFT JOIN camps.notification_specific ns ON nm.nm_id=ns.nm_id AND nm.nm_type=ns.nm_type AND (IF(ns.nm_type='role',ns.type_value='" + ses.getAttribute("roles") + "' , ns.type_value='" + ses.getAttribute("user_id") + "' ) )  LEFT JOIN (SELECT nh.nm_id,nh.user_id,MAX(nh.viewed_date)viewed_date,MAX(nh.delivery_date)delivery_date FROM camps.notification_history nh WHERE nh.user_id='" + ses.getAttribute("user_id") + "' GROUP BY nh.nm_id)nh ON nh.nm_id=nm.nm_id  LEFT JOIN camps.notification_query nq ON nq.nm_id=nm.nm_id  WHERE  CASE WHEN nm.notify='once' THEN nh.nm_id IS NULL WHEN nm.notify='until view'  THEN nh.viewed_date IS NULL AND (nh.delivery_date IS NULL OR nh.delivery_date< NOW() - INTERVAL nm.repeat_after MINUTE)WHEN nm.notify='repeat'  THEN (nh.delivery_date IS NULL OR nh.delivery_date< NOW() - INTERVAL nm.repeat_after MINUTE) END AND nm.status>0");
                if (db.rs.next()) {
                    if(db.rs.getString("trigger_type").equalsIgnoreCase("query")){
                    db.read1(db.rs.getString("query").replaceAll("__XXX__", ses.getAttribute("user_id").toString()));
                    if(db.rs1.next()){
                        flag=1;
                      data += "{\"title\":\"" + db.rs.getString("nm_title") + "\",\"msg\":\"" + db.rs1.getString("qdesc") + "\",\"url\":\"" + db.rs.getString("nm_link") + "\"}";                      
                    }
                    }
                    else{
                         flag=1;
                    data += "{\"title\":\"" + db.rs.getString("nm_title") + "\",\"msg\":\"" + db.rs.getString("nm_desc") + "\",\"url\":\"" + db.rs.getString("nm_link") + "\"}";
                    }
                    nm_id += "'" + db.rs.getString("nm_id") + "'";
                    count++;
                }
                while (db.rs.next()) {
                     if(db.rs.getString("trigger_type").equalsIgnoreCase("query")){
                    db.read1(db.rs.getString("query").replaceAll("__XXX__", ses.getAttribute("userId").toString()));
                    if(db.rs1.next()){
                        if(flag==1){
                            data += ",";
                        }
                      data += "{\"title\":\"" + db.rs.getString("nm_title") + "\",\"msg\":\"" + db.rs1.getString("qdesc") + "\",\"url\":\"" + db.rs.getString("nm_link") + "\"}";                      
                       flag=1;
                    }
                    }
                    else{
                          if(flag==1){
                            data += ",";
                        }
                    data += "{\"title\":\"" + db.rs.getString("nm_title") + "\",\"msg\":\"" + db.rs.getString("nm_desc") + "\",\"url\":\"" + db.rs.getString("nm_link") + "\"}";
                    flag=1;
                    }
                     nm_id += ",'" + db.rs.getString("nm_id") + "'"; 
                    count++;
                }
                if(count>0)
                db.insert("INSERT INTO camps.notification_history (nh_id,nm_id,ss_id,delivery_date,viewed_date) SELECT NULL,nm.nm_id,'" + ses.getAttribute("userId") + "',NOW(),NULL FROM camps.notification_master nm WHERE nm.nm_id IN ("+nm_id+")");
            } catch (Exception e) {
            } finally {
                try {
                    db.closeConnection();
                } catch (SQLException ex) {
                    Logger.getLogger(notification.class.getName()).log(Level.SEVERE, null, ex);
                }
                out.print("{\"root\": {\"result\": \"true\",\"count\": \"" + count + "\",\"notifi\": {\"notif\": [" + data + "]}} } ");

            }
        }
    }

//    @Override
//    protected void doGet(HttpServletRequest request, HttpServletResponse response)
//            throws ServletException, IOException {
//        processRequest(request, response);
//    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        processRequest(request, response);
    }

    @Override
    public String getServletInfo() {
        return "Short description";
    }
}
