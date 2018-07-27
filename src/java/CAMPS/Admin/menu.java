package CAMPS.Admin;


import CAMPS.Connect.DBConnect;
import java.sql.SQLException;
import java.util.ArrayList;
import java.util.logging.Level;
import java.util.logging.Logger;

public class menu {

    DBConnect db = new DBConnect();
    String menu1 = "";

    public String displaymenu(int parent, String role, String hostname) {
        try {  
            db.getConnection();
            if (parent == 0) {
                menu1 += "<ul class=\"list\">";
            } 
            db.read("SELECT rm.resource_id,rm.label,IFNULL(rm.img,'link')img,CASE WHEN rm.link='#' THEN '#' WHEN (rm.extraParameters='1') THEN rm.link ELSE CONCAT('"+hostname+"',rm.link) END link,COUNT(rm1.resource_id) COUNT FROM admin.resource_master rm  INNER JOIN admin.role_resource_mapping rrm ON FIND_IN_SET(rm.resource_id,rrm.resources) AND rrm.role_id IN ("+role+") AND rm.parent_id='"+parent+"' LEFT JOIN (admin.resource_master rm1  INNER JOIN admin.role_resource_mapping rrm1 ON FIND_IN_SET(rm1.resource_id,rrm1.resources) AND rrm1.role_id IN ("+role+")) ON rm.resource_id=rm1.parent_id GROUP BY rm.resource_id ORDER BY rm.sortorder");
            while (db.rs.next()) {
                if (db.rs.getInt("count") == 0) {
                    menu1 += "<li><a href='" + db.rs.getString("link")+ "' title='" + db.rs.getString("label") + "' ><i class=\"material-icons\">" + db.rs.getString("img") + "</i><span>" + db.rs.getString("label") + "</span> </a></li>";
                } else {     
                     menu a = new menu();
                    menu1 += "<li><a href='" + db.rs.getString("link") + "' class=\"menu-toggle\" title='" + db.rs.getString("label") + "' ><i class=\"material-icons\">" + db.rs.getString("img") + "</i><span>" + db.rs.getString("label") + " </span></a><ul class=\"ml-menu\">" + a.displaymenu(db.rs.getInt("resource_id"), role, hostname) + "</ul></li>";
                }
            }         
        } catch (Exception e) {           
        }
        finally{
            try {
                db.closeConnection();
            } catch (SQLException ex) {
                Logger.getLogger(menu.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        return menu1;
    }
}
