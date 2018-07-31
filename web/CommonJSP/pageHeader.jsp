<%@page import="CAMPS.Connect.DBConnect"%>
<!DOCTYPE html>
<%@page contentType="text/html" pageEncoding="UTF-8"%>
<%@page import="CAMPS.Admin.menu"%>
﻿<html>
    <head> 
        <meta charset="UTF-8">
        <meta http-equiv="X-UA-Compatible" content="IE=Edge">
        <meta content="width=device-width, initial-scale=1, maximum-scale=1, user-scalable=no" name="viewport">
        <title>CMS BIT</title>
        <%String host_string = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath() + "/";%>
        <!-- Favicon-->
        <link rel="icon" href="favicon.ico" type="image/x-icon" />
        <!-- Jquery Core Js -->
        <script src="plugins/jquery/jquery.min.js"></script>

        <!-- Google Fonts -->
        <link href="https://fonts.googleapis.com/css?family=Roboto:400,700&subset=latin,cyrillic-ext" rel="stylesheet" type="text/css">
        <link href="https://fonts.googleapis.com/icon?family=Material+Icons" rel="stylesheet" type="text/css">

        <!-- Bootstrap Core Css -->
        <link href="<%=host_string%>plugins/bootstrap/css/bootstrap.css" rel="stylesheet"/>

        <!-- Waves Effect Css -->
        <link href="<%=host_string%>plugins/node-waves/waves.css" rel="stylesheet" />

        <!-- Animation Css -->
        <link href="<%=host_string%>plugins/animate-css/animate.css" rel="stylesheet" />

        <!-- Morris Chart Css-->
        <link href="<%=host_string%>plugins/morrisjs/morris.css" rel="stylesheet" />

        <!-- Custom Css -->
        <link href="<%=host_string%>css/style.css" rel="stylesheet">

        <!-- AdminBSB Themes. You can choose a theme from css/themes instead of get all themes -->
        <link href="<%=host_string%>css/themes/theme-blue.css" rel="stylesheet" />

        <!-- Jquery Core Js -->
        <script src="<%=host_string%>plugins/jquery/jquery.min.js"></script>

        <!-- Bootstrap Core Js -->
        <script src="<%=host_string%>plugins/bootstrap/js/bootstrap.js"></script>

        <!-- Select Plugin Js -->
        <script src="<%=host_string%>plugins/bootstrap-select/js/bootstrap-select.js"></script>

        <!-- Slimscroll Plugin Js -->
        <script src="<%=host_string%>plugins/jquery-slimscroll/jquery.slimscroll.js"></script>

        <!-- Waves Effect Plugin Js -->
        <script src="<%=host_string%>plugins/node-waves/waves.js"></script>

        <!-- Jquery CountTo Plugin Js -->
        <script src="<%=host_string%>plugins/jquery-countto/jquery.countTo.js"></script>

        <!-- Morris Plugin Js -->
        <script src="<%=host_string%>plugins/raphael/raphael.min.js"></script>
        <script src="<%=host_string%>plugins/morrisjs/morris.js"></script>

        <!-- ChartJs -->
        <script src="<%=host_string%>plugins/chartjs/Chart.bundle.js"></script>

        <!-- Flot Charts Plugin Js -->
        <script src="<%=host_string%>plugins/flot-charts/jquery.flot.js"></script>
        <script src="<%=host_string%>plugins/flot-charts/jquery.flot.resize.js"></script>
        <script src="<%=host_string%>plugins/flot-charts/jquery.flot.pie.js"></script>
        <script src="<%=host_string%>plugins/flot-charts/jquery.flot.categories.js"></script>
        <script src="<%=host_string%>plugins/flot-charts/jquery.flot.time.js"></script>

        <!-- Sparkline Chart Plugin Js -->
        <script src="<%=host_string%>plugins/jquery-sparkline/jquery.sparkline.js"></script>
        <!-- Bootstrap Notify Plugin Js -->
        <script src="<%=host_string%>plugins/bootstrap-notify/bootstrap-notify.js"></script>

        <!-- Custom Js -->
        <script src="<%=host_string%>js/admin.js"></script>
        <script src="<%=host_string%>js/pages/index.js"></script>
        <script src="<%=host_string%>js/pages/CommonJSP/notifications.js"/>
        <!-- Demo Js -->
        <script src="<%=host_string%>js/demo.js"></script>
    </head>

    <body class="theme-blue">
        <!-- Page Loader -->
        <div class="page-loader-wrapper">
            <div class="loader">
                <div class="preloader">
                    <div class="spinner-layer pl-red">
                        <div class="circle-clipper left">
                            <div class="circle"></div>
                        </div>
                        <div class="circle-clipper right">
                            <div class="circle"></div>
                        </div>
                    </div>
                </div>
                <p>Please wait...</p>
            </div>
        </div>
        <!-- #END# Page Loader -->
        <!-- Overlay For Sidebars -->
        <div class="overlay"></div>
        <% DBConnect con = new DBConnect();
            try {
                con.getConnection();
                if (session.getAttribute("roles") == null) {
                    response.sendRedirect(host_string + "CommonJSP/signin.jsp");
                } else {
        %>
        <!-- #END# Overlay For Sidebars -->
        <nav class="navbar">
            <div class="container-fluid">
                <div class="navbar-header">
                    <a href="javascript:void(0);" class="navbar-toggle collapsed" data-toggle="collapse" data-target="#navbar-collapse" aria-expanded="false"></a>
                    <a href="javascript:void(0);" class="bars" style="display: block;"></a>
                    <a class="navbar-brand" href="widgets/../../index.html">CAMPS</a>
                </div>
                <div class="collapse navbar-collapse" id="navbar-collapse">
                    <ul class="nav navbar-nav navbar-right">                    
                        <!-- Notifications -->
                        <%
                            String data = "";
                            int count = 0;
                            con.read("SELECT nm.nm_id,nm.nm_title,nm.nm_desc,nm.nm_link,nm.trigger_type,nq.query,nm.trigger_type,CONCAT('\"title\":\"',nm.nm_title,'\",\"msg\":\"',nm.nm_desc,'\",\"url\":\"',nm.nm_link,'\"') DATA,nm.trigger_type FROM camps.notification_master nm LEFT JOIN camps.notification_specific ns ON nm.nm_id=ns.nm_id AND nm.nm_type=ns.nm_type AND (IF(ns.nm_type='role',ns.type_value='" + session.getAttribute("roles") + "' , ns.type_value='" + session.getAttribute("user_id") + "' ) )  LEFT JOIN (SELECT nh.nm_id,nh.user_id,MAX(nh.viewed_date)viewed_date,MAX(nh.delivery_date)delivery_date FROM camps.notification_history nh WHERE nh.user_id='" + session.getAttribute("user_id") + "' GROUP BY nh.nm_id)nh ON nh.nm_id=nm.nm_id  LEFT JOIN camps.notification_query nq ON nq.nm_id=nm.nm_id  WHERE  CASE WHEN nm.notify='once' THEN nh.nm_id IS NULL WHEN nm.notify='until view'  THEN nh.viewed_date IS NULL AND (nh.delivery_date IS NULL OR nh.delivery_date< NOW() - INTERVAL nm.repeat_after MINUTE)WHEN nm.notify='repeat'  THEN (nh.delivery_date IS NULL OR nh.delivery_date< NOW() - INTERVAL nm.repeat_after MINUTE) END AND nm.status>0");
                            while (con.rs.next()) {
                                if (con.rs.getString("trigger_type").equalsIgnoreCase("query")) {
                                    con.read1(con.rs.getString("query").replaceAll("__XXX__", session.getAttribute("userId").toString()));
                                    if (con.rs1.next()) {
                                        data += "<li><a href='" + con.rs.getString("nm_link") + "' class=' waves-effect waves-block'><div class='menu-info'><h4>" + con.rs.getString("nm_title") + "</h4><p>" + con.rs1.getString("qdesc") + "</p></div></a> </li>";
                                        count++;
                                    }
                                } else {
                                    data += "<li><a href='" + con.rs.getString("nm_link") + "' class=' waves-effect waves-block'><div class='menu-info'><h4>" + con.rs.getString("nm_title") + "</h4><p>" + con.rs.getString("nm_desc") + "</p></div></a> </li>";
                                    count++;
                                }

                            }
                        %>
                        <li class="dropdown">
                            <a href="javascript:void(0);"  class="dropdown-toggle" data-toggle="dropdown" role="button">
                                <i class="material-icons">notifications</i>
                                <span class="label-count"> <%=count%> </span>
                            </a>
                            <ul class="dropdown-menu">
                                <li class="header">NOTIFICATIONS</li>
                                <li class="body">
                                    <div class="slimScrollDiv" style="position: relative; overflow: hidden; width: auto; height: 254px;"><ul class="menu" style="overflow: hidden; width: auto; height: 254px;">
                                            <%=data%>  
                                        </ul><div class="slimScrollBar" style="background: rgba(0, 0, 0, 0.5) none repeat scroll 0% 0%; width: 4px; position: absolute; top: 0px; opacity: 0.4; border-radius: 0px; z-index: 99; right: 1px; display: block;"></div><div class="slimScrollRail" style="width: 4px; height: 100%; position: absolute; top: 0px; display: none; border-radius: 0px; background: rgb(51, 51, 51) none repeat scroll 0% 0%; opacity: 0.2; z-index: 90; right: 1px;"></div></div>
                                </li>
                                <li class="footer">
                                    <a href="javascript:void(0);" class=" waves-effect waves-block">View All Notifications</a>
                                </li>
                            </ul>
                        </li>
                        <li>
                            <div class="navbar-header">               
                                <div class="info-container">                    
                                    <div class="user-helper-dropdown">
                                        <i class="material-icons" data-toggle="dropdown" aria-haspopup="true" aria-expanded="true">  <div class="profile image">
                                                <%
                                                    if ("Student".equalsIgnoreCase(session.getAttribute("uType").toString())) {
                                                        con.read("SELECT TO_BASE64(sp.photo) photo FROM camps.student_photo sp WHERE sp.student_id='" + session.getAttribute("ss_id") + "' AND sp.status=1 ");
                                                    } else {
                                                        con.read("SELECT TO_BASE64(sp.photo) photo FROM camps.staff_photo sp WHERE sp.staff_id='" + session.getAttribute("ss_id") + "' AND sp.status=1 ");
                                                    }
                                                    //con.read("SELECT TO_BASE64(spv.photo)photo FROM staff_personal_copy spv WHERE spv.staff_id='"+session.getAttribute("userId")+"'");
                                                    if (con.rs.next()) {
                                                        out.print("<img src='data:image/jpeg;base64," + con.rs.getString("photo") + "' width='48' height='48' alt='User' />");
                                                    } else {
                                                        out.print("<img src='" + host_string + "images/user.png' alt='User' width='48' height='48'>");
                                                    }
                                                %>

                                            </div></i>
                                        <ul class="dropdown-menu ">
                                            <li> <div style="text-align: center;font-size: larger;color: #2196f3;"><% out.print(session.getAttribute("user_name").toString() + " (" + session.getAttribute("ss_id") + ")"); %></div></li>
                                            <li role="separator" class="divider"></li>

                                            <li role="separator" class="divider"></li>
                                            <li><a href="<%=host_string%>logout"><i class="material-icons">input</i>Sign Out</a></li>
                                        </ul>
                                    </div>
                                </div>
                            </div>

                        </li>

                        <!-- #END# Notifications -->

                    </ul>

                </div>
            </div>
        </nav>

        <section>
            <!-- Left Sidebar -->
            <aside id="leftsidebar" class="sidebar">
                <!-- User Info -->

                <!-- #User Info -->
                <!-- Menu -->
                <div class="menu">

                    <%
                        String hostname = request.getScheme() + "://" + request.getServerName() + ":" + request.getServerPort() + request.getContextPath() + "/";
                        menu menuobj = new menu();
                        out.println("<ul class=\"list\">" + menuobj.displaymenu(0, session.getAttribute("roles").toString(), hostname));
                    %>

                </div>
                <!-- #Menu -->
                <!-- Footer -->
                <div class="legal">
                    <div class="copyright">
                        <a href="javascript:void(0);">SDC BIT</a>.
                    </div>

                </div>
                <%  }
                    } catch (Exception e) {
                        out.print(e);
                    } finally {
                        con.closeConnection();
                    }
                %>
                <!-- #Footer -->
            </aside>
            <!-- #END# Left Sidebar -->
            <!-- Right Sidebar -->

            <!-- #END# Right Sidebar -->
        </section>