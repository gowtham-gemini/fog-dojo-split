
UPDATE mail_template
SET content='<div class="mainarea" style="width:600px; height:auto; float:left; border:1px solid #ececec;"><div class="maincontent" style="width:550px; height:auto; float:left; margin:15px 0 0 22px; padding:0 0 15px 0;"><h1 style="font-family:Arial,Helvetica,sans-serif;font-size:21px;font-weight:normal;color:#ea5800;margin:0;padding:0;height:auto;width:400px"><i><b>Ticket Info<br /></b></i></h1><h2 style="font-family:Arial,Helvetica,sans-serif;font-size:17px;font-weight:bold;color:#666;margin:15px 0 0 0;padding:0;height:auto;width:400px">Hello [userName] ,</h2><p style="font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:normal;color:#333;margin:15px 0 0 0;padding:0;height:auto;width:550px">[ticketStatus] Given below is ticket info<br />Ticket Id: [ticketId]<br />Department: [department]<br />status: [status]<br />Subject:[subject]<br />Priority:[priority]<br />Content:[content]<br />Posted Date:[postedDate]<br />Regards,</p><p style=" font-weight: bolder; font-family:Arial,Helvetica,sans-serif;font-size:13px;font-weight:normal;color:#333;margin:15px 0 0 0;padding:0;height:auto;width:550px"><b>[signature]</b></p></div><div><b></b></div></div>'
WHERE id= 31;



