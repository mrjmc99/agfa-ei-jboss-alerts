install:
e:
cd E:\software\
git clone https://github.com/mrjmc99/agfa-ei-jboss-alerts
copy /y \\fhovapppacms001\e$\Software\agfa-ei-jboss-alerts\jboss-check-config.ini e:\Software\agfa-ei-jboss-alerts\jboss-check-config.ini
schtasks /end /tn "Check Jboss Status"
schtasks /delete /tn "Check Jboss Status" /f
schtasks /create /ru "NT AUTHORITY\SYSTEM" /sc ONSTART /tr "'C:\Program Files\Python311\python.exe' E:\software\agfa-ei-jboss-alerts\jboss-check.py" /tn "Check Jboss Status"
schtasks /run /tn "Check Jboss Status"

switch to dev:
e:
cd E:\software\agfa-ei-jboss-alerts
git pull
git switch dev
schtasks /end /tn "Check Jboss Status"
schtasks /run /tn "Check Jboss Status"

switch to main:
e:
cd E:\software\agfa-ei-jboss-alerts
git pull
git switch main
schtasks /end /tn "Check Jboss Status"
schtasks /run /tn "Check Jboss Status"