# CatchCatchTV

A web-based CCTV monitoring system designed for secure, real-time surveillance.

**Deployment Link https://catchcatchtv.up.railway.app/login**

## Core Features
* **Secure Access & Authentication** - allows user to autheticate using their username or email
* **System Alerts & Logs** - records the IP address, the time of log, and detection of the guest using the system
* **Real-time Surveillance Monitoring** - allows connection to a cctv by pasting the stream url in the settings
* **AI Object Detection (toggleable)** - object and range AI detection
* **Monitoring Dashboard for User Stream Management** - allows admin to oversee all the users streaming camera
* **IP Blocking & Role Assignment** - suspicious account may be blocked by the admin, and the role of a guest may be upgraded to admin
* **Automated Alerts for Discord** - allows user to link the system logs to their discord
* **Custom Nickname Display** - user may customize their preferred nickname to appear in the system

##  Setup Instructions

**1. Extract the project**
- Download the ZIP
- Extract the project and locate the project files including the main.py and requirements.txt

**2. Open the Command Propmt (CMD)**
- click the address bar in the file explorer that says "C:Users\...", type cmd, then hit Enter. This shall launch the terminal of the folder directly.

**3. Install Required Libraries**
- Run the command below in order to install all necessary Pythong dependencies:

```Terminal Bash
pip install -r requirements.txt
```

**4. Configure Environment file**
- Locate the file named .env.example
- rename it as .env

**5. Database Initialization**
- Open the file db_setup.sql and copy its entire content.
- Open pgAdmin 4 (Postgre or preferred SQL tool), open the Query Tool, paste the copied script, and run the content in order to set up the tables.

**6. Launching the System**
- Run the system once the installation is completed and the database is prepared.

```Terminal Bash
python main.py
```







