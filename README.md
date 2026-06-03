# CatchCatchTV

A web-based CCTV monitoring system designed for secure, real-time surveillance.

**Live Link https://catchcatchtv.up.railway.app/login**

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

                                        ┌─────────────────────┐
                                        │       INTERNET      │
                                        └──────────┬──────────┘
                                                   │
                                                   │
                                  ┌────────────────┴────────────────┐
                                  │      ROUTER / INTERNET HUB      │
                                  │   Admin  │Passwword: [password] │
                                  └────────────────┬────────────────┘
                                                   │
                                                   │
                                  ┌────────────────┴────────────────┐
                                  │         NETWORK SWITCH          │      
                                  │                                 │
                                  └───┬──────────┬──────────┬───────┘
                                      │          │          │
                                      │          │          │

      ┌────────────┴────────────┐   ┌───────────┴───────────┐   ┌─────────────┴─────────────┐
      │     MAIN SYSTEM SERVER  │   │      POSTGRESQL       │   │       CCTV CAMERAS        │
      ├─────────────────────────┤   ├───────────────────────┤   ├───────────────────────────┤
      │ User Login Verification │   │ User Accounts         │   │ Live Video Feed           │
      │ User Dashboard          │   │ Camera Information    │   │ Surveillance Monitoring   │
      │ Camera Monitoring       │   │ Activity Logs         │   │ Security Observation      │
      │ Object Detection        │   │ Detection Records     │   └───────────────────────────┘
      │ Security Monitoring     │   │ Incident Reports      │
      │ Alert Generation        │   │ System Records        │
      └────────────┬────────────┘   └───────────┬───────────┘
                   │                            │
                   └──────────────┬─────────────┘
                                  │
                                  ▼

                    ┌─────────────────────────────────┐
                    │        SECURITY FEATURES        │
                    ├─────────────────────────────────┤
                    │ Login Protection                │
                    │ Suspicious Activity Detection   │
                    │ Unauthorized Access Blocking    │
                    │ User Session Protection         │
                    │ System Maintenance Controls     │
                    └─────────────────┬───────────────┘
                                      

                    ┌─────────────────────────────────┐
                    │        ALERT NOTIFICATION       │
                    │     Sends Security Warnings     │
                    └─────────────────┬───────────────┘
                                      │
                                      ▼

                    ┌─────────────────────────────────┐
                    │         DISCORD CHANNEL         │
                    │    Receives Real-Time Alerts    │
                    └─────────────────────────────────┘


      ┌─────────────────────────────────────────────────────────────┐
      │                         SYSTEM USERS                        │
      ├─────────────────────────────────────────────────────────────┤
      │ Administrator                                               │
      │ Security Personnel                                          │
      │ Authorized Users                                            │
      │                                                             │
      │ Login → View Cameras → Monitor Activity → Receive Alerts    │
      └─────────────────────────────────────────────────────────────┘

'''
      <img width="445" height="591" alt="Screenshot_13" src="https://github.com/user-attachments/assets/cfefb092-50a9-42ea-818a-5a0380e1a2fa" />
      <img width="1919" height="895" alt="f70e7d92-1bfa-440d-8e4a-143fc18a42b7 (1)" src="https://github.com/user-attachments/assets/eba59908-8958-4593-a9dc-a2a09c64c22b" />
      <img width="1919" height="895" alt="bac203c4-2062-42ef-9a2e-f6bb5a9d9f07" src="https://github.com/user-attachments/assets/1a9566f1-4ae3-4345-99df-db3f346075fd" />










