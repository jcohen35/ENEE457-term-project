# How to run:
## 1. Create a virtual environment on PowerShell/WSL
  - WSL:
    - python3 -m venv <environment name>
    - source <environment name>/bin/activate
  - PowerShell:
    - python -m venv venv
    - .venv\bin\activate.ps1
## 2. Install the Pycryptodome package if not done so already:
  - For WSL: python3 -m pip install pycryptodome
  - For PowerShell: python -m pip install pycryptodome
## 3. Run the Server file first
  - To run:
    - WSL: python3 server.py
    - PowerShell: python server.py
## 4. Then run the Client file on two separate terminals to simulate two people talking to each other
  - On PowerShell, run ipconfig
    - Enter IPv4 address
  - On WSL, run ifconfig
    - It will be the eth0 inet address


Now you should be able to send a message on one client, watch the server read it, and see the message show up on the other client's side.


## To disconnect: 
  - Press Ctrl+C on the server terminal. We are working on disconnecting the client-side.
