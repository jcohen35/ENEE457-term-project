# How to run:
## 1. Create a virtual environment on powershell/wsl
  - WSL:
    - python3 -m venv <environment name>
    - source <environment name>/bin/activate
  - Powershell:
    - python -m venv venv
    - .venv\bin\activate.ps1
## 2. Install Pycryptodome package if not done so already:
  - For WSL: python3 -m pip install <package name>
  - For Powershell: python -m pip install <package name>
## 3. Run server file first
## 4. Then run Client file on two different terminals to simulate two people talking to each other
  - On Powershell run ipconfig
    - Enter IPv4 address
  - On WSL run ifconfig
    - It will be the eth0 inet address

Now you should be able to send a message on one client, see the server read it, and see the message show up on the other client's side.

To disconnect, press Ctrl+C on the server terminal. We are working on disconnecting the client-side.
