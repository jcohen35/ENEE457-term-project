# How to run:
## 1. Create a virtual environment on PowerShell/WSL
  - WSL:
    - ```python3 -m venv <environment name>```
    - ```source <environment name>/bin/activate```
  - PowerShell:
    - ```python -m venv <environment name>```
    - ```.\<environment name>\bin\activate.ps1```
  - To deactivate virtual environment for both:
    - ```deactivate```
## 2. Install the Pycryptodome package if not done so already
  - For WSL: ```python3 -m pip install pycryptodome```
  - For PowerShell: ```python -m pip install pycryptodome```
## 3. Run the Server file first
  - To run (You can use WSL when working locally; however, it's best to use PowerShell for the project when testing, as WSL is a virtual interface):
    - WSL: ```python3 server.py```
    - PowerShell: ```python server.py```
## 4. Then run the Client file on two separate terminals to simulate two people talking to each other
  - The clients will need the server's IP address
    - On PowerShell, run ```ipconfig```
      - Enter IPv4 address
    - On WSL, run ```ifconfig```
      - It will be the eth0 inet address
     

## Testing
Now you should be able to send a message to one client, watch the server read it, and see the message appear on the other client's side. Each client will be able to talk to the other locally or over the same network on different machines using PowerShell.

## To disconnect
  - Press Ctrl+C on the server terminal. We are working on disconnecting the client-side.
