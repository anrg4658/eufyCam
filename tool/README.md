This guide outlines the verification steps using the **eufyCam E40 2-Cam Kit (HomeBase 2)** as the primary example.

---

## 1. Device Pairing
1. **Register a eufy Account**: Create a new account via the eufy app.
2. **Bind HomeBase 2**: Follow the in-app "Add Device" instructions to pair the HomeBase 2.
3. **Bind First E40**: Follow the in-app instructions to pair one E40 camera to the HomeBase 2.
4. **Bind Second E40**: Follow the in-app instructions to pair the second E40 camera directly to the router.
5. **Verify Connection**: Confirm both devices are successfully bound and can stream video normally.

## 2. Environment Configuration
1. **Install Python**: Set up the Python runtime environment on your PC from [python.org](https://www.python.org/) and install pip using the command: `python -m ensurepip --default-pip`.
2. **Install Dependencies**: Execute the following command:
   `pip install pycryptodome opencv-python pillow`
3. **Prepare Tools**: Copy all files from the `tools` directory to your PC.

## 3. Exploitation Implementation
1. **Network Check**: Ensure your PC is on the same subnet as the eufy devices and confirm your PC's local IP address.
2. **Scan for Devices**: 
   * Run `GetSNGUI.py`.
   * Enter your local network's **Broadcast Address** (e.g., if your PC's local IP is `192.168.0.2`, use `192.168.0.255`) and click **Start Scan**.
   * The tool will display the IP:Port and SN for the HomeBase and cameras.
   * Select the camera row and click **Copy Selected SN**.
3. **Retrieve Account ID**: 
   * Run `GetAccountGUI.py`.
   * Paste the SN into the **Station SN** field and enter the camera's IP in the **Target IP** field.
   * Click **Start Scan**, then click **Copy** after the Account ID detected.
4. **Generate RTSP URL**: 
   * Run `GetRTSP.py`.
   * Paste the **Account ID**, paste the **HomeBase SN** found in Step 2, and enter the **HomeBase IP**.
   * Click **Scan & Retrieve**; an address will appear in the **RTSP Stream URL** field. Click **Copy URL**.
5. **View Live Stream**: 
   * Run `rtspPlayer.py`, paste the RTSP URL, and click **Play**.
   * You should now see the real-time feed from the E40 camera that is bound to the HomeBase 2.
