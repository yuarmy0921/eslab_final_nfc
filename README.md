# ESLAB Final - Mimicking Self-driving Cars (NFC + Wifi)

## Overview
- BL475E-IOT01A board reads the value in NFCEEPROM and sends it to the server by wi-fi

## Settings
![image](https://user-images.githubusercontent.com/55664878/174324823-2a23e468-1505-4de9-9485-2997f5c7c541.png)
- Revise "nsapi.default-wifi-ssid" and "nsapi.default-wifi-password" to your wi-fi AP at lines 14 and 15 of mbed_app.json

![image](https://user-images.githubusercontent.com/55664878/174325206-3c94e842-6a94-4d91-b6ba-695463c91207.png)
- Revise HOSTNAME to your server ip at line 49 of source/main.cpp

![image](https://user-images.githubusercontent.com/55664878/174326271-9347d530-dd6b-4a9d-8886-4fcd3540e5fc.png) \

- Install the board to the car as what presented above
- Connect the board and Raspberry Pi by a typeA-USB cable

## Usage
- Open your server and wait for the board connecting to it
- If the board haven't connected for a long time, click the RESET button on the board and try again

