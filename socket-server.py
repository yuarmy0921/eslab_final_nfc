#!/usr/bin/env python3

import socket
import json
import numpy as np
import matplotlib.pyplot as plot
<<<<<<< HEAD
HOST = '192.168.50.166' # IP address
PORT = 8080 # Port to listen on (use ports > 1023)
t_axis = []
x_plot = []
y_plot = []
z_plot = []
gx_plot = []
gy_plot = []
gz_plot = []
=======
HOST = '192.168.50.226' # IP address
PORT = 6531 # Port to listen on (use ports > 1023)
>>>>>>> 4ebfb68e2e924ad97a91bfab53c02907bc8ed848
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((HOST, PORT))
    s.listen()
    print("Starting server at: ", (HOST, PORT))
    conn, addr = s.accept()
    x = []
    y = []
    z = []
    gx = []
    gy = []
    gz = []
    with conn:
        print("Connected at", addr)
<<<<<<< HEAD
        #conn.send(b'1')
        while True:
            data = conn.recv(1024).decode('utf-8', errors='ignore')
            #print(unicode(data, errors='replace'))
            print("Received from socket server:", data)
            
        
=======
        conn.send(b'1')
        k = 0
        while len(x) < 200:
            data = conn.recv(1024).decode('utf-8', errors='ignore')
            #print(unicode(data, errors='replace'))
            print("Received from socket server:", data)
            if (data.count('{') != 1):
            # Incomplete data are received.
            # Some codes here
                continue
            obj = json.loads(data)
            x += [obj['x']]
            y += [obj['y']]
            z += [obj['z']]
            gx += [obj['gx']]
            gy += [obj['gy']]
            gz += [obj['gz']]
            k += 1
            
            
        plot.figure(1)
        plot.scatter(range(200), x, c='red', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("x")

        plot.figure(2)
        plot.scatter(range(200), y, c='orange', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("y")
        
        plot.figure(3)
        plot.scatter(range(200), z, c='green', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("z")
        
        plot.figure(4)
        plot.scatter(range(200), gx, c='blue', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("gx")

        plot.figure(5)
        plot.scatter(range(200), gy, c='purple', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("gy")

        plot.figure(6)
        plot.scatter(range(200), gz, c='black', s=2) # x, y, z, gx, gy, gz
        plot.xlabel("sample num")
        plot.ylabel("gz")
        
        plot.show()
>>>>>>> 4ebfb68e2e924ad97a91bfab53c02907bc8ed848
