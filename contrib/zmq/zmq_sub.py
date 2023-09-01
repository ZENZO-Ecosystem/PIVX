#!/usr/bin/env python

import array
import binascii
import zmq
import struct

port = 28332

zmqContext = zmq.Context()
zmqSubSocket = zmqContext.socket(zmq.SUB)
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"hashtxlock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawblock")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtx")
zmqSubSocket.setsockopt(zmq.SUBSCRIBE, b"rawtxlock")
zmqSubSocket.connect("tcp://127.0.0.1:%i" % port)

try:
    while True:
        msg = zmqSubSocket.recv_multipart()
        topic = str(msg[0].decode("utf-8"))
        body = msg[1]
        sequence = "Unknown";

        if len(msg[-1]) == 4:
          msgSequence = struct.unpack('<I', msg[-1])[-1]
          sequence = str(msgSequence)

        if topic == "hashblock":
            print('- HASH BLOCK ('+sequence+') -')
            print(body.hex())
        elif topic == "hashtx":
            print ('- HASH TX ('+sequence+') -')
            print(body.hex())
        elif topic == "hashtxlock":
            print('- HASH TX LOCK ('+sequence+') -')
            print(body.hex())
        elif topic == "rawblock":
            print('- RAW BLOCK HEADER ('+sequence+') -')
            print(body.hex())
        elif topic == "rawtx":
            print('- RAW TX ('+sequence+') -')
            print(body.hex())
        elif topic == "rawtxlock":
            print('- RAW TX LOCK ('+sequence+') -')
            print(body.hex())

except KeyboardInterrupt:
    zmqContext.destroy()
