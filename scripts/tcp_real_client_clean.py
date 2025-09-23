import socket
s=socket.socket()
s.connect(('127.0.0.1',40001))
s.send(b"msg0")
s.send(b"msg1")
s.send(b"msg2")
resp = s.recv(1024)
print("resp:", resp)
s.close()