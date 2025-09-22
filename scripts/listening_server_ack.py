import socket, sys
s=socket.socket()
s.bind(('127.0.0.1',40001))
s.listen(1)
print("Server listening on 127.0.0.1:40001")
c,a=s.accept()
print("conn from", a)
try:
    while True:
        data=c.recv(4096)
        if not data:
            break
        print("recv:", data[:100])
        c.send(b"ACK:"+data[:10])
finally:
    c.close(); s.close()
