1. Start the client using `python3 client.py`.
2. Start the server using `python3 server.py`.
3. The client and the server will exchange messages.
4. The client and the server will print the generated keys.

Settings like host and port can be changed using arguments. 

```bash
python3 client.py PORT TARGETPORT HOST TARGETHOST
python3 server.py PORT CLIENTPORT HOST TARGETHOST
```

Changing the default settings shouldn't be required.