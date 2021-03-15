#Pivoting

## Windows

### Kali PORT -> WIN -> Victim NW PORT

* Check IP Helper Service is running and IPV6 must be enabled for the interface

```cmd
C:\Windows\system32> netsh interface portproxy add v4tov4 listenport=4455 listenaddress=10.11.0.22 connectport=445 connectaddress=192.168.1.110
## update firewall settings
C:\Windows\system32> netsh advfirewall firewall add rule name="forward_port_rule" protocol=TCP dir=in localip=10.11.0.22 localport=4455 action=allow
```

Check
```cmd
netstat -anp TCP | find "4455" 
```
Nice summary of the oscp slides
https://sushant747.gitbooks.io/total-oscp-guide/content/port_forwarding_and_tunneling.html
