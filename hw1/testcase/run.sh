sh clean.sh && ./launcher ./sandbox.so config-example.txt cat /etc/passwd
sh clean.sh && ./launcher ./sandbox.so config-example.txt cat /etc/hosts
sh clean.sh && ./launcher ./sandbox.so config-example.txt cat /etc/ssl/certs/Amazon_Root_CA_1.pem
sh clean.sh && ./launcher ./sandbox.so config-example.txt wget http://google.com -t 1
sh clean.sh && ./launcher ./sandbox.so config-example.txt wget https://www.nycu.edu.tw -t 1
sh clean.sh && ./launcher ./sandbox.so config-example.txt wget http://www.google.com -q -t 1
sh clean.sh ./launcher ./sandbox.so config-example.txt python3 -c 'import os;os.system("wget http://www.google.com -q -t 1")'

sh clean.sh && ./launcher ./sandbox.so config.txt cat /tmp/testfile ; ./launcher ./sandbox.so config.txt cat /etc/passwd ; ./launcher ./sandbox.so config.txt cat /etc/hosts
sh clean.sh && ./launcher ./sandbox.so config.txt wget http://google.com/ -t 1 -o /dev/null ; ./launcher ./sandbox.so config.txt wget http://linux.cs.nctu.edu.tw ; ./launcher ./sandbox.so config.txt wget https://freebsd.cs.nctu.edu.tw
sh clean.sh && ./launcher ./sandbox.so config.txt ./case3
