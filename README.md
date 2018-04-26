# sshmulti
A multi-threaded ssh tool for pushing or pulling files via SCP and running remote commands via SSH.

This script is designed to perform SSH operations to a list of hosts.

Installation:    
Host machine needs a full python/python3 dev environment:    
sudo apt-get install build-essential libssl-dev libffi-dev python-dev python3-dev

Prep to run the tool (do this only once per install):    
virtualenv -p /usr/bin/python3 ./.env    
source .env/bin/activate    
pip install -r ./requirements.txt    

Do this once per shell session (post install):    
source .env/bin/activate    

Run the tool:    
Key based auth mode (simply omit the pasword):    
./sshtool.py -c ./config.json -u 'tc' -i ./tempfile.txt -r /home/tc/tempfile.txt -k 'ls -la /home/tc/tempfile.txt'    

Username/Password based auth mode (include the password):    
./sshtool.py -c ./config.json -u 'tc' -p "Admin123" -i ./tempfile.txt -r /home/tc/tempfile.txt -k 'ls -la /home/tc/tempfile.txt'    

The list of IP's to process is JSON, stored in ./config.json    

Authors:  Chris Gleeson + open source code scp.py from: https://github.com/randomInteger/scp.py
I am not the original author of the code in scp.py, please see the fork above...
All other code besides imports is original.

Multithreading:    

This tool is multithreaded.  Despite Python's GIL preventing true concurrency,
operations which incur a substantial wait time can be massively sped up by this approach.

Timing tests:

8 threads, 5 targets, success:    
real	0m0.849s    
user	0m0.340s    
sys	0m0.052s    

8 threads, 5 targets, failure:    
real	0m6.347s    
user	0m0.224s    
sys	0m0.036s    

1 threads, 5 targets, success:    
real	0m2.634s    
user	0m0.388s    
sys	0m0.040s    

1 threads, 5 targets, failure:    
real	0m30.321s    
user	0m0.284s    
sys	0m0.024s    

Results:  As expected, because much of the time involved in these operations is waiting for SSH to respond,
if we set max threads >= the number of targets, there is a massive speed increase.

Further increasing the max thread limit above the number of targets does nothing, also as expected.

The default is 16 threads can run at any one time.  You can change this value
by finding both instances of "ThreadPool(16)" and changing both to a new value.
