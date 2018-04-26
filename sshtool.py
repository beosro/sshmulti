#!/usr/bin/env python3
"""
This script is designed to perform SSH operations to a list of hosts via
multithreading.  Mulitple threads work well for this tool because most of the
time is waiting (GIL doesn't limit us much for this type of I/O heavy application).

Examples:

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

Arguments:

Username - required
config_file - required, JSON, a list of remote host IPs to try and connect to
password - Optional, if supplied the tool will use username/password instead of public key auth
remote_file - If you want to GET or PUT a file, you need to specify the path on the remote hosts
install_file - If you want to PUT a file to remote IPs, supply this path to the local file.
    install_file and local_file are mutually exclusive!
local_file - If you want to GET a file, this is where the file goes on the local machine.
remote_command - Specify this to have your remote command run on every host ip.

Outputs:  All output is sent to stdout, it can be captured and redirected as needed.

The list of IP's to process is JSON, stored in ./config.json

Authors:  Chris Gleeson, 2018.
"""
import os
import sys
import json
import copy
import getopt
import datetime
import subprocess
import paramiko
from scp import SCPClient
from multiprocessing.dummy import Pool as ThreadPool

def usage():
    """
    Prints usage for sshtool.py
    """
    print('Usage: sshtool.py [-h] -c <config_file> -u username [-p password -i <install_file> -r <remote_file> -l <local_file> -k <remote_command>]')
    print('Usage: config_file must be valid JSON.')


def parse_args():
    """
    Parses input arguments and returns them to main.

    Exits on any raised exception or if any required arguments are missing.
    """
    config_file = ''
    install_file = ''
    remote_file = ''
    local_file = ''
    remote_command = ''
    username = ''
    password = ''

    #Attempt to parse args
    try:
        opts, args = getopt.getopt(sys.argv[1:],"hc:u:p:i:r:l:k:",["help","config_file=","username=","password=","install_file=","remote_file=","local_file=","remote_command="])
    except getopt.GetoptError as err:
        print(err)
        usage()
        sys.exit(2)

    #Populate local variables from args
    for opt, arg in opts:
        if opt in ("-h", "--help"):
            usage()
            sys.exit()
        elif opt in ("-c", "--config_file"):
            config_file = arg
            if not os.access(config_file, os.R_OK):
                print('ERROR: config_file not specified, or is not readable!  Exiting...')
                usage()
                sys.exit()
        elif opt in ("-u", "--username"):
            username = arg
        elif opt in ("-p", "--password"):
            password = arg
        elif opt in ("-i", "--install_file"):
            install_file = arg
            if not os.access(install_file, os.R_OK):
                print('ERROR: install_file not specified or does not exist!  Exiting...')
                usage()
                sys.exit()
        elif opt in ("-r", "--remote_file"):
            remote_file = arg
        elif opt in ("-l", "--local_file"):
            local_file = arg
        elif opt in ("-k", "--remote_command"):
            remote_command = arg

    return (config_file, username, password, install_file, remote_file, local_file, remote_command)


def create_config_object(filepath):
    """
    Takes a string that holds a file path and attempts to read the file and
    parse the file as JSON.

    Returns:  Parsed json object via json.loads()

    Rasies:  IOError if the file cannot be read, TypeError on bad Type,
    ValueError on failed parsing.
    """
    try:
        json_raw = open(filepath).read()
        json_object = json.loads(json_raw)
    except IOError as err:
        print("Error:  Failed to open file %s!  Exiting..." % filepath)
        raise
    except TypeError as err:
        print("Error: Parsing of file %s failed!  Exiting..." % filepath)
        raise
    except ValueError as err:
        print("Error: Parsing of file %s failed!  Exiting..." % filepath)
        raise
    return json_object


def preview_targets(config):
    print("Preview:  The following addresses are targets of this operation...")
    i = 0
    for ip in config:
        i += 1
        print("Target %s: %s" % (i,ip))
    print("Preview:  Found a total of %s targets.  Proceeding." % i)


def ssh_cmd_key(ip, username, cmd):
    """
    Returns a tuple containing (stdout, stderr) from the command that was run.

    Authentication:  Public key.

    Runs a remote command over SSH.
    """
    commands = ['ssh', '-oBatchMode=yes', '-oStrictHostKeyChecking=no', '-oConnectTimeout=1', username+'@'+ip, cmd]
    ssh = subprocess.Popen(commands, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    error = ssh.stderr.readlines()
    ssh.communicate()[0]
    code = ssh.returncode
    return (result, error, code)


def putfile_key(ip, username, install_file, remote_file):
    """
    Returns:  Boolean True for success, False for fail.

    Copies (via scp) the local file to the remote path specified by remote_file.

    Authentication:  Public key.

    Copies the local install_file to the path at remote_file on the remote host via
    SCP.
    """
    commands = ['scp', '-oBatchMode=yes', '-oStrictHostKeyChecking=no', '-oConnectTimeout=1', install_file, username+'@'+ip+':'+remote_file]
    ssh = subprocess.Popen(commands, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    error = ssh.stderr.readlines()
    ssh.communicate()[0]
    code = ssh.returncode
    if code == 0:
        return True
    else:
        return False


def getfile_key(ip, username, remote_file, local_file):
    """
    Returns:  Boolean True for success, False for fail.

    Copies (via scp) the local file to the remote path specified by remote_file.

    Authentication:  Public key.

    Copies the remote remote_file to the path at local_file on the local machine.
    """
    commands = ['scp', '-oBatchMode=yes', '-oStrictHostKeyChecking=no', '-oConnectTimeout=1', username+'@'+ip+':'+remote_file, local_file]
    ssh = subprocess.Popen(commands, shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    result = ssh.stdout.readlines()
    error = ssh.stderr.readlines()
    ssh.communicate()[0]
    code = ssh.returncode
    if code == 0:
        return True
    else:
        return False


def ssh_cmd_up(ip, username, password, cmd):
    """
    Returns a tuple containing (stdout, stderr) from the command that was run.

    Authentication:  Username/Password

    Runs a remote command over SSH via username/password based auth, auto-accepts
    unknown keys!
    """
    try:
        ssh = paramiko.SSHClient()
        #This option is dangerous:  We auto accept unknown keys.
        #This gets around the prompt, necessary, but never do this unless you trust
        #the host you are connecting to!
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        stdin, stdout, stderr = ssh.exec_command(cmd)
        status = stdout.channel.recv_exit_status()
        stdout = stdout.readlines()
        stderr = stderr.readlines()
        ssh.close()
        return (stdout,stderr,status)
    except:
        return ("error", "error", 255)


def putfile_up(ip, username, password, install_file, remote_file):
    """
    Returns:  Boolean True for success, False for fail.

    Authentication:  Username/Password

    Copies the local install_file to the path at remote_file on the remote host via
    SCP, auto-accepts unknown keys!
    """
    try:
        ssh = paramiko.SSHClient()
        #This option is dangerous:  We auto accept unknown keys.
        #This gets around the prompt, necessary, but never do this unless you trust
        #the host you are connecting to!
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(ssh.get_transport())
        scp.put(install_file, remote_file)
        scp.close()
        return True
    except:
        return False


def getfile_up(ip, username, password, remote_file, local_file):
    """
    Returns:  Boolean True for success, False for fail.

    Authentication:  Username/Password

    Copies the remote remote_file to the path at local_file on the local machine.
    """
    try:
        ssh = paramiko.SSHClient()
        #This option is dangerous:  We auto accept unknown keys.
        #This gets around the prompt, necessary, but never do this unless you trust
        #the host you are connecting to!
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(ip, username=username, password=password)
        # SCPCLient takes a paramiko transport as its only argument
        scp = SCPClient(ssh.get_transport())
        scp.get(remote_file, local_file)
        scp.close()
        return True
    except:
        return False


def ssh_actions_key(host_map):
    #ssh_actions_key(ip, username, install_file, remote_file, local_file, remote_command):
    """
    Performs a remote SSH command or file push (or both) to the ip passed in.

    Authentication:  Public key.

    Returns:  Nothing, all output is sent to stdout.
    """
    #parse data/parameters from the host map
    ip = host_map["ip"]
    username = host_map["username"]
    install_file = host_map["install_file"]
    remote_file = host_map["remote_file"]
    local_file = host_map["local_file"]
    remote_command = host_map["remote_command"]

    #Prep return list:  A list of statements we would have printed, to be
    #printed later in sequence.  Else the multithreading causes thread output
    #to occur in a random sequence to stdout.
    messages = []
    messages.append("\n")

    #Print an update at the beginning just so we know stuff is happening
    print("\nRun:  Beginning actions against ip:", ip)

    messages.append("Run:  Authentication mode:  Key Based Authentication.")
    messages.append("Run:  Connecting to: " + ip)
    if install_file != "":
        put_result = putfile_key(ip, username, install_file, remote_file)
        if put_result == False:
            messages.append("Run:  Error attempting to install " + install_file + " to path " + remote_file + " on " + ip + " Investigate SSH keys!")
            messages.append("Run:  Possible failures:  IP unreachable, key incorrect, SSH disabled")
        else:
            messages.append("Run:  Successfully installed " + install_file + " to path " + remote_file + " on " + ip)
    elif local_file != "":
        get_result = getfile_key(ip, username, remote_file, local_file)
        if get_result == False:
            messages.append("Run:  Error attempting to fetch " + remote_file + " from ip " + ip + " to local path " + local_file + " Investigate SSH keys!")
            messages.append("Run:  Possible failures:  IP unreachable, key incorrect, SSH disabled")
        else:
            messages.append("Run:  Successfully copied " + remote_file + " from ip " + ip + " to local path " + local_file)
    if remote_command != "":
        (ssh_result, ssh_error, ssh_code) = ssh_cmd_key(ip, username, remote_command)
        if ssh_code == 0:
            #success
            messages.append("Run:  Remote command " + remote_command + " successful on ip " + ip + ". Command returns:")
            for line in ssh_result:
                line = line.strip()
                decoded = line.decode('UTF-8')
                messages.append(decoded)
        else:
            messages.append("Run:  Remote command " + remote_command + " FAILED on ip " + ip)
            messages.append("Run:  Possible failures:  IP unreachable, key incorrect, SSH disabled.")
            messages.append("Run:  SSH std output:")
            for line in ssh_result:
                line = line.strip()
                decoded = line.decode('UTF-8')
                messages.append(decoded)
            messages.append("Run:  SSH ERR output:")
            for line in ssh_error:
                line = line.strip()
                decoded = line.decode('UTF-8')
                messages.append(decoded)
            messages.append("Run:  SSH return code was: " + str(ssh_code))
    print("Run:  Completed actions against ip:", ip)
    messages.append("Run:  Completed actions for: " + ip)
    return messages

def ssh_actions_up(host_map):
    """
    Performs a remote SSH command or file push (or both) to the ip passed in.

    Authentication:  Username/Password

    Returns:  Nothing, all output is sent to stdout.
    """
    #parse data/parameters from the host map
    ip = host_map["ip"]
    username = host_map["username"]
    password = host_map["password"]
    install_file = host_map["install_file"]
    remote_file = host_map["remote_file"]
    local_file = host_map["local_file"]
    remote_command = host_map["remote_command"]

    #Prep return list:  A list of statements we would have printed, to be
    #printed later in sequence.  Else the multithreading causes thread output
    #to occur in a random sequence to stdout.
    messages = []
    messages.append("\n")
    #list.append is thread safe, but if you wanted a shared object:  https://docs.python.org/3.6/library/queue.html

    messages.append("Run:  Authentication mode:  Username/Password Based Authentication.")
    messages.append("Run:  Connecting to: " + ip)
    if install_file != "":
        put_result = putfile_up(ip, username, password, install_file, remote_file)
        if put_result == False:
            messages.append("Run:  Error attempting to install " + install_file + " to path " + remote_file + " on " + ip + " Investigate SSH keys!")
            messages.append("Run:  Possible failures:  IP unreachable, username/password incorrect, SSH disabled")
        else:
            messages.append("Run:  Successfully installed " + install_file + " to path " + remote_file + " on " + ip)
    elif local_file != "":
        get_result = getfile_up(ip, username, password, remote_file, local_file)
        if get_result == False:
            messages.append("Run:  Error attempting to fetch " + remote_file + " from ip " + ip + " to local path " + local_file + " Investigate SSH keys!")
            messages.append("Run:  Possible failures:  IP unreachable, username/pasword incorrect, SSH disabled")
        else:
            messages.append("Run:  Successfully copied " + remote_file + " from ip " + ip + " to local path " + local_file)
    if remote_command != "":
        (ssh_result, ssh_error, ssh_code) = ssh_cmd_up(ip, username, password, remote_command)
        if ssh_code == 0:
            #success
            messages.append("Run:  Remote command " + remote_command + " successful on ip " + ip + ". Command returns:")
            for line in ssh_result:
                line = line.strip()
                messages.append(line)
        else:
            messages.append("Run:  Remote command " + remote_command + " FAILED on ip " + ip)
            messages.append("Run:  Possible failures:  IP unreachable, username/password incorrect, SSH disabled.")
            messages.append("Run:  SSH std output:")
            for line in ssh_result:
                line = line.strip()
                messages.append(line)
            messages.append("Run:  SSH ERR output:")
            for line in ssh_error:
                line = line.strip()
                messages.append(line)
            messages.append("Run:  SSH return code was: " + str(ssh_code))
    messages.append("Run:  Completed actions for: " + ip)
    return messages


def thread_mapper_key(config, username, install_file, remote_file, local_file, remote_command):
    """
    Launches multiple worker threads to process work in "parallel".

    Authentication:  Key based.

    Returns:  A list of results from the method called.
    """
    #pool.map requires a single iterable, so I have to build a list of dicts
    #and pass that to the mapper, which then maps the items as input arguments
    #to the method call
    host_map = {}
    host_map["username"] = username
    host_map["install_file"] = install_file
    host_map["remote_file"] = remote_file
    host_map["local_file"] = local_file
    host_map["remote_command"] = remote_command
    host_list = []
    results = []

    for ip in config:
        new_host_map = copy.copy(host_map)
        new_host_map["ip"] = ip
        host_list.append(new_host_map)

    # Make a Pool of workers
    try:
        pool = ThreadPool(16)
        results = pool.map(ssh_actions_key, host_list)
        #close the pool and wait for the work to finish
        pool.close()
        pool.join()
    except:
        print("ThreadPool EXCEPTION! Shutting down.")
        print(sys.exc_info()[0])
        raise
    return results


def thread_mapper_up(config, username, password, install_file, remote_file, local_file, remote_command):
    """
    Launches multiple worker threads to process work in "parallel".

    Authentication:  Username/Password

    Returns:  A list of results from the method called.
    """
    #pool.map requires a single iterable, so I have to build a list of dicts
    #and pass that to the mapper, which then maps the items as input arguments
    #to the method call
    host_map = {}
    host_map["username"] = username
    host_map["password"] = password
    host_map["install_file"] = install_file
    host_map["remote_file"] = remote_file
    host_map["local_file"] = local_file
    host_map["remote_command"] = remote_command
    host_list = []

    for ip in config:
        new_host_map = copy.copy(host_map)
        new_host_map["ip"] = ip
        host_list.append(new_host_map)

    # Make a Pool of workers
    pool = ThreadPool(16)
    results = pool.map(ssh_actions_up, host_list)
    #close the pool and wait for the work to finish
    pool.close()
    pool.join()
    return results

def main():
    #Run begins
    print("\n**********SSHTOOL BEGIN RUN**********")

    #Parse args and populate file references
    (config_file, username, password, install_file, remote_file, local_file, remote_command) = parse_args()

    #INFO statements
    print('INFO: sshtool is starting...')
    print('INFO: Config file is: ', config_file)

    #Parse config file
    config = create_config_object(config_file)

    #Preview targets
    preview_targets(config)

    #SSH actions
    #Logic here:  We know ahead of time if we are using Key or User/Pwd based auth
    #based on looking at the password argument (see usage).
    if password == "":
        print("\nRun:  Configuring for SSH via key based auth...")
        output = thread_mapper_key(config, username, install_file, remote_file, local_file, remote_command)
    else:
        print("\nRun:  Configuring for SSH via username/password auth...")
        output = thread_mapper_up(config, username, password, install_file, remote_file, local_file, remote_command)

    #Format and print the stored output messages from each run in order.
    for run in output:
        print('\n'.join(run))

    #Run is complete
    print("\n**********SSHTOOL RUN FINISHED**********")

if __name__ == "__main__":
    main()
