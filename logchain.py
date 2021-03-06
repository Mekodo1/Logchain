import hashlib
import time
import json
import math
import socket
import _thread
from argparse import ArgumentParser
import nacl.encoding
import nacl.signing


class Blockchain:
  def __init__(self, ip=None, port=9999, node_ip=None, node_port=None):
    self.ip = socket.gethostbyname(socket.gethostname())
    if ip != None:
      self.ip = ip
    self.port = port
    self.init_node = [[node_ip, node_port]]

    self.avg_block_time    = 60.0
    self.min_block_time    = 53.0
    self.max_block_time    = 67.0
    self.base_target_gamma  = 64
    self.min_base_target  = 138350580
    self.init_base_target  = 153722867
    self.max_base_target  = 7686143350
    self.balance      = int(1000000000 / 4)
    self.logfile      = "/var/www/html/data/audit.log"

    self.prv_key      = nacl.signing.SigningKey.generate()
    self.pub_key      = self.prv_key.verify_key.encode(encoder = nacl.encoding.HexEncoder).decode()

    self.account_hit    = 0
    self.fullchain      = []
    self.nodes        = []
    self.logdata      = []
    self.verify_logdata    = []
    self.mining = True
    _thread.start_new_thread(self.start_server, ())

    # Create genesis block or get blockchain
    if self.init_node[0][0] == None:
      self.append_block()
    else:
      self.send_msg("nodes")
      self.send_msg("blockchain")

    time.sleep(1)

    # Get list of nodes from other nodes each 5 mins
    _thread.start_new_thread(self.get_nodes, ())

    # Get content of the logfile each 10 seconds
    _thread.start_new_thread(self.get_log_content, ())

    # Mining for blocks
    while self.mining:
      if(len(self.fullchain) > 0):
        self.mine()
      time.sleep(1)

  ### COMMUNICATION FUNCTIONS ###

  def start_server(self):
    # start listing on definied port
    self.nodes.append([self.ip,self.port,self.pub_key])
    serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    serversocket.bind((self.ip, self.port))
    serversocket.listen(10)
    print("Server is listening on " + self.ip + ":" + str(self.port))

    # Wait for connection from other node
    while True:
      clientsocket,addr = serversocket.accept()
      clientsocket.settimeout(60)
      _thread.start_new_thread(self.accept_client, (clientsocket,))

  def verify_node(self, clientsocket, msg, send=True):
    try:
      msg = json.loads(msg.decode('ascii'))
    except:
      return False

    exists = False
    # check for every known node if the public key and the ip are matching
    for node in self.nodes:
      if msg[0] == node[0]:
        exists = True
        if msg[2] == node[2]:
          if send == True:
            # send own verifyinformation to the connecting node
            clientsocket.send(json.dumps([self.ip,self.port,self.pub_key]).encode('ascii'))
          return msg[2]
        else:
          clientsocket.send("public key is not the same as registered".encode('ascii'))
          return False

    if exists == False:
      self.nodes.append(msg)
      if send == True:
        clientsocket.send(json.dumps([self.ip,self.port,self.pub_key]).encode('ascii'))
      return msg[2]

  def verify_msg(self, pub_key, msg):
    try:
      pub_key = nacl.signing.VerifyKey(pub_key, encoder=nacl.encoding.HexEncoder)
      msg = pub_key.verify(msg)
    except:
      print("Invalid signature from request")
      return False
    return msg

  def accept_client(self, clientsocket):
    # verify connecting node
    msg = clientsocket.recv(1024)
    pub_key = self.verify_node(clientsocket, msg)
    if pub_key == False:
      clientsocket.close()
      return False

    while True:
      # wait for message from client and verify message
      msg = clientsocket.recv(100000000)
      if not msg:
        break

      msg = self.verify_msg(pub_key,msg)
      if msg != False:
        msg = json.loads(msg.decode('ascii'))
        print("Received Message \""+msg[0]+"\" from "+clientsocket.getpeername()[0])

        # handle the received command
        if msg[0] == "nodes":
          clientsocket.send(self.prv_key.sign(json.dumps(["nodes",self.nodes]).encode()))
        elif msg[0] == "blockchain":
          clientsocket.send(self.prv_key.sign(json.dumps(["blockchain",self.fullchain]).encode()))
        elif msg[0] == "new_block":
          if self.verify_block(msg[1]):
            self.fullchain.append(msg[1])
            print("Got a new valid Block!")
            self.verify_logs()
          else:
            print("Got an invalid Block!")
        elif msg[0] == "logs":
          for log in msg[1]:
            if log not in self.logdata and log not in self.verify_logdata:
              self.logdata.append(log)
      else:
        break
    clientsocket.close()
      
  def send_msg(self, cmd):
    temp = []
    nodes = self.nodes
    if not nodes:
      nodes = self.init_node

    for node in nodes:
      # connect to each known node and send command
      if node[0] != self.ip or node[1] != self.port:
        clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        clientsocket.connect((node[0], node[1]))
        clientsocket.send(json.dumps([self.ip,self.port,self.pub_key]).encode('ascii'))
        msg = clientsocket.recv(1024)

        pub_key = self.verify_node(clientsocket, msg, False)
        if pub_key == False:
          clientsocket.close()
          return False

        if cmd == "blockchain":
          clientsocket.send(self.prv_key.sign(json.dumps(["blockchain"]).encode()))
          msg = clientsocket.recv(100000000)
          msg = self.verify_msg(pub_key,msg)
          if msg != False:
            msg = json.loads(msg.decode('ascii'))
            temp.append(msg[1])
        elif cmd == "nodes":
          clientsocket.send(self.prv_key.sign(json.dumps(["nodes"]).encode()))
          msg = clientsocket.recv(100000000)
          msg = self.verify_msg(pub_key,msg)
          if msg != False:
            msg = json.loads(msg.decode('ascii'))
            temp.append(msg[1])
        elif cmd == "new_block":
          clientsocket.send(self.prv_key.sign(json.dumps([cmd, self.fullchain[len(self.fullchain) -1]]).encode()))
        elif cmd == "logs":
          clientsocket.send(self.prv_key.sign(json.dumps([cmd, self.logdata]).encode()))

        print("Sent message \""+cmd+"\" to "+node[0] + ":" + str(node[1]))
        clientsocket.close()

    # read received blockchains  and check them for validity
    if cmd == "blockchain":
      if temp:
        for chain in temp:
          if len(self.fullchain) < 1 or chain[len(chain) - 1]['diff'] > self.fullchain[len(self.fullchain) - 1]['diff']:
            print("Got a new Blockchain!")
            self.fullchain = chain

    # read received nodes and integrate them into the known nodes
    if cmd == "nodes":
      for temp_nodes in temp:
        for temp_node in temp_nodes:
          if temp_node not in self.nodes:
            self.nodes.append(temp_node)
            print("Got a new Node!")

  def get_nodes(self):
    while 1:
      self.send_msg("nodes")
      time.sleep(300)

  def get_log_content(self):
    # read every 10 second the definied logfile and save the logs into a queue array
    while 1:
      f = open(self.logfile,"r")
      lines = f.readlines()
      f.close()
      f = open(self.logfile,"w")
      f.close()
      new_log = False
      for line in lines:
        line = json.loads(line)
        arr = []
        for key, value in line.items():
          arr.append(value)
        if line not in self.logdata:
          self.logdata.append([self.ip,arr])
          new_log = True
      if new_log == True:
        self.send_msg("logs")
      time.sleep(10)

  def verify_logs(self):
    for log in self.logdata:
      self.verify_logdata.append(log)
    self.logdata = []

    cur_index = len(self.fullchain) - 1
    in_queue = False
    send_logs = False
    num_prev_blocks = 5
    if cur_index < 5:
      num_prev_blocks = len(self.fullchain) - 1 

    # check for each log if it is in the last 5 blocks or till the genesis block
    for i, log in enumerate(self.verify_logdata):
      in_queue = False
      for j in reversed(range(cur_index - num_prev_blocks,cur_index + 1)):
        if log in self.fullchain[j]['data']:
          in_queue = True
          # when the log is in the fith last block then it is verified
          if j == cur_index - 5:
            del self.verify_logdata[i]
          break

      # when the log is not into the last blocks then send it again
      if in_queue == False:
        self.logdata.append(self.verify_logdata[i])
        del self.verify_logdata[i]
        send_logs = True

    if send_logs:
      self.send_msg("logs")

  ### BLOCKCHAIN FUNCTIONS ###

  def hash(self, string):
    return hashlib.sha256(string.encode()).hexdigest()

  def base_target(self, time):
    # calculate the base target like described in the nxt whitepaper
    i = 3
    if len(self.fullchain) < 3:
      i = len(self.fullchain)

    avg_time = int((time - self.fullchain[len(self.fullchain) - i]['timestamp']) / i)
    if avg_time > self.avg_block_time:
      base_target = self.fullchain[i - 1]['base_target'] * min(avg_time,self.max_block_time) / self.avg_block_time
    else:
      base_target = self.fullchain[i - 1]['base_target'] - (self.fullchain[i - 1]['base_target'] * self.base_target_gamma * (self.avg_block_time - max(avg_time,self.min_block_time)) / self.avg_block_time / 100)

    # limit the base target value
    if base_target < 0 or base_target > self.max_base_target:
      base_target = self.max_base_target
    if base_target < self.min_base_target:
      base_target = self.min_base_target

    return int(base_target)


  def target(self, time):
    # calculate the nodes current target for this second
    time_last_block = time - self.fullchain[len(self.fullchain) - 1]['timestamp']
    target = self.fullchain[len(self.fullchain) - 1]['base_target'] * time_last_block * self.balance
    return target

  def difficulty(self, base_target):
    return int(self.fullchain[len(self.fullchain) - 1]['diff'] + (int(math.pow(2,64))/base_target))

  def get_account_hit(self, pub_key, index):
    if len(self.fullchain) > 0:
      # convert the first 8 byte of the signed generation signature to an integer
      signature = self.hash(self.fullchain[index]['gen_sig'] + pub_key)
      return int(signature[:16], 16)
    else:
      return 0

  def prev_hash(self, index):
    return self.hash(json.dumps(self.fullchain[index], sort_keys=True))

  def get_current_logs(self):
    temp = []
    for log in self.logdata:
      temp.append(log)

    return temp

  def mine(self):
    # check if the current account hit is lower than the target value and the permission to forge a block is given
    self.account_hit = self.get_account_hit(self.pub_key,len(self.fullchain) - 1)
    if self.target(int(time.time())) > self.account_hit:
      self.append_block()
      self.send_msg("new_block")
      print("Created a new Block!")
      self.print_chain()
      self.verify_logs()

  def verify_block(self, block):
    # verify the block over the previous hash and the index
    if len(self.fullchain) < block['index']:
      print("Blockindex is too high. Request for new Blockchain!")
      self.send_msg("blockchain")
      return False

    elif not block['prev_hash'] == self.prev_hash(block['index'] - 1):
      print("Previous Blockhash doesn't match!")
      return False

    # check if it is a valid older block
    elif len(self.fullchain) > block['index']:
      if block['diff'] > self.fullchain[block['index']]['diff'] and self.get_account_hit(block['val_pub_key'],block['index'] - 1) >= self.target(block['timestamp'] - self.fullchain[block['index'] - 1]['timestamp']):
        difference = len(self.fullchain) - block['index'] - 1
        for x in range(0,difference):
          del self.fullchain[len(self.fullchain) - 1 - x]
        return True
      else:
        print("User wasn't allowed to mine!")
        return False

    elif len(self.fullchain) == block['index'] and self.get_account_hit(block['val_pub_key'], len(self.fullchain) - 1) >= self.target(block['timestamp'] - self.fullchain[block['index'] - 1]['timestamp']):
      return True

    print("Unknown error occurred!")
    return False

  def append_block(self):
    # set the structure of each block and the default values for the genesis block
    blockdata = {
      'index' : len(self.fullchain),
      'prev_hash': '0',
      'timestamp' : int(time.time()),
      'val_pub_key': self.pub_key,
      'gen_sig': self.pub_key,
      'base_target': self.init_base_target,
      'diff': int(math.pow(2,64)/self.init_base_target),
      'data': self.get_current_logs(),
    }
    if blockdata['index'] != 0:
      blockdata['prev_hash'] = self.prev_hash(len(self.fullchain) - 1)
      blockdata['gen_sig'] = self.hash(self.fullchain[len(self.fullchain) - 1]['gen_sig'] + self.pub_key)
      blockdata['base_target'] = self.base_target(blockdata['timestamp'])
      blockdata['diff'] = self.difficulty(blockdata['base_target'])

    self.fullchain.append(blockdata)

  def print_chain(self):
    # print the whole blockchain into console
    show_keys = ['index','prev_hash','timestamp','base_target']
    for block in self.fullchain:
      for key in block:
        if key == "data":
          print("data:")
          for log in block[key]:
            print(log)
        else:
          print(key + ":\t" + str(block[key]))
      print("")
    print("")

if __name__ == '__main__':
  parser = ArgumentParser()
  parser.add_argument('-i', '--ip', default=None, type=str, help='address')
  parser.add_argument('-p', '--port', default=9999, type=int, help='port to listen on')
  parser.add_argument('-ni', '--node_ip', default=None, type=str, help='address')
  parser.add_argument('-np', '--node_port', default=9999, type=int, help='port to listen on')
  args = parser.parse_args()
  ip = args.ip
  port = args.port
  node_ip = args.node_ip
  node_port = args.node_port
  
  blockchain = Blockchain(ip=ip, port=port, node_ip=node_ip, node_port=node_port)
