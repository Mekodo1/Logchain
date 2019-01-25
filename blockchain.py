import hashlib
import time
import json
import math
import socket
import _thread
from argparse import ArgumentParser
import nacl.utils
from nacl.public import PrivateKey, Box
import pymysql

class Blockchain:
	def __init__(self, ip=None, port=9999, node_ip=None, node_port=None):
		self.ip = socket.gethostbyname(socket.gethostname())
		if ip != None:
			self.ip = ip
		self.port = port
		self.init_node = [[node_ip, node_port]]

		self.avg_block_time		= 60.0
		self.min_block_time		= 53.0
		self.max_block_time		= 67.0
		self.balance			= int(1000000000 / 4) # Anzahl der Teilnehmer im Netzwerk
		self.base_target_gamma	= 64
		self.min_base_target	= 138350580
		self.init_base_target	= 153722867
		self.max_base_target	= 7686143350
		self.account_hit		= 0
		self.fullchain			= []
		self.nodes				= []
		self.logdata			= []
		self.queue_logdata		= []
		self.logfile			= "example.txt"

		self.con = pymysql.connect('localhost', 'nextclouduser', '', 'nextcloud')

		self.prv_key			= PrivateKey.generate()
		self.pub_key			= self.prv_key.public_key.encode(encoder = nacl.encoding.HexEncoder).decode()

		_thread.start_new_thread(self.start_server, ())

		if self.init_node[0][0] == None:
			self.append_block()
		else:
			self.send_msg("nodes")
			self.send_msg("blockchain")

		time.sleep(1)

		_thread.start_new_thread(self.get_nodes, ())
		_thread.start_new_thread(self.get_log_content, ())

		while 1:
			if(len(self.fullchain) > 0):
				self.mine()
			time.sleep(1)

	### COMMUNICATION FUNCTIONS ###

	def start_server(self):
		self.nodes.append([self.ip,self.port,self.pub_key])
		serversocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		serversocket.bind((self.ip, self.port))
		serversocket.listen(10)
		print("Server is listening on " + self.ip + ":" + str(self.port))
		while True:
			clientsocket,addr = serversocket.accept()
			clientsocket.settimeout(60)
			_thread.start_new_thread(self.accept_client, (clientsocket,))

	def accept_client(self, clientsocket):
		msg = clientsocket.recv(1024)
		msg = json.loads(msg.decode('ascii'))
		exists = False
		for node in self.nodes:
			if msg[0] == node[0] and msg[1] == node[1]:
				exists = True
				if msg[2] == node[2]:
					clientsocket.send("success".encode('ascii'))
				else:
					clientsocket.send("public key is not the same as registered".encode('ascii'))
					return False

		if exists == False:
			self.nodes.append(msg)
			clientsocket.send("success".encode('ascii'))

		while True:
			msg = clientsocket.recv(1024)
			if not msg:
				break
			msg = json.loads(msg.decode('ascii'))
			print("Received Message \""+msg[0]+"\" from "+clientsocket.getpeername()[0])

			if msg[0] == "blockchain":
				clientsocket.send(json.dumps(["blockchain",self.fullchain]).encode('ascii'))
			elif msg[0] == "nodes":
				clientsocket.send(json.dumps(["nodes",self.nodes]).encode('ascii'))
			elif msg[0] == "new_block":
				if self.verify_block(msg[1]):
					self.fullchain.append(msg[1])
					print("Got a new valid Block!")
					self.data_lookup()
				else:
					print("Got an invalid Block!")
			elif msg[0] == "logs":
				for log in msg[1]:
					if log not in self.logdata and log not in self.queue_logdata:
						self.logdata.append(log)
		clientsocket.close()
			
	def send_msg(self, cmd):
		temp = []
		nodes = self.nodes
		if not nodes:
			nodes = self.init_node

		for node in nodes:
			if node[0] != self.ip or node[1] != self.port:
				clientsocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
				clientsocket.connect((node[0], node[1]))
				clientsocket.send(json.dumps([self.ip,self.port,self.pub_key]).encode('ascii'))
				msg = clientsocket.recv(1024)

				if msg.decode('ascii') == "success":
					if cmd == "blockchain":
						clientsocket.send(json.dumps(["blockchain"]).encode('ascii'))
						msg = clientsocket.recv(102400)
						msg = json.loads(msg.decode('ascii'))
						temp.append(msg[1])
					elif cmd == "nodes":
						clientsocket.send(json.dumps(["nodes"]).encode('ascii'))
						msg = clientsocket.recv(1024)
						msg = json.loads(msg.decode('ascii'))
						temp.append(msg[1])
					elif cmd == "new_block":
						clientsocket.send(json.dumps([cmd, self.fullchain[len(self.fullchain) -1]]).encode('ascii'))
					elif cmd == "logs":
						clientsocket.send(json.dumps([cmd, self.logdata]).encode('ascii'))

				print("Sent message \""+cmd+"\" to "+node[0] + ":" + str(node[1]))
				clientsocket.close()

		if cmd == "blockchain":
			if temp:
				for chain in temp:
					if len(self.fullchain) < 1 or chain[len(chain) - 1]['diff'] > self.fullchain[len(self.fullchain) - 1]['diff']:
						print("Got a new Blockchain!")
						self.fullchain = chain

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
		while 1:
			with self.con:
				cur = self.con.cursor()
				cur.execute("SELECT * FROM oc_activity")

				rows = cur.fetchall()
				new_log = False

				for row in rows:
					in_blockchain = False
					for block in self.fullchain:
						if [self.ip,row] in block['data']:
							in_blockchain = True
							break
					if in_blockchain == False and [self.ip,list(row)] not in self.logdata and [self.ip,list(row)] not in self.queue_logdata:
						self.logdata.append([self.ip,list(row)])
						new_log = True
				if new_log == True:
					self.send_msg("logs")
				time.sleep(10)

	def data_lookup(self):
		for log in self.logdata:
			self.queue_logdata.append(log)
		self.logdata = []

		cur_index = len(self.fullchain) - 1
		in_queue = False
		send_logs = False
		num_prev_blocks = 5
		if cur_index < 5:
			num_prev_blocks = len(self.fullchain) - 1 

		for i, log in enumerate(self.queue_logdata):
			in_queue = False
			for j in reversed(range(cur_index - num_prev_blocks,cur_index + 1)):
				if log in self.fullchain[j]['data']:
					in_queue = True
					if j == cur_index - 5:		# hier nicht num_prev_blocks, da es genau 5 abwarten soll bis es rausfliegt
						del self.queue_logdata[i]
					break
			if in_queue == False:
				self.logdata.append(self.queue_logdata[i])
				del self.queue_logdata[i]
				send_logs = True

		if send_logs:
			self.send_msg("logs")

	### BLOCKCHAIN FUNCTIONS ###

	def hash(self, string):
		return hashlib.sha256(string.encode()).hexdigest()

	def base_target(self, time):
		i = 3
		if len(self.fullchain) < 3:
			i = len(self.fullchain)

		avg_time = int((time - self.fullchain[len(self.fullchain) - i]['timestamp']) / i)
		print("avg_time:" + str(avg_time))
		print("avg_time (ges):" + str((self.fullchain[len(self.fullchain) - 1]['timestamp'] - self.fullchain[0]['timestamp']) / len(self.fullchain)))
		if avg_time > self.avg_block_time:
			base_target = self.fullchain[i - 1]['base_target'] * min(avg_time,self.max_block_time) / self.avg_block_time
		else:
			base_target = self.fullchain[i - 1]['base_target'] - (self.fullchain[i - 1]['base_target'] * self.base_target_gamma * (self.avg_block_time - max(avg_time,self.min_block_time)) / self.avg_block_time / 100)

		if base_target < 0 or base_target > self.max_base_target:
			base_target = self.max_base_target
		if base_target < self.min_base_target:
			base_target = self.min_base_target

		return int(base_target)


	def target(self, time):
		time_last_block = time - self.fullchain[len(self.fullchain) - 1]['timestamp']
		target = self.fullchain[len(self.fullchain) - 1]['base_target'] * time_last_block * self.balance
		return target

	def difficulty(self, base_target):
		return int(self.fullchain[len(self.fullchain) - 1]['diff'] + (int(math.pow(2,64))/base_target))

	def get_account_hit(self, pub_key, index):
		if len(self.fullchain) > 0:
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
		self.account_hit = self.get_account_hit(self.pub_key,len(self.fullchain) - 1)
		if self.target(int(time.time())) > self.account_hit:
			self.append_block()
			self.send_msg("new_block")
			print("Created a new Block!")
			self.print_chain()
			self.data_lookup()

	def verify_block(self, block):
		if len(self.fullchain) < block['index']:
			print("BLockindex is too high. Request for new Blockchain!")
			self.send_msg("blockchain")
			return False

		elif not block['prev_hash'] == self.prev_hash(block['index'] - 1):
			print("Previous Blockhash doesn't match!")
			return False

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
		blockdata = {
			'index' : len(self.fullchain),
			'prev_hash': '0',
			'timestamp' : int(time.time()),
			'val_pub_key': self.pub_key,
			'val_id': self.hash(self.pub_key),
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
		#show_keys = ['index','prev_hash','timestamp','base_target','data']
		for block in self.fullchain:
			for key in block:
				#if key in show_keys:
				print(key + ": " + str(block[key]))
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

	# def verify_chain_upwards(self, index):
	# 	if index == 0:
	# 		try:
	# 			len(self.fullchain[index])
	# 			self.verify_chain_upwards(index + 1)
	# 		except:
	# 			return True
	# 			print("Blockchain valide")
	# 	elif not index == 0 and self.fullchain[index]['prev_hash'] == self.prev_hash(index - 1):
	# 		try:
	# 			len(self.fullchain[index])
	# 			self.verify_chain_upwards(index + 1)
	# 		except:
	# 			print("Blockchain valide")
	# 			return True
	# 	else:
	# 		print("Im Block " + str(index) + " gibt es ein Problem.")
	# 		return False
