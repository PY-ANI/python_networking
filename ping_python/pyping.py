from os import getpid
from sys import exit, byteorder, argv
from time import sleep, time
import socket
import select
import ctypes
import struct
import argparse
# from logging import ge



class Ping():
	
	port = 1
	packet_size = 48
	count = 0
	interval = 1000 # in ms
	timeout = 2000 # in ms
	dest_ip = None
	pid = getpid()&0xffff
	sequence = 0
	sent_packets = 0
	revc_packets = 0
	avg_delay = 0
	max_packet_size = 65507 # in ms
	max_wait_time = 10000 # in ms
	max_interval_time = 6000 # in ms
	parser = argparse.ArgumentParser(
		prog="PYPING",
		description="High level implementation of conventional ping utility command using python socket module.",
		)
	raw_sock = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)

	def __init__(self):
		self.raw_sock.settimeout(self.timeout)
		self.getParser()

	def CheckSum(self,bytedata:bytes):
		count = 0 # Counter var
		csum = 0 # Sum var
		endianess = byteorder

		for i in range(0,bytedata.__len__()-1,2):
			if endianess == "little":
				hbyte = bytedata[i+1]
				lbyte = bytedata[i]
			else:
				lbyte = bytedata[i+1]
				hbyte = bytedata[i]
			
			csum += (hbyte*256+lbyte) # creating 16bit integer by concatonating two 8 bit integer
			count+=2

		if count < bytedata.__len__():
			csum += bytedata[count]

		csum = (csum >> 16)+(csum & 0xffff) # handeling carry and normalising bit count to 16bit
		csum += (csum >> 16)
		csum = ~csum & 0xffff # ones complement of checksum
		csum = socket.htons(csum) # converting byteorder to network byteorder
		return csum
	
	def request_packet(self):
		type_header = 8
		code_header = 0
		checksum = 0
		icmp_header = struct.pack("!BBHHH",type_header,code_header,checksum,self.pid,self.sequence)
		payload = [(i|self.sequence)&0xff for i in range(self.packet_size)]
		payload = bytes(payload)
		checksum = self.CheckSum(icmp_header+payload)
		icmp_header = struct.pack("!BBHHH",type_header,code_header,checksum,self.pid,self.sequence)
		payload = icmp_header + payload
		return payload
	
	def ping(self):
		print(f"Ping ({self.dest_ip}) - Packet size ({self.packet_size}) :-")

		try:
			while True:
				self.sequence += 1
				req_packet = self.request_packet()
				prev_time = time()
				self.raw_sock.sendto(req_packet,(self.dest_ip,self.port))
				data , addr = self.raw_sock.recvfrom(self.packet_size+28)
				delta_time = time()-prev_time

				check_header = struct.unpack("!H",data[22:24])[0]
				chunk = data[20:22]+data[24:]

				# check = self.CheckSum(chunk)  # calculating recv data checksum
				# print(check, check_header)  # validating checksum

				chunk_len = chunk.__len__()+2
				self.sent_packets += req_packet.__len__()
				self.revc_packets += chunk_len
				self.avg_delay += delta_time

				print(f"{chunk_len} bytes from {self.dest_ip}: seq_no={self.sequence}  delay={delta_time*1000:.2f} ms")

				if self.sequence == self.count: break

				sleep(self.interval/1000)

		except KeyboardInterrupt:
			pass
		
		print(f"\n----- ({self.dest_ip}) Ping Stats -----")
		print(f"Ping Count : {self.sequence}, Sent-Bytes : {self.sent_packets}, Recv-Bytes : {self.revc_packets}, Avg-Delay : {((self.avg_delay*1000)/self.sequence):.2f} ms")

	def getParser(self):
		self.parser.add_argument("dest_ip",nargs="?")
		self.parser.add_argument("-c","--count",type=int,nargs="?",default=0,help="Ping count (default = 0). If set to 0 ,command will run till key interrupt.")
		self.parser.add_argument("-p","--packet_size",type=int,nargs="?",default=48,help="Set packet size(default 48).")
		self.parser.add_argument("-t","--timeout",type=float,nargs="?",default=2000,help="Set timeout (default=2000) in mili seconds.")
		self.parser.add_argument("-i","--interval",type=float,nargs="?",default=1000,help="Set ping interval (default=1000) in mili seconds.")

	def PingCli(self):
		args = self.parser.parse_args(argv[1:])
		for arg in args._get_kwargs(): self.__setattr__(*arg)

		try:
			self.dest_ip, self.port = socket.getaddrinfo(self.dest_ip, self.port)[0][-1]
		except Exception as e:
			print("Unknown ipV4 Format!")
			print("Expected ip or domain address.")
			exit(0)
		
		if self.count < 0 or self.count > 1000:
			print("Count out of range.")
			exit(0)
		
		if self.packet_size < 0 or self.packet_size > self.max_packet_size:
			print("Packet size out of range.")
			exit(0)
		
		if self.timeout > self.max_wait_time and self.timeout < 0:
			print("Timeout out of range.")
			exit(0)
		
		if self.interval > self.max_interval_time and self.interval < 0:
			print("Interval out of range.")
			exit(0)
		
		self.raw_sock.settimeout(self.timeout)
		self.ping()

if __name__ == "__main__":

	ping = Ping()
	ping.PingCli()