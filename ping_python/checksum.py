from sys import byteorder
from socket import htons

def CheckSum(bytedata):
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
		
		csum += (hbyte*256+lbyte)
		count+=2

	if count < bytedata.__len__():
		csum += bytedata[count]

	csum = (csum >> 16)+(csum & 0xffff)
	csum += (csum >> 16)
	csum = ~csum & 0xffff
	csum = htons(csum) # converting byteorder to network byteorder
	return csum

if  __name__ == "__main__":

	# data = b"\x08\x00\x00\x01\x00\x01\x93\x84\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

	data = b"\x00\x00\x00\x01\x00\x01\x0a\xb2\x01\x66\x00\x00\x00\x00\x93\x84\x00\x00\x00\x00\x00\x00\x10\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30\x31\x32\x33\x34\x35\x36\x37"

	check = 0xa18e

	print(CheckSum(data))
	print(CheckSum(data)+~check+1)