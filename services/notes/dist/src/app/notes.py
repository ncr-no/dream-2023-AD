#!/usr/bin/env -S PORT=1338 LOG_LEVEL=DEBUG python3
_B='utf-8'
_A=None

import os
import socket, logging
import itertools as it
import time, inspect
from socketserver import ForkingTCPServer, UnixStreamServer, StreamRequestHandler, BaseRequestHandler
from typing import Generator, ClassVar, Any, Dict, Callable, List, Tuple
import random, math


class Served(ForkingTCPServer):
	def __init__(A,server_address,RequestHandlerClass,bind_and_activate=...):A.address_family=socket.AF_INET;super().__init__(server_address,RequestHandlerClass,bind_and_activate)

logging.basicConfig(level=os.environ.get('LOG_LEVEL','info').upper(),format='{asctime} ┃ {name} ┃ {msg}',datefmt='%H:%M:%S',style='{')
addr='',int(os.environ['PORT'])

"""
We are making use of the cyclic group that g in mod p induces.

Due to the prime nature of p, any g ∈ [2,p] is a generator that produces all elements with q=p-1 (the group's order) (lookup Euler's totent function).
As specified in https://en.wikipedia.org/wiki/Discrete_logarithm#Cryptography, there exists no effective algorithm for dlog.

The following will represent g^z mod p using [z]

This indicates that p is the lowest number n for which g ≡ g^n  mod p, for any g ∈ [2,p).

Since, these parameters are public you are welcome to generate your own p.

g belongs to [2,p). 1 being the neutral element is not a generator. 

Due to the fact that outdated private settings are no longer valid, updating these parameters will temporarily disrupt your service.
"""

p = int('CA5FD16F55E38BC578BD1F79D73CDB7A93CE6E142C704AA6829620456989E76C335CBC88E56053A170BD1A7744D862C5B95BFA2A6BEC9AECF901C5616FFAA70FD8D338E46D2861242B00052F36FE7F87A180284D64CFF42F943CFC53C9992CD1C601337BC5B86C32FC17148D4983E8005764BC0927B21A473E9E16E662AFA7DF96ACDD8D877F07510D06D29EAC7E67AFC600C1BD51DB10C81179D2FDF8BE03B0BE4689777C074FBEB300E8CBD7F0F14AEF6611E5017ECBF682E222873326DD181EE472BA383B1E34DB087FDD00015FFD70F5FD3A10AC89527F5E0FE5578D006E2F50F05E74EC3159A7D460E8374556B1D4636F197C784177AD0D20FA6D467E29BE90FF861071175A3B7F9689FE97A3E41DE1835428350EB8D586FD3036090920D2B1E43553E83937C87E81B5C2036D96F1AEBCB1A6E1FF1E178DAC6D970703250F9AF4914B0F045A5A0911336B091063F44B7FE540FF97B929777F9854CA3FA84D365A14518A5CB3967465DF77F7B57565532375E1AEA56EEEA01771B03911871303153B85970E9F9C6060A01ED2266C65F452384853A7F2359AF66DC932ACBBFBAB640E77DB685F461D58A525470EE93D1713676E7A28D1EAF44FF54593BA459331932E6E7643017FD794AE621338F615EA3AADEBA80844B4B405C70AD0F3920D9FFD6456C4D3CE80E6032AA60BCC90868926E3F00BC5EE6CF1A8BDED5FFADB', 16)
g=0x1337

assert pow(g,p-1,p)==1,'Public parameters are not correct. Please make sure that your p is prime.'
logging.debug(f"using public paremters g={g:#x}{ p=:#x}")
notes_dir=os.path.join(os.path.dirname(__file__),'notes')
filenamelength_max=os.statvfs(notes_dir).f_namemax
note_maxsize=256
filename_alphabet='abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_+-'
keylen_hex_max=math.ceil(p.bit_length()/4)
keylen_byte_max=math.ceil(p.bit_length()/8)
prompt='> '

def verify(y,t,c,s):return pow(g,s,p)==t*pow(y,c,p)%p

def get_key():
	A=random.getrandbits(p.bit_length()-1)
	while A==0:A=random.getrandbits(p.bit_length()-1)
	return A

def list_notes():
	for A in os.listdir(notes_dir):
		if A.startswith('.'):continue
		yield A

def delete_old_notes():
	D=time.time()
	for A in list_notes():
		B=os.path.join(notes_dir,A);E=int(os.stat(B).st_mtime);C=(D-E)//60
		if C>20:logging.debug(f"deleting {A}, it is {C} minutes old");os.remove(B)

def create_new_note(title,key,content):
	B=title
	if not all(A in filename_alphabet for A in B):C=OSError();C.strerror=f"note name may only contain '{filename_alphabet}'";raise C
	D=os.path.join(notes_dir,B)
	with open(D,'xb')as A:random.seed(0);A.write(key.to_bytes(keylen_byte_max,byteorder='big'));A.write(b'\n');E=bytes(A^B for(A,B)in zip(content.encode(_B),(random.getrandbits(8)for A in it.count())));A.write(E);random.seed()

def display_note(title):
	A=title
	if not all(A in filename_alphabet for A in A):B=OSError();B.strerror=f"filename may only contain '{filename_alphabet}'";raise B
	D=os.path.join(notes_dir,A)
	with open(D,'rb')as C:random.seed(0);C.seek(keylen_byte_max+1);E=bytes(A^B for(A,B)in zip(b''.join(C),(random.getrandbits(8)for A in it.count()))).decode(_B);random.seed()
	return E

def read_key(title):
	A=title
	if not all(A in filename_alphabet for A in A):B=OSError();B.strerror=f"filename may only contain '{filename_alphabet}'";raise B
	C=os.path.join(notes_dir,A)
	with open(C,'rb')as D:E=int.from_bytes(D.read(keylen_byte_max+1).rstrip(b'\n'),byteorder='big')
	return E


class NotesHandler(StreamRequestHandler):
	def setup(A):A._commands={'help':A.help,'ls':A.ls,'create':A.create,'read':A.read,'exit':_A,'quit':_A};A.l=logging.getLogger(f"[{A.client_address[0]}]:{A.client_address[1]}");return super().setup()
	
	def handle(A):
		delete_old_notes()
		try:
			A.send_line(f"""Doc Yamin's Note-Taking Service...
Taking notes is highly helpful because time travel can be very complicated.
However, it would be exceedingly challenging to locate an ssl implementation on Github in 1998.

Therefore, there is no need for SSL or any other additional technology in authentication process used here.
You only need to remember one number to store and retrieve your note. So, it can also be used when you only have a connection and a simple TI-30.


I am using a zero-knowledge protocol based on Schnorr's Signature algorithm.

The protocol works as follows where you are the prover:
                    Verifier ____ Prover

                             <--- [r], r from Z_q
                  c from Z_q --->
                             <--- s := r + c·x % q
   verify [s] == [r]·y^c % q

The public parameters used in this implementation are: g={g:#x} and p={p:#x} .

Truly futuristic tech here.

Any note saved on this service is not guaranteed to be recovered by Dr. Mudassar Yamin Enterprise.""");A.help()
			while True:
				A.l.debug('prompts');A.send_line(prompt,end='')
				try:B=A.read_line().split()
				except OSError:break
				if not B:continue
				if B[0]not in A._commands:A.send_line(f"command '{B[0]}' not found");A.help();continue
				C=A._commands[B[0]]
				if C is _A:break
				A.l.debug(f"executing command: '{' '.join(B)}'")
				try:C(*B[1:])
				except TypeError as D:A.send_line(f"{D}")
		except(BrokenPipeError,):pass
	
	def help(A):
		A.send_line('Please choose one of the following commands:')
		for(C,B)in A._commands.items():D=' '.join(A for A in inspect.signature(B).parameters)if B is not _A else'';A.send_line(f"\t{C} {D}")
	
	def ls(A):
		for B in list_notes():A.send_line(f"{B}")
	
	def create(A,title):
		B=title
		try:C=read_key(B)
		except OSError as F:C=_A
		if C is not _A:A.send_line(f"Note creation failed {B}, Note already exists with y={C:#x}");return
		A.send_line('Ok');G=A.recv_value('Please provide the y to secure the value')
		if not A.proof_of_knowlege(G):A.l.warning(f"failed creating '{B}'");return
		A.send_line(f"You can now enter the note contents (send an empty line to stop, max size = {note_maxsize} bytes):");D=note_maxsize;H=''
		while D>0:
			E=A.read_line(max_size=D)
			if E=='\n':break
			H+=E;D=note_maxsize-len(E.encode(_B))
		A.l.info(f"creating '{B}'")
		try:create_new_note(B,G,H)
		except OSError as F:A.send_line(f"Note creation failed: {F.strerror}");return
		A.send_line(f"Note creation completed! {B}")
	
	def read(A,title):
		B=title
		try:D=read_key(B)
		except OSError as C:A.send_line(f"failed to read key for note '{B}': {C.strerror}");return
		A.send_line('Ok')
		if not A.proof_of_knowlege(D):A.l.warning(f"read attempt failure for '{B}'");return
		try:E=display_note(B)
		except OSError as C:A.send_line(f"failed to read key for note '{B}': {C.strerror}");return
		A.l.info(f"read success '{B}'");A.send_line('Please find the note contents below (empty line is the last line):');A.send_line(E);A.send_line()
	
	def proof_of_knowlege(A,y):
		A.send_line(f"Please identify yourslef by proving that you know x s.t. y = g^x in Z_q where g={g:#x}{ p=:#x} and y={y:#x} to authenticate yourself.");A.send_line('All numbers are implicitly base 16');C=A.recv_value('Please provide [r]');A.l.debug(f"<-- [r] {C:x}");B=get_key();A.send_value('Here is your challenge c',B);A.l.debug(f"--> c {B:x}");D=A.recv_value('Please provide r + c·x mod p-1');A.l.debug(f"<-- s {D:x}")
		if verify(y,C,B,D):A.send_line(f"verification succeeded");return True
		A.send_line(f"verification failed");return False
	
	def recv_value(A,msg):A.send_line(f"{msg} <--",end='');B=int(A.read_line().strip(),16);return B
	
	def read_line(A,max_size=-1):return A.rfile.readline(max_size).decode(_B)
	
	def send_value(A,msg,v):A.send_line(f"{msg} -->{v:#x}")
	
	def send_line(A,msg='',end='\n'):A.request.sendall(f"{msg}{end}".encode(_B))

if __name__=='__main__':
	with Served(addr,NotesHandler)as server:print(f"Serving at {addr[0]}:{addr[1]}");server.serve_forever()
