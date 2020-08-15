from tkinter import *
from tkinter import ttk


# Client Code
#-----------------------------------------------------------------------------------------
import hashlib
import base64
import json
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from Cryptodome.Cipher import AES
from Cryptodome import Random

# For AES Encryptiion
BLOCK_SIZE = 16
pad = lambda s: bytes(s + (BLOCK_SIZE - len(s) % BLOCK_SIZE) * chr(BLOCK_SIZE - len(s) % BLOCK_SIZE), 'utf-8')
unpad = lambda s: s[0:-ord(s[-1:])]
# We use the symmetric Encryption So this password have to be the same in both client and server
password = "852020"
homeAccess = False

def encrypt(raw, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    raw = pad(raw)
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return base64.b64encode(iv + cipher.encrypt(raw))
 
def decrypt(enc, password):
    private_key = hashlib.sha256(password.encode("utf-8")).digest()
    enc = base64.b64decode(enc)
    iv = enc[:16]
    cipher = AES.new(private_key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(enc[16:]))
#bytes.decode(decrypt(s.recv(1024), password))

# For Hashing  SHA-1
def myHash(ps):
    hashPassword = hashlib.sha1(ps.encode("utf-8"))
    encrypt = hashPassword.hexdigest()
    return encrypt

# Receiver
def receive():
    while True:
        try:
            msg = bytes.decode(decrypt(client.recv(bufsiz), password))
            msg = json.loads(msg)

            # Signup error replay
            if msg["to"] == "valid":

                mg=msg["msg"]
                iusername.delete(0,END)
                iusername.insert(0,mg)
                iusername.config(fg="red")

                print(msg["msg"])

            # Login error reply
            elif msg["to"] == "loginReply":
                homeAccess = bool(msg["access"])
                print(msg["msg"])

            # Login Access
            elif msg["to"] == "loginAccessReply":
                homeAccess = bool(msg["access"])
                accessGranted(access = homeAccess)
                print(homeAccess)
            # Recieve msg
            elif msg["to"] == superuser:
                global message
                message=msg['msg']
                cl('other',message)
            # Resiver Going Offline
            elif msg["to"] == "offline":
                print(msg["msg"])

        except OSError:
            break

# sender
def send(event = None, data = ""):
    client.send(encrypt(data, password))

def sentMsg(msg):
    smsg={'to':'et','msg':msg,"from":superuser}
    smsg = json.dumps(smsg)
    send(data = smsg)

# Signup Password validation
def signupAccount(username, ps, reps, email):
    if username and ps and reps and email :
        if "/" not in username:
            if "@" in email:
                if len(ps) >= 8 :
                    if ps == reps :
                        newPassword = myHash(ps)
                        data = {"to":"//signup", "username":username, "ps":newPassword, "email":email}
                        send(data = json.dumps(data))
                    
# Try Login Access 
def loginAccount(username, ps):
    global superuser
    superuser = username
    data = {"to":"//login", "username":username, "ps":myHash(ps)}
    send(data = json.dumps(data))

# Access Granted
def accessGranted(access = False):
    if access :
        changeFrame(lf, homeFrame)

# Enter server IP
host = input("Enter Host IP : ")
port = 33000
bufsiz = 1024
addr = (host, port)

# Create socket and Connect to  IP and port
client = socket(AF_INET, SOCK_STREAM)
client.connect(addr)

# Create a thread for recieve 
receiveThread = Thread(target = receive)
receiveThread.start()
#-----------------------------------------------------------------------------------------


root = Tk()
root.title("Whisper")
# width = root.winfo_screenwidth()
# height = root.winfo_screenheight()
# root.geometry(f"{width}x{height}+0+0")
root.geometry("1600x800+0+0")

fg = "#ffffff"
bg = "#333333"
wbg = "white"
color = "#FFA500"
placeholderFg = "light gray"
font = ("book antiqua", 11, 'bold')
msgList=[]
msList=[]


# setting Bg Color
root.config(background = bg)

# For close Button
def onClosing(event = None):
    data = {"to":"//clientDisconnect","con":1}
    send(data = json.dumps(data))
    client.close()
    root.quit()
root.protocol("WM_DELETE_WINDOW", onClosing)

def changeFrame(old, new):
    old.destroy()
    new()

def loginFrame():
    global lf

    # Login frame create
    lf = Frame(root,bg = bg, bd = 0, width = 800, height = 800, relief = "solid")
    lf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # Title
    title = Label(lf, text = 'Whisper', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    username = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    username.insert(0, "Username  ")
    placeHolder(username, "Username  ")
    
    password = Entry(lf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♫")

    # Button
    loginButton = Button(lf, font = ("book antiqua", 13, 'bold'), text = "Login", relief = "flat", padx = 22, bg = bg, fg = color, command = lambda username = username, ps=password : loginAccount(username.get(), ps.get()))
    signupButton = Button(lf, font = ("book antiqua", 13, 'bold'), text = "Signup", relief = "flat", padx = 18, bg = bg, fg = color, command = lambda : changeFrame(lf, signupFrame))

    # Padding Bottom
    # Lpadlabel=Label(lf, bg = bg)

    # Adding into current frame
    title.grid(row = 0, column = 1)
    username.grid(row = 1, column = 0, columnspan = 4, pady = 20, ipady = 7, ipadx = 30)
    password.grid(row = 2, column = 0, columnspan = 4, pady = 20, ipady = 7, ipadx = 30)
    loginButton.grid(row = 3, column = 1, columnspan = 2)
    signupButton.grid(row = 4, column = 1, columnspan = 2, pady = 30)
    # Lpadlabel.grid(row = 5, column = 1, pady = 10)

    # Adding current frame to root
    lf.pack(anchor = "center", pady = 100)

def signupFrame():
    # Signup frame create
    sf = Frame(root, bg = bg, bd = 0, width = 800, height = 800, relief = "solid")
    sf.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # title
    title = Label(sf, text = 'Signup ', font = ('times', 26, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)

    # Entry field
    global iusername
    iusername = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    iusername.insert(0, "Username  ")
    placeHolder(iusername, "Username  ")
   
    password = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    password.insert(0, "Password  ")
    placeHolder(password, "Password  ", "♫")
    
    rePassword = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    rePassword.insert(0, "Comfirm Password  ")
    placeHolder(rePassword, "Comfirm Password  ", "♫")
    
    email = Entry(sf, font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    email.insert(0, "Email  ")
    placeHolder(email, "Email  ")
    
    # Button
    signupButton = Button(sf, text = "Signup", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 18, bg = bg, fg = color, command = lambda username = iusername, ps = password, reps = password, email = email : signupAccount(username.get(), ps.get(), reps.get(), email.get()))
    backButton = Button(sf, text = "Back", font = ("book antiqua", 13, 'bold'), relief = "flat", padx = 24, bg = bg, fg = color, command = lambda : changeFrame(sf, loginFrame))

    # Padding
    # Spadlabel = Label(sf, bg = bg)

    # Adding into current frame
    title.grid(row = 0, column = 1)
    iusername.grid(row = 1, column = 0, columnspan = 4, ipady = 7, ipadx = 30)
    password.grid(row = 2, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    rePassword.grid(row = 3, column = 0, columnspan = 4, ipady = 7,ipadx = 30)
    email.grid(row = 4, column = 0, columnspan = 4, pady = 30, ipady = 7, ipadx = 30)
    signupButton.grid(row = 5, column = 1, columnspan = 2)
    backButton.grid(row = 6, column = 1, columnspan = 2, pady = 30)
    # Spadlabel.grid(row = 7, column = 1, pady = 20)

    # Adding current frame to root
    sf.pack(anchor = "center", pady = 100)

def homeFrame():
    navigationFrame()
    chatFrame()
   

def navigationFrame():
    global navFrame
    global user_list

    # Navigation Frame
    navFrame= Frame(root, bg = bg, bd = 0, width = 300, height = 800, relief = "solid")
    navFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)

    # Scrollbar
    scrollBar = Scrollbar(navFrame, bg = 'red', troughcolor = "red")
    searchBar=Entry(navFrame,font = font, width = 26, bg = bg, fg = placeholderFg, relief = 'solid', highlightcolor = color, highlightbackground = color, highlightthickness = 1, borderwidth =3)
    searchBar.insert(0,"search users")
    user_list = Listbox(navFrame, yscrollcommand = scrollBar.set, bg = bg,height=40,width=36)

    for line in range(5):
        user_list.insert(END, "Number" + str(line))

    settingButton = Button(navFrame, text = "Setting")
    settingButton.pack(side = BOTTOM)

    scrollBar.pack(side = RIGHT, fill = Y)
    scrollBar.config(command = user_list.yview)
    searchBar.pack(side=TOP,pady=5)
    user_list.pack(side = LEFT, fill = BOTH)
    navFrame.pack(side = LEFT, padx = 10)

def chatFrame():
    global chatFrame
    chatFrame = Frame(root, bg = bg, bd = 0, width = 1000, height = 710, relief = "solid")
    chatFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)
    global msgShowFrame
    msgShowFrame=Frame(chatFrame,bg=bg,width=1000,height=400)
    

    
    my_msg = StringVar()  # For the messages to be sent.
    my_msg.set("Type your messages here.")
    global scrollable_frame

    cv = Canvas(msgShowFrame,bg='blue',width=1000,height=400)
    sbar = Scrollbar(msgShowFrame, command = cv.yview)
    cv.config(yscrollcommand = sbar.set)
    f = Frame(cv,bg='red',width=1000,height=400)
    
    global cl
    def cl(fom,mg):
        if fom=='me':
            t=Label(f, text =mg ,bg='green')
            t.pack(side=TOP,anchor='ne',padx=500,ipadx=40)
        elif fom=='other':
            t=Label(f,text=mg)
            t.pack(side=TOP,sticky='w')
    
    cv.create_window((0,0), window = f,anchor='n')
    
    cv.pack(side = 'left', fill = 'both', expand = True)
    sbar.pack(side = 'right', fill = 'y')
    root.bind("<Configure>", lambda e: cv.config(scrollregion = cv.bbox('all')))
    
    
    #text frame
    sentMsgFrame=Frame(chatFrame,bg=bg,width=1000,height=200)
    global sentMsgEntry
    MessageText=Text(sentMsgFrame,width=17,height=3,exportselection=0,wrap=CHAR)
    global reFrash
    
    def sent():
        
        global o
        o=MessageText.get(1.0,END)
        cl('me',o)
        
        
        sentMsg(o)
        MessageText.delete(1.0,END)
        





    MessageText.pack(side=LEFT)
    
    SentMsgButton=Button(sentMsgFrame,text="send", relief = "flat" ,bg=bg,width=10,font = font,command=sent)
    SentMsgButton.pack(side=LEFT)

    
    msgShowFrame.pack(side=TOP)
    
    
    sentMsgFrame.pack(side=BOTTOM,pady=50)
    
    # sentMsgButton.pack(side=RIGHT,ipady=10)
    chatFrame.pack(side = LEFT,padx=30)

def settingFrame():

    def click_1():
        a = radio_button.get()
        if a == 1:
            root.config(bg = wbg)
            navFrame.config(bg = wbg)
            chatFrame.config(bg = wbg)
            user_list.config(bg = wbg)
            setFrame.config(bg = wbg)
            setLabel.config(bg = wbg)
            modLabel.config(bg = wbg)

        elif a == 2:
            root.config(bg = bg)
            navFrame.config(bg = bg)
            chatFrame.config(bg = bg)
            user_list.config(bg = bg)
            setFrame.config(bg = bg)
            setLabel.config(bg = bg)
            modLabel.config(bg = bg)

    setFrame = Frame(root, bg = bg, bd = 0, width = 300, height = 500, relief = "solid")
    setFrame.config(highlightcolor = color, highlightbackground = color, highlightthickness = 2, borderwidth = 2)
    setFrame.pack(side=LEFT, padx = 30)

    setLabel = Label(setFrame, text = "Setting", font = ('times', 24, 'bold', 'italic'), padx = 150, pady = 20, bg = bg, fg = color)
    modLabel = Label(setFrame, text = "Mode", font = ('times', 14, 'bold'), bg = bg, fg = color)
    setLabel.grid(row = 0, column = 1, columnspan = 3)
    modLabel.grid(row = 1, column = 1)

    radio_button = IntVar()

    rb1 = ttk.Radiobutton(setFrame, text = "Light Mode", variable = radio_button, value = 1, command = click_1)
    rb2 = ttk.Radiobutton(setFrame, text = "Dark Mode", variable = radio_button, value = 2, command = click_1, style = "Wild.TRadiobutton")
    sty = ttk.Style()
    sty.configure("Wild.TRadiobutton", background = bg, foreground = wbg)
    rb1.grid(row = 1, column = 2, sticky = "e")
    rb2.grid( row = 1, column = 3, sticky = "w")

#for Place holder
def placeHolder(ent, plce = "" , s = ""):
    #for placehokder text
    def putPlaceholder(ent):
        ent.config(show = "")
        ent.config(fg = "light gray")
        ent.insert(0, plce)

    #if click the entry
    def focIn(*args):
        if ent.get() == plce:
            ent.delete(0, END)
            ent.config(fg = color)
            ent.config(show = s)
        
    #not click the entry
    def focOut(*args):
        if not ent.get():
            putPlaceholder(ent)
        
    ent.bind("<FocusIn>", focIn)
    ent.bind("<FocusOut>", focOut)


loginFrame()
root.mainloop()
