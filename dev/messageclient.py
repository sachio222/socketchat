#!/usr/bin/python3

import os
import sys
import socket
from threading import Thread, Lock

class Client():
    def __init__(self):
        pass

    def sender(self):
        #0
        """Takes input, checks for input type, and begins sending to recip.

        Accepts input, and checks if it's a command. If it's prefixed with a '/'
                Then it is routed to the inp_ctrl_handler where different
                controls are mapped. If it doesn't begin with '/', it's treated
                as a generic message. 
        """
        while True:
            msg = input('')
            if msg:
                if msg[0] == '/':
                    typ_pfx = 'C'
                    self.inp_ctrl_handler(msg)
                else:
                    typ_pfx = 'M'
            else:
                msg = ''

            self.pack_n_send(serv_sock, typ_pfx, msg)
            
    def pack_n_send(self, sock, typ_pfx, msg):
        #1
        """Called by Sender. Adds message type, length prefixes and sends
        
        typ_pfx: (Type prefix) 1 byte. tells recipient how to handle message. 
        len_pfx: (Length prefix) 4 bytes. tells socket when to stop receiving message.

        Example packet:
            M0005Hello - Message type, 5 characters, "Hello"
        """
        
        len_pfx = len(msg)
        len_pfx = str(len_pfx).rjust(4, '0')
        packed_msg = f'{typ_pfx}{len_pfx}{msg}'
        sock.send(packed_msg.encode())
            
    def receiver(self):
        #1
        """A Threaded socket that calls a function to check message type."""
        while True:
            typ_pfx = serv_sock.recv(1)
            if not typ_pfx:
                serv_sock.close()
                print("-!- Aw, snap. Server's disconnected.")
                break
            self._inb_typ_hndlr(typ_pfx)

    def _inb_typ_hndlr(self, typ_pfx):
        #0
        """Called by Receiver. Routes messages based on message type.
        
        Checks messages for type. M is standard message. F is sending a file.
                C is for a controller message. A is for file acceptance. Routes
                every type to a dedicated handler.
        
        """
        typ_pfx = typ_pfx.decode().upper()

        if typ_pfx == 'M':
            # Standard message type.
            self._m_hndlr()
        elif typ_pfx == 'F':
            # For sending files.
            self._f_hndlr()
        elif typ_pfx == 'C':
            # For controller input.
            self._c_hndlr()
        elif typ_pfx == 'A':
            # For dialog messages for file sending.
            self._a_hndlr()
        elif typ_pfx == 'U':
            # Does user exist?
            self._u_hndlr()
        elif typ_pfx == 'X':
            # Transfer file.
            self._x_hndlr()
        else:
            print('-x- Unknown message type error.')

    def _m_hndlr(self):
        #0
        """Standard message. Unpacks message, and prints to own screen."""
        trim_msg = self.unpack_msg()
        self.print_message(trim_msg)

    def _f_hndlr(self):
        #0
        """File Recipient. Prompts to accept or reject. Sends response."""
        
        # Incoming filename and filesize.
        self.filesize = self.unpack_msg()    
        print(self.filesize.decode())
        print('-?- Do you want to accept this file? (Y/N)') #  TODO <-- come from server
        choice = input('>>')
        # print("Sending here, ths is fine")
        self.pack_n_send(serv_sock, 'A', choice)

        # Accept file
        if choice == 'n':
            pass
        elif choice == 'y':
            # Bring in the file!!
            pass

    def _c_hndlr(self):
        #0
        """Control messages from another user. Not displayed."""

        trim_msg = self.unpack_msg()
    
    def _a_hndlr(self):
        #0
        """Recipient Acceptance. Yes or no"""

        choice = self.unpack_msg()
        print(choice)
        print("sending")
        if choice.decode().lower() == 'y':
            print('sending')
            with open('image.jpg', 'rb') as f:
                serv_sock.send(b'X')
                serv_sock.sendfile(f, 0)
        elif choice.lower() == 'n':
            self.pack_n_send(serv_sock, 'M', '-=- Transfer Cancelled.')

    def _u_hndlr(self):
        """Receives server response from user lookup"""

        user_exists = self.unpack_msg().decode()
        print("-=- Checking recipient...")
        print(user_exists)

        if user_exists:
            self.filesize = self.get_filesize('image.jpg', serv_sock)
            msg = f"{self.filesize}"
            self.pack_n_send(serv_sock, 'F', msg)
        else:
            print("User does not exist. Try again or type 'cancel'")
            return
        
    def _x_hndlr(self):

        """File sender. Transfer handler."""

        print("Filetransfer dawg!")
        chunk = serv_sock.recv(BFFR)
        bytes_recd = len(chunk)

        with open('image[2].png', 'wb') as f:
            while bytes_recd < 78223:
                f.write(chunk)
                chunk = serv_sock.recv(BFFR)
                bytes_recd += len(chunk)

    def inp_ctrl_handler(self, msg):
        #0
        """Sorts through input control messages and calls controller funcs."""
        if type(msg) == bytes:
            msg.decode()

        if msg == '/sendfile':
            # For sending file. Call send dialog.
            self.pack_n_send(serv_sock, 'M', '/sendfile')
            print('-=- Sending file')
            fn = input('-=- Choose file name: ')
            recip = input('-=- Choose recip: ')
            self.pack_n_send(serv_sock, 'U', recip)        

    def _pfxtoint(self, client_cnxn, data, n=4):
        #1
        """Converts size prefix data to int."""
        return int(data[:n])

    # def check_user(self, user):
    #     #0
    #     """Adds U as prefix. Returns true if user is connected."""
    #     self.pack_n_send('U', user)

    def unpack_msg(self):
        #1
        """Unpacks prefix for file size, and returns trimmed message as bytes.
        
        This method does not read the message type. Call receiver() before
                invoking this method. Once the input has been routed, this
                helper function is called to unpack the already sorted user
                inputs. 
        """

        sz_pfx = serv_sock.recv(4)
        buffer = self._pfxtoint(serv_sock, sz_pfx, 4)
        trim_msg = serv_sock.recv(buffer)
        

        return trim_msg # As bytes

    def get_filesize(self, path, sock):
        """Calculates filesize of a path and sends integer."""

        with open('image.jpg', 'rb') as f:
            # self.filesize = os.path.getsize(f)
            filesize = 78223 
        return filesize

    def print_message(self, msg, style='yellow'):
        #1
        """Print message to screen.
        TODO
            add fun formatting.
            
        """

        ERASE_LINE = '\x1b[2K'
        sys.stdout.write(ERASE_LINE)

        if type(msg) == bytes:
            msg = msg.decode()
        
        print(msg)

    def start(self):
        self.t1 = Thread(target=self.receiver)
        self.t2 = Thread(target=self.sender)
        self.t1.start()
        self.t2.start()
        
if __name__ == "__main__":

    BFFR = 4096
    host = '127.0.0.1'
    # port = int(input('-=- Port, please: '))

    # DEBUG
    port = 1515

    channel = Client()

    serv_sock = socket.socket()
    serv_sock.connect((host, port))

    print(f'-+- Connected to {host}')
    # name = serv_sock.recv(BFFR)
    # print(name.decode())

    channel.start()