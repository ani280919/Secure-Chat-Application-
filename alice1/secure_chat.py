import socket
import sys
import ssl
from OpenSSL import crypto

class Common(object):
    """ This class contains the common functions used by both server and client
    """
    def __init__(self):
        pass
    
    def load_root_CA(self, rootCA_path):
        """ Pre loads the root CA in certificate store

        Args:
            rootCA_path (string): file path of rootCS

        Returns:
            certifcate_store
        """
        certificate_store = crypto.X509Store()
        trusted_cert = open(rootCA_path,'rt').read()
        certificate_store.add_cert(crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert))
        
        return certificate_store

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

    def verify_certificate(self, certificate, trust_store):
        """verifies the given certificate

        Args:
            certificate : certificate
            trust_store : preloaded certificates

        Returns:
            bool: tells whether certificate is valid or not
        """
        try:
            crypto.X509StoreContext(trust_store, crypto.load_certificate(crypto.FILETYPE_ASN1, certificate)).verify_certificate()
            return True
        
        except Exception as exc:
            print (exc)
            return False

class Client(Common):
    """Client class

    Args:
        Common (Class): Common functions class is inherited
    """
    def __init__(self, server_name, port_number):
        """ init class

        Args:
            server_name (string): server name
            port_number (string): port number
        """
        Common.__init__(self)
        self.server_name = server_name
        self.port_number = int(port_number)
        ip_addr = socket.gethostbyname(self.server_name)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        self.socket.connect((ip_addr, self.port_number))
        print(f"Alice> Connected to {self.server_name}")
        
        self.trust_store = self.load_root_CA("./rootCA/root.crt")       # Preload root CA 
        
        self.context = self.context_init("./alice/alice.crt", "./alice/alice.key")  # init context
        
        self.application_layer_handshake()      # TCP Handshake
        if (self.tls_handshake()):              # TLS Handshake
            self.chat()
        else:
            print("Alice> Somewhere Something went wrong. Check again!!")
    
    def application_layer_handshake(self):
        """ Performs TCP Handshake
        """
        print("Alice> Sending chat_hello")
        self.socket.sendall("chat_hello".encode('UTF-8'))
        response = self.socket.recv(1024).decode('UTF-8')
        
        if response!= "chat_reply":
            print("Alice> TCP Handshake falied")
            self.socket.close()
    
    def tls_handshake(self):
        """Performs TLS Handshake

        Returns:
            bool: if TLS Handshake is successful or not
        """
        input_str = input("Alice> ")
        self.socket.sendall(input_str.encode('UTF-8'))
        response = self.socket.recv(1024).decode('UTF-8')
        
        if response == "chat_STARTTLS_ACK":     # If Ack is recieved
            # Exchanging client, server hello's
            print("Alice> Sending client_hello")
            self.socket.sendall("client_hello".encode('UTF-8'))
            response = self.socket.recv(1024).decode('UTF-8')
            
            if response!= "server_hello":
                print("Alice> TLS Handshake failed")
                self.socket.close()
                return False
                
            print("Alice> server_hello recieved, verfying certificates")
            
            # wrapping the socket
            secure_socket = self.context.wrap_socket(self.socket, server_hostname = self.server_name)
            server_certificate = secure_socket.getpeercert(binary_form = True)    # getting the server's cert
            
            
            if self.verify_certificate(server_certificate, self.trust_store):   # verifying the recived cert
                secure_socket.sendall("Server Certificate Verification is done".encode('UTF-8'))
                response = secure_socket.recv(1024).decode('UTF-8')
                
                if response != "Client Certificate Verification is done":
                    print("Alice> Mutual Authentication failed")
                    self.socket.close()
                    secure_socket.close()
                    return False
                    
                print("Alice> " + response)
                
                self.socket = secure_socket  
                print("Alice> Handshake is completed")   
            else:
                print("Alice> Invalid Server Certificate. Handshake failed")
                self.socket.close()
                secure_socket.close()
                return False
        
        elif response == "chat_STARTTLS_NOT_SUPPORTED":     # if TLS is not supported
            print("TLS Connection is not estiblished. Chat is not secure!!")
            
        else:
            print("Alice> ERROR: 'chat_STARTTLS_ACK' not sent by server. Handshake failed")
            self.socket.close()
            return False
        
        return True
    
    def chat(self):
        print("======================= Chat Feature Activated =======================")
        
        while(True):
            input_str = input("Alice> ")
            if input_str!= "chat_close":
                self.socket.sendall(input_str.encode('UTF-8'))
                response = self.socket.recv(1024).decode('UTF-8')
                if response == "chat_close":
                    self.socket.shutdown(socket.SHUT_RDWR)
                    self.socket.close()
                    print("Bob closed the chat")
                    return 

                else:
                    print("Bob> ", response)
            
            else:       # if chat_close, then close the socket
                self.socket.sendall(input_str.encode('UTF-8'))
                self.socket.shutdown(socket.SHUT_RDWR)
                self.socket.close()
                print("Alice closed the chat")
                return
            
        
class Server(Common):
    """Server class

    Args:
        Common (Class): Common functions class is inherited
    """
    def __init__(self, port_number):
        """ init class

        Args:
            port_number (string): port number
        """
        Common.__init__(self)
        self.port_number = int(port_number)
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((socket.gethostname(), self.port_number))
        self.socket.listen()
        print("Bob> Started listening")
        
        self.connection, client_address = self.socket.accept()
        self.client_name = socket.gethostbyaddr(client_address[0])[0]
        self.trust_store = self.load_root_CA("./rootCA/root.crt")       # pre loading root CA
        
        self.context = self.context_init("./bob/bob.crt", "./bob/bob.key")  # init context
        
        self.application_layer_handshake()      # TCP Handshake
        if (self.tls_handshake()):              # TLS Handshake
            self.chat()
            
        else:
            print("Bob> Somewhere Something went wrong. Check again!!")
        
    def application_layer_handshake(self):
        """ Performs TCP Handshake
        """
        data = self.connection.recv(1024).decode('UTF-8')
        
        if data == "chat_hello":
            print("Bob> Recieved chat_hello \nBob> Sending chat_reply")
            self.connection.sendall("chat_reply".encode('UTF-8'))
            print(f"Bob> Connected to {self.client_name}")
        
        else:
            print("Bob> TCP Handshake is failed")
            self.connection.close()
            
    def tls_handshake(self):
        """Performs TLS Handshake

        Returns:
            bool: if TLS Handshake is successful or not
        """
        message = self.connection.recv(1024).decode('UTF-8')
        
        if message == "chat_STARTTLS":      # if chat_STARTTLS is recieved
            self.connection.sendall("chat_STARTTLS_ACK".encode('UTF-8'))
            
            data = self.connection.recv(1024).decode('UTF-8')

            # exchanging client, server hello's
            if data == "client_hello":
                print("Bob> Recieved client_hello \nBob> Sending server_hello")
                self.connection.sendall("server_hello".encode('UTF-8'))
            
            else:
                print("Bob> TLS Handshake failed")
                self.connection.close()
                return False
            
            print("Bob> client_hello recieved, verfying certificates")
            
            # wrapping the socket
            secure_socket = self.context.wrap_socket(self.connection, server_side = True)
            client_certificate = secure_socket.getpeercert(binary_form = True)  # getting the client's cert
            
            if self.verify_certificate(client_certificate, self.trust_store):   # verifying the recived cert
                data = secure_socket.recv(1024).decode('UTF-8')
                
                if data == "Server Certificate Verification is done":
                    print("Bob> " + data)
                    secure_socket.sendall("Client Certificate Verification is done".encode('UTF-8'))
                
                else:
                    print("Bob> Mutual Authentication failed")
                    self.connection.close()
                    secure_socket.close()
                    return False
                
                self.connection = secure_socket  
                print("Bob> Handshake is completed")                   
            
            else:
                print("Bob> Invalid Client Certificate. Handshake failed")
                self.connection.close()
                secure_socket.close()
                return False
            
        elif message == "chat_STARTNOTLS":          # if NO TLS is recieved
            self.connection.sendall("chat_STARTTLS_NOT_SUPPORTED".encode('UTF-8'))
            print("TLS Connection is not estiblished. Chat is not secure!!")
        
        else:
            print("Bob> ERROR: Send 'chat_STARTTLS' to chat securely. Handshake failed")
            self.connection.close()
            return False

        return True
    
    def chat(self):    
        print("======================= Chat Feature Activated =======================")
        while(True):
            message = self.connection.recv(1024).decode('UTF-8')

            if message!= "chat_close":
                print("Alice> ", message)
                input_str = input("Bob> ")
                self.connection.sendall(input_str.encode('UTF-8'))
                if input_str == "chat_close":
                    self.connection.shutdown(socket.SHUT_RDWR)
                    self.connection.close()
                    print("Bob closed the chat")
                    return
                
            else:        #  if chat_close, then close the socket
                self.connection.shutdown(socket.SHUT_RDWR)
                self.connection.close()
                print("Alice closed the chat")
                return
            
                 
def main():
    arg_len = len(sys.argv)
    
    if (arg_len) < 2:
        print ("secure_chat.py -c <servername> <port>/secure_chat.py -s <port>")
        sys.exit()
        
    if sys.argv[1] == '-c':
        if arg_len < 4:
            print ("Compulsory arguments for Client are not given. Please check: \nsecure_chat.py -c <servername> <port>")
            sys.exit()
        else:
            Client(sys.argv[2], sys.argv[3])         # Client Object
    
    elif sys.argv[1] == '-s':
        if arg_len < 3:
            print ("Compulsory arguments for Server are not given. Please check: \nsecure_chat.py -s <port>")
            sys.exit()
        else:
            Server(sys.argv[2])                      # Server Object
            
    else:
        print ("secure_chat.py -c <servername> <port>/secure_chat.py -s <port>")
        sys.exit()
            
main()
