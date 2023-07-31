# Secure-Chat-Application-
## To run Task 2
------------------------------------------------------------------------------------------------------------------------------------------------------

**<ins>Bob:</ins>**

run `make`

or

run `python3 secure_chat.py -c $(SERVER_NAME) $(PORT)`

**<ins>Alice:</ins>**

run `make`

or

run `python3 secure_chat.py -s $(PORT)`

------------------------------------------------------------------------------------------------------------------------------------------------------

## To run Task 3
First run `bash ~/poison-dns-alice1-bob1.sh`

**<ins>Trudy:</ins>**

run `make downgrade`

or

run `python3 secure_chat_interceptor.py -d $(CLIENT_NAME) $(SERVER_NAME) $(PORT)`

**<ins>Bob:</ins>**

run `make`

or

run `python3 secure_chat.py -s $(PORT)`

**<ins>Alice:</ins>**

run `make`

or

run `python3 secure_chat.py -c $(SERVER_NAME) $(PORT)`

---------------------------------------------------------------------------------------------------------------------------------------------------
## To run Task 4
First run `bash ~/poison-dns-alice1-bob1.sh`

**<ins>Bob:</ins>**

run `make`

or

run `python3 secure_chat.py -c $(SERVER_NAME) $(PORT)`

**<ins>Alice:</ins>**

run `make`

or

run `python3 secure_chat.py -s $(PORT)`



**<ins>Trudy:</ins>**

run `make mitm`

or

run `python3 secure_chat_interceptor.py -m $(CLIENT_NAME) $(SERVER_NAME) $(PORT)`

---------------------------------------------------------------------------------------------------------------------------------------------------


## Files Delivered:
* **alice1**
    * alice folder 
        * alice.csr
        * alice.crt
        * alice.key
    * Makefile - makefile to run the client
    * rootCA folder
        * root.crt
    * secure_chat.py

* **bob1**
    * bob folder 
        * bob.csr
        * bob.crt
        * bob.key
    * Makefile - makefile to run the server
    * rootCA folder
        * root.crt
    * secure_chat.py

* **trudy1**
    * fakealice folder 
        * fakealice.csr
        * fakealice.crt
        * fakealice.key
    * fakebob folder 
        * fakebob.csr
        * fakebob.crt
        * fakebob.key
    * Makefile - makefile to run the server
    * rootCA folder
        * root.crt
        * root.key
    * secure_chat_interceptor.py
* **pcap** - contains the pcap traces
	*task2_tls 
	*task2_notls
	*task3
	*task4
* **rootCA**
	*root.crt
	*root.key
