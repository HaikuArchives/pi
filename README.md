## pi

"pi" is a user level packet injector that uses libpcap to inject and read packets. It can be used for the purpose for testing the network stack. At present it can only deal with ipv4 tcp packets. Extensions to other protocols will be added. You will need to know the mac address, ipv4 address and port number for both source and destination.

**My setup as an example**

I am using pi to test the tcp stack for Haiku OS. My host system is ubuntu 14.04 and I am running Haiku inside Virtual Box. By default virtual box had set up a NAT (network address translation) service for Haiku to use. I changed it to a Bridged adapter using Settings->Network->AdapterType so that Haiku is treated like a remote machine and there are no problems with packet injection.

The virtual box assigns a MAC address to the virtual machines which can be viewed under Settings->Network->Advanced. Once Haiku is running, I can use ifconfig to check the ip address assigned to it.

I use Haiku as a tcp server. There are number of applications one can use for that purpose. I prefer netcat or "nc" (nc -nvvlp "port" will start a tcp server at the specified port). Or even better, I use "tcptester" which comes with Haiku. It allows me to requests packets of certain sizes and characteristics from the server. My host linux system serves as a fake tcp client and I use it to make requests to the server and then inject artifical replies or new data as per the test I am running.

Link to a demo video: https://www.youtube.com/watch?v=FDN1i80neLI&feature=youtu.be

**To run pi**
>Clone the repository to your local system  
>Open terminal and cd into the cloned directory  
>Type "make" to compile (pre-requisite: libpcap version > 1.0)  
>Run the script "creat_config" and answer the questions that follows  
>Type "./pi <interface_name> <test_number>" (run with sudo if any problem)  

Check pi_test.h for the available test cases and their corresponding test numbers.
If you are on a machine that uses big-endian format or you wish to save the captured packets in a format that is readable by applications such as Wireshark, you can make the appropriate changes in the Makefile (instructions on how to do so are present).

If the socket descriptor for only one end exists and you are faking it from the other end (usually the case with testing), you may want to stop your host system from sending automatic resets (RST tcp packets). On linux it can be acheived by issuing:

`sudo iptables -A OUTPUT -p tcp -o <interface> --sport <fake_end_port_number> --tcp-flags RST RST -j DROP`

**To write a new test**

Say you want to write a new test for tcp persist, then:
1. Open pi_test.h and define a new macro for your test, e.g. #define TEST_PERSIST 10 (the number should be unique)
2. In the same file provide the declaration for the function that will be handling it, e.g. int test_persist(pcap_t* handle);
3. Open main.c, scroll down to the switch case and add a case for your test, e.g. case TEST_PERSIST: rt = test_persist(handle);
4. Open test.c, code the function that you declared in step 2
