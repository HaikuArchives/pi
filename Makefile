_header_dir = ./headers/
_src_dir = ./src
_links = -lpcap

all:
	gcc -o pi -D DUMP_TO_FILE=0 -D ENDIANESS=L_ENDIAN -I ${_header_dir} ${_src_dir}/*.c ${_links}

# Change L_ENDIAN to B_ENDIAN if the host system follows Big-Endian format
# Change DUMP_TO_FILE to 1 if you want to dump the captured packets to a savefile
