# File chunking: file I/O.

# Note: This code was written based on the book "Computer Networking: A Top-Down Approach" by Kurose and Ross, specifically chapter 3.4 
# 'Principles of Reliable Data Transfer', on reliable data transfer protocols (pipelined sliding window protocol). We are using Go-Back-N (GBN).

#File contains utility functions for handling file chunking and reassembly for the SRFT protocol. It serves for both sender and receiver parts of the protocol. 
# The main functions include:
# 1. for the sender side: provide functions to read a file, split it into chunks.
# 2. for the receiver side: provide functions to write the received file chunks to disk and to reassemble them into the original file.

import os
import sys
from config import MAX_PAYLOAD_SIZE

class FileHandler:
    #Create a constructor for the file handler with the output file path.
    def __init__(self):
        self.input_file = None
        self.output_file = None
        self.output_path = None
        self.file_path = None
        self.bytes_written = 0
        self.file_size = 0

## 1. Sender side: open a file, read it, split it into chunks, and create Packet objects for each chunk.
    def open_input_file(self, file_path: str):
        try:
            self.input_file = open(file_path, 'rb')
            self.file_size = os.path.getsize(file_path)
            print(f"Opened file {file_path} of size {self.file_size} bytes.")
        except Exception as e:
            print(f"Error opening file {file_path}: {e}")
            sys.exit(1)

    #Read the file and split it into chunks of the specified size.
    def read_file_chunks(self, usable_chunk_size: int):
        if self.input_file is None:
            print("File not opened. Call open_file() first.")
            return

        usable_chunk_size = min(usable_chunk_size, MAX_PAYLOAD_SIZE)  ###I am not sure if the MAX_PAYLOAD_SIZE includes the header size or not. If it does, we need to subtract the header size from the chunk size to ensure that the total packet size does not exceed the maximum allowed by our protocol.

        while True:
            chunk = self.input_file.read(usable_chunk_size)
            if not chunk:
                break
            yield chunk
            
    #Close the file after reading all chunks.    
    def close_input_file(self):
        if self.input_file is not None:
            self.input_file.close()
            self.input_file = None
    
## 2. Receiver side: write the received file chunks to disk and reassemble them into the original file.
    #Create a constructor for the file handler with the output file path.
    def open_output_file(self, output_path: str):
        self.output_file = open(output_path, "wb") #Open the file in binary write/read mode
        self.output_path = output_path
        self.bytes_written = 0

    def write_payload_chunk(self, payload: bytes, is_last_chunk: bool):
        if self.output_file is None:
            print("Output file not opened. Call open_output_file() first.")
            return
        
        if payload:
            self.output_file.write(payload)
            self.bytes_written += len(payload)
        
        #Close the file at the end and in this way flush the buffered data to disk (we don't need to call flush() on every chunk). 
        #This increases performance by reducing the number of disk writes during large transfers.
        if is_last_chunk:
            print(f"Received FIN. The transfer of file {self.output_path} complete. Total bytes written: {self.bytes_written}")
            self.output_file.close() #close() flushes Python buffer.
            self.output_file = None