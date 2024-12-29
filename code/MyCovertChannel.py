from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
from time import time, sleep
import multiprocessing
import random

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()

    def shuffle_list(self, range_list, seed):
        # This function basically shuffles the list based on the given seed
        random.seed(seed)
        random.shuffle(range_list)
        return range_list
        
    def send(self, log_file_name, idle_time, index_range, random_seed):
        # Create random binary mesage
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)

        index_ranges = index_range
        
        # Split binary message into chunks of 8 bits (process string with chunks)
        chunks = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
        print(f"Binary message chunks (8 bits each): {chunks}")

        # Process each chunk
        for chunk_index, chunk in enumerate(chunks):
            # Prepare a list with ("bit value either 0 or 1", index of the bit). Also enumerate them.
            char_to_send = [(bit, idx) for idx, bit in enumerate(chunk)]

            # Since we pop the processed bit from the list loop over until the char_to_send is empty
            while char_to_send:
                # Randomly choose which bit will be processed
                random_index = random.randint(0, len(char_to_send) - 1)
                selected_char = char_to_send.pop(random_index)

                # Shuffle the index_range list. This list will provide a guide for encoding and decoding of burst count
                index_ranges = self.shuffle_list(index_ranges, random_seed)

                # Extract bit value (either "1" or "0")
                bit, idx = selected_char

                # Compute the corresponding burst range index
                # Meanings of this ranges are shown below:
                # index_range = [(0th is "0"),(0th is "1"),(1th is "0"),(1th is "1"), .... ,(15th is "0"), (15th is "1")]
                i = idx * 2 + 1 if bit == "1" else idx * 2
                burst_count_range = index_ranges[i]

                # From the chosen burst range pick a burst count randomly
                burst_count = random.randint(*burst_count_range)

                # Send bursts
                for _ in range(burst_count):
                    packet = IP(dst="172.18.0.3") / TCP(dport=8000, flags="S")
                    super().send(packet)

                # Increase the random_seed based on randomly choosen index (idx which is chosen on line 35-36 and extracted on line 42)
                # This increase will be also applied in the receiver

                # Sleep for a little time
                sleep(idle_time)



    def receive(self, idle_threshold, log_file_name, index_range, random_seed):
        manager = multiprocessing.Manager()
        shared_data = manager.dict()

        # Declaration of the shared variables for processes
        shared_data['received_message'] = []
        shared_data['burst_packet_count'] = 0
        shared_data['sender_started'] = False
        shared_data['last_packet_time'] = time()
        shared_data['i'] = -1
        shared_data['received_bit_count'] = 0
        shared_data['seed'] = random_seed
        shared_data['ranges'] = index_range

        def packet_handler(packet):
            
            # This part is for the first packet to initialzie packet time and start of the packet handling
            if not shared_data['sender_started']:
                shared_data['sender_started'] = True
                shared_data['last_packet_time'] = time()

            if TCP in packet:
                current_time = time()
                idle_time = current_time - shared_data['last_packet_time']

                if idle_time > idle_threshold:
                    index = None
                    bit = None

                    # Shuffle the range list as done in the sender
                    shared_data['ranges'] = self.shuffle_list(shared_data['ranges'], shared_data['seed'])


                    # Get the corresponding index and bit value
                    for idx, (low, high) in enumerate(shared_data['ranges']):
                        if low <= shared_data['burst_packet_count'] <= high:
                            index, bit = idx // 2, idx % 2
                            break
                    
                    # Increment the seed with same value as sender (index value of the sended/received bit)
                    shared_data['seed'] = shared_data['seed'] + index

                    if index is not None:
                        if shared_data['received_bit_count'] % 8 == 0:
                            # If the received bit count is multiple of 8 that means it is the starting
                            # bit of the upcoming char. So increment the i (char index) with 1.
                            # Also allocate new space for upcoming char.
                            shared_data['i'] = shared_data['i'] + 1
                            shared_data['received_message'] += 8 * [None]

                        # Increment bit count
                        shared_data['received_bit_count'] = shared_data['received_bit_count'] + 1

                        msg = shared_data['received_message']

                        # i*8 because every char is 8 bit. Then add index to insert bit to correct position.
                        msg[shared_data['i']*8+index] = str(bit)
                        shared_data['received_message'] = msg

                    # Reset burst count
                    shared_data['burst_packet_count'] = 0


                # Increment burst count and update last package time
                shared_data['burst_packet_count'] += 1
                shared_data['last_packet_time'] = current_time
        
        def start_sniffing():
            print("sniff started")
            sniff_socket = sniff(
                filter=f"tcp and src host 172.18.0.2 and dst port 8000",
                prn=packet_handler
            )

        sniff_thread = multiprocessing.Process(target=start_sniffing, args=())
        sniff_thread.start()

        while True:
                sleep(0.3)
                if shared_data['sender_started'] and (time() - shared_data['last_packet_time']) > 0.6:
                    index = None
                    bit = None

                    shared_data['ranges'] = self.shuffle_list(shared_data['ranges'], shared_data['seed'])
                    
                    for idx, (low, high) in enumerate(shared_data['ranges']):
                        if low <= shared_data['burst_packet_count'] <= high:
                            index, bit = idx // 2, idx % 2
                            break

                    if index is not None:
                        if shared_data['received_bit_count'] % 8 == 0:
                            shared_data['i'] = shared_data['i'] + 1
                            shared_data['received_message'] += 8 * [None]
                        print(shared_data['i'])
                        shared_data['received_bit_count'] = shared_data['received_bit_count'] + 1
                        msg = shared_data['received_message']
                        msg[shared_data['i']*8+index] = str(bit)
                        shared_data['received_message'] = msg
                        print(f"Decoded burst: {shared_data['burst_packet_count']} packets -> Bit '{bit}' (Index: {index})")
                        print(shared_data['received_message'])

                    shared_data['burst_packet_count'] = 0

                    print("No packets received in the last 0.6 seconds. Terminating sniffing.")
                    sniff_thread.terminate()
                    break

        sniff_thread.join()

        msg = "".join(shared_data['received_message'])
        decoded_message = "".join(
            self.convert_eight_bits_to_character(msg[i:i + 8])
            for i in range(0, len(msg), 8)
        )

        self.log_message(decoded_message, log_file_name)
        print(f"Received message: {decoded_message}")