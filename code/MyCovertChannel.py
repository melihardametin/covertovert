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
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Binary message to send: {binary_message}")

        # Define index ranges for bursts
        index_ranges = index_range
        
        # Split binary message into chunks of 8 bits
        chunks = [binary_message[i:i + 8] for i in range(0, len(binary_message), 8)]
        print(f"Binary message chunks (8 bits each): {chunks}")

        # Process each chunk
        for chunk_index, chunk in enumerate(chunks):
            print(f"Processing chunk {chunk_index + 1}/{len(chunks)}: {chunk}")

            # Prepare the message for this chunk
            char_to_send = [(bit, idx) for idx, bit in enumerate(chunk)]

            while char_to_send:
                random_index = random.randint(0, len(char_to_send) - 1)
                selected_char = char_to_send.pop(random_index)

                index_ranges = self.shuffle_list(index_ranges, random_seed)

                bit, idx = selected_char
                i = idx * 2 + 1 if bit == "1" else idx * 2
                burst_count_range = index_ranges[i]
                burst_count = random.randint(*burst_count_range)

                print(burst_count)

                for _ in range(burst_count):
                    packet = IP(dst="172.18.0.3") / TCP(dport=8000, flags="S")
                    super().send(packet)

                random_seed += idx


                print(f"Sent burst of {burst_count} packets for bit '{bit}' (Index: {idx}) in chunk {chunk_index + 1}")
                sleep(idle_time)



    def receive(self, idle_threshold, log_file_name, index_range, random_seed):
        manager = multiprocessing.Manager()
        shared_data = manager.dict()
        shared_data['received_message'] = []
        shared_data['burst_packet_count'] = 0
        shared_data['sender_started'] = False
        shared_data['last_packet_time'] = time()
        shared_data['i'] = -1
        shared_data['received_bit_count'] = 0
        shared_data['seed'] = random_seed
        shared_data['ranges'] = index_range

        def packet_handler(packet):

            if not shared_data['sender_started']:
                shared_data['sender_started'] = True
                shared_data['last_packet_time'] = time()

            if TCP in packet:
                current_time = time()
                idle_time = current_time - shared_data['last_packet_time']

                if idle_time > idle_threshold:
                    index = None
                    bit = None

                    shared_data['ranges'] = self.shuffle_list(shared_data['ranges'], shared_data['seed'])
                    
                    for idx, (low, high) in enumerate(shared_data['ranges']):
                        if low <= shared_data['burst_packet_count'] <= high:
                            index, bit = idx // 2, idx % 2
                            break
                    
                    shared_data['seed'] = shared_data['seed'] + index

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

                shared_data['burst_packet_count'] += 1
                shared_data['last_packet_time'] = current_time
        
        # Start sniffing with socket access
        def start_sniffing():
            print("sniff started")
            sniff_socket = sniff(
                filter=f"tcp and src host 172.18.0.2 and dst port 8000",
                prn=packet_handler
            )
            print("sniff ended")

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