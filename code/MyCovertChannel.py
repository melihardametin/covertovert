from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
from time import time, sleep
import multiprocessing
import random

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        
    def send(self, log_file_name, idle_time):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Binary message to send: {binary_message}")

        # Define index ranges for bursts
        index_ranges = [(1, 3), (4, 6), (7, 9), (10, 12), (13, 15), (16, 18), (19, 21), (22, 24),
                        (25, 27), (28, 30), (31, 33), (34, 36), (37, 39), (40, 42), (43, 45), (46, 48)]
        
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

                bit, idx = selected_char
                i = idx * 2 + 1 if bit == "1" else idx * 2
                burst_count_range = index_ranges[i]
                burst_count = random.randint(*burst_count_range)

                print(burst_count)

                for _ in range(burst_count):
                    packet = IP(dst="172.18.0.3") / TCP(dport=8000, flags="S")
                    super().send(packet)

                print(f"Sent burst of {burst_count} packets for bit '{bit}' (Index: {idx}) in chunk {chunk_index + 1}")
                sleep(idle_time)



    def receive(self, idle_threshold, log_file_name):
        manager = multiprocessing.Manager()
        shared_data = manager.dict()
        shared_data['received_message'] = []
        shared_data['burst_packet_count'] = 0
        shared_data['sender_started'] = False
        shared_data['last_packet_time'] = time()
        shared_data['i'] = -1
        shared_data['received_bit_count'] = 0
        
        index_ranges = [(1, 3), (4, 6), (7, 9), (10, 12), (13, 15), (16, 18), (19, 21), (22, 24),
                        (25, 27), (28, 30), (31, 33), (34, 36), (37, 39), (40, 42), (43, 45), (46, 48)]

        def find_index_and_bit(burst_count):
            for idx, (low, high) in enumerate(index_ranges):
                if low <= burst_count <= high:
                    return idx // 2, idx % 2
            return None, None

        def packet_handler(packet):

            if not shared_data['sender_started']:
                shared_data['sender_started'] = True
                shared_data['last_packet_time'] = time()

            if TCP in packet:
                current_time = time()
                idle_time = current_time - shared_data['last_packet_time']

                if idle_time > idle_threshold:
                    
                    index, bit = find_index_and_bit(shared_data['burst_packet_count'])
                    print(index, bit)

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
                sleep(0.6)
                if shared_data['sender_started'] and (time() - shared_data['last_packet_time']) > 0.6:
                    index, bit = find_index_and_bit(shared_data['burst_packet_count'])
                    print(index, bit)

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