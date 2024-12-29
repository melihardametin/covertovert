from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
from time import time, sleep
import multiprocessing

class MyCovertChannel(CovertChannelBase):
    def __init__(self):
        super().__init__()
        
    def send(self, log_file_name, idle_time, packets_for_1, packets_for_0):
        binary_message = self.generate_random_binary_message_with_logging(log_file_name)
        print(f"Binary message to send: {binary_message}")

        for bit in binary_message:
            num_packets = packets_for_1 if bit == "1" else packets_for_0

            for _ in range(num_packets):
                packet = IP(dst="172.18.0.3") / TCP(dport=8000, flags="S")
                super().send(packet)

            print(f"Sent burst of {num_packets} packets for bit '{bit}'")
            sleep(idle_time)



    def receive(self, idle_threshold, packets_for_1, packets_for_0, log_file_name):
        manager = multiprocessing.Manager()
        shared_data = manager.dict()
        shared_data['received_message'] = ""
        shared_data['burst_packet_count'] = 0
        shared_data['sender_started'] = False
        shared_data['last_packet_time'] = time()
        

        def packet_handler(packet):

            if not shared_data['sender_started']:
                shared_data['sender_started'] = True
                shared_data['last_packet_time'] = time()

            if TCP in packet:
                current_time = time()
                idle_time = current_time - shared_data['last_packet_time']

                if idle_time > idle_threshold:
                    if shared_data['burst_packet_count'] == packets_for_1:
                        shared_data['received_message'] += "1"
                    elif shared_data['burst_packet_count'] == packets_for_0:
                        shared_data['received_message'] += "0"

                    print(f"Decoded burst: {shared_data['burst_packet_count']} packets -> '{shared_data['received_message'][-1:]}'")
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
                    if shared_data['burst_packet_count'] == packets_for_1:
                        shared_data['received_message'] += "1"
                    elif shared_data['burst_packet_count'] == packets_for_0:
                        shared_data['received_message'] += "0"

                    print(f"Decoded burst: {shared_data['burst_packet_count']} packets -> '{shared_data['received_message'][-1:]}'")
                    print("No packets received in the last 0.6 seconds. Terminating sniffing.")
                    sniff_thread.terminate()
                    break

        sniff_thread.join()

        decoded_message = "".join(
            self.convert_eight_bits_to_character(shared_data['received_message'][i:i + 8])
            for i in range(0, len(shared_data['received_message']), 8)
        )

        self.log_message(decoded_message, log_file_name)
        print(f"Received message: {decoded_message}")