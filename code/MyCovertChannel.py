from CovertChannelBase import CovertChannelBase
from scapy.all import IP, TCP, send, sniff
from time import time, sleep
import threading

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
        received_message = ""
        burst_packet_count = 0
        sender_started = False
        last_packet_time = time()
        sniff_socket = None
        sender_finished = False

        def packet_handler(packet):
            nonlocal burst_packet_count, last_packet_time, received_message, sender_started

            if not sender_started:
                sender_started = True
                last_packet_time = time()

            if TCP in packet:
                current_time = time()
                idle_time = current_time - last_packet_time

                if idle_time > idle_threshold:
                    if burst_packet_count == packets_for_1:
                        received_message += "1"
                    elif burst_packet_count == packets_for_0:
                        received_message += "0"

                    print(f"Decoded burst: {burst_packet_count} packets -> '{received_message[-1:]}'")
                    burst_packet_count = 0

                burst_packet_count += 1
                last_packet_time = current_time
        

        def monitor_terminated():
            nonlocal last_packet_time, sender_started, burst_packet_count, received_message, sniff_thread, sender_finished
            while True:
                sleep(0.6)
                if sender_started and (time() - last_packet_time) > 0.6:
                    if burst_packet_count == packets_for_1:
                        received_message += "1"
                    elif burst_packet_count == packets_for_0:
                        received_message += "0"

                    print(f"Decoded burst: {burst_packet_count} packets -> '{received_message[-1:]}'")
                    print("No packets received in the last 0.6 seconds. Terminating sniffing.")
                    burst_packet_count = 0
                    sender_finished = True
                    
                    # Force close the sniffing socket
                    packet = IP(dst="172.18.0.3") / TCP(dport=8000, flags="S")
                    send(packet, iface="eth0", verbose=False)
                    

        # Start sniffing with socket access
        def start_sniffing():
            nonlocal sniff_socket
            sniff_socket = sniff(
                filter=f"tcp and src host 172.18.0.2 and dst port 8000",
                prn=packet_handler,
                timeout=40,
                stop_filter=lambda _: sender_finished
            )

        # Run sniff in a separate thread
        sniff_thread = threading.Thread(target=start_sniffing)
        sniff_thread.start()

        # Run monitor thread
        monitor_thread = threading.Thread(target=monitor_terminated)
        monitor_thread.start()

        # Wait for threads to complete
        monitor_thread.join()
        sniff_thread.join()

        # Convert binary message to readable text
        decoded_message = "".join(
            self.convert_eight_bits_to_character(received_message[i:i + 8])
            for i in range(0, len(received_message), 8)
        )

        # Log the received message
        self.log_message(decoded_message, log_file_name)
        print(f"Received message: {decoded_message}")