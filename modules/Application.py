import random
import math

from modules.mechanisms.REPT import REPT
from modules.mechanisms.PEPT import PEPT
from modules.mechanisms.ART import ART
from modules.mechanisms.MGT import MGT

class Application(object):
    def __init__(self, env, host, start_time, stop_time, send_interval, method):
        self.env = env
        self.host = host
        self.start_time = start_time
        self.stop_time = stop_time
        self.send_interval = send_interval
        self.seq_no = 0

        self.method = method

        if method == 'ART':
            self.mechanism = ART(env, self)
        if method == 'MGT':
            self.mechanism = MGT(env, self)
        if method == 'PEPT':
            self.mechanism = PEPT(env, self)
        if method == 'REPT':
            self.mechanism = REPT(env, self)


        # Metrics
        self.detection_events = []
        self.num_malicious_packets_received = 0
        self.num_packets_received = 0
        self.num_packets_sent = 0
        self.num_packets_sent_overhead = 0 
        self.bytes_sent = 0
        self.bytes_sent_overhead = 0

        if send_interval > 0:
            self.send_action = env.process(self.send())

        self.forward_action = None

        self.lower_layer = None

    def dist(self, p1, p2):
        d = math.sqrt((p1[0] - p2[0])**2 + (p1[1] -p2[1])**2)
        return d

    def latest_position_entries(self):
        position_updates = []
        for node, update in self.host.get_active_position_table().items():
            position_updates.append({
                'id': node,
                'pos': update
            })  # only append last packet
        return position_updates


    def send(self):
        yield self.env.timeout(self.start_time)
        while True:
            pkt = {
                'seq_no': f'{self.host.transceiver.id}-{self.seq_no}',
                'size': 100,
                'created_at': self.env.now,
                'type': 'BROADCAST',
                'position_table': self.latest_position_entries(),
                'sender_pos': self.host.get_claimed_position(),
                'is_malicious': self.host.is_malicious,
            }
            if self.method == 'PEPT':
                pkt['size'] += 4 * len(pkt['position_table']) # 4 bytes for uint32_t <- we're only counting the ids
                self.bytes_sent_overhead += 4 * len(pkt['position_table']) # Excluding the base 100bytes

            self.seq_no += 1
            self.lower_layer.receive_from_upper(pkt)
            # 5s warm up period
            if self.env.now > 5.0:
                self.num_packets_sent += 1
                self.bytes_sent += pkt['size']

            yield self.env.timeout(self.send_interval)

    def set_lower_layer(self, layer):
        self.lower_layer = layer

    def receive_from_lower(self, packet):
        # 5s warm up period
        if self.env.now > 5.0:
            self.num_packets_received += 1
            if packet['type'] == 'BROADCAST' and packet['is_malicious']:
                self.num_malicious_packets_received += 1
            self.mechanism.handle_packet(packet)

        if packet['type'] == 'BROADCAST':
            self.host.update_position_table(packet['seq_no'].split("-")[0], packet['sender_pos'], packet['created_at'], self.env.now)

        # packet_type = packet['type']
        # if packet_type == 'BROADCAST':
        #     if self.method == 'ART':
        #         acceptance_range_threshold(self,packet)
        #     if self.method == 'MGT':
        #         mobility_grade_threshold(self, packet)
        #     if self.method == 'PEPT':
        #         proactive_exchange_of_position_tables(self, packet)
        #     if self.method == 'REPT':
        #         reactive_exchange_of_position_tables(self, packet)


        # # Handle position request and response packets
        # if packet['type'] == 'PREQ':
        #     handle_position_request(self, packet)
        # elif packet['type'] == 'PRES':
        #     handle_position_response(self, packet)
        # else:
        #     # Store position information from the packet
        #     self.store_packet_position_info(packet) # Used for old implementation  

        #     acceptance_range_threshold(self,packet)

        #     self.host.update_position_table(packet['seq_no'].split("-")[0], packet['sender_pos'], packet['created_at'], self.env.now)

        #     # Check if the node id is unknown or not otherwise pick a random packet
        #     if self.env.now > 1 and not any(packet['seq_no'].split("-")[0] == rcvd_packet['seq_no'].split("-")[0] for rcvd_packet in self.packet_rcvd):
                
        #     elif self.env.now - self.last_reactive_call >= 1 and random.random() < 0.3:
        #         self.last_reactive_call = self.env.now
        #         reactive_exchange_of_position_tables(self, packet)


    

   


