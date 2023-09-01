import random

class REPT(object):
    def __init__(self, env, application, max_speed = 33):
        self.env = env
        self.application = application
        self.host = application.host
        self.max_speed = max_speed
        self.audit_time = 0.5 # 0.5 second audit time

        # Data to remember for my own audit
        self.current_audit_id = None
        self.rejectors = []
        self.acceptors = []
        self.responses = []

    def handle_packet(self, packet):
        packet_type = packet['type']

        if packet_type == 'BROADCAST':
            self.handle_broadcast(packet)

        if packet_type == 'PREQ':
            self.handle_PREQ(packet)

        if packet_type == 'PRES':
            self.handle_PRES(packet)

    def handle_broadcast(self, packet):
        sender_node_id = packet['seq_no'].split("-")[0]
        sender_pos = packet['sender_pos']

        # if there is already another exchange going on, dont bother
        if self.current_audit_id:
            return

        position_table = self.host.get_active_position_table()

        # if this is a new node start audit
        if sender_node_id not in position_table:
            self.audit(sender_node_id, sender_pos)
            return

        if random.random() < 0.3:
            self.audit(sender_node_id, sender_pos)


        
    def audit(self, node_id, sender_pos):
        self.current_audit_id = node_id

        # Send preq
        self.send_PREQ(node_id, sender_pos)

        # wait for audit to expire
        self.env.process(self.on_audit_expire())


    def on_audit_expire(self):
        yield self.env.timeout(self.audit_time)

        votes_is_malicious = 0
        votes_is_genuine = 0

        # process all received responses
        for response in self.responses:
            neighbor_id = response['seq_no'].split("-")[0]
            message_received = response['message_received']

            if neighbor_id in self.acceptors:
                if message_received:
                    votes_is_genuine += 1
                else:
                    votes_is_malicious += 1

            if neighbor_id in self.rejectors:
                if message_received:
                    votes_is_malicious += 1
                else:
                    votes_is_genuine += 1
            
        num_reqs = len(self.rejectors) + len(self.acceptors)
        num_votes = votes_is_malicious + votes_is_genuine

        is_malicious = votes_is_malicious > 1

        if is_malicious:
            detection_info = {
                'detected_at': self.env.now,
                'detected_by': self.host.transceiver.id,
                'detected_node': self.current_audit_id,
                'votes_is_malicious': votes_is_malicious,
                'votes_is_genuine': votes_is_genuine,
                'method': 'REPT'
            }
            self.application.detection_events.append(detection_info)

        # clean up
        self.rejectors = []
        self.acceptors = []
        self.responses = []
        self.current_audit_id = None

    def handle_PREQ(self, packet):
        node_id = packet['node_id']
        acceptors = packet['acceptors']
        rejectors = packet['rejectors']

        my_id = f'{self.host.transceiver.id}'

        if my_id in rejectors:
            position_table = self.host.get_active_position_table()
            if node_id in position_table:
                ts = position_table[node_id]['timestamp']
                age = self.env.now - ts
                is_expired = age > 0.5
                if not is_expired:
                    self.send_PRES(node_id,  True)

        if my_id in acceptors:
            position_table = self.host.get_active_position_table()
            if node_id not in position_table:
                self.send_PRES(node_id,  False)  
                return

            ts = position_table[node_id]['timestamp']
            age = self.env.now - ts
            is_expired = age > 0.5
            if is_expired:
                self.send_PRES(node_id, False)  



    def handle_PRES(self, packet):
        if packet['node_id'] == self.current_audit_id:
            self.responses.append(packet)

    def send_PRES(self, node_id, message_received):
        pres_packet = {
            'seq_no': f'{self.host.transceiver.id}-XX',
            'type': 'PRES',
            'node_id': node_id,
            'message_received': message_received
        }

        # Calculate the packet cost
        packet_cost = 0
        packet_cost = 4 + 4 + 1  # seq_no, node_id, and combined type & message_received costs respectively

        self.application.num_packets_sent_overhead += 1
        self.application.bytes_sent_overhead += packet_cost
        self.application.lower_layer.receive_from_upper(pres_packet)  # Send the packet

    def send_PREQ(self, node_id, sender_pos):
        position_table = self.host.get_active_position_table()

        acceptors = []
        rejectors = []

        for neighbor_id, entry in position_table.items():
            neighbor_pos = entry['position']
            position_age = self.env.now - entry['created_at']

            if node_id == neighbor_id:
                continue

            dist = self.application.dist(neighbor_pos, sender_pos)

            min_dist = dist - position_age * self.max_speed
            max_dist = dist + position_age * self.max_speed

            if min_dist > self.host.transmission_range:
                rejectors.append(neighbor_id)

            if max_dist < self.host.transmission_range:
                acceptors.append(neighbor_id)

        preq_packet = {
            'seq_no': f'{self.host.transceiver.id}-XX',
            'type': 'PREQ',
            'node_id': node_id,
            'acceptors': acceptors,
            'rejectors': rejectors
        }

        # Calculate the packet cost
        packet_cost = 0
        packet_cost = 4 + 1 + 4  # seq_no, type, and node_id costs respectively
        packet_cost += 4 * len(acceptors)  # Cost for each acceptor
        packet_cost += 4 * len(rejectors)  # Cost for each rejector

        self.application.num_packets_sent_overhead += 1
        self.application.bytes_sent_overhead += packet_cost
        self.application.lower_layer.receive_from_upper(preq_packet)  # Send the packet

        self.acceptors = acceptors
        self.rejectors = rejectors

