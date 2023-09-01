class ART(object):
    def __init__(self, env, application, range_factor = 1.05):
        self.env = env
        self.application = application
        self.host = application.host
        self.range_factor = range_factor

    def handle_packet(self, packet):
        source_node_id = packet['seq_no'].split("-")[0]
        created_at = packet['created_at']

        p = self.host.get_position()

        # Compare the distance from the position claim in the packet to the self pos
        d = self.application.dist(packet['sender_pos'], p)
        
        if d > self.host.transmission_range * self.range_factor:
            detection_info = {
                'detected_at': self.env.now,
                'detected_by': self.host.transceiver.id,
                'detected_node': source_node_id,
                'sender': source_node_id,
                'claimed_position_x': packet['sender_pos'][0],
                'claimed_position_y': packet['sender_pos'][1],
                'packet_created_at' : created_at,
                'distance': d,
                'method': 'ART'
            }
            self.application.detection_events.append(detection_info)
