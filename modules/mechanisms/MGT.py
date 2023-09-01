class MGT(object):
    def __init__(self, env, application, max_speed = 33):
        self.env = env
        self.application = application
        self.host = application.host
        self.max_speed = max_speed

    def handle_packet(self, packet):
        source_node_id = packet['seq_no'].split("-")[0]
        pos = packet['sender_pos']
        created_at = packet['created_at']

        position_table = self.host.get_active_position_table()

        if source_node_id not in position_table:
            return "Node not found in position table."
        
        # Get the last and second last position
        last_position_info = position_table[source_node_id]

        # Calculate the distance 
        d = self.application.dist(last_position_info['position'], pos)
        # Calculate time difference
        t_diff = created_at - last_position_info['created_at']

        speed = d / t_diff
        
        if speed > self.max_speed:
            detection_info = {
                'detected_at': self.env.now,
                'detected_by': self.host.transceiver.id,
                'detected_node': source_node_id,
                'sender': source_node_id,
                'claimed_position_x': packet['sender_pos'][0],
                'claimed_position_y': packet['sender_pos'][1],
                'packet_created_at' : created_at,
                'speed': speed,
                'method': 'MGT'
            }
            self.application.detection_events.append(detection_info)

