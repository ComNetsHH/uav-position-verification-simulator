class PEPT(object):
    def __init__(self, env, application, max_speed = 33):
        self.env = env
        self.application = application
        self.host = application.host
        self.max_speed = max_speed

    def handle_packet(self, packet):
        source_node_id = packet['seq_no'].split("-")[0]
        pos = packet['sender_pos']
        packet_position_table = packet['position_table']
        created_at = packet['created_at']

         # Return if packet position table is empty
        if not packet_position_table:
            return

        own_position_table = self.host.get_active_position_table()

        detected_nodes = []

        # Case 1: node is in neighbors position table although (judging from my position info) he cant be
        for entry in packet_position_table:
            node_id = entry['id']

            if node_id not in own_position_table:
                continue

            last_position_update = own_position_table[node_id]

            dist_node_neighbor = self.application.dist(last_position_update['position'], pos)

            # When comparing the distance, 
            # consider that the positions were measured at different times, the nodes could have been moving in the meantime
            time_diff = abs(created_at - last_position_update['created_at']) + 1.5 # the position in my neighbors table could be 1.5 s old
            dist_buffer = time_diff * 2 * self.max_speed

            if dist_node_neighbor > self.host.transmission_range + dist_buffer:
                detected_nodes.append(node_id)
                # detection_info = {
                #     'detected_at': self.env.now,
                #     'detected_by': self.host.transceiver.id,
                #     'detected_node': node_id,
                #     'sender': source_node_id,
                #     'claimed_position_x': packet['sender_pos'][0],
                #     'claimed_position_y': packet['sender_pos'][1],
                #     'packet_created_at' : created_at,
                #     'method': 'PEPT'
                # }
                # self.application.detection_events.append(detection_info)


        # Case 2: node is not in my neighbors position table although (juding from my position info) he should
        for node_id, entry in own_position_table.items():
            node_pos = entry['position']
            ts = entry['timestamp']

            # if the update is too recent ignore, as maybe there was no chance to receive it yet
            if self.env.now - ts < 1:
                continue

            node_is_in_neighbor_list = len([x for x in packet_position_table if x['id'] == node_id]) > 0

            dist_node_neighbor = self.application.dist(node_pos, pos)

            # When comparing the distance, 
            # consider that the positions were measured at different times, the nodes could have been moving in the meantime
            time_diff = abs(created_at - entry['created_at'])
            dist_buffer = time_diff * 2 * self.max_speed

            if (dist_node_neighbor + dist_buffer <= self.host.transmission_range) and not node_is_in_neighbor_list:
                detected_nodes.append(node_id)
                # detection_info = {
                #     'detected_at': self.env.now,
                #     'detected_by': self.host.transceiver.id,
                #     'detected_node': node_id,
                #     'sender': source_node_id,
                #     'claimed_position_x': packet['sender_pos'][0],
                #     'claimed_position_y': packet['sender_pos'][1],
                #     'packet_created_at' : created_at,
                #     'method': 'PEPT'
                # }
                # self.application.detection_events.append(detection_info)
        
        # More than a third of packets are flagged, thats suspicios
        #print(len(detected_nodes), len(packet_position_table), detected_nodes)
        if len(detected_nodes) >= len(packet_position_table) / 4:
            detection_info = {
                'detected_at': self.env.now,
                'detected_by': self.host.transceiver.id,
                'detected_node': source_node_id,
                'sender': source_node_id,
                'claimed_position_x': packet['sender_pos'][0],
                'claimed_position_y': packet['sender_pos'][1],
                'packet_created_at' : created_at,
                'method': 'PEPT'
            }
            self.application.detection_events.append(detection_info)
            return
        
        for node_id in detected_nodes:
            detection_info = {
                'detected_at': self.env.now,
                'detected_by': self.host.transceiver.id,
                'detected_node': source_node_id,
                'sender': node_id,
                'claimed_position_x': packet['sender_pos'][0],
                'claimed_position_y': packet['sender_pos'][1],
                'packet_created_at' : created_at,
                'method': 'PEPT'
            }
            self.application.detection_events.append(detection_info)
