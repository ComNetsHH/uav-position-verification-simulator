
def proactive_exchange_of_position_tables(self, packet):
        sender_node_id = packet['seq_no'].split("-")[0]
        sender_pos = packet['sender_pos']
        packet_position_table = packet['position_table']
        packet_created_at = packet['created_at']

        # Return if packet position table is empty
        if not packet_position_table:
            return

        # Check if any node in own position table could possibly be in senders position table
        for node_id, positions in self.host.position_table.items():
            if node_id == sender_node_id:
                continue
            # Iterate thru all positions with the same 'created_at' as the 'packet_created_at'
            for position in positions:
                if position['created_at'] == packet_created_at :
                    distance = self.dist(sender_pos, position['position'])
                    if distance < self.host.transceiver.radio_medium.radio_range * 0.98:
                        # Check if sender's position table has any entry for node_id
                        if node_id not in packet_position_table:
                            # If not, record the discrepancy
                            detection_info = {
                            'detected_at': self.env.now,
                            'claimed_position': packet['sender_pos'],                  
                            'packet': packet,
                            }
                            self.detected_nodes_PEPT.setdefault(int(sender_node_id), []).append(detection_info)
                            self.detected_packets_PEPT.append(packet)

       