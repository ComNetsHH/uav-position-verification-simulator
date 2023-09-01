
def reactive_exchange_of_position_tables(self, packet):
    suspect_node_id = packet['seq_no'].split("-")[0]
    acceptors, rejectors = set_acc_rej(self, packet)
    if suspect_node_id not in self.verification_data:
        self.verification_data[suspect_node_id] = {
            'acceptors': [], 
            'rejectors': [], 
            'discrepancies': [],
            'responses': [], 
            'label': True, # False if majority of responses don't match
            'verification_at': self.env.now
            }
    self.verification_data[suspect_node_id]["acceptors"] = acceptors
    self.verification_data[suspect_node_id]["rejectors"] = rejectors

    pkt = {
        'seq_no': f'{self.host.transceiver.id}-{self.seq_no}',
        'size': 10,
        'created_at': self.env.now,
        'type': 'PREQ',
        'suspicious_node_id': suspect_node_id,  # Node ID of the suspect node
        'requester_node_id': self.host.transceiver.id,  # Node ID of the requester node
    }

    # Stop verification if no acceptor at all
    if acceptors != []:
        return
    
    self.transmission_dist_from_sender.append(0)
    self.seen_seq_nos.append(pkt['seq_no'])
    self.seq_no += 1
    self.lower_layer.receive_from_upper(pkt)
    self.num_packet_sent += 1
    self.packet_sent.append(pkt)

def handle_position_request(self, packet):
        # Retrieve the requested position records
        suspicious_node_id = packet['suspicious_node_id']

        # Check if the response packet for the suspicious_node_id was sent within the last second
        last_pos_response_time = self.last_pos_response_times.get(suspicious_node_id, None)
        if last_pos_response_time is not None and self.env.now - last_pos_response_time < 1:
            return  # Do not send a response
    
        if suspicious_node_id in self.host.position_table:
            positions = self.host.position_table[suspicious_node_id]

            # Create a position response packet
            pres_packet = {
                'seq_no': f'{self.host.transceiver.id}-{self.seq_no}',
                'size': 10,
                'created_at': self.env.now,
                'type': 'PRES',
                'suspicious_node_id': suspicious_node_id,
                'requester_id': packet['requester_node_id'],
                'positions': positions,
            }

            # pres_packet['dest'] = packet['requester_node_id']  # Set the destination
            self.transmission_dist_from_sender.append(0)
            self.seen_seq_nos.append(pres_packet['seq_no'])
            self.seq_no += 1
            self.lower_layer.receive_from_upper(pres_packet)  # Send the packet
            self.num_packet_sent += 1
            self.packet_sent.append(pres_packet)
            self.last_pos_response_times[suspicious_node_id] = self.env.now  # Update the last response time

def handle_position_response(self, packet):
    suspicious_node_id = packet['suspicious_node_id']
    sender_node_id = packet['seq_no'].split("-")[0]

    # If there's no verification data for the suspicious node, return
    if suspicious_node_id not in self.verification_data:
        return

    # If the sender node is neither an acceptor nor a rejector for the suspicious node, return
    if sender_node_id not in self.verification_data[suspicious_node_id]['acceptors'] and sender_node_id not in self.verification_data[suspicious_node_id]['rejectors']:
        return

    # Check if any of the positions in the packet were created within the last second or two
    recent_position_exists = any(abs(position['created_at'] - self.verification_data[suspicious_node_id]['verification_at']  ) <= 2 for position in packet['positions'])
    
    self.verification_data[suspicious_node_id]['responses'].append(packet)

    # Check if acceptor has sent any position data
    if (sender_node_id in self.verification_data[suspicious_node_id]['acceptors'] and not recent_position_exists):#packet['positions'] == []):
        # If there are no acceptor position records, add the packet to the 'discrepancies' list for the suspicious node
        self.verification_data[suspicious_node_id]['discrepancies'].append(packet)
        evaluate_majority_label(self, suspicious_node_id)
        return
    
    # Check if rejectors has sent any position data
    if (sender_node_id in self.verification_data[suspicious_node_id]['rejectors'] and recent_position_exists):#packet['positions'] != []):
        # If there are no acceptor position records, add the packet to the 'discrepancies' list for the suspicious node
        self.verification_data[suspicious_node_id]['discrepancies'].append(packet)
        evaluate_majority_label(self, suspicious_node_id)
        return
        

def set_acc_rej(self, packet):
    # Get the suspicious node's ID and position at packet creation time
    suspect_node_id = packet['seq_no'].split("-")[0]
    packet_created_at = packet['created_at']
    suspect_node_positions = self.host.position_table[suspect_node_id]
    suspect_node_position_at_time = next((position for position in suspect_node_positions if position['created_at'] == packet_created_at), None)
    
    if suspect_node_position_at_time is None:
        print(f"No position found for node {suspect_node_id} at time {packet_created_at}")
        return [], []

    # Initialize acceptor and rejector lists
    acceptors = []
    rejectors = []

    # Go through all known nodes in the position table
    for node_id, positions in self.host.position_table.items():
        # If the node is the same as the suspect node, skip this iteration
        if node_id == suspect_node_id:
            continue

        # Get the position of the current node at the packet creation time
        node_position_at_time = next((position for position in positions if position['created_at'] == packet_created_at), None)

        # If no position found for this node at the packet creation time, skip this iteration
        if node_position_at_time is None:
            continue

        # Calculate the distance between the suspicious node and current node
        distance = self.dist(suspect_node_position_at_time['position'], node_position_at_time['position'])

        # Classify the node as acceptor or rejector
        if distance <= self.host.transceiver.radio_medium.radio_range*0.98:
            acceptors.append(node_id)
        else:
            rejectors.append(node_id)

    return acceptors, rejectors

def evaluate_majority_label(self, suspicious_node_id):
    # Retrieve the verification data for the suspicious node
    suspicious_node_data = self.verification_data[suspicious_node_id]
    total_neighbors = len(suspicious_node_data['acceptors']) + len(suspicious_node_data['rejectors'])
    total_discrepancies = len(suspicious_node_data['discrepancies'])
    total_responses = len(suspicious_node_data['responses'])

    # If more than half of the neighbors reported discrepancies, the label is False (i.e., the node is malicious)
    if total_discrepancies > total_responses / 2 and total_responses > 1:
        suspicious_node_data['label'] = False
    else:
        suspicious_node_data['label'] = True    

    # Otherwise, the label remains True 