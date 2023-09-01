import math
import random

from modules.Application import Application
from modules.TdmaTransceiver import TdmaTransceiver
from modules.Position import Position



class Node(object):
    def __init__(self, env, sim_size, pos, scheduler, radio_medium, method='ART', lying_intensity=0):
        self.position = Position(env, pos, -sim_size/2, sim_size/2, -sim_size/2, sim_size/2)
        self.env = env
        self.transmission_range = radio_medium.radio_range

        self.lying_intensity = lying_intensity
        self.is_malicious = lying_intensity > 0

        self.time_to_forget = 1.5 # forget position of node after 1.5 seconds
        
        self.own_position_history = []  # store own position history
        self.position_table = {} 

        send_interval = 0.5
 
        self.application = Application(env, self, random.uniform(0, 5), math.inf, send_interval, method)
        self.transceiver = TdmaTransceiver(env, self, scheduler, radio_medium, scheduler.slot_duration)

        # Wire up
        self.application.set_lower_layer(self.transceiver)
        self.transceiver.set_upper_layer(self.application)

    def update_position_table(self, node_id, pos, creation_time, timestamp):
        self.position_table[node_id] = {'position': pos, 'created_at': creation_time, 'timestamp': timestamp}


    def get_active_position_table(self):
        return {id: entry for id, entry in self.position_table.items() if entry['timestamp'] > self.env.now - self.time_to_forget}

    def get_position(self):
        return self.position.get_position()

    def get_claimed_position(self):
        (x,y) = self.get_position()
        R = math.sqrt(random.random()) * self.lying_intensity
        phi = random.uniform(0, 2 * math.pi)
        x_new = x + math.cos(phi) * R
        y_new = y + math.sin(phi) * R
        return (x_new, y_new)