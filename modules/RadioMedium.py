import math, random

class RadioMedium(object):
    def __init__(self, env, radio_range, per = 0):
        self.env = env
        self.radio_range = radio_range
        self.radios = []
        self.radio_propagation = 300000000
        self.transmission_delay = 0.001
        self.packet_error_rate = per
        self.total_delays = []

    def register(self, radio):
        self.radios.append(radio)

    def dist(self, source, dest):
        p1 = source.host.get_position()
        p2 = dest.host.get_position()
        d = math.sqrt((p1[0] - p2[0])**2 + (p1[1] -p2[1])**2)
        return d

    def receive_from_upper(self, source, packet):
        # find all neighbors, 
        # calc reception times
        receivers = []
        for r in self.radios:
            dist = self.dist(source, r)
            if source.id != r.id and dist <= self.radio_range:
                receivers.append((dist, r))

        self.env.process(self.on_transmit(packet, receivers))

    def on_transmit(self, packet, receivers):
        receivers.sort(key=lambda tup: tup[0])
        idx = 0
        total_delay = 0
        while True:
            if idx >= len(receivers):
                self.total_delays.append(total_delay)  # Store the total delay for this transmission
                return
            delay = self.transmission_delay + (receivers[idx][0] / self.radio_propagation)
            total_delay += delay
            yield self.env.timeout(delay)
            if random.random() >= self.packet_error_rate:
                receivers[idx][1].receive_from_lower(packet)
            idx += 1

        
