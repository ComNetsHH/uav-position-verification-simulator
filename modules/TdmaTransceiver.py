class TdmaTransceiver(object):
    def __init__(self, env, host, scheduler, radio_medium, slot_duration):
        self.env = env
        self.host = host
        self.radio_medium = radio_medium
        self.scheduler = scheduler
        self.slot_duration = slot_duration

        self.upper_layer = None
        self.id = self.scheduler.register(self)
        self.radio_medium.register(self)

        self.queue = []

    def set_upper_layer(self, layer):
        self.upper_layer = layer

    def receive_from_upper(self, packet):
        self.queue.append(packet)
        self.scheduler.report_buffer_status(self.id, len(self.queue))

    def receive_from_lower(self, packet):
        self.upper_layer.receive_from_lower(packet)

    def set_schedule(self, schedule):
        self.schedule = schedule
        self.action = self.env.process(self.run())

    def send(self, pkt):
        self.radio_medium.receive_from_upper(self, pkt)
        
    def run(self):
        slot_idx = 0
        while True:
            if slot_idx >= len(self.schedule):
                return
            if self.schedule[slot_idx] == self.id and len(self.queue) > 0:
                pkt = self.queue[0]
                self.queue = self.queue[1:]
                self.send(pkt)
            yield self.env.timeout(self.slot_duration) 
            slot_idx += 1