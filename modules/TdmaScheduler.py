import matplotlib.pyplot as plt
import numpy as np
import random

class TdmaScheduler(object):
    radio_idx = 0
    def __init__(self, env, nodes, slot_duration, frame_length):
        self.env = env
        self.slot_duration = slot_duration
        self.frame_length = frame_length
        self.radios = []
        self.buffer_status = dict()
        self.buffer_log = dict()
        self.nodes = nodes

        self.action = env.process(self.run())

        self.utilization = []

    def run(self):
        while True:
            yield self.env.timeout(self.slot_duration * self.frame_length)
            self.compute_schedule()

    def compute_schedule(self):
        if(len(self.radios) == 0):
            return

        schedule = [-1 for x in np.zeros(self.frame_length)]
        schedule_idx = 0
        node_idx = random.randint(0, len(self.radios)-1)
        total_buffer_status = sum(self.buffer_status.values())
        slots_to_schedule = min(total_buffer_status, self.frame_length)

        u = slots_to_schedule / self.frame_length
        t = self.env.now
        self.utilization.append((t,u))

        while schedule_idx < slots_to_schedule:
            node_buffer_status = self.buffer_status[node_idx]
            if node_buffer_status > 0:
                schedule[schedule_idx] = node_idx
                self.buffer_status[node_idx] -=1
                schedule_idx += 1
                node_idx = (node_idx + 1) % (len(self.radios))
            else:
                node_idx = (node_idx + 1) % (len(self.radios))

        for r in self.radios:
            r.set_schedule(schedule)

    def register(self, radio):
        self.radios.append(radio)
        idx = TdmaScheduler.radio_idx
        TdmaScheduler.radio_idx += 1
        self.buffer_status[idx] = 0
        return idx

    def report_buffer_status(self, id, buffer_status):
        self.buffer_status[id] = buffer_status
        # Update buffer log with new buffer status
        if id not in self.buffer_log:
            self.buffer_log[id] = [buffer_status]
        else:
            self.buffer_log[id].append(buffer_status)

    # def plot_avg_buffer_status(self):
    #     # Calculate average buffer status
    #     avg_buffer_status = {}
    #     for id, buffer_status in self.buffer_log.items():
    #         avg_buffer_status[id] = sum(buffer_status) / len(buffer_status)
        
    #     # Prepare the data
    #     radio_ids = sorted(avg_buffer_status.keys())
    #     avg_buffer_statuses = [avg_buffer_status[radio_id] for radio_id in radio_ids]
        
    #     # Create the plot
    #     plt.figure(figsize=(15, 8))  
    #     plt.bar(range(len(radio_ids)), avg_buffer_statuses, tick_label=radio_ids)
    #     plt.title('Average Buffer Status for Each Node')
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Average Buffer Status')
    #     plt.xticks(rotation=45, fontsize=8)
    #     plt.grid(False)
    #     plt.tight_layout()
    #     plt.savefig(f"avg_buffer_status_T{self.env.now}_N{len(self.nodes)}_FL{self.frame_length}.png", dpi=300)
    #     plt.close()


