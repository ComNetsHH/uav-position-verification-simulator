import simpy
import random
import math
import random
import os, sys, json
import polars as pl
import numpy as np

from modules.Node import Node
from modules.TdmaScheduler import TdmaScheduler
from modules.RadioMedium import RadioMedium
from modules.Evaluation import Evaluation

def get_params(run_idx = 0):
    v = 'v018'
    params = []

    for per in [0, 0.1, 0.5]:
        for rep in range(2):
            for num_malicious in [60, 30, 15]:
                #for lying_intensity in np.arange(0, 505, 5):
                for lying_intensity in [0, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50, 75, 100, 125, 150, 175, 200, 300, 400, 500]:
                    for method in ['ART', 'MGT', 'PEPT', 'REPT']:
                        params.append({
                            'v': v,
                            'per': per,
                            'rep': rep,
                            'lying_intensity': lying_intensity,
                            'method': method,
                            'num_malicious': num_malicious
                        })
    print(f'running {run_idx} of {len(params)}')
    return params[run_idx]

def monitor(env, nodes, simtime, scheduler):
    idx = 1
    steps = 10
    while True:
        yield env.timeout(simtime / steps)
        print("Progress: ", f'{idx * 100 / steps:.2f}%')
        idx += 1
        print('Scheduler utilization:', scheduler.utilization[-1][1])

def main(rep = 0, v = '001', detection_mechanism = 'REPT', lying_intensity = 100, per=0, num_malicious= 60):

    study_name = f'./res/v{v}'
    os.makedirs(study_name, exist_ok=True)

    fname = f'{detection_mechanism}_l{lying_intensity}_m{num_malicious}_per{int(per*100)}_r{rep}'

    # If results already exist abort
    if os.path.isfile(f'{study_name}/summary-{fname}.json'):
        return

    sim_time = 10
    no_of_nodes, frame_length = 300, 100

    slot_duration = 0.0005
    sim_size = 5000
    transmission_range = 500

    random.seed(rep + 1)
        
    nodes = []  # Initialize nodes for this iteration
    TdmaScheduler.radio_idx = 0
    env = simpy.Environment()
    radio_medium = RadioMedium(env, transmission_range, per)
    scheduler = TdmaScheduler(env, nodes, slot_duration, frame_length)


    env.process(monitor(env, nodes, sim_time, scheduler))

    malicious_nodes = []

    for i in range(no_of_nodes):
        x = random.uniform(-sim_size/2, sim_size/2)
        y = random.uniform(-sim_size/2, sim_size/2)
        if (i < num_malicious):
            malicious_nodes.append(i)
            n = Node(env, sim_size, (x, y), scheduler, radio_medium, detection_mechanism, lying_intensity)
            nodes.append(n)
        else:
            n = Node(env, sim_size, (x, y), scheduler, radio_medium, detection_mechanism)
            nodes.append(n)


    env.run(until=sim_time)

    num_detected = 0
    num_malicious_packets_recvieved = 0
    detection_events = []
    bytes_sent = 0
    bytes_sent_overhead = 0
    packets_sent = 0
    packets_sent_overhead = 0

    for n in nodes:
        detection_events += n.application.detection_events
        num_detected += len([x for x in n.application.detection_events if int(x['detected_node']) in malicious_nodes])
        num_malicious_packets_recvieved +=  n.application.num_malicious_packets_received
        bytes_sent += n.application.bytes_sent
        bytes_sent_overhead += n.application.bytes_sent_overhead
        packets_sent += n.application.num_packets_sent
        packets_sent_overhead += n.application.num_packets_sent_overhead

    # print(num_detected / num_malicious)
    event_log = pl.DataFrame(detection_events)
    event_log.write_csv(f'{study_name}/{fname}.csv')

    with open(f'{study_name}/summary-{fname}.json', 'w') as f:
        json.dump({
            'num_malicious_packets_received': num_malicious_packets_recvieved,
            'num_malicious_detected': num_detected,
            'malicious_nodes': malicious_nodes,
            'bytes_sent': bytes_sent,
            'bytes_sent_overhead': bytes_sent_overhead,
            'packets_sent': packets_sent,
            'packets_sent_overhead': packets_sent_overhead,
        }, f)


if __name__ == '__main__':
    # run_idx = int(sys.argv[1])
    # offset = int(sys.argv[2])
    run_idx = 0
    offset = 0
    params = get_params(run_idx + offset)
    # main(
    #     params.get('rep'), 
    #     params.get('v'), 
    #     params.get('method'),
    #     params.get('lying_intensity'),
    #     params.get('per'),
    #     params.get('num_malicious')
    # )
    main(    )
