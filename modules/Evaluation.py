import matplotlib.pyplot as plt
import numpy as np
import os
from collections import defaultdict

# plt.rcParams.update({
#     "text.usetex": True,
# })


class Evaluation:
    def __init__(self, env, lying_intensity, slot_duration, frame_length):
        self.env = env
        self.lying_intensity = lying_intensity
        self.slot_duration = slot_duration
        self.frame_length = frame_length
        # self.scheduler = scheduler
        self.nodes = []
        self.malicious_nodes = []

        # self.detected_nodes = []
        self.ART_detection_per_time_step = []
        self.time_steps = []

        # Initialize an empty dictionary to store all detection times for each malicious node
        self.all_detection_times = dict()

        # Initialize an empty dictionary to store first detection times for each malicious node
        self.first_detection_times = dict()

        self.true_positives = []  # list to store number of true positives at each time step
        self.false_negatives = []  # list to store number of false negatives at each time step
        self.tpr_over_time = []  # list to store true positive rate at each time step


    def initialize(self,nodes):
        self.nodes = nodes
        for n in nodes:
            if(n._false_pos != (0,0)):
                self.malicious_nodes.append(n)

        self.all_detection_times = {node_id: [] for node_id in self.malicious_nodes}  # Fully initialize the dictionary here

    def add_plot_info(self, plt, **kwargs):
        """
        This function adds extra information to a matplotlib plot.

        Arguments:
        plt: The matplotlib.pyplot object where the text should be added.
        kwargs: Any keyword arguments to display in the plot.
        """
        info_strs = []

        for key, value in kwargs.items():
            info_strs.append(f'{key}: {value}')

        # Make room for the text by adjusting the right boundary
        plt.subplots_adjust(right=0.8)

        for i, info_str in enumerate(info_strs):
            # Adjust x to position the text on the right side
            plt.text(1.05, 0.95 - i * 0.05, info_str, transform=plt.gca().transAxes, fontsize=10, va='top')

    
    def plot_average_detection_times(self):
        avg_detection_times = {node_id: sum(times) / len(times) if times else 0 
                               for node_id, times in self.all_detection_times.items()}
        avg_times = [avg_detection_times[node_id] for node_id in sorted(avg_detection_times.keys())]
        malicious_node_ids = sorted(avg_detection_times.keys())
        plt.figure(figsize=(10, 6))
        plt.bar(range(len(malicious_node_ids)), avg_times, tick_label=malicious_node_ids)
        plt.title('Average Detection Time for Each Malicious Node by ART')
        plt.xlabel('Malicious Node ID')
        plt.ylabel('Average Detection Time')
        plt.xticks(rotation='vertical') 
        sim_time = self.env.now  
        self.add_plot_info(plt, len(self.nodes), sim_time, Method='ART')
        plt.grid(False)
        plt.savefig("detection_results/ART_average_detection_time_.png", dpi=300)
        plt.close()



        ## Detection times

    def plot_node_detection_over_time(self, methods):
        # Get list of node ids and malicious node ids
        node_ids = [node.transceiver.id for node in self.nodes]
        malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

        color_dict = {'MGT': 'steelblue', 'ART': 'orange','PEPT': 'red', 'REPT': 'seagreen'}

        plt.figure(figsize=(10, 5))
        
        for method in methods:
            # Collect the first detection times for each malicious node
            first_detection_times = self.collect_first_detection_times(method)

            # Sort the dictionary by detection times (values), convert to list of tuples
            sorted_times = sorted(first_detection_times.items(), key=lambda x: x[1])

            # If there are no detections for this method, continue to the next one
            if not sorted_times:
                continue

            # Unpack into separate lists
            detected_ids, detection_times = zip(*sorted_times)

            # Generate cumulative count of detected nodes over time
            # cumulative_counts = range(1, len(detected_ids) + 1)
            cumulative_counts = [i / len(malicious_node_ids) * 100 for i in range(1, len(detected_ids) + 1)]

            # Create the line plot
            plt.plot(detection_times, cumulative_counts, label=f'{method} Detection Count', color=color_dict[method])
        
        fontsize = 16
        plt.ylim(0, 100)
        plt.xlabel('Time of First Detection ($\mathrm{s}$)', fontsize=fontsize)
        plt.ylabel('Ratio of Malicious Nodes Detected (\%)', fontsize=fontsize)
        plt.title('First Detection Time of Malicious Nodes', fontsize=18)
        plt.legend()

        sim_time = self.env.now
        self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method='/'.join(methods), Malicious=len(self.malicious_nodes))
        plt.grid(True)
        directory = f"detection_results/first_detection_times"
        if not os.path.exists(directory):
            os.makedirs(directory)
        plt.savefig(f"detection_results/first_detection_times/{'_'.join(methods)}_first_detection_times_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
        plt.close()

    def collect_first_detection_times(self, method):
        # Initialize an empty dictionary to store the first detection time for each malicious node
        first_detection_times = {}
        malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

        # Iterate over all nodes in the system
        for node in self.nodes:
            # Choose the correct dictionary of detected nodes based on the method
            detected_nodes_dict = None
            if method in ['ART', 'MGT', 'PEPT']:
                detected_nodes_dict = getattr(node.application, f'detected_nodes_{method}')
            elif method == 'REPT':
                detected_nodes_dict = node.application.verification_data

            if detected_nodes_dict is None:
                raise ValueError(f"Invalid detection method: {method}")

            # Iterate over all detected nodes for the current node
            for detected_node_id, detection_info_list in detected_nodes_dict.items():
                # If the detected node is malicious, proceed
                if int(detected_node_id) in malicious_node_ids:
                    if method == 'REPT':
                        if detection_info_list['label'] is False:
                            verification_time = detection_info_list['verification_at']
                            if int(detected_node_id) not in first_detection_times or verification_time < first_detection_times[int(detected_node_id)]:
                                first_detection_times[int(detected_node_id)] = verification_time
                    else:
                        # Sort the detection_info_list by 'detected_at' in ascending order
                        sorted_detection_info_list = sorted(detection_info_list, key=lambda x: x['detected_at'])

                        # The first detection time is the 'detected_at' value of the first item in the sorted list
                        first_detection_time = sorted_detection_info_list[0]['detected_at']

                        # If the malicious node is not in the first_detection_times dict yet, or if the new detection time is earlier, update it
                        if detected_node_id not in first_detection_times or first_detection_time < first_detection_times[detected_node_id]:
                            first_detection_times[detected_node_id] = first_detection_time

        return first_detection_times
    

    ##Interdection times
    def plot_inter_detection_time_histogram(self, methods):
        # Get list of malicious node ids
        malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

        plt.figure(figsize=(10, 5))

        max_inter_detection_time = 0
        all_inter_detection_times = {}
        color_dict = {'MGT': 'steelblue', 'ART': 'orange','PEPT': 'red', 'REPT': 'seagreen'}

        for method in methods:
            # Collect the inter detection times for each malicious node
            inter_detection_times = self.collect_inter_detection_times(method)

            # Sort the dictionary by inter detection times (values), convert to list of tuples
            sorted_times = sorted(inter_detection_times.items(), key=lambda x: x[1])

            # If there are no detections for this method, continue to the next one
            if not sorted_times:
                continue

            inter_detection_intervals_all = np.array([])

            for node_id, detection_times in inter_detection_times.items():
                # Apply np.diff to get inter detection intervals
                inter_detection_intervals = np.diff(detection_times)
                # Concatenate to the existing intervals
                inter_detection_intervals_all = np.concatenate((inter_detection_intervals_all, inter_detection_intervals))

            # Update max_inter_detection_time if necessary
            max_inter_detection_time = max(max_inter_detection_time, np.max(inter_detection_intervals_all))

            all_inter_detection_times[method] = inter_detection_intervals_all

        # Define bins up to max_inter_detection_time
        bins = np.arange(0, max_inter_detection_time + 1, 1)  # Bin size is 1

        for method in methods:
            if method in all_inter_detection_times:
                # Calculate the probabilities
                counts, bins = np.histogram(all_inter_detection_times[method], bins=bins)
                probabilities = counts / np.sum(counts)  # Normalize counts to get probabilities

                # Plot the histogram using probabilities
                plt.bar(bins[:-1], probabilities, width=np.diff(bins), align='edge', label=f'Inter-Detection Time ({method})', alpha=0.7, color=color_dict[method])
        fontsize = 16
        plt.xlabel('Inter-Detection Time ($\mathrm{s}$)',fontsize=fontsize)
        plt.ylabel('Probability (\%)',fontsize=fontsize)
        plt.title('Inter-Detection Time Histogram for Malicious Nodes',fontsize=18)
        plt.legend()

        sim_time = self.env.now
        self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method='/'.join(methods), Malicious=len(self.malicious_nodes))
        plt.grid(True)
        directory = f"detection_results/inter_detection_times"
        if not os.path.exists(directory):
            os.makedirs(directory)
        plt.savefig(f"detection_results/inter_detection_times/{'_'.join(methods)}_inter_detection_times_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
        plt.close()


    def collect_inter_detection_times(self, method):
        # Initialize an empty dictionary to store the inter detection times for each malicious node
        inter_detection_times = {node.transceiver.id: [] for node in self.malicious_nodes}
        malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

        # Iterate over all nodes in the system
        for node in self.nodes:
            detected_nodes_dict = None
            if method in ['ART', 'MGT', 'PEPT']:
                detected_nodes_dict = getattr(node.application, f'detected_nodes_{method}')
            elif method == 'REPT':
                detected_nodes_dict = node.application.verification_data

            if detected_nodes_dict is None:
                raise ValueError(f"Invalid detection method: {method}")

            # Iterate over all detected nodes for the current node
            for detected_node_id, detection_info_list in detected_nodes_dict.items():
                if int(detected_node_id) in malicious_node_ids:
                    if method == 'REPT':
                        if detection_info_list['label'] is False:
                            verification_time = detection_info_list['verification_at']
                            inter_detection_times[int(detected_node_id)].append(verification_time)
                    else:
                        # Sort the detections by time
                        sorted_detection_info_list = sorted(detection_info_list, key=lambda x: x['detected_at'])
                        detection_times = [info['detected_at'] for info in sorted_detection_info_list]
                        # Append to list of detection times for this malicious node
                        inter_detection_times[detected_node_id].extend(detection_times)
        
        # After all detections are recorded, sort the entire dictionary by the detection times for each malicious node id
        inter_detection_times = {k: sorted(v) for k, v in inter_detection_times.items()}

        return inter_detection_times
    

    ## Node detection rate with standard deviations
    def plot_node_detection_rate_with_standard_deviations(self, nodes_per_intensity_per_seed, method):
       # Get list of node ids and malicious node ids
        node_ids = [node.transceiver.id for node in self.nodes]
        malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

        # Initialize a dictionary to hold counts of malicious packets for each node
        malicious_packets_counts = {node_id: 0 for node_id in node_ids}
        color_dict = {'MGT': 'steelblue', 'ART': 'orange'}
            
        # Initialize a dictionary to store average ratios and standard deviations for each intensity level
        avg_ratios_per_intensity = {}
        std_devs_per_intensity = {}

        if method == 'ART' or method == 'MGT':
            # A dict to track the cumulative ratio for each intensity, and then each seed
            cumulative_ratios = defaultdict(lambda: defaultdict(list))

            # Iterate over seeds and nodes_per_intensity items
            for seed, nodes_per_intensity in nodes_per_intensity_per_seed.items():
                for intensity, nodes in nodes_per_intensity.items():
                    # Iterate over all nodes
                    for node in nodes:
                        # Create a list of all the packets that should have been detected from the received packets,
                        # i.e., the packets with sequence numbers starting with the one of malicious_node_ids and with 
                        # type 'BROADCAST'
                        packets_to_detect = [packet for packet in node.application.packet_rcvd if int(packet['seq_no'].split('-')[0]) in malicious_node_ids and packet['type'] == 'BROADCAST']
                        if packets_to_detect:
                            ratio = len([packet for packet in getattr(node.application, f'detected_packets_{method}') if packet in packets_to_detect]) / len(packets_to_detect)
                        else:
                            ratio = 0  # Or 1 that indicates no packets were detected?

                        # Add this node's ratio to the cumulative ratio for this intensity and this seed
                        cumulative_ratios[intensity][seed].append(ratio)

            # Calculate average ratio and standard deviation for each intensity
            for intensity, seeds in cumulative_ratios.items():
                ratios_across_seeds = [np.mean(ratios) for ratios in seeds.values()]
                avg_ratios_per_intensity[intensity] = np.mean(ratios_across_seeds)
                std_devs_per_intensity[intensity] = np.std(ratios_across_seeds, dtype=np.float64)

            # Extract intensities and average ratios from the dictionary
            intensities = list(avg_ratios_per_intensity.keys())
            average_ratios = list(avg_ratios_per_intensity.values())

            # Extract standard deviations
            standard_deviations = list(std_devs_per_intensity.values())

            plt.figure(figsize=(10, 5))

            # Plot the data with error bars representing standard deviation
            plt.errorbar(intensities, average_ratios, yerr=standard_deviations, marker='o', capsize=5, color=color_dict[method])


            # Set the title and labels
            fontsize = 16
            plt.title('Average Detection Ratios vs Intensity Levels',fontsize=18)
            plt.xlabel('Intensity Levels ($\mathrm{m}$)',fontsize=fontsize)
            plt.ylabel('Average range of Detection Ratios (\%)',fontsize=fontsize)
            plt.yticks(fontsize=14)

            directory = f"detection_results/{method}/"
            if not os.path.exists(directory):
                os.makedirs(directory)
            plt.savefig(f"detection_results/{method}/st_node_detection_rate_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
            plt.close()
            # Show the plot
            plt.show()


    '''
    These are the old function for plotting different graphs.
    They need to be modified to work with the current implementation.
    '''

    # def plot_first_detection_times(self):
    #     # Extract the detection times in the order of the malicious node IDs
    #     detection_times = [self.first_detection_times[node_id] for node_id in sorted(self.first_detection_times.keys())]

    #     # Generate a list of malicious node IDs
    #     malicious_node_ids = sorted(self.first_detection_times.keys())

    #     # Plot first detection time for each malicious node
    #     plt.figure(figsize=(10, 6))
    #     plt.bar(range(len(malicious_node_ids)), detection_times, tick_label=malicious_node_ids)
    #     plt.title('First Detection Time for Each Malicious Node by ART')
    #     plt.xlabel('Malicious Node ID')
    #     plt.ylabel('Detection Time')
    #     plt.xticks(rotation='vertical') 
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method='ART')
    #     plt.grid(False)
    #     plt.savefig("detection_results/ART_first_detection_time.png", dpi=300)
    #     plt.close()


    # def calculate_tpr(self, true_positive, false_negative):
    #     if true_positive + false_negative == 0:
    #         return 0
    #     else:
    #         return true_positive / (true_positive + false_negative)

    # def update_tpr(self):
    #     true_positive = len([node for node in self.detected_nodes if node in self.malicious_nodes])
    #     false_negative = len([node for node in self.malicious_nodes if node not in self.detected_nodes])
        
    #     self.true_positives.append(true_positive)
    #     self.false_negatives.append(false_negative)

    #     tpr = self.calculate_tpr(true_positive, false_negative)
    #     self.tpr_over_time.append(tpr)

    # def plot_tpr(self):
    #     # Generate a list of time steps
    #     time_steps = list(range(len(self.tpr_over_time)))

    #     # Plot TPR over time
    #     plt.figure(figsize=(10, 6))
    #     plt.plot(time_steps, self.tpr_over_time, marker='o')
    #     plt.title('True Positive Rate Over Time')
    #     plt.xlabel('Time Step')
    #     plt.ylabel('True Positive Rate')
    #     plt.grid(True)
    #     plt.savefig("detection_results/tpr_over_time.png", dpi=300)
    #     plt.close()

    # def ART(self,nodes):
    #     ratio = []
    #     self.detected_nodes =[]
    #     for n in nodes:
    #         # if(n.false_pos != (0,0)):
    #         #     self.malicious_nodes.append(n.transceiver.id)
    #         for dn in n.application.detected_nodes:
    #             if dn not in self.detected_nodes:
    #                 self.detected_nodes.append(dn)
    #         # if(n.false_pos != (0,0)):
    #     for n in self.malicious_nodes:
    #         if(n in self.detected_nodes):
    #             ratio.append(n)
    #             # print(n)

    #     x =self.percentage_in_b(self.detected_nodes, self.malicious_nodes)
    #     print("detection rate: ", x)
    #     self.ART_detection_per_time_step.append(x)
        

    # def percentage_in_b(self, a, b):
    #     a_set = set(a)
    #     b_set = set(b)
    #     common_elements = a_set.intersection(b_set)

    #     if len(a_set) == 0:
    #         return 0.0  # Handle the case when set `a` is empty

    #     percentage = len(common_elements) / len(a_set) * 100
    #     return percentage
    
    # def plot_no_of_pkt_rcvd(self):
    #     packet_counts = {node.transceiver.id: len(node.application.packet_rcvd) for node in self.nodes}
    #     node_ids = sorted(packet_counts.keys())
    #     packet_counts = [packet_counts[node_id] for node_id in node_ids]
        
    #     plt.figure(figsize=(15, 8))
    #     plt.bar(range(len(node_ids)), packet_counts, tick_label=node_ids)
    #     plt.title('Number of Packets Received by Each Node')
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Number of Packets Received')
    #     plt.xticks(rotation='vertical') 
    #     plt.grid(False)
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Malicious=len(self.malicious_nodes), LIntensity=self.lying_intensity, FrameLength=self.frame_length,SlotDuration=self.slot_duration)
    #     plt.xlim([-0.5, len(node_ids)-0.5]) 
    #     plt.savefig(f"detection_results/recieved_packet_counts_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
    #     plt.close()
    #     # plt.show()

    # def plot_detection_vs_true_detection(self, method):
    #     if method not in ['ART', 'MGT', 'REPT']:
    #         print("Invalid method. Choose either 'ART' or 'MGT'.")
    #         return
        
    #     malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #     detected_attr = 'detected_nodes_' + method
    #     detected_counts = {node.transceiver.id: len(getattr(node.application, detected_attr)) for node in self.nodes}
    #     true_detected_counts = {node.transceiver.id: len([detected_node for detected_node in getattr(node.application, detected_attr) if detected_node in malicious_node_ids]) for node in self.nodes}

    #     node_ids = sorted(detected_counts.keys())
    #     detected_counts = [detected_counts[node_id] for node_id in node_ids]
    #     true_detected_counts = [true_detected_counts[node_id] for node_id in node_ids]

    #     plt.figure(figsize=(15, 8))

    #     plt.plot(node_ids, detected_counts, marker='o',  color='b', label='Detected')
    #     plt.plot(node_ids, true_detected_counts, marker='o', markersize=4, color='r', label='True Detected')

    #     plt.xlabel('Node ID')
    #     plt.ylabel('Number of Nodes Detected')
    #     plt.title(f'Number of Detected Nodes by {method} vs True Detected Nodes for Each Node')
    #     plt.legend()
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method)
    #     plt.grid(True)
    #     plt.savefig(f"detection_results/{method}_detection_vs_true_detection_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()

    # def plot_detection_accuracy(self, method):
    #     if method not in ['ART', 'MGT', 'PEPT', 'REPT']:
    #         print("Invalid method. Choose either 'ART' or 'MGT' or 'PEPT'.")
    #         return
        
    #     node_ids = [node.transceiver.id for node in self.nodes]  # Get node ids here

    #     if method == 'PEPT':
    #         # Initialize dictionary to hold detections for each node.
    #         all_detected_nodes = {node_id: [] for node_id in node_ids}
    #         malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #         # Populate the dictionary with detections.
    #         for node in self.nodes:
    #             all_detected_nodes[node.transceiver.id] = node.application.detected_nodes_PEPT

    #         # Create detected_counts and true_detected_counts dictionaries.
    #         detected_counts = {node_id: len(all_detected_nodes[node_id]) for node_id in node_ids}
    #         true_detected_counts = {node_id: sum([detected_node['sender_node'] in malicious_node_ids for detected_node in all_detected_nodes[node_id]]) for node_id in node_ids}
    #     else:
    #         detected_attr = 'detected_nodes_' + method
    #         detected_counts = {node.transceiver.id: len(getattr(node.application, detected_attr)) for node in self.nodes}
    #         true_detected_counts = {node.transceiver.id: len([detected_node for detected_node in getattr(node.application, detected_attr) if detected_node in self.malicious_nodes]) for node in self.nodes}

    #     node_ids = sorted(detected_counts.keys())
    #     detected_counts = [detected_counts[node_id] for node_id in node_ids]
    #     true_detected_counts = [true_detected_counts[node_id] for node_id in node_ids]

    #     # Calculate accuracy for each node
    #     accuracy = [true / total if total != 0 else 0 for true, total in zip(true_detected_counts, detected_counts)]

    #     # Calculate average accuracy
    #     avg_accuracy = np.mean(accuracy)

    #     plt.figure(figsize=(15, 8))
        
    #     # Change plot type to bar
    #     plt.bar(node_ids, accuracy, color='g', label='Accuracy')
    #     plt.axhline(avg_accuracy, color='r', linestyle='--', label='Average Accuracy')  # Add average line

    #     plt.xlabel('Node ID')
    #     plt.ylabel('Accuracy')
    #     plt.title(f'Accuracy of Detection by {method} for Each Node')
    #     plt.legend()
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method, Malicious=len(self.malicious_nodes), LIntensity=self.lying_intensity)
    #     plt.grid(True)
    #     plt.savefig(f"detection_results/{method}_accuracy_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()

    # def plot_packet_detection_accuracy(self, method):
    #     if method not in ['ART', 'MGT', 'PEPT', 'REPT']:
    #         print("Invalid method. Choose either 'ART' or 'MGT' or 'PEPT'.")
    #         return
        
    #     node_ids = [node.transceiver.id for node in self.nodes]  # Get node ids here
    #     malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #     # Initialize dictionaries to hold counts
    #     total_detected_counts = {node_id: 0 for node_id in node_ids}
    #     correct_detected_counts = {node_id: 0 for node_id in node_ids}

    #     # Iterate over all nodes
    #     for node in self.nodes:
    #         # Iterate over all detected packets of the node
    #         for packet in node.application.detected_packets_ART:
    #             # Extract the node_id from the sequence number
    #             source_node_id = int(packet['seq_no'].split('-')[0])
    #             detecting_node_id = node.transceiver.id
    #             total_detected_counts[detecting_node_id] += 1
    #             if source_node_id in malicious_node_ids:
    #                 correct_detected_counts[detecting_node_id] += 1

    #     # Calculate accuracy for each node
    #     accuracy = [correct / total if total != 0 else 0 for correct, total in zip(correct_detected_counts.values(), total_detected_counts.values())]

    #     # Calculate average accuracy
    #     avg_accuracy = sum(accuracy) / len(accuracy)

    #     plt.figure(figsize=(15, 8))
        
    #     # Change plot type to bar
    #     plt.bar(node_ids, accuracy, color='g', label='Accuracy')
    #     plt.axhline(avg_accuracy, color='r', linestyle='--', label='Average Accuracy')  # Add average line

    #     plt.xlabel('Node ID')
    #     plt.ylabel('Accuracy')
    #     plt.title(f'Packet detetction accuracy by {method} for Each Node')
    #     plt.legend()
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method, Malicious=len(self.malicious_nodes), LIntensity=self.lying_intensity, FrameLength=self.frame_length,SlotDuration=self.slot_duration)
    #     plt.grid(True)
    #     plt.savefig(f"detection_results/{method}_packet_accuracy_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()


    # def plot_total_discrepancies(self):
    #     # Count discrepancies for each node
    #     discrepancy_counts = {node.transceiver.id: len(node.application.discrepancies) for node in self.nodes}

    #     node_ids = sorted(discrepancy_counts.keys())
    #     discrepancy_counts = [discrepancy_counts[node_id] for node_id in node_ids]

    #     # Calculate average
    #     avg_discrepancies = np.mean(discrepancy_counts)

    #     plt.figure(figsize=(15, 8))

    #     # Change to bar plot
    #     plt.bar(node_ids, discrepancy_counts, color='b', label='Total Discrepancies')
    #     plt.axhline(avg_discrepancies, color='r', linestyle='--', label='Average Discrepancies')

    #     plt.xlabel('Node ID')
    #     plt.ylabel('Total Discrepancies Detected')
    #     plt.title('Total Discrepancies Detected by Each Node')
    #     plt.legend()

    #     plt.grid(True)
    #     plt.savefig(f"detection_results/PEPT_detection_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()



    # def plot_detection_times(self):
    #     # Average detection times
    #     avg_detection_times = {node_id: sum(times) / len(times) if times else 0
    #                         for node_id, times in self.all_detection_times.items()}
    #     avg_times = [avg_detection_times.get(node_id, 0) for node_id in sorted(self.all_detection_times.keys())]
        
    #     # First detection times
    #     detection_times = [self.first_detection_times.get(node_id, 0) for node_id in sorted(self.all_detection_times.keys())]

    #     # Sorted malicious node IDs
    #     malicious_node_ids = sorted(self.all_detection_times.keys())

    #     plt.figure(figsize=(15, 8))
    #     plt.plot(malicious_node_ids, avg_times, marker='o', color='b', label='Average Detection Time')
    #     plt.plot(malicious_node_ids, detection_times, marker='o', color='r', label='First Detection Time')

    #     plt.xlabel('Malicious Node ID')
    #     plt.ylabel('Detection Time')
    #     plt.title('Detection Times for Each Malicious Node by ART')
    #     plt.legend()
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method='ART')
    #     plt.grid(True)
    #     plt.xticks(rotation='vertical')
    #     plt.savefig(f"detection_results/ART_detection_time_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()



    # def plot_buffer_status(self):
    #     # buffer_status is a dictionary {node_id: number_of_packets_waiting_to_send}
    #     buffer_status = self.scheduler.buffer_status

    #     # Extract the node IDs and corresponding buffer statuses
    #     node_ids = sorted(buffer_status.keys())
    #     buffer_statuses = [buffer_status[node_id] for node_id in node_ids]

    #     # Create the plot
    #     plt.figure(figsize=(10, 6))
    #     plt.bar(range(len(node_ids)), buffer_statuses, tick_label=node_ids)
    #     plt.title('Buffer Status for Each Node')
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Number of Packets Waiting to Send')
    #     plt.xticks(rotation='vertical') 
    #     sim_time = self.env.now  
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time )
    #     plt.grid(False)
    #     plt.savefig(f"detection_results/buffer_status_T{self.env.now}_{len(self.nodes)}.png", dpi=300)
    #     plt.close()

    # def plot_false_positves(self, method, intensity):
    #     # Get list of node ids and malicious node ids
    #     node_ids = [node.transceiver.id for node in self.nodes]
    #     malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #     # Initialize a dictionary to hold counts of non-malicious packets for each node
    #     non_malicious_packets_counts = {node_id: 0 for node_id in node_ids}

    #     if method == 'ART':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             for packet in node.application.detected_packets_ART:
    #                 # Extract the node_id from the sequence number
    #                 source_node_id = int(packet['seq_no'].split('-')[0])
    #                 detecting_node_id = node.transceiver.id
    #                 # total_detected_counts[detecting_node_id] += 1
    #                 if source_node_id not in malicious_node_ids:
    #                     non_malicious_packets_counts[detecting_node_id] += 1

    #     if method == 'MGT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             for packet in node.application.detected_packets_MGT:
    #                 # Extract the node_id from the sequence number
    #                 source_node_id = int(packet['seq_no'].split('-')[0])
    #                 detecting_node_id = node.transceiver.id
    #                 # total_detected_counts[detecting_node_id] += 1
    #                 if source_node_id not in malicious_node_ids:
    #                     non_malicious_packets_counts[detecting_node_id] += 1
        
    #     if method == 'PEPT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             # for detected_packet in node.application.detected_nodes_PEPT:
    #             for detected_packet in node.application.detected_packets_PEPT:
    #                 # sender_node = detected_packet['sender_node']
    #                 source_node_id = int(detected_packet['seq_no'].split('-')[0])
    #                 # neighbor_node = detected_packet['neighbor_id']

    #                 # if neighbor_node not in malicious_node_ids:#and 
    #                 if source_node_id not in malicious_node_ids:
    #                     non_malicious_packets_counts[node.transceiver.id] += 1
        
    #     if method == 'REPT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             detecting_node_id = node.transceiver.id
    #             for suspect_node_id, suspect_node_data in node.application.verification_data.items():
    #                 if suspect_node_data['label'] == False and int(suspect_node_id) not in malicious_node_ids:
    #                     non_malicious_packets_counts[detecting_node_id] += 1


    #     plt.figure(figsize=(15, 8))
    #     plt.bar(node_ids, list(non_malicious_packets_counts.values()), color='g', label='Non-malicious packets')
        
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Count')
    #     plt.title(f'Count of Non-malicious Packets Detected using {method} for Each Node')
    #     plt.legend()
        
    #     sim_time = self.env.now
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method, Malicious=len(self.malicious_nodes), LIntensity=intensity)
    #     plt.grid(True)
    #     directory = f"detection_results/{method}/false_positives"
    #     if not os.path.exists(directory):
    #         os.makedirs(directory)
    #     plt.savefig(f"detection_results/{method}/false_positives/false_positives_T{self.env.now}_N{len(self.nodes)}_L{intensity}.png", dpi=300)
    #     plt.close()


    # def plot_true_positves(self, method, intensity):
    #     # Get list of node ids and malicious node ids
    #     node_ids = [node.transceiver.id for node in self.nodes]
    #     malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #     # Initialize a dictionary to hold counts of malicious packets for each node
    #     malicious_packets_counts = {node_id: 0 for node_id in node_ids}

    #     # Initialize a dictionary to hold counts of detected malicious packets for each node
    #     detected_malicious_packets_counts = {node_id: 0 for node_id in node_ids}

    #     if method == 'ART':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             for packet in node.application.detected_packets_ART:
    #                 # Extract the node_id from the sequence number
    #                 source_node_id = int(packet['seq_no'].split('-')[0])
    #                 detecting_node_id = node.transceiver.id
    #                 # total_detected_counts[detecting_node_id] += 1
    #                 if source_node_id in malicious_node_ids:
    #                     malicious_packets_counts[detecting_node_id] += 1

    #     if method == 'MGT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             for packet in node.application.detected_packets_MGT:
    #                 # Extract the node_id from the sequence number
    #                 source_node_id = int(packet['seq_no'].split('-')[0])
    #                 detecting_node_id = node.transceiver.id
    #                 # total_detected_counts[detecting_node_id] += 1
    #                 if source_node_id in malicious_node_ids:
    #                     malicious_packets_counts[detecting_node_id] += 1
        
    #     if method == 'PEPT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             # for detected_packet in node.application.detected_nodes_PEPT:
    #             for detected_packet in node.application.detected_packets_MGT:
    #                 # sender_node = int(detected_packet['sender_node'])
    #                 # neighbor_node = int(detected_packet['neighbor_id'])
    #                 source_node_id = int(detected_packet['seq_no'].split('-')[0])
    #                 # if neighbor_node in malicious_node_ids:#or 
    #                 if source_node_id in malicious_node_ids:
    #                     malicious_packets_counts[node.transceiver.id] += 1

    #     if method == 'REPT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # detecting_node_id = node.transceiver.id
    #             m_count = 0
    #             d_count = 0
    #             for suspect_node_id, suspect_node_data in node.application.verification_data.items():
    #                 if int(suspect_node_id) in malicious_node_ids:
    #                     m_count=+1
    #                     if suspect_node_data['label'] == False:
    #                         d_count+=1
    #                     # malicious_packets_counts[node.transceiver.id] += 1
    #             if m_count != 0:
    #                 ratio = d_count/m_count
    #                 if ratio > 1:
    #                     ratio = 1
    #             else:
    #                 ratio = None
    #             # cumulative_ratios[intensity] += ratio
                
    #             malicious_packets_counts[node.transceiver.id] =ratio


    #     plt.figure(figsize=(15, 8))

    #     plt.bar(node_ids, list(malicious_packets_counts.values()), color='r', label='Malicious packets')
    #     # plt.bar(node_ids, list(detected_malicious_packets_counts.values()), color='g', label='Malicious packets')
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Count')
    #     plt.title(f'Count of Malicious Packets Detected using {method} for Each Node')
    #     plt.legend()
        
    #     sim_time = self.env.now
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method, Malicious=len(self.malicious_nodes), LIntensity=intensity)
    #     plt.grid(True)
    #     directory = f"detection_results/{method}/true_positives"
    #     if not os.path.exists(directory):
    #         os.makedirs(directory)
    #     plt.savefig(f"detection_results/{method}/true_positives/true_positives_T{self.env.now}_N{len(self.nodes)}_L{intensity}.png", dpi=300)
    #     plt.close()

    # def plot_node_detection_rate(self, nodes_per_intensity, method):
    #     # Get list of node ids and malicious node ids
    #     node_ids = [node.transceiver.id for node in self.nodes]
    #     malicious_node_ids = [node.transceiver.id for node in self.malicious_nodes]

    #     # Initialize a dictionary to hold counts of malicious packets for each node
    #     malicious_packets_counts = {node_id: 0 for node_id in node_ids}

    #     if method == 'ART':
    #         # A dict to track the cumulative ratio for each intensity
    #         cumulative_ratios = {}
    #         # Iterate over nodes_per_intensity items
    #         for intensity, nodes in nodes_per_intensity.items():
    #             cumulative_ratios[intensity] = 0
    #             # Iterate over all nodes
    #             for node in nodes:
    #                 # Create a list of all the packets that should have been detected from the recieved packets,
    #                 # i.e. the packets with sequence numbers starting with the one of malicious_node_ids and with 
    #                 # type 'BROADCAST'
    #                 packets_to_detect = [packet for packet in node.application.packet_rcvd if int(packet['seq_no'].split('-')[0]) in malicious_node_ids and packet['type'] == 'BROADCAST']
    #                 if packets_to_detect:
    #                     ratio = len([packet for packet in node.application.detected_packets_ART if packet in packets_to_detect]) / len(packets_to_detect)
    #                 else:
    #                     ratio = 0  # Or 1 that indicates no packets were detected?

    #                 # Add this node's ratio to the cumulative ratio for this intensity?(Hopefully corret)
    #                 cumulative_ratios[intensity] += ratio
                
    #             # Now we can find the average ratio for each intensity by dividing the cumulative ratio for the intensity by the number of nodes for that intensity
    #             cumulative_ratios[intensity] /= len(nodes)

    #         # Now, cumulative_ratios is a dictionary where each key is an intensity, and each value is the average ratio for that intensity.
    #         # average_ratios = {intensity: total_ratio / len(nodes_per_intensity[intensity]) for intensity, total_ratio in cumulative_ratios.items()}

    #         # Extract intensities and average ratios from the dictionary
    #         intensities = list(cumulative_ratios.keys())
    #         average_ratios = list(cumulative_ratios.values())

    #         plt.figure(figsize=(15, 8))

    #         # Plot the data
    #         plt.plot(intensities, average_ratios, marker='o')

    #         # Set the title and labels
    #         plt.title('Average Detection Ratios vs Intensity Levels')
    #         plt.xlabel('Intensity Levels')
    #         plt.ylabel('Average Detection Ratios')
    #         directory = f"detection_results/{method}/"
    #         if not os.path.exists(directory):
    #             os.makedirs(directory)
    #         plt.savefig(f"detection_results/{method}/node_detection_rate_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
    #         plt.close()
    #         # Show the plot
    #         plt.show()
    #     if method == 'MGT':
    #         # A dict to track the cumulative ratio for each intensity
    #         cumulative_ratios = {}
    #         # Iterate over nodes_per_intensity items
    #         for intensity, nodes in nodes_per_intensity.items():
    #             cumulative_ratios[intensity] = 0
    #             # Iterate over all nodes
    #             for node in nodes:
    #                 # Create a list of all the packets that should have been detected from the recieved packets,
    #                 # i.e. the packets with sequence numbers starting with the one of malicious_node_ids and with 
    #                 # type 'BROADCAST'
    #                 packets_to_detect = [packet for packet in node.application.packet_rcvd if int(packet['seq_no'].split('-')[0]) in malicious_node_ids and packet['type'] == 'BROADCAST']
    #                 if packets_to_detect:
    #                     ratio = len([packet for packet in node.application.detected_packets_MGT if packet in packets_to_detect]) / len(packets_to_detect)
    #                 else:
    #                     ratio = 0  # Or 1 that indicates no packets were detected?

    #                 # Add this node's ratio to the cumulative ratio for this intensity?(Hopefully corret)
    #                 cumulative_ratios[intensity] += ratio
                
    #             # Now we can find the average ratio for each intensity by dividing the cumulative ratio for the intensity by the number of nodes for that intensity
    #             cumulative_ratios[intensity] /= len(nodes)

    #         # Now, cumulative_ratios is a dictionary where each key is an intensity, and each value is the average ratio for that intensity.
    #         # average_ratios = {intensity: total_ratio / len(nodes_per_intensity[intensity]) for intensity, total_ratio in cumulative_ratios.items()}

    #         # Extract intensities and average ratios from the dictionary
    #         intensities = list(cumulative_ratios.keys())
    #         average_ratios = list(cumulative_ratios.values())

    #         plt.figure(figsize=(15, 8))

    #         # Plot the data
    #         plt.plot(intensities, average_ratios, marker='o')

    #         # Set the title and labels
    #         plt.title('Average Detection Ratios vs Intensity Levels')
    #         plt.xlabel('Intensity Levels')
    #         plt.ylabel('Average Detection Ratios')
    #         directory = f"detection_results/{method}/"
    #         if not os.path.exists(directory):
    #             os.makedirs(directory)
    #         plt.savefig(f"detection_results/{method}/node_detection_rate_T{self.env.now}_N{len(self.nodes)}.png", dpi=300)
    #         plt.close()
    #         # Show the plot
    #         plt.show()
        
    #     if method == 'PEPT':
    #         # Iterate over all nodes
    #         for node in self.nodes:
    #             # Iterate over all detected packets of the node
    #             for detected_packet in node.application.detected_nodes_PEPT:
    #                 sender_node = int(detected_packet['sender_node'])
    #                 neighbor_node = int(detected_packet['neighbor_id'])

    #                 if sender_node in malicious_node_ids or neighbor_node in malicious_node_ids:
    #                     malicious_packets_counts[node.transceiver.id] += 1

    #     # This will not work as detected_packets_REPT is always empty
    #     # if method == 'REPT':
    #     #     # Iterate over all nodes
    #     #     for node in self.nodes:
    #     #         # Iterate over all detected packets of the node
    #     #         for packet in node.application.detected_packets_REPT:
    #     #             # Extract the node_id from the sequence number
    #     #             source_node_id = int(packet['suspicious_node_id'])
    #     #             detecting_node_id = node.transceiver.id
    #     #             # total_detected_counts[detecting_node_id] += 1
    #     #             if source_node_id in malicious_node_ids:
    #     #                 malicious_packets_counts[detecting_node_id] += 1

    #     plt.figure(figsize=(15, 8))

    #     plt.bar(node_ids, list(malicious_packets_counts.values()), color='r', label='Malicious packets')
        
    #     plt.xlabel('Node ID')
    #     plt.ylabel('Count')
    #     plt.title(f'Count of Malicious Packets Detected using {method} for Each Node')
    #     plt.legend()
        
    #     sim_time = self.env.now
    #     self.add_plot_info(plt, Nodes=len(self.nodes), Time=sim_time, Method=method, Malicious=len(self.malicious_nodes), LIntensity=intensity)
    #     plt.grid(True)
    #     directory = f"detection_results/{method}/true_positives"
    #     if not os.path.exists(directory):
    #         os.makedirs(directory)
    #     plt.savefig(f"detection_results/{method}/true_positives/true_positives_T{self.env.now}_N{len(self.nodes)}_L{intensity}.png", dpi=300)
    #     plt.close()