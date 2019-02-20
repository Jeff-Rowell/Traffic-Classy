# import tkinter as tk
import logging
import subprocess
import numpy as np
import tensorflow as tf
from scapy.all import rdpcap
from ipaddress import IPv4Address


def capture_packets(interface="enp0s3", num_packets=100, save_file="test.pcap"):
    print("[+] Running tcpdump on interface \"%s\" capturing %d packets to file: \"%s\""
          % (interface, num_packets, save_file))
    subprocess.call(["/usr/sbin/tcpdump", "-i", interface, "-c", str(num_packets), "-w", save_file])

    good_packet_list = []
    good_packet_matrix = []
    try:
        data = rdpcap(save_file)
        sessions = data.sessions()

        i = 1
        for session in sessions:
            for packet in sessions[session]:
                if packet.haslayer("TCP") and packet.haslayer("IP"):
                    if i % 256 != 0:
                        good_packet_list.append(packet)
                        i += 1
                    else:
                        good_packet_list.append(packet)
                        good_packet_matrix.append([i for i in good_packet_list])
                        good_packet_list.clear()
                        i += 1
        if i % 256 != 0:
            good_packet_matrix.append([i for i in good_packet_list])
            index = len(good_packet_matrix) - 1
            diff = 256 - len(good_packet_matrix[index])
            for num in range(diff):
                good_packet_matrix[index].append(None)
        good_packet_list.clear()

    except FileNotFoundError as e:
        logging.basicConfig(filename='errors.log', level=logging.DEBUG)
        logging.exception(e)
        print("[-] File not found error.")
        exit(1)

    return good_packet_matrix


def process_packets(packet_matrix):
    X = np.zeros(shape=(len(packet_matrix), 1024), dtype=np.int64)
    X_norm = np.zeros(shape=(len(packet_matrix), 1024), dtype=np.float)

    row_index = 0
    for row in packet_matrix:
        for i in range(len(row)):
            if row[i] is None:
                X[row_index, (i * 4)] = 0
                X[row_index, (i * 4) + 1] = 0
                X[row_index, (i * 4) + 2] = 0
                X[row_index, (i * 4) + 3] = 0
            else:
                X[row_index, (i * 4)] = np.int64(IPv4Address(row[i].getlayer("IP").src))
                X[row_index, (i * 4) + 1] = np.int64(IPv4Address(row[i].getlayer("IP").dst))
                X[row_index, (i * 4) + 2] = np.int64(row[i].sport)
                X[row_index, (i * 4) + 3] = np.int64(row[i].dport)
        row_index += 1

    npinfo = np.iinfo(np.int)
    min_ip = npinfo.max
    max_ip = npinfo.min
    min_port = npinfo.max
    max_port = npinfo.min

    # find min and max values for the IPv4 addresses and the port numbers
    for row in X:
        for i in range(0, len(row), 4):
            if row[i] != 0 and row[i] < min_ip:
                min_ip = row[i]
            if row[i + 1] != 0 and row[i + 1] < min_ip:
                min_ip = row[i + 1]
            if row[i] != 0 and row[i] > max_ip:
                max_ip = row[i]
            if row[i + 1] != 0 and row[i + 1] > max_ip:
                max_ip = row[i + 1]

            if row[i + 2] != 0 and row[i + 2] < min_port:
                min_port = row[i + 2]
            if row[i + 3] != 0 and row[i + 3] < min_port:
                min_port = row[i + 3]
            if row[i + 2] != 0 and row[i + 2] > max_port:
                max_port = row[i + 2]
            if row[i + 3] != 0 and row[i + 3] > max_port:
                max_port = row[i + 3]

    ip_diff = max_ip - min_ip
    port_diff = max_port - min_port
    row_index = 0

    for row in X:
        for i in range(0, len(row), 4):
            if row[i] != 0:
                X_norm[row_index, i] = 2 * ((row[i] - min_ip) / ip_diff) - 1
            if row[i + 1] != 0:
                X_norm[row_index, i + 1] = 2 * ((row[i + 1] - min_ip) / ip_diff) - 1
            if row[i + 2] != 0:
                X_norm[row_index, i + 2] = 2 * ((row[i + 2] - min_port) / port_diff) - 1
            if row[i + 3] != 0:
                X_norm[row_index, i + 3] = 2 * ((row[i + 3] - min_port) / port_diff) - 1
        row_index += 1

    return X_norm


if __name__ == "__main__":

    with tf.Session() as sess:
        saver = tf.train.import_meta_graph("./model/cnn-model.ckpt-20.meta")
        saver.restore(sess, tf.train.latest_checkpoint("./model/", latest_filename="checkpoint"))
        graph = tf.get_default_graph()
        packets = capture_packets(interface="enp0s3", num_packets=500, save_file="test.pcap")
        X = process_packets(packet_matrix=packets)
        tf_x = graph.get_tensor_by_name("tf_x:0")
        keep_prob = graph.get_tensor_by_name("keep_prob:0")
        feed = {tf_x: X, keep_prob: 1.0}
        probabilities = graph.get_tensor_by_name("probabilities:0")
        probas = sess.run(probabilities, feed_dict=feed)

        if probas[0][1] >= 0.5:
            print("[*] The packets are %f%% nefarious\n" % (probas[0][1] * 100))

            ret_val = subprocess.call(["iptables", "-A", "INPUT", "-s", "192.168.56.104", "-j", "DROP"])
            if ret_val == 0:
                print("[+] Firewall rule added to block 192.168.56.104 traffic")
            else:
                print("[-] Failed to establish firewall rule")


            # Program crashes here. scapy and tkinter don't work together because of tkinter's mainloop()
            # method being single threaded, scapy and tkinter need to both execute in their own threads...
            #
            # I'll just print stuff to the screen for now... I'll have to come back to this.
            # ---------------------------------------------------------------------------------
            # root = tk.Tk()
            # frame = tk.Frame(root)
            # frame.pack()
            #
            # button = tk.Button(frame, text="No, quit without setting rules.", command=quit())
            # button.pack(side=tk.RIGHT)
            # fw_rule = tk.Button(frame, text="Set firewall rule", fg="red", command=print("Set rules here..."))
            # fw_rule.pack(side=tk.LEFT)
            # root.mainloop()
