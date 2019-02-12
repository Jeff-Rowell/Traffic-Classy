from scapy.all import rdpcap
import os
import logging
import numpy as np
from ipaddress import IPv4Address
import tensorflow as tf
import matplotlib.pyplot as plt


class TrafficClassyHelper(object):

    def __init__(self, good_path, bad_path):
        self.good_path = good_path
        self.bad_path = bad_path

    def read_input(self):
        '''
        Helper function to read in the PCAP files and store the packets into lists.

        :return: good_packet_list - A list of the benign packets.
                 bad_packet_list  - A list of the "nefarious" packets.
        '''

        good_packet_list = []
        bad_packet_list = []
        print("[*] Reading PCAP files from \"" + self.good_path + "\" directory....")
        try:
            for good_filename in os.listdir(self.good_path):
                print("[*] Processing packets from file: " + "\"" + str(good_filename) + "\"")
                data = rdpcap(self.good_path + "/" + good_filename)
                sessions = data.sessions()

                for session in sessions:
                    for packet in sessions[session]:
                        if packet.haslayer("TCP") and packet.haslayer("IP"):
                            good_packet_list.append(packet)
        except FileNotFoundError as e:
            logging.basicConfig(filename='errors.log', level=logging.DEBUG)
            logging.exception(e)
            print("[-] File not found error.")

            exit(1)

        print("\n[*] Reading PCAP files from \"" + self.bad_path + "\" directory....")
        try:
            for bad_filename in os.listdir(self.bad_path):
                print("[*] Processing packets from file: \"" + str(bad_filename) + "\"")
                data = rdpcap(self.bad_path + "/" + bad_filename)
                sessions = data.sessions()

                for session in sessions:
                    for packet in sessions[session]:
                        if packet.haslayer("TCP") and packet.haslayer("IP"):
                            bad_packet_list.append(packet)
        except FileNotFoundError as e:
            logging.basicConfig(filename='errors.log', level=logging.DEBUG)
            logging.exception(e)
            print("[-] File not found error.")
            exit(1)

        print("[+] Read in " + str(len(good_packet_list)) + " good packets and " +
              str(len(bad_packet_list)) + " bad packets containing TCP and IP layers")

        return good_packet_list, bad_packet_list

    def build_input_data(self, good_data, bad_data):
        '''
        Builds the dataset X from a list of good PCAP files and bad PCAP files and returns the input data and
        corresponding labels ready for data splitting. Returns the normalized input data (in the range [-1, 1]),
        and their respective labels.

        :param good_data: A list of benign packets.
        :param bad_data:  A list of nefarious packets.
        :return: X - The input matrix to the network consiting of column labels of the source IP, destination IP,
                     source port, and destination port in each row. Data is normalized in the range [-1, 1].
                     Has shape: (len(good_data) + len(bad_data), 4)

                 y - The labels, 0 or 1, for each row in the input matrix.
                     Has shape:  (len(good_data) + len(bad_data), 1)
        '''

        X = np.zeros(shape=(len(good_data)+len(bad_data), 4), dtype=np.int64)
        X_norm = np.zeros(shape=(len(good_data)+len(bad_data), 4), dtype=np.float)
        good_labels = [0 for i in range(len(good_data))]
        bad_labels = [1 for i in range(len(bad_data))]
        y = good_labels + bad_labels

        row = 0
        for packet in good_data:
                X[row, 0] = np.int64(IPv4Address(packet.getlayer("IP").src))
                X[row, 1] = np.int64(IPv4Address(packet.getlayer("IP").dst))
                X[row, 2] = np.int64(packet.sport)
                X[row, 3] = np.int64(packet.dport)
                row += 1

        for packet in bad_data:
                X[row, 0] = np.int64(IPv4Address(packet.getlayer("IP").src))
                X[row, 1] = np.int64(IPv4Address(packet.getlayer("IP").dst))
                X[row, 2] = np.int64(packet.sport)
                X[row, 3] = np.int64(packet.dport)
                row += 1

        npinfo = np.iinfo(np.int)
        min_ip = npinfo.max
        max_ip = npinfo.min
        min_port = npinfo.max
        max_port = npinfo.min

        # find min and max values for the IPv4 addresses and the port numbers
        for row in X:
            if row[0] < min_ip:
                min_ip = row[0]
            if row[1] < min_ip:
                min_ip = row[1]
            if row[0] > max_ip:
                max_ip = row[0]
            if row[1] > max_ip:
                max_ip = row[1]

            if row[2] < min_port:
                min_port = row[2]
            if row[3] < min_port:
                min_port = row[3]
            if row[2] > max_port:
                max_port = row[2]
            if row[3] > max_port:
                max_port = row[3]

        ip_diff = max_ip - min_ip
        port_diff = max_port - min_port
        row_index = 0

        # Normalize the input data between [-1, 1]
        for row in X:
            X_norm[row_index, 0] = 2 * ((row[0] - min_ip) / ip_diff) - 1
            X_norm[row_index, 1] = 2 * ((row[1] - min_ip) / ip_diff) - 1
            X_norm[row_index, 2] = 2 * ((row[2] - min_port) / port_diff) - 1
            X_norm[row_index, 3] = 2 * ((row[3] - min_port) / port_diff) - 1
            row_index += 1

        return X_norm, y

    @staticmethod
    def plot_data(X):
        '''
        Plots the input data from the PCAP files. Generates two different plots; one contains the
        source IP vs. destination IP and the other contains the source port vs. the destination
        port. Does not require an instance of the TrafficClassyHelper class to use this method.

        :param X: The normalized PCAP data.
        :return: A plot of the source IPs vs. destination IPs, and another
                 plot of the source ports vs. destination ports.
        '''

        plt.title("Source IPv4 Address vs. Destination IPv4 Address")
        plt.xlabel("Source IPv4 Address")
        plt.ylabel("Destination IPv4 Address")
        for row in X:
            plt.plot(row[0], row[1], 'o')
        plt.show()

        plt.title("Source Port vs. Destination Port")
        plt.xlabel("Source Port")
        plt.ylabel("Destination Port")
        for row in X:
            plt.plot(row[2], row[3], 'o')
        plt.show()


class TrafficClassyCNN(object):

    def __init__(self):
        helper = TrafficClassyHelper("good_pcaps", "bad_pcaps")
        good_packets, bad_packets = helper.read_input()
        self.X, self.y = helper.build_input_data(good_data=good_packets, bad_data=bad_packets)
        batch_gen = self.slice_generator(shuffle=True, random_seed=123)

        '''
        TODO:
        -----
        Here we cannot be calling the build_conv_layer method for all of the generated batches,
        and this is not the proper place to start building the network. This will need to be 
        refactored at some point...
        '''
        for i, (batch_x, batch_y) in enumerate(batch_gen):
            if i == 1:
                break
            self.X = tf.convert_to_tensor(batch_x, dtype=tf.float32, name="tf_x")
            self.y = tf.convert_to_tensor(batch_y, dtype=tf.int32, name="tf_y")

            # Reshape the input into a rank 4 tensor ==> [batchsize x 256 x 4 x 1]
            self.X = tf.reshape(self.X, shape=[-1, 256, 4, 1], name='X_rashaped')
            self.build_conv_layer(name="test", kernel_size=(6, 2), n_output_size=32)

    def slice_generator(self, slice_size=256, shuffle=False, random_seed=None):
        '''
        Returns a generator of a tuple for a match of samples in slice_size chunks. Optionally can randomize
        the data as well.

        :param slice_size: The desired size of each slice or batch of data to be returned.
        :param shuffle: True if the data is to be randomized, false otherwise.
        :param random_seed: The random seed to be used for randomizing the data.
        :return: A generator with a tuple for a match of samples, (i.e. a 'slice_size' chunk of
                 the data X and their respective labels y).
        '''

        indices = np.arange(len(self.y))
        temp_X = np.c_[self.X, self.y]

        if shuffle:
            rng = np.random.RandomState(random_seed)
            rng.shuffle(indices)
            temp_X = temp_X[indices]

        X = temp_X[:, :-1]
        y = temp_X[:, -1:]

        for i in range(0, X.shape[0], slice_size):
            if len(X[i:i+slice_size, :]) != slice_size:
                diff = slice_size - len(X[i:i+slice_size, :])
                filler = np.zeros(shape=(diff, 4), dtype=np.float)
                X = np.vstack((X, filler))
                filler = np.zeros(shape=(diff, 1), dtype=np.int32)
                y = np.vstack((y, filler))
            yield (X[i:i+slice_size, :], y[i:i+slice_size])

    def build_conv_layer(self, name, kernel_size, n_output_size, padding_mode="SAME", strides=(2, 2, 2, 2)):
        '''
        A simple wrapper function that aids in building convolutional layers of the network. Returns the
        constructed convolution layer with the weights (filter) and biases have been initialized, as well as
        the convolutional layer itself with its ReLU activation function.

        :param name: The variable name that defines the scope of the convolutional subpart.
        :param kernel_size: The size of the filter.
        :param n_output_size: The number of convolutional filters.
        :param padding_mode: The padding mode; either "SAME", "VALID", or "FULL" padding modes can be used.
        :param strides: The amount to 'slide' the convolutional filter in each direction of the tensor.
        :return: The fully constructed convolutional layer.
        '''

        print("\n[*] Building convolutional layers....")
        with tf.variable_scope(name):
            input_shape = self.X.get_shape().as_list()
            n_input_size = input_shape[-1]
            weights_shape = list(kernel_size) + [n_input_size, n_output_size]
            weights = tf.get_variable(name="_weights", shape=weights_shape)
            print("[*] " + str(weights))

            biases = tf.get_variable(name="_biases", initializer=tf.zeros(shape=[n_output_size]))
            print("[*] " + str(biases))

            conv = tf.nn.conv2d(input=self.X, filter=weights, strides=strides, padding=padding_mode)
            print("[*] " + str(conv))

            conv = tf.nn.bias_add(conv, biases, name="net_pre_activation")
            print("[*] " + str(conv))

            conv = tf.nn.relu(conv, name="activation")
            print("[*] " + str(conv) + "\n[+] Got convolutional layers built")

            return conv


cnn = TrafficClassyCNN()
