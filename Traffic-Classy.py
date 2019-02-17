from scapy.all import rdpcap
import os
import logging
import numpy as np
from ipaddress import IPv4Address
import tensorflow as tf
import matplotlib.pyplot as plt
from sklearn.model_selection import train_test_split


class TrafficClassyHelper(object):

    def __init__(self, good_path, bad_path):
        self.good_path = good_path
        self.bad_path = bad_path

    def read_input(self):
        '''
        Helper function to read in the PCAP files and store the packets into fixed sized matrices. Each
        PCAP file is broken down into a matrix with 256 packets per row.

        :return: good_packet_matrix - A matrix of the benign packets segmented to have 256 packets per row.
                 bad_packet_matrix  - A matrix of the nefarious packets segmented to have 256 packets per row.
        '''

        good_packet_list = []
        bad_packet_list = []
        good_packet_matrix = []
        bad_packet_matrix = []
        good_count = 0
        bad_count = 0
        print("[*] Reading PCAP files from \"" + self.good_path + "\" directory....")
        try:
            for good_filename in os.listdir(self.good_path):
                print("[*] Processing packets from file: " + "\"" + good_filename + "\"")
                data = rdpcap(self.good_path + "/" + good_filename)
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
                                good_count += len(good_packet_list)
                                good_packet_list.clear()
                                i += 1
                if i % 256 != 0:
                    good_packet_matrix.append([i for i in good_packet_list])
                    index = len(good_packet_matrix) - 1
                    diff = 256 - len(good_packet_matrix[index])
                    good_count -= diff
                    for num in range(diff):
                        good_packet_matrix[index].append(None)
                good_count += len(good_packet_list)
                good_packet_list.clear()

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
                i = 1
                for session in sessions:
                    for packet in sessions[session]:
                        if packet.haslayer("TCP") and packet.haslayer("IP"):
                            if i % 256 != 0:
                                bad_packet_list.append(packet)
                                i += 1
                            else:
                                bad_packet_list.append(packet)
                                bad_packet_matrix.append([i for i in bad_packet_list])
                                bad_count += len(bad_packet_list)
                                bad_packet_list.clear()
                                i += 1

                if i % 256 != 0:
                    bad_packet_matrix.append([i for i in bad_packet_list])
                    index = len(bad_packet_matrix) - 1
                    diff = 256 - len(bad_packet_matrix[index])
                    bad_count -= diff
                    for num in range(diff):
                        bad_packet_matrix[index].append(None)
                bad_count += len(bad_packet_list)
                bad_packet_list.clear()

        except FileNotFoundError as e:
            logging.basicConfig(filename='errors.log', level=logging.DEBUG)
            logging.exception(e)
            print("[-] File not found error.")
            exit(1)

        print("[+] Read in " + str(good_count) + " good packets and " +
              str(bad_count) + " bad packets containing TCP and IP layers\n")

        return good_packet_matrix, bad_packet_matrix

    def build_input_data(self, good_data, bad_data):
        '''
        Builds the dataset X from a matrix of good PCAP files and bad PCAP files and returns the input data and
        corresponding labels ready for data splitting. Returns the normalized input data (in the range [-1, 1]),
        and their respective labels.

        :param good_data: A fixed size matrix of benign packets.
        :param bad_data:  A fixed size matrix of nefarious packets.
        :return: X - The input matrix to the network consisting of column labels of the source IP, destination IP,
                     source port, and destination port in each row. Data is normalized in the range [-1, 1].
                     Has shape: (len(good_data) + len(bad_data), 4)

                 y - The labels, 0 or 1, for each row in the input matrix.
                     Has shape:  (len(good_data) + len(bad_data), 1)
        '''

        X = np.zeros(shape=(len(good_data)+len(bad_data), 1024), dtype=np.int64)
        X_norm = np.zeros(shape=(len(good_data)+len(bad_data), 1024), dtype=np.float)
        good_labels = [0 for i in range(len(good_data))]
        bad_labels = [1 for i in range(len(bad_data))]
        y = good_labels + bad_labels

        row_index = 0
        for row in good_data:
            for i in range(len(row)):
                if row[i] is None:
                    X[row_index, (i*4)] = 0
                    X[row_index, (i*4)+1] = 0
                    X[row_index, (i*4)+2] = 0
                    X[row_index, (i*4)+3] = 0
                else:
                    X[row_index, (i*4)] = np.int64(IPv4Address(row[i].getlayer("IP").src))
                    X[row_index, (i*4)+1] = np.int64(IPv4Address(row[i].getlayer("IP").dst))
                    X[row_index, (i*4)+2] = np.int64(row[i].sport)
                    X[row_index, (i*4)+3] = np.int64(row[i].dport)
            row_index += 1

        for row in bad_data:
            for i in range(len(row)):
                if row[i] is None:
                    X[row_index, (i*4)] = 0
                    X[row_index, (i*4)+1] = 0
                    X[row_index, (i*4)+2] = 0
                    X[row_index, (i*4)+3] = 0
                else:
                    X[row_index, (i*4)] = np.int64(IPv4Address(row[i].getlayer("IP").src))
                    X[row_index, (i*4)+1] = np.int64(IPv4Address(row[i].getlayer("IP").dst))
                    X[row_index, (i*4)+2] = np.int64(row[i].sport)
                    X[row_index, (i*4)+3] = np.int64(row[i].dport)
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
                if row[i+1] != 0 and row[i+1] < min_ip:
                    min_ip = row[i+1]
                if row[i] != 0 and row[i] > max_ip:
                    max_ip = row[i]
                if row[i+1] != 0 and row[i+1] > max_ip:
                    max_ip = row[i+1]

                if row[i+2] != 0 and row[i+2] < min_port:
                    min_port = row[i+2]
                if row[i+3] != 0 and row[i+3] < min_port:
                    min_port = row[i+3]
                if row[i+2] != 0 and row[i+2] > max_port:
                    max_port = row[i+2]
                if row[i+3] != 0 and row[i+3] > max_port:
                    max_port = row[i+3]

        ip_diff = max_ip - min_ip
        port_diff = max_port - min_port
        row_index = 0

        for row in X:
            for i in range(0, len(row), 4):
                if row[i] != 0:
                    X_norm[row_index, i] = 2 * ((row[i] - min_ip) / ip_diff) - 1
                if row[i+1] != 0:
                    X_norm[row_index, i+1] = 2 * ((row[i+1] - min_ip) / ip_diff) - 1
                if row[i+2] != 0:
                    X_norm[row_index, i+2] = 2 * ((row[i+2] - min_port) / port_diff) - 1
                if row[i+3] != 0:
                    X_norm[row_index, i+3] = 2 * ((row[i+3] - min_port) / port_diff) - 1
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
        plt.xlim((-1.5, 1.5))
        plt.ylim((-1.5, 1.5))
        x = X[:, [i for i in range(len(X[0])) if i % 4 == 0]]  # All the source IPs
        y = X[:, [i for i in range(len(X[0])) if i % 4 == 1]]  # All the dest. IPs
        x_filtered = x[x != 0]  # Don't plot the zeros
        y_filtered = y[y != 0]  # Don't plot the zeros
        plt.scatter(x_filtered, y_filtered)
        plt.show()

        plt.title("Source Port vs. Destination Port")
        plt.xlabel("Source Port")
        plt.ylabel("Destination Port")
        plt.xlim((-1.5, 1.5))
        plt.ylim((-1.5, 1.5))
        x = X[:, [i for i in range(len(X[0])) if i % 4 == 2]]  # All the source ports
        y = X[:, [i for i in range(len(X[0])) if i % 4 == 3]]  # All the dest. ports
        x_filtered = x[x != 0]  # Don't plot the zeros
        y_filtered = y[y != 0]  # Don't plot the zeros
        plt.scatter(x_filtered, y_filtered)
        plt.show()


class TrafficClassyCNN(object):

    def __init__(self, validate=True):
        helper = TrafficClassyHelper("good_pcaps", "bad_pcaps")
        good_packets, bad_packets = helper.read_input()
        self.X, self.y = helper.build_input_data(good_data=good_packets, bad_data=bad_packets)
        helper.plot_data(self.X)
        self.validate = validate

        # 80-20 train-test split
        self.X_train, self.X_test, self.y_train, self.y_test = train_test_split(self.X, self.y,
                                                                                test_size=0.2, random_state=1)

        # Or 60-20-20 train-validate-test split
        if self.validate:
            self.X_train, self.X_valid, self.y_train, self.y_valid = train_test_split(self.X_train, self.y_train,
                                                                                      test_size=0.2, random_state=1)
            print("[*] Validation data X_valid and y_valid have shapes:", self.X_valid.shape, len(self.y_valid))
        print("[*] Training data X_train and y_train have shapes:", self.X_train.shape, len(self.y_train))
        print("[*] Testing data X_test and y_test have shapes:", self.X_test.shape, len(self.y_test))

    def slice_generator(self, slice_size=16, shuffle=False, random_seed=None):
        '''
        Returns a generator of a tuple for a match of samples in slice_size chunks. Optionally can randomize
        the data as well.

        :param slice_size: The desired size of each slice or batch of data to be returned.
        :param shuffle: True if the data is to be randomized, false otherwise.
        :param random_seed: The random seed to be used for randomizing the data.
        :return: A generator with a tuple for a match of samples, (i.e. a 'slice_size' chunk of
                 the data X and their respective labels y).
        '''

        indices = np.arange(len(self.y_train))
        temp_X = np.c_[self.X_train, self.y_train]

        if shuffle:
            rng = np.random.RandomState(random_seed)
            rng.shuffle(indices)
            temp_X = temp_X[indices]

        X = temp_X[:, :-1]
        y = temp_X[:, -1:]
        y = y.reshape((len(y)))
        for i in range(0, X.shape[0], slice_size):
            yield (X[i:i+slice_size, :], y[i:i+slice_size])

    def build_conv_layer(self, input, name, kernel_size, n_output_size, padding_mode="SAME", strides=(1, 2, 2, 1)):
        '''
        A simple wrapper function that aids in building convolutional layers of the network. Returns the
        constructed convolution layer with the weights (filter) and biases have been initialized, as well as
        the convolutional layer itself with a leaky ReLU activation function. The weights are initialized using
        the Xavier initialization scheme via the call to tf.get_variable() and the biases are initialized to
        zeros.

        :param input: The input layer of the convolution to build.
        :param name: The variable name that defines the scope of the convolutional subpart.
        :param kernel_size: The size of the filter.
        :param n_output_size: The number of convolutional filters.
        :param padding_mode: The padding mode; either "SAME", "VALID", or "FULL" padding modes can be used.
        :param strides: The amount to 'slide' the convolutional filter in each direction of the tensor.
        :return: The fully constructed convolutional layer.
        '''

        print("\n[*] Building convolutional layer....")
        with tf.variable_scope(name):
            input_shape = input.get_shape().as_list()
            n_input_size = input_shape[-1]
            weights_shape = list(kernel_size) + [n_input_size, n_output_size]
            weights = tf.get_variable(name="_weights", shape=weights_shape)
            print("[*] " + str(weights))

            biases = tf.get_variable(name="_biases", initializer=tf.zeros(shape=[n_output_size]))
            print("[*] " + str(biases))

            conv = tf.nn.conv2d(input=input, filter=weights, strides=strides, padding=padding_mode)
            print("[*] " + str(conv))

            conv = tf.nn.bias_add(conv, biases, name="net_pre_activation")
            print("[*] " + str(conv))

            conv = tf.nn.relu(conv, name="activation")
            print("[*] " + str(conv) + "\n[+] Got convolutional layer built")

            return conv

    def build_fully_connected_layer(self, input, name, n_output_units, activation_fcn=None):
        '''
        A simple wrapper function that aids in building a fully connnected layer for the network.
        Behaves differently for the two fully connected layers at the end of the network. The first time
        this method gets called the input is a 4D tensor and will require non-linearity, and the output from
        the first fully connected layer is being passed to leaky ReLU. The second time this method gets called the
        input will be flattened into an array and will later be passed in to logits, meaning a linear activation
        will be used.

        :param input: The input tensor.
        :param name: The name of the layer and scope of our tensorflow variable.
        :param n_output_units: The number of output nodes in the network. This will either be the number of
                               our pre_activation nodes or number of prediction classes.
        :param activation_fcn: The activation function to be used. Does not have to be leaky ReLU, can be any
                               other activation function supported by tensorflow. If None, that indicates a
                               linear activation will be used at a later point via softmax with logits.
        :return: The fully connected layer.
        '''

        print("\n[*] Building fully connected layer....")
        with tf.variable_scope(name):
            input_shape = input.get_shape().as_list()[1:]
            n_input_units = np.prod(input_shape)
            if len(input_shape) > 1:
                input = tf.reshape(input, shape=(-1, n_input_units))

            weights_shape = [n_input_units, n_output_units]
            weights = tf.get_variable(name="_weights", shape=weights_shape)
            print("[*] " + str(weights))

            biases = tf.get_variable(name="_biases", initializer=tf.zeros(shape=[n_output_units]))
            print("[*] " + str(biases))

            layer = tf.matmul(input, weights)
            print("[*] " + str(layer))

            layer = tf.nn.bias_add(layer, biases, name="pre_net_activation")
            print("[*] " + str(layer))

            if activation_fcn is None:
                print("[*] " + str(layer) + "\n[+] Got fully connected layer built")
                return layer

            layer = activation_fcn(layer, name="activation_fcn")
            print("[*] " + str(layer) + "\n[+] Got fully connected layer built")
            return layer

    def build_cnn(self, learning_rate):
        '''
        Fully constructs the network using the build_conv_layer() and build_fully_connected_layer() methods.
        Makes use of tensorflow's built in max_pool() method for the pooling layers.

        :param learning_rate: The learning rate hyperparameter.
        :return: A fully constructed tensorflow context with all global variables ready to be initialized
                 and run.
        '''

        tf_x = tf.placeholder(tf.float32, shape=[None, 1024], name="tf_x")

        tf_y = tf.placeholder(tf.int32, shape=[None], name="tf_y")

        # Reshape the input into a rank 4 tensor ==> [batchsize x 256 x 4 x 1]
        tf_x_reshaped = tf.reshape(tf_x, shape=[-1, 256, 4, 1], name='X_rashaped')

        tf_y_onehot = tf.one_hot(indices=tf_y, depth=2, dtype=tf.float32, name="tf_y_onehot")

        hidden1 = self.build_conv_layer(input=tf_x_reshaped, name="conv_1", kernel_size=(6, 2),
                                        n_output_size=32, padding_mode="VALID")

        hidden1_pooled = tf.nn.max_pool(hidden1, ksize=[1, 4, 1, 1], strides=[1, 4, 1, 1], padding="SAME")

        hidden2 = self.build_conv_layer(input=hidden1_pooled, name="conv_2", kernel_size=(6, 2),
                                        n_output_size=64, padding_mode="VALID")

        hidden2_pooled = tf.nn.max_pool(hidden2, ksize=[1, 2, 1, 1], strides=[1, 2, 1, 1], padding="SAME")

        hidden3 = self.build_fully_connected_layer(input=hidden2_pooled, name="fc_1",
                                                   n_output_units=448, activation_fcn=tf.nn.leaky_relu)
        keep_prob = tf.placeholder(tf.float32, name="keep_prob")

        hidden3_dropout = tf.nn.dropout(hidden3, keep_prob=keep_prob, name="dropout_layer")

        hidden4 = self.build_fully_connected_layer(input=hidden3_dropout, name="fc_2",
                                                   n_output_units=2, activation_fcn=None)

        preds = {"probabilities": tf.nn.softmax(logits=hidden4, name="probabilities"),
                 "labels": tf.cast(tf.argmax(hidden4, axis=1), tf.int32, name="labels")}
        cross_entropy_loss = tf.reduce_mean(tf.nn.softmax_cross_entropy_with_logits(logits=hidden4, labels=tf_y_onehot),
                                            name="cross_entropy_loss")

        # Using the fancy gradient optimizer Adam which was inspired by RMSProp and AdaGrad.
        # Adam uses clever updates to the step size when descending the gradient by using the
        # running average of gradient momentums...
        #
        # More on optimizers can be seen here: https://www.youtube.com/watch?v=_JB0AO7QxSA&t=3020s
        optimizer = tf.train.AdamOptimizer(learning_rate)
        optimizer = optimizer.minimize(cross_entropy_loss, name="train_op")

        correct_preds = tf.equal(preds["labels"], tf_y, name="correct_predictions")
        accuracy = tf.reduce_mean(tf.cast(correct_preds, tf.float32), name="accuracy")

    def train(self, sess, initialize=True, epochs=20, shuffle=True, dropout=0.5, random_seed=None):
        '''
        Trains the neural network.

        :param sess: The tensorflow session to execute.
        :param initialize: A flag to indicate whether or not to initialzie the tensorflow variables.
        :param epochs: The number of passes through the data set.
        :param shuffle: A flag that tells the batch generator to randomize the data or not.
        :param dropout: The dropout rate.
        :param random_seed: The random seed for setting numpy.random.
        :return: Trained model.
        '''

        training_loss = []
        if initialize:
            sess.run(tf.global_variables_initializer())

        np.random.seed(random_seed)
        for epoch in range(1, epochs+1):
            batch_gen = self.slice_generator(shuffle=shuffle)
            avg_loss = 0.0
            for i, (batch_x, batch_y) in enumerate(batch_gen):
                feed = {"tf_x:0": batch_x, "tf_y:0": batch_y, "keep_prob:0": dropout}
                loss, _ = sess.run(["cross_entropy_loss:0", "train_op"], feed_dict=feed)
                avg_loss += loss

            training_loss.append(avg_loss/(i+1))
            print("Epoch %02d Training Avg. Loss: %7.3f" % (epoch, avg_loss), end=" ")
            if self.validate:
                feed = {"tf_x:0": self.X_valid, "tf_y:0": self.y_valid, "keep_prob:0": 1.0}
                valid_acc = sess.run("accuracy:0", feed_dict=feed)
                print("Validation Accuracy: %7.3f" % valid_acc)
            else:
                print()

    def predict(self, sess, return_proba=False):

        feed = {"tf_x:0": self.X_test, "keep_prob:0": 1.0}
        if return_proba:
            return sess.run("probabilities:0", feed_dict=feed)
        else:
            return sess.run("labels:0", feed_dict=feed)


if __name__ == "__main__":
    cnn = TrafficClassyCNN(validate=True)
    learning_rate = 1e-5
    random_seed = 123
    g = tf.Graph()
    with g.as_default():
        tf.set_random_seed(random_seed)
        cnn.build_cnn(learning_rate=learning_rate)
        saver = tf.train.Saver()

    with tf.Session(graph=g) as sess:
        # Write graph to Tensorboard for visualization. This is accessed by running: tensorboard --logdir=<filename>
        writer = tf.summary.FileWriter("./Files/tf_graph", sess.graph)
        cnn.train(sess=sess, random_seed=123)
        preds = cnn.predict(sess=sess, return_proba=False)
        print("\n[+] Test Accuracy: %.3f%%" % (100 * np.sum(preds == cnn.y_test) / len(cnn.y_test)))
        writer.close()
del g
