# Traffic-Classy
The scope of this project is to implement a neural network that can learn benign 
and nefarious network activity through training via PCAP (packet capture) files.
The first model prototype consists of a Convolutional Neural Network (CNN) 
trained on acceptable network traffic (being Google search queries and other
"average" day-to-day traffic we would see in our networks) and unacceptable
traffic obtained from Metasploitable 2 exploits. The Metasploitable 2 PCAPs
consists of different exploits ranging from old rlogin exploits, vsftp
version2.1 vulnerablilities to exploiting the distributed C compiler (distcc)
vulnerabilities along with privelege escalation yielding a root bind shell.
This data is held in the **good_pcaps** and **bad_pcaps** directories.

For the first prototype the idea was to read in packets from a PCAP file and 
check the packets for TCP and IP layers. If those layers existed in the packets,
then the source IP, destination IP, source port, and destination port were extracted
and stored in a matrix in that particular order. IPv4 addresses are dotted fours (32 bits)
so they first get converted to integers then normalized in the range [-1, 1]. Since the ports
are only half words they too are stored in integers then normalized accordingly in the range [-1, 1].
The thought here was to use a kernel with a vertical stride (against the rows) of 6, with a 
horizontal stride (against the columns) of 2 to teach the network "good" and "bad" relationships
between the source and destination IPv4 addresses and ports. 

The model initially started with two convolution layers and two max pooling layers. The output of
the last pooling layer is flattened into a vector with 512 elements and passed into an MLP with
two output classes (benign and nefarious) as shown below.

![cnn-prototype1](https://user-images.githubusercontent.com/32188816/53281262-dc6ab400-36e2-11e9-8638-63fa094495ee.jpg)

For training the CNN, SGD and its variants were avoided due to saturated neurons (input being either extremely negative 
or extremely positive) killing the gradients, and the sigmoid outputs are not zero-centered meaning that if the input is 
always positive then the gradients will always all be either positive or negatigve, resulting in undesirable performance. 
As such, the popular Adam Optimizer is used, which was derived from the concepts of the RMSProp and AdaGrad optimizers.
The activation function used for the CNN is a Leaky ReLU. Since the data is normalized in [-1, 1] I did not want to 
use the basic ReLU since it saturates negative numbers (the corresponding Y-Value of negative inputs are always 0
thus causing the gradients to be 0). In addition to the non saturating benefit of Leaky ReLU, it is also very efficient 
and in general converges faster than the sigmoid and hyperbolic tangent functions. Finally, a linear activation is used
for the fully connected layer at the end of the CNN using softmax cross entropy with logits. Once the first model was
fully constructed the following shows the resulting TensorBoard and the complete architecture for the first prototype.

![tensor_board_graph_cropped](https://user-images.githubusercontent.com/32188816/53288657-410c2a00-3748-11e9-945e-6861e8dadd08.png)

CNNs are feature extraction engines by nature, meaning that we can give it many features and it will extract the meaningful
features and then feed those into the MLP at the end of the model. For the second prototype, I decided to give it some features from the PCAP files and see how that effected the performance of the model. The features that I added are the packet length, SEQ number, ACK numbers, window size, and the source and destination MAC addresses. These are all stored in their own columns and normalized in the range [-1, 1] using their respective minimum and maximum values. The hope with adding the new features is that it will give the model more context of what average network traffic looks like opposed to nefarious network traffic, and if the features are meaningless the CNN will weed those out before they reach the first fully connected layer (i.e. the input to the MLP at the end of the CNN) through the CNN's filtering and max pooling operations. The second model's prototype is shown below.

![cnn-prototype2](https://user-images.githubusercontent.com/32188816/53323106-788aeb80-389a-11e9-9dc0-8c33946a7a8d.jpg)
