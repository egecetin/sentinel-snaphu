import numpy as np
import matplotlib.pyplot as plt

# read the usage data from the file
data = np.loadtxt("usage.log", delimiter=",", skiprows=1)

timestamps = data[:, 0]
durations = [ts - timestamps[0] for ts in timestamps]

# plot the usage data as a line graph
plt.plot(durations, data[:, 1], label="CPU")
plt.plot(durations, data[:, 2], label="RAM")
plt.plot(durations, data[:, 3], label="Disk")

# set the labels and title of the graph
plt.xlabel("Time (seconds)")
plt.ylabel("Usage (percent)")
plt.title("System Usage Graph")
plt.legend()

# save the usage graph
plt.savefig("usage.png")

plt.clf()

# plot the network data as a line graph
plt.plot(durations, data[:, 4] * 8 / 1000 / 1000, label="Upload")
plt.plot(durations, data[:, 5] * 8 / 1000 / 1000, label="Download")

plt.xlabel("Time (seconds)")
plt.ylabel("Usage (Mbps)")
plt.title("System Network Usage Graph")
plt.legend()

# save the network graph
plt.savefig("network.png")
