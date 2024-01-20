import socket
import datetime, time
log_filename = "network_log.txt"

# Generate timestamp for the log file
timestamp = datetime.datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
log_filename = f"{timestamp}_{log_filename}"

# Create or open the log file in append mode
log_file = open(log_filename, "a")
while True:
    # Get the list of network connections
    connections = socket.net_connections()

    # Write the connections to the log file
    log_file.write(f"Timestamp: {datetime.datetime.now()}\n")
    for connection in connections:
        log_file.write(f"{connection}\n")
    log_file.write("\n")

    # Wait for a specified interval (e.g., 5 seconds) before checking again
    time.sleep(5)
    
log_file.close()

try:
	# Code for monitoring network connections
    print("hah")
except Exception as e:
	print(f"An error occurred: {e}")
	log_file.close()