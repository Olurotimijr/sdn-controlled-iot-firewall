FROM python:3.9-slim

# Upgrade pip and setuptools to specific versions
RUN pip install --upgrade pip setuptools==65.5.1 wheel

# Install a compatible version of Eventlet
RUN pip install eventlet==0.30.2

# Install the Ryu SDN framework
RUN pip install ryu

# Copy the firewall script into the container
COPY firewall.py /firewall.py

# Copy the trusted MACs file into the container
COPY trusted_macs.txt /trusted_macs.txt

# Expose the OpenFlow port (6633)
EXPOSE 6633

# Command to run the Ryu controller
CMD ["ryu-manager", "/firewall.py"]
