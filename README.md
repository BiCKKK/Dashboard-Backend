# Network Controller Backend  

This repository contains the backend for the Network Controller, which provides RESTful API endpoints to manage and monitor programmable network topologies.
The flask service for Mininet network simulation is setup in Dashboard-Backend/SmartGridSim/topologies, and the controller flask service is setup in Dashboard-Backend/BPFabric/controller.

## Prerequisites  

- Access to the **Netlab VM**. Ensure that the VM is correctly set up and running before proceeding.  

## Setup Instructions  

Follow these steps to set up and run the backend server:  

1. **Open Two Terminal Windows in the Netlab VM:**  

   - **First Terminal:**  
     Navigate to the `BPFabric` controller directory and run the Flask server:  
     ```bash
     cd Dashboard-Backend/BPFabric/controller
     python3 app.py
     ```  

   - **Second Terminal:**  
     Navigate to the `SmartGridSim` topologies directory and run the Flask server with superuser privileges:  
     ```bash
     cd Dashboard-Backend/SmartGridSim/topologies
     sudo python3 app.py
     ```  

2. Both servers must be running simultaneously for the dashboard to function correctly.  

## Tools Used  

This backend integrates and extends the functionalities of the following tools:  

- **[BPFabric](https://github.com/UofG-netlab/BPFabric)**
- **[SmartGridSim](https://github.com/filipholik/SmartGridSim)**
## Usage Notes  

- Always ensure both Flask servers are running before interacting with the frontend.  
- From the frontend dashboard:  
  - **Start a Simulation:** Initialises the network topology.  
  - **Connect the Controller:** Links the controller to the topology.  
- **Before shutting down both Flask servers:**  
  - Disconnect the controller and stop the simulation from the frontend dashboard.  
  - This ensures a clean shutdown and avoids errors in future sessions.  
 
