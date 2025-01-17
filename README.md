# Network programming

This repository contains my learning journey and code experiments in analyzing network packets using the **Npcap SDK**. The project explores various aspects of packet structures, encapsulation, and decapsulation processes, focusing on Ethernet, IP, and TCP/UDP headers.


## Table of Contents

1. [Overview](#overview)
2. [Features](#features)
3. [Learning Progress](#learning-progress)
4. [Project Setup](#project-setup)



## Overview
![image](https://github.com/user-attachments/assets/c9f4e59e-198e-48df-9db5-c06ba74cdf8e)
This project utilizes the **Npcap SDK** to analyze raw packet data captured from network interfaces. By breaking down Ethernet, IP, and TCP/UDP headers, the project aims to provide a deeper understanding of how packets are structured and transmitted over a network.



## Features

- Packet capture and analysis using **Npcap SDK**.
- Decoding of **Ethernet (L2)**, **IP (L3)**, and **TCP/UDP (L4)** headers.
- Examination of issues related to **Large Send Offload (LSO)**.
- Demonstration of encapsulation and decapsulation packet.



## Learning Progress

1. **Packet Analysis with Npcap SDK**:
   - Used example codes from the **Npcap SDK** to capture and analyze raw packets.
   - Extracted and printed key fields from captured packets.

2. **Ethernet Header Analysis**:
   - Parsed and analyzed Ethernet (Layer 2) headers.
   - Studied and printed issues caused by **Large Send Offload (LSO)** during packet processing.

3. **IP Header Analysis**:
   - Analyzed the structure of IP headers within Ethernet packets.
   - Identified and decoded key fields like version, header length, total length, and protocol type.

4. **TCP/UDP Header Analysis**:
   - Parsed TCP and UDP headers (Layer 4) to understand fields like source and destination ports, sequence numbers, and checksums.

5. **Encapsulation and Decapsulation**:
   - Explored how Ethernet, IP, and TCP/UDP headers encapsulate data at different layers.
   - Visualized the decapsulation process to understand how raw frame data is interpreted at each protocol layer.



## Project Setup

To set up the project environment, refer to the [SETUP.md](Network-programming/NpcapSamples/SETTING.md) file.

Make sure to follow the steps in `SETUP.md` to ensure the project runs smoothly.
