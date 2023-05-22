# Packet Sniffing Backdoor

## What is it

This application is a proof of concept packet sniffing backdoor. When running in SERVER mode, the packet sniffer listens for packets on port 53 using libpcap. This allows
the application to process packets even if the system has a firewall. When it receives a command from the client, it executes it and sends the response
back to the client. The application masks the process name to prevent it from being detected in the process table

## Prerequisites

You must have the following installed:

- setproctitle
- scapy

## To run

Use:

    python main.py SERVER
    python main.py CLIENT TARGET_IP