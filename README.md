# Mobile-Application-Security-Analyzer
Mobile App Security Analyzer Automated Tool

This project provides a mobile application security analysis setup using a MobSF server running in Docker and a client application (now distributed as an .exe) that interacts with the server to analyze APKs and produce concise reports using AI-assisted summarization.

-------------------------------

Technology Stack

MobSF (Mobile Security Framework) running in Docker

Python (for AI modules and report processing)

PyTorch & Transformers (for AI summarization)

Rich (for console tables and formatting)

Client: Converted Python script to .exe using PyInstaller

OS: Windows (client) / Docker-compatible host for MobSF

-------------------------------

Project Structure

server/ → Dockerized MobSF setup

client/ → Python scripts for client, now converted to .exe

reports/ → Generated security analysis reports (JSON + console summaries)

models/ → PyTorch models used for AI summarization

-------------------------------

Setup Instructions

1. Start the MobSF Server

1. Ensure Docker is installed on your system.


2. Pull the MobSF image or use the provided Docker setup.


3. Run the following command to start the server:


docker-compose build wrapper
docker-compose up -d

MobSF will be available at http://localhost:8000.
WrapperApi will be available at https://localhost:5000/docs

The server handles APK analysis requests from the client.

-------------------------------

2. Running the Client

1. Navigate to the folder containing client.exe.

2. Run the client with an APK as input:

client.exe "C:\path\to\your\app.apk"

The client will communicate with the MobSF server.

Generates a concise security report in the console.

AI summarization provides short remediation suggestions for each issue.

-------------------------------

3. AI Summarization

Uses pre-trained PyTorch/Transformers models.

Produces short, clear remediation suggestions for:

Debug certificates

Hardcoded secrets

Exported activities

Weak hashing algorithms

HTTP endpoints

Configurable max_length/min_length for concise outputs.

-------------------------------

4. Risk Distribution Visualization

Reports include risk distribution with weighted percentages:

Critical: Red

High: Orange

Warning: Yellow

Info: Green

Unknown: White

Easily identifies most severe issues at a glance.

-------------------------------

5. Notes

Python environment is needed to generate AI-assisted suggestions if modifying scripts.

The .exe client already includes required dependencies and can run on systems without Python installed.

-------------------------------

6. How It Works

1. Client uploads APK to MobSF server.


2. Server analyzes APK and returns detailed JSON report.


3. Client parses the report:

Critical/high issues are detailed

Warnings/info are summarized

AI generates remediation suggestions


4. Final report displayed in console tables with colored risk bars.

-------------------------------

This setup allows a complete mobile app security analysis with minimal manual effort and AI-assisted remediation guidance, packaged for team use.
