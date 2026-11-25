\# Automated Network Forensic Analysis for Attack Timeline Reconstruction



Detects Portscan and DDoS attacks in network flow data and reconstructs an ordered attack timeline.



\## Dataset

CIC-IDS-2017, Friday file (friday.csv, \~200 MB, 547,557 flows x 89 columns).

Download it from Kaggle and place it in the project folder. It is not included in this repo because of its size.

Note: the Timestamp column in this file is damaged, so event order is based on row order (Event\_Order).



\## Method

1\. data\_loader.py: loads friday.csv, keeps 13 relevant columns, adds Event\_Order.

2\. attack\_detection.py: rule-based detection.

&#x20;  - Portscan: short duration + low packet count + SYN flag

&#x20;  - DDoS: long flow duration + high packet count

3\. timeline\_reconstruction.py: sorts flagged flows by Event\_Order and labels each as PortScan, DDoS or PortScan+DDoS. Output: attack\_timeline.csv (sample\_timeline.csv has the first 1,000 rows).



\## Results

\- Portscan: 157,866 of 159,066 detected (\~99% recall)

\- DDoS: 92,166 of 95,144 detected (\~97% recall)

\- Timeline: 329,381 flagged events (170,960 DDoS, 158,421 PortScan)

\- Limitation: 79,349 benign flows were wrongly flagged (24.1% of flagged events), a known weakness of simple rules.



\## Architecture

Five layers: Input, Processing and Analysis, Storage (PostgreSQL), API (FastAPI), Presentation (React dashboard with PDF/CSV report).

This repo contains the Input and Processing/Analysis layers. The other layers were built by teammates: \[Swetha,Shanmadhi,].



\## How to run

python data\_loader.py

python attack\_detection.py

python timeline\_reconstruction.py



\## Tech

Python, pandas

