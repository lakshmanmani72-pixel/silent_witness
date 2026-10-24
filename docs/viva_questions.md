# SILENT WITNESS — College Viva & Presentation Q&A
### 25 Essential Questions & Answers for 3rd-Year IT / Computer Science Students

---

### Q1: What is a Network Intrusion Detection System (NIDS)?
**Answer:** A NIDS is a cybersecurity tool that passively monitors network traffic passing through a network segment. It analyzes packet headers and traffic patterns to detect suspicious activities, policy violations, or known attack signatures, alerting administrators without interrupting traffic flow.

---

### Q2: How does an IDS differ from an IPS (Intrusion Prevention System)?
**Answer:** An IDS is **passive**: it listens to traffic (like a security camera) and issues alerts when threats are identified. An IPS is **active**: it sits in the traffic path (in-line) and can automatically drop, reject, or contain malicious packets or offending IP addresses in real time. SILENT WITNESS combines IDS detection with an optional safe response containment layer (acting as an IDS with controlled automated response).

---

### Q3: What is a TCP SYN Flood attack?
**Answer:** A SYN Flood is a type of Denial-of-Service (DoS) attack where an attacker sends a high volume of TCP SYN (synchronize) connection requests without sending the final ACK (acknowledgment) to complete the 3-way handshake. The victim's server allocates memory in its connection backlog table for each half-open connection until system resources are exhausted and legitimate clients are denied service.

---

### Q4: How does SILENT WITNESS detect a SYN Flood attack?
**Answer:** The system tracks incoming TCP packets where the SYN flag is set and the ACK flag is absent. It counts these SYN-only packets from each unique source IP within a rolling 10-second time window. If a source IP exceeds 50 packets in the window, it is flagged as **HIGH** severity; if it exceeds 100 packets, it is escalated to **CRITICAL**.

---

### Q5: What is a Port Scan, and what is its purpose?
**Answer:** A port scan is a reconnaissance technique where an attacker probes a target system across multiple TCP or UDP port numbers to identify open listening ports, active services, operating system versions, and potential security vulnerabilities prior to launching an attack.

---

### Q6: How does the system detect Port Scanning?
**Answer:** SILENT WITNESS monitors the distinct destination ports contacted by each source IP within a configurable rolling window (default: 60 seconds). If a single source IP attempts to contact more than 100 distinct destination ports within that window, the detector classifies it as a **HIGH** severity Port Scan.

---

### Q7: What is a "Rolling Time Window" algorithm?
**Answer:** A rolling (sliding) time window is an algorithm that maintains a dynamic record of events occurring within the last $N$ seconds. Instead of resetting counters at arbitrary fixed intervals (which attackers could bypass by timing bursts across interval boundaries), the system continuously expires events older than $T_{\text{current}} - \text{window}$, ensuring accurate rate calculation at any given second.

---

### Q8: What data structure was used to implement the rolling window and why?
**Answer:** A Python `collections.deque` (double-ended queue) is used for timestamped counters. It provides $O(1)$ constant time for appending new events and $O(1)$ amortized time for popping expired events from the left, ensuring negligible CPU overhead even under high packet rates.

---

### Q9: Why is Scapy used in this project?
**Answer:** Scapy is a powerful Python packet manipulation and capture library. It provides high-level APIs to passively sniff raw network interfaces, decode Layer 2, Layer 3 (IPv4/IPv6), and Layer 4 (TCP/UDP/ICMP) headers, and extract metadata cleanly without requiring low-level C socket programming.

---

### Q10: Why does the system only capture packet metadata and not raw payloads?
**Answer:** For privacy, compliance, and performance reasons:
1. **Privacy**: Packet payloads may contain sensitive user data, passwords, or personal messages.
2. **Performance**: Inspecting payloads consumes high CPU and disk storage.
3. **Detection Sufficiency**: Network-layer threats like SYN floods and port scans are identified entirely from header flags, IP addresses, and port numbers.

---

### Q11: What is a "False Positive" in network security?
**Answer:** A false positive occurs when the detection system incorrectly flags legitimate, benign traffic as an attack. For example, a busy web browser opening multiple parallel connections to download webpage assets could look like rapid traffic, which is why thresholds must be tuned and normal handshakes (SYN+ACK) filtered out.

---

### Q12: How does SILENT WITNESS prevent false positives during normal browsing?
**Answer:** Normal TCP traffic involves established connections with both SYN and ACK flags set, or pure ACK/PSH packets. The detector strictly inspects TCP flags and only counts packets where SYN is 1 and ACK is 0, completely ignoring regular HTTP/HTTPS traffic handshakes.

---

### Q13: What is "Dry-Run" mode and why is it essential?
**Answer:** Dry-run mode evaluates detection rules and records the exact containment action the firewall *would* have taken, but without executing system-level firewall modifications. This is crucial for:
- Safe classroom and viva demonstrations on student laptops.
- Preventing accidental lockout of the operator.
- Verifying detection accuracy in production before trusting automated blocking.

---

### Q14: How does the automated containment (blocking) workflow operate?
**Answer:** When an event is classified as HIGH or CRITICAL:
1. The IP format is validated.
2. The IP is checked against an allow-list (loopback and gateway IPs can never be blocked).
3. The system verifies the IP is not already blocked.
4. Hourly rate limits are checked.
5. The block record is stored with an expiration timestamp.
6. If real firewall mode is enabled on Linux, an iptables drop rule is inserted.

---

### Q15: Why is an IP Allow-List necessary?
**Answer:** Without an allow-list, an attacker spoofing the IP of the default network gateway or a local DNS server could trick an automated defense system into blocking critical network infrastructure, causing a self-inflicted denial-of-service.

---

### Q16: Why do blocked IP records expire automatically?
**Answer:** Permanent IP blocks cause several operational problems:
1. Attackers frequently use dynamic IP addresses that are later reassigned to innocent users (DHCP churn).
2. Large firewall rule tables degrade network routing performance.
3. Temporary containment (e.g., 60 minutes) mitigates the attack burst while allowing network recovery without permanent manual cleanup.

---

### Q17: What are the fundamental limitations of IP address blocking?
**Answer:**
1. **IP Spoofing**: Attackers can forge the source IP header in UDP or TCP SYN packets.
2. **Botnets / Distributed Attacks (DDoS)**: Attacks originate from thousands of distinct IP addresses, making single-IP blocking ineffective.
3. **NAT (Network Address Translation)**: Blocking an IP behind a shared corporate or campus router can inadvertently block hundreds of legitimate users.

---

### Q18: What is the difference between Simulation Mode and Live Monitoring Mode?
**Answer:**
- **Simulation Mode**: Generates synthetic, mathematically structured packet metadata internally. It requires zero administrative privileges and no packet capture drivers, making it 100% reliable for demonstration.
- **Live Monitoring Mode**: Connects to the host's actual network adapter using Scapy/Npcap to passively inspect real network packets passing through the machine.

---

### Q19: Why was SQLite selected as the database engine?
**Answer:** SQLite is serverless, zero-configuration, and stores the entire database in a single local file. With Write-Ahead Logging (WAL) enabled, it easily handles thousands of concurrent reads and writes with sub-millisecond query latency, eliminating the need to set up complex external database servers (like MySQL or PostgreSQL) for a single-machine project.

---

### Q20: What is Write-Ahead Logging (WAL) in SQLite?
**Answer:** In standard rollback journal mode, writing locks the entire database. In WAL mode, changes are appended to a separate log file, allowing readers to read concurrently while writes take place. This ensures the live dashboard UI remains fast and responsive even while traffic stats are continuously written.

---

### Q21: How are real-time updates pushed to the frontend dashboard?
**Answer:** The FastAPI backend maintains an active WebSocket server endpoint (`/ws/events`). When the Event Processor registers a new detection, it broadcasts a JSON event to all connected clients. If the WebSocket connection drops, the frontend gracefully falls back to periodic polling.

---

### Q22: Why does the system use subprocess argument lists instead of shell strings for iptables?
**Answer:** Using `subprocess.run(["iptables", "-I", ...], shell=False)` prevents **Command Injection vulnerabilities**. If `shell=True` were used, an attacker could craft an IP string containing shell metacharacters (e.g. `; rm -rf /`) that could execute arbitrary commands with root privileges.

---

### Q23: What is Alert Cooldown and why is it implemented?
**Answer:** When a host sends 10,000 SYN packets in a second, generating 10,000 individual alerts would overwhelm the database and flood the administrator's dashboard. The alert cooldown timer ensures only one high-priority alert is generated per source IP per time window (e.g. every 30 seconds).

---

### Q24: What metrics are displayed on the SOC Overview dashboard?
**Answer:**
1. **Total Threats Detected** (cumulative volume)
2. **Critical Threats** (SYN floods &gt; 100 packets)
3. **High Severity Threats** (Port scans & moderate floods)
4. **Active Blocked IPs** (currently contained hosts)
5. **Packets Analyzed** (inspected header volume)
6. **System Uptime** (continuous monitoring duration)
7. **Traffic Volume & Threat Rate Area Chart**
8. **Threat Vector Donut Chart & Severity Distribution**

---

### Q25: How would you extend this project for a production enterprise environment?
**Answer:**
1. **Distributed Sensor Network**: Deploy lightweight packet capture agents (e.g., Zeek or Suricata) on network taps and aggregate logs to a central Elasticsearch/Kafka cluster.
2. **Machine Learning / Behavioral Analysis**: Train anomaly detection models (Isolation Forests or Autoencoders) to identify novel zero-day attacks that bypass static thresholds.
3. **BGP Flowspec Integration**: Integrate with core border routers via BGP to blackhole DDoS traffic upstream at the ISP level before it reaches local firewalls.
