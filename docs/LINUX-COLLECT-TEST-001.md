LINUX-COLLECT-TEST-001
Host: LINUX-LAB-01 (Kali Linux VM on VMware)
Date: 2026-11-10
Test: Hands-on collector run on a real Linux host with simulatedfailed SSH login activity (3 ssh runs x 3 wrong passwords).
Procedure
Recorded wc -l /var/log/auth.log before the activity.
Generated failed login attempts: ssh labtest@localhost (x3, wrong password).
Re-ran wc -l /var/log/auth.log after the activity.
Ran sudo python3 collectors/linux/collector.py --host-id LINUX-LAB-01.
Verified the evidence inside the collector output.
Results
auth.log lines before: 3
auth.log lines after: 36
New failed-password records captured: 9
Collector sources: auth_log = collected, syslog = collected,systemd_services = collected, ssh_metadata = collected
Verdict
PASS — the collector captured the simulated failed-password activity.