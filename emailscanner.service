[Unit]
Description=Email scanner
Wants=network-online.target
After=network-online.target

[Service]
WorkingDirectory=/opt/EmailScanner
Type=simple
User=emailscanner
Group=emailscanner

ExecStart=/bin/python /opt/EmailScanner/emailscanner.py

StandardOutput=syslog
StandardError=syslog
TimeoutStopSec=0

KillSignal=SIGKILL

[Install]
WantedBy=multi-user.target
