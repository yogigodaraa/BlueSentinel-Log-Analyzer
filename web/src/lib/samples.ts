/**
 * Pre-canned log samples for the interactive demo. Each one triggers
 * a different subset of detections so users can see how the engine
 * responds to different attack shapes.
 */

export interface Sample {
  id: string;
  title: string;
  description: string;
  log: string;
}

export const SAMPLES: Sample[] = [
  {
    id: "kill-chain",
    title: "Full kill-chain attack",
    description:
      "20 failed SSH attempts → successful login → sudo abuse → discovery → lateral movement → firewall disable → log tampering → data destruction. The engine should reconstruct this as one chain with a high score.",
    log: `Apr 20 09:05:00 prod-01 sshd[4221]: Failed password for root from 203.0.113.5 port 44251 ssh2
Apr 20 09:05:02 prod-01 sshd[4222]: Failed password for root from 203.0.113.5 port 44252 ssh2
Apr 20 09:05:04 prod-01 sshd[4223]: Failed password for root from 203.0.113.5 port 44253 ssh2
Apr 20 09:05:06 prod-01 sshd[4224]: Failed password for root from 203.0.113.5 port 44254 ssh2
Apr 20 09:05:08 prod-01 sshd[4225]: Failed password for root from 203.0.113.5 port 44255 ssh2
Apr 20 09:06:00 prod-01 sshd[4226]: Accepted password for root from 203.0.113.5 port 44256 ssh2
Apr 20 09:06:30 prod-01 sudo[5001]: authentication failure for root
Apr 20 09:07:00 prod-01 bash[5010]: cat /etc/passwd
Apr 20 09:08:00 prod-01 sshd[5100]: Accepted publickey for root from 203.0.113.5 port 44300 ssh2
Apr 20 09:09:00 prod-01 root: iptables -F
Apr 20 09:10:00 prod-01 root: rm /var/log/auth.log
Apr 20 09:11:00 prod-01 root: rm -rf /data/warehouse/*`,
  },
  {
    id: "brute-force-only",
    title: "Brute force only (not a full attack)",
    description:
      "Just repeated failed logins — no successful follow-through. Should produce individual detections but no strong attack chain.",
    log: `Apr 20 14:00:00 web-03 sshd[1100]: Failed password for admin from 198.51.100.7 port 50022 ssh2
Apr 20 14:00:05 web-03 sshd[1101]: Failed password for admin from 198.51.100.7 port 50023 ssh2
Apr 20 14:00:10 web-03 sshd[1102]: Failed password for admin from 198.51.100.7 port 50024 ssh2
Apr 20 14:00:15 web-03 sshd[1103]: Failed password for admin from 198.51.100.7 port 50025 ssh2
Apr 20 14:00:20 web-03 sshd[1104]: Failed password for admin from 198.51.100.7 port 50026 ssh2`,
  },
  {
    id: "noise",
    title: "Benign noise",
    description: "Normal cron and session activity. Should produce zero detections.",
    log: `Apr 20 09:00:00 prod-01 CROND[3201]: (root) CMD (/usr/local/bin/backup.sh)
Apr 20 09:00:01 prod-01 systemd[1]: session-42.scope: Succeeded.
Apr 20 09:05:00 prod-01 sshd[4221]: Session closed for user alice
Apr 20 09:06:00 prod-01 CROND[3301]: (app) CMD (rotate-logs.sh)
Apr 20 09:10:00 prod-01 systemd[1]: Started cron job.`,
  },
  {
    id: "insider",
    title: "Suspected insider threat",
    description:
      "User who normally uses sudo legitimately starts exfiltrating /etc/shadow and creating new accounts. Mixed signals — the engine should flag it but with a lower confidence than a full kill chain.",
    log: `Apr 20 11:00:00 db-02 sudo[6100]: pam_unix(sudo:session): session opened for user root by alice(uid=1001)
Apr 20 11:02:00 db-02 bash[6200]: cat /etc/shadow > /tmp/backup
Apr 20 11:05:00 db-02 useradd[6300]: new user: name=svc_backup, UID=1500
Apr 20 11:10:00 db-02 sudo[6400]: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/bin/bash`,
  },
];
