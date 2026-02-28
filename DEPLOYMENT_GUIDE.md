# Deployment Guide: Support Portal (Golang + SQLite)

This document contains the necessary configuration files to run your Support Portal on a Linux Virtual Machine (e.g., Ubuntu Debian) behind an Nginx reverse proxy.

## 1. Prerequisites on the VM
Before the GitHub CI/CD pipeline can run, you must SSH into your VM and install/setup the following:

```bash
# Update System
sudo apt update && sudo apt upgrade -y

# Install Nginx
sudo apt install nginx -y

# Make the directory where GitHub Actions will drop the files
sudo mkdir -p /var/www/helpdesk
sudo chown -R $USER:$USER /var/www/helpdesk

# Prepare SQLite Database Folder (important for write-permissions)
# We place it in /var/lib instead of the code directory so it doesn't get overwritten by git/scp
sudo mkdir -p /var/lib/helpdesk
sudo chown -R $USER:$USER /var/lib/helpdesk
```

> **Note on SQLite path**: You will need to change your `main.go` code slightly so it saves the database to an absolute path like `/var/lib/helpdesk/helpdesk.db` when running in production, instead of the relative `./helpdesk.db` which might get confused by systemd's working directory.

---

## 2. Systemd Service Setup
Systemd will ensure your Golang binary automatically starts when the VM boots, and automatically restarts if it crashes.

1. Create a new service file:
   ```bash
   sudo nano /etc/systemd/system/helpdesk.service
   ```
2. Paste this configuration (Replace `your_username` with your VM user's name like `ubuntu` or `root`):
   ```ini
   [Unit]
   Description=Helpdesk Support Portal App
   After=network.target

   [Service]
   Type=simple
   User=your_username
   # The folder where the git actions dumps the files
   WorkingDirectory=/var/www/helpdesk 
   # The compiled binary
   ExecStart=/var/www/helpdesk/helpdesk_app
   Restart=on-failure
   RestartSec=5
   
   # Optional: If you want to use environment variables for your JWT Secret
   # Environment="JWT_SECRET=super_secret_production_key"

   [Install]
   WantedBy=multi-user.target
   ```
3. Enable and start the service:
   ```bash
   sudo systemctl daemon-reload
   sudo systemctl enable helpdesk.service
   sudo systemctl start helpdesk.service
   ```

---

## 3. Nginx Reverse Proxy Setup
Nginx will sit at port 80 (and 443 for SSL), serving as the public face of your webserver and proxying requests to your Go app running natively on port 8080.

1. Create a new Nginx sites-available file:
   ```bash
   sudo nano /etc/nginx/sites-available/helpdesk
   ```
2. Paste this configuration:
   ```nginx
   server {
       listen 80;
       server_name yourdomain.com www.yourdomain.com; # GANTI DENGAN IP VM ATAU DOMAIN ANDA

       # Proxy requests to Golang Server
       location / {
           proxy_pass http://127.0.0.1:8080;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
           
           # If you add Websockets later for live Kanban updates:
           # proxy_set_header Upgrade $http_upgrade;
           # proxy_set_header Connection "upgrade";
       }
   }
   ```
3. Enable the site and restart Nginx:
   ```bash
   sudo ln -s /etc/nginx/sites-available/helpdesk /etc/nginx/sites-enabled/
   # Test Nginx syntax
   sudo nginx -t
   # Restart Nginx
   sudo systemctl restart nginx
   ```

---

## 4. GitHub Secrets Setup
Now that your VM is ready, you must feed the credentials to your GitHub repository so the deployment file (`.github/workflows/deploy.yml`) can SSH in automatically.

Go to your Repository **Settings > Secrets and variables > Actions > New repository secret**. Add these 3 secrets:
1. `VM_HOST` : The public IP address of your VM (e.g. `203.0.113.45`).
2. `VM_USERNAME` : The SSH username for your VM (e.g. `ubuntu` or `root`).
3. `VM_SSH_KEY` : The **Private Key** content (usually starts with `-----BEGIN OPENSSH PRIVATE KEY-----`).
