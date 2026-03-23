# UniFi WiFi Manager

A simple web app for managing UniFi WiFi across multiple sites.

Built to solve a real problem — keeping guest WiFi secure, rotating passwords, and handling vouchers without constantly logging into the UniFi controller.

Originally used for managing client networks and holiday lets, but works just as well for offices or internal IT setups.

Currently running on Plesk with Node.js installed using MySQL

---

## What it does

### WiFi password management
- Change WiFi passwords instantly
- Set schedules to rotate passwords automatically
- Use either random or fixed passwords
- Keep a history of changes

### Hotspot vouchers
- Create UniFi vouchers without logging into the controller
- Generate vouchers from bookings (check-in / check-out dates)
- Store and view voucher codes in one place
- Create multiple vouchers at once

### Scheduling
- Built-in scheduler for password rotation
- Daily, weekly or monthly schedules
- Timezone support

### Multi-user setup
- Multiple users with access to different sites
- Super admin vs standard users
- Optional 2FA for admin accounts

### UniFi integration
- Works with cloud-hosted or self-hosted controllers
- Supports UniFi OS and legacy setups
- Sync sites and WiFi networks into the app

### QR codes
- Generate QR codes for WiFi access
- Simple printable pages for guests

---

## Why this exists

UniFi is great, but:

- rotating WiFi passwords manually is a pain
- vouchers are buried in the UI
- managing multiple sites gets messy fast

This app puts everything in one place and automates the repetitive stuff.

---

## Stack

- Node.js
- Express
- MySQL
- EJS
- UniFi API

---

## Getting started

### Clone the repo:

git clone https://github.com/OrbITServices/unifi-wifi-manager.git  
cd unifi-wifi-manager  

### Install dependencies:

npm install  

### Create a `.env` file with:

PORT=3000  
SESSION_SECRET=change-me  

DB_HOST=localhost  
DB_USER=root  
DB_PASS=password  
DB_NAME=unifi_app  

###Run the app:

node app.js  
