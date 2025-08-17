# MDXX Pro — Replit Edition

**What you get**
- Student portal (`/`): Register → Email code → Login → Trade (BUY/SELL) BTC/ETH/LTC/BNB
- Admin portal (`/admin`): live activity, edit balances, resend codes, override candles, export CSV, class reset, impersonate
- Live market data from Binance (1m); override any symbol with your candles
- Email confirmations via SMTP (Gmail App Password) or console fallback

## Run on Replit (free)
1. Create a new Repl → Import this repo (or upload the ZIP).
2. Add a file named `.env` (copy from `.env.example` and fill values).
3. Press **Run**.
4. Replit will install requirements and start the server. Click the **Open in new tab** button.

## Important
- Replit free instances sleep after inactivity (first visit wakes it).
- Default DB is SQLite (file `mdxx.db` stored in your Repl).
