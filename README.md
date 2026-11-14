# Book Shelf

A reading tracker with a decorated 3D bookshelf: reading sessions, streaks, ratings, notebooks,
book search by language, author and genre pages, multiple libraries, themes, and accounts that
keep your library on the server.

It is one folder: `index.html` (the whole app), `assets/` (shelf pictures and icons), `sw.js` and
`manifest.webmanifest` (install on a phone), and `server.py`, a small Python server with no
dependencies that serves the app and stores accounts in SQLite.

## Run it on your computer

```bash
python3 server.py
```

Then open http://localhost:8765/index.html.

## Deploy

The app needs `server.py` running for accounts, saving to your account and share links.
A static host (GitHub Pages, Netlify, Vercel) can show the app, but only in
"Continue without an account" mode, with data kept in each browser.

| Setting | What it does |
|---|---|
| `PORT` | Port to listen on. Most hosts set this for you. Default 8765. |
| `DATA_DIR` | Folder for `bookshelf.db`. Put it on a persistent disk. Default `./data`. |
| `TRUST_PROXY=1` | Set when running behind the host's HTTPS proxy. |

**Keep the database on a persistent disk.** If `DATA_DIR` is on the host's normal file system,
every redeploy or restart wipes all accounts.

**Use HTTPS.** Installing on a phone and offline use only work over `https://`. The hosts
below give you HTTPS automatically.

### Render (Docker)

1. Put this folder in a GitHub repository. `data/` is in `.gitignore`, so your local accounts stay out.
2. In Render, choose **New → Blueprint** and pick the repository. `render.yaml` creates a web
   service with a 1 GB disk at `/data`. Persistent disks need a paid plan.

### Railway or Fly.io (Docker)

Deploy the folder with its `Dockerfile`, add a volume mounted at `/data`, and set
`TRUST_PROXY=1`.

### Any Linux server (VPS)

```bash
DATA_DIR=/var/lib/bookshelf TRUST_PROXY=1 PORT=8765 python3 server.py
```

Put Nginx or Caddy in front for HTTPS, and run it as a service (for example with systemd)
so it restarts after a reboot.

## Notes

- Book data comes from Open Library and Google Books, called from the visitor's browser. Google
  Books has a shared daily limit, so results sometimes come from Open Library alone.
- Scan text downloads Tesseract.js from jsDelivr on first use.
- Shelf images are from Poly Haven (CC0) and Wikimedia Commons. Several Commons images need
  credit, listed in `assets/CREDITS.txt`, which the app links from Profile. Keep that file.
- There is no password reset: accounts have no email step.
