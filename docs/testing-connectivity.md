# Testing the ways Silo connects

Silo can reach a server four ways: its main address, fallback relays, a Tor onion address, and, when no server can be reached at all, straight to other devices on the same local network. This guide tests each one on a single Windows computer, using Docker Desktop and the installed app. The commands are for Windows PowerShell, one per line, run from the repository folder (for example `C:\Users\Micha\Desktop\ai\silo`).

Everything you can see happen is in the app's **Connection settings**: the line "Connected to …" shows the address in use and says "through Tor" when it is, the list below it shows every address the app knows, and the local network section shows who it's linked to.

## 1. Start the connectivity lab

`docker-compose.lab.yml` changes the normal setup so the server isn't published directly. Two relays forward to it instead:

| Container | Address | Plays the part of |
| --- | --- | --- |
| `main-door` | `http://127.0.0.1:8443` | The main address your app already uses |
| `relay` | `http://127.0.0.1:8444` | A fallback relay the server lists in its signed address list |

Stopping a container is like that address being blocked. The server and its data keep running, so your existing account works unchanged.

Tell Docker to use both files for the rest of this PowerShell window, then start everything:

```powershell
$env:COMPOSE_FILE = "docker-compose.yml;docker-compose.lab.yml"
docker compose up -d --build
docker compose ps
```

You should see `db`, `server`, `main-door` and `relay` running. If Docker complains about `!reset`, update Docker Desktop. In any new PowerShell window, run the `$env:COMPOSE_FILE` line again first.

Start Silo (or restart it if it was open), sign in, and open Connection settings. You should see "Connected to `http://127.0.0.1:8443`" and `http://127.0.0.1:8444` in the address list. The relay appears because the server signed it into its list.

## 2. Fallback relay: block the main address

```powershell
docker compose stop main-door
```

Within a few seconds the app should switch by itself: Connection settings now says "Connected to `http://127.0.0.1:8444`". Send a message to check everything still works; anyone else on the server gets it as usual.

Bring the main address back:

```powershell
docker compose start main-door
```

The app stays on the relay. That's on purpose: it sticks with an address that works rather than jumping back and forth. It moves again only when the relay fails.

To test the other direction, stop the relay instead (`docker compose stop relay`) while the app is on it, and it moves back to `127.0.0.1:8443`. Run `docker compose start relay` afterwards.

**What a real relay looks like:** the same `tools/relay/relay.mjs` running on another machine people can reach, with its address added to `PUBLIC_URLS`. It only forwards encrypted bytes. See "Running a relay" in the README.

## 3. Tor onion address

You need Tor running on this computer for the app to use. The easiest is [Tor Browser](https://www.torproject.org/download/): install it, open it, click **Connect**, and leave it open. It offers Tor to other apps on port 9150.

Start the onion service and get its address (the first start can take a minute):

```powershell
docker compose --profile tor up -d --build
docker compose logs tor
```

Look for `Silo onion address: http://….onion`. The server publishes it automatically.

In Silo's Connection settings:

1. Set **Tor proxy host** to `127.0.0.1` and **Port** to `9150`, then click **Save Tor settings**.
2. Restart Silo so it fetches the new address list. The onion address now shows in the list, marked "(Tor)".

Now block both normal addresses:

```powershell
docker compose stop main-door relay
```

The app should move to the onion address and say "Connected to `http://….onion` through Tor". It's slower: Tor routes every connection through three relays, so give it up to a minute. Send a message to check.

Undo it with:

```powershell
docker compose start main-door relay
```

Two more things worth trying:

- **Send all traffic through Tor.** Tick the box in Connection settings and save. Now even the normal addresses go through Tor, so the server never sees your IP. On this test setup Tor can't reach `127.0.0.1`, so the app ends up on the onion address, which is the right outcome. Untick it when you're done.
- **Add an address by hand.** This is for when a friend sends you an address because the usual one is blocked. Paste it into "Add another address for this server" and Silo first checks that the same server, with the same identity key, answers there. Anything else is refused as a different server.

If Tor Browser is closed, connecting through Tor fails with an error and the app keeps trying the other addresses. That's expected.

## 4. Local network, with no server at all

When the server can't be reached at all, devices on the same network can still deliver messages directly. You need two Silo devices belonging to two people who share a server. Both copies can run on this computer, or on two computers on the same Wi-Fi.

**A second copy on this computer.** Start the installed app with its own data folder. It acts as a separate device:

```powershell
& "$env:LOCALAPPDATA\Programs\Silo\silo.exe" --user-data-dir=C:\Users\Micha\silo-test2
```

(If that path doesn't exist, right-click the Silo shortcut in the Start menu and choose **Open file location** to find `silo.exe`.)

Sign up a second person in that window. Make a sign-up code from your first account, or from the server:

```powershell
docker compose exec server node apps/server/dist/cli/create-invite.js --uses 1 --hours 24
```

Then, with the server still running:

1. Invite the second person to one of your servers, and send a DM each way, so each device knows the other's keys.
2. In **both** copies, open Connection settings and tick **Find people on this local network**.
3. Windows Firewall will ask whether Silo may communicate on networks. Allow it on **Private networks**. (If your network is set to Public in Windows settings, Windows blocks the local links; set it to Private.)
4. After a few seconds each copy should say "Linked on this network: …" with the other person's name.

Now take the server away completely:

```powershell
docker compose stop server
```

Keep both copies open and signed in: for now local delivery only works if the app was already running when the server went away, so don't restart them until the server is back. Send a DM and a channel message from one copy. The other copy gets them straight away, marked as sent locally. Then bring the server back:

```powershell
docker compose start server
```

The messages are also sent through the server, so everyone who wasn't on your network gets them. Nobody sees them twice.

**On two computers** the steps are the same. The other computer needs to reach your server while setting up, so the simplest way is to give it the onion address (step 3), and both computers need to be on the same Wi-Fi or network with it set to Private.

## 5. Go back to the normal setup

```powershell
docker compose --profile tor stop tor
$env:COMPOSE_FILE = ""
docker compose up -d --remove-orphans
```

This publishes the server on `127.0.0.1:8443` directly again and removes the lab relays. The app drops `127.0.0.1:8444` from its list the next time it reads the server's signed list. Your account and messages are untouched. To remove the second copy's data, delete `C:\Users\Micha\silo-test2`.

## When something doesn't switch

- **"Connected to" never changes.** The app only moves when the address in use fails. Make sure `docker compose ps` shows the container stopped.
- **The onion address isn't in the list.** Restart Silo after the Tor container has printed its address, and check the Tor proxy port matches what you're running (9150 for Tor Browser, 9050 for the Tor service).
- **"No one you know is on this network right now."** Both copies need local network turned on, the firewall allowed on private networks, and a server in common that both joined while the server was up.
- **An address is refused as "a different server".** That's the identity check working: something other than your server answered there.
