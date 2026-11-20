# LANShield anti-cheat prototype

Monitoring tools for school and local esports events. They watch the event network and the player PCs, and
show anything suspicious on a live console for the referee. They add to each game's own anti-cheat
(Vanguard, Easy Anti-Cheat and so on); they don't replace it.

**Status: prototype.** The tests run on a simulated match and on a Linux machine. It has **not yet been
tried at a real event or on Windows player PCs**. See *Before using this at an event* below.

Python 3.9 or newer, standard library only. Nothing to install.

## What it catches

| Signal | How | Severity |
|---|---|---|
| VPN use | Lookups of VPN providers; WireGuard/OpenVPN/IPsec ports; VPN adapters on the PC | Serious |
| Remote control or "remote coaching" | Lookups of TeamViewer, AnyDesk, Parsec and similar; RDP/VNC ports; those programs running | Serious |
| Cheat software | Cheat Engine, injectors and debuggers running; visits to cheat forums and sellers | Serious |
| Macro tools | AutoHotkey and similar running | Serious |
| Hardware cheats | Cronus Zen, XIM and programmable keystroke devices plugged in | Serious |
| Someone else playing | Signed-in game account differs from the registered player | Serious |
| Hiding from monitoring | Encrypted DNS (DNS-over-TLS/HTTPS) lookups and port 853 | Serious |
| Unapproved USB device | Any device not on the approved list | To check |
| Unknown website | Lookups of anything not on the approved list | To check |
| Connection with no lookup | A connection to an IP the station never looked up, on a non-game port | To check |
| Spare VPN adapter | VPN adapter installed but switched off | To check |

"To check" means the referee should look; it isn't proof of cheating. Every flag is kept in an evidence
file along with the referee's ruling.

## The three parts

```
 player PCs ──► station check ──┐
                                ├──► referee console (http://<laptop>:8080)
 event router ─► DNS + connection logs ──┘
```

1. **`lanshield.station`**: runs on each player PC. Lists running programs, USB devices and network
   adapters, and sends them to the console. Works on Windows, macOS and Linux.
2. **`lanshield.netmon`**: reads the event router's logs: dnsmasq/Pi-hole DNS logs, Linux `conntrack`
   events, or a CSV of connections (`timestamp,src_ip,dst_ip,dst_port,proto`).
3. **`lanshield.console`**: follows those logs live, receives station reports and serves the referee
   dashboard. The referee can filter by station and resolve each flag with a note.

## Try it with the simulated match

From this folder:

```bash
cp config.example.json config.json

# Automated tests (20 tests: every planted cheat caught, no false alarms on normal traffic)
python -m unittest -v

# Scan the sample logs and station reports
python -m lanshield.netmon -c config.json samples/dnsmasq.log samples/flows.csv
python -m lanshield.station --station P03 -c config.json --from-file samples/stations/P03.json

# Live demo: console in one terminal, simulated match in another (2x speed, looping)
mkdir -p run && touch run/dnsmasq.log run/flows.csv
python -m lanshield.console -c config.json --log run/dnsmasq.log --log run/flows.csv
python -m lanshield.simulate --live run --console http://localhost:8080 --speed 2 --loop
# then open http://localhost:8080
```

The simulated match has 10 stations with normal game traffic and these planted attempts:
P02 NordVPN, P03 Cheat Engine plus a Cronus Zen, P04 AnyDesk, P05 AutoHotkey plus TeamViewer,
P06 a cheat forum plus an active NordLynx adapter, P07 a direct-IP connection, P08 encrypted DNS plus the
wrong account, P09 TikTok, P10 an unknown USB keyboard plus a switched-off WireGuard adapter.
Spectator Wi-Fi also looks up NordVPN, which must be ignored. P01 is clean.

## Running it at an event

1. **Config.** Copy `config.example.json` to `config.json`. Fill in each station's IP, player and team,
   and add the game and league domains you need to `allowed_domains`. Give player PCs fixed IPs
   (DHCP reservations) so each IP always means the same station.
2. **Router.** Use a router you control for the player network (a Raspberry Pi or small Linux box works).
   Turn on DNS query logging (`log-queries` in dnsmasq, or Pi-hole) and connection logging
   (`conntrack -E -e NEW >> /var/log/conntrack.log`). Block outbound DNS other than your own resolver,
   so stations can't skip your logs.
3. **Console.** On the referee laptop or the router:
   `python -m lanshield.console -c config.json --log /var/log/dnsmasq.log --log /var/log/conntrack.log`
4. **Stations.** On each player PC, at check-in:
   `python -m lanshield.station --station P03 --account <their game name> --console http://<console-ip>:8080 --watch 60`

## Before using this at an event

- **Test on your own Windows PCs first.** The Windows collection (`tasklist`, `Get-PnpDevice`,
  `Get-NetAdapter`) is written but hasn't been run on Windows yet. Run the station check on one PC and
  confirm it lists the right programs and devices.
- **Check the USB IDs.** The device IDs in `config.example.json` are starting examples. Plug in your own
  approved mice, keyboards and controllers, run the station check, and copy their IDs into `approved_usb`.
  Confirm any banned-device IDs against the actual hardware.
- **Tune the approved-domain list.** Run a practice session and resolve the "unknown website" flags by
  adding legitimate domains to `allowed_domains`.
- **Keep the console on the staff network.** It has no login, so anyone who can reach it can see and
  resolve flags.
- **Tell players and parents.** The station check reads program names, USB device names and network
  adapter names. It doesn't record keystrokes, screens, webcams or browsing content, and it only runs on
  event PCs. Keep `evidence.jsonl` only as long as your stated retention period.
- **Limits.** A player with admin rights can rename a cheat program, and network checks can be dodged
  by a phone hotspot. Lock down admin rights on event PCs, and have staff watch the room for phones.
