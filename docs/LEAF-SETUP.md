# Setting up a ChatNet server (leaf or hub)

The goal: what you install is identical to what the ChatNet servers run. You add only the data ChatNet gives you.

## 1. Build

Needs gcc, meson, ninja, pkg-config, flex, bison, and the development packages for openssl, sqlite3 and libltdl.

    git clone https://github.com/chatnet-gg/cnircd && cd cnircd
    git checkout v1.3.0                      # or the release the admin tells you
    meson setup build --prefix=$HOME/ircd --optimization 2 -Dopenssl=enabled
    ninja -C build && meson install -C build

The binary is `bin/solanum`. Use the default build options (nick and topic length are part of the network standard).

## 2. Configuration files

Copy these next to your `ircd.conf` (the `etc-live` directory of your install):

| file | from | edit? |
|---|---|---|
| `chatnet-common.conf` | `etc/` | never: the network standard |
| `chatnet-clients.conf` | `etc/` | never: the network standard (servers that serve users) |
| `chatnet-webirc.conf` | `etc/` | never, only if you run a web gateway |
| `ircd.conf` | `etc/ircd.conf.sample` | yes: only the `<<-- ... -->` placeholders |
| `exempt-cw.conf` | `etc/exempt-cw.conf.sample` | no: copy it before the first start, the server rewrites it |
| `uplink.plan` | `etc/uplink.plan.sample` | only if you use cn_uplink |
| `ssl.pem`, `dh.pem` | your own certificate | yes |

`ircd.conf.sample` contains only what is local to your server. Modules, privsets, aliases, services and channel/general
settings come from the two `.include` lines, so they cannot drift from the standard.

## 3. What the ChatNet admin gives you

Your server name and SID, the link password and the address of the server you link to, the password hashes for the
staff operator blocks in the sample, and the `exempt{}` for your address on the uplink. The uplink also needs a
`connect{}` for you.

## 4. Check before you link

    python3 tools/chatnet-audit.py /path/to/ircd.conf leaf

It must print `0 difference(s)`. Use `leaf-webirc` if you run a web gateway, `hub` for a hub.
