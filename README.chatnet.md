# cnircd -- ChatNet's Solanum fork

This is [Solanum](https://github.com/solanum-ircd/solanum), forked at
commit `48db98ab2b4191ba75047a74c79a353e4f82bf5a`, with the patches
[ChatNet](https://chatnet.gg/) runs in production applied on top. If
you're linking a leaf into ChatNet, build this instead of vanilla
Solanum -- it saves you from re-discovering the same build/runtime
issues we already hit.

Get the leaf config template and your SID/link password from
[chatnet.gg/routing](https://chatnet.gg/routing.html) -- this repo is
just the ircd itself.

## Patches on top of upstream, in commit order

1. **Drop `arc4random_stir()` calls** -- glibc >= 2.36 dropped this
   legacy BSD reseed call; `librb`'s no-TLS PRNG backend still called
   it, which is an undefined-reference link failure on current
   distros (Debian bookworm and newer). Safe to drop: glibc's
   `arc4random()` already self-reseeds.
2. **`authd`: pin nameserver validation to `PF_INET`** -- upstream's
   `PF_UNSPEC` probe returns `EAFNOSUPPORT` in some container
   runtimes, which kills DNS resolution (and then the whole ircd, via
   a separate respawn-path bug) even though real nameservers are
   configured. ChatNet only uses IPv4 nameservers, so this sidesteps
   the unsupported probe rather than fixing it generally -- if you
   need real dual-stack nameserver validation, don't cherry-pick this
   one.
3. **Hide channel mode `+P` from `MODE` queries** -- ChatNet-specific.
   `+P` marks a channel as permanent (survives its last member
   parting) for services-side use; this keeps that mechanism intact
   but stops it from showing up in a regular `/mode #chan` unless the
   querying client holds the `auspex:cmodes` oper privilege. Skip or
   revert this one if your network doesn't want that behavior --
   grant `auspex:cmodes` to every oper privset to get full visibility
   back with zero source changes.
4. **Hide service bots from `/STATS p`** -- ChatNet-specific. Stock
   `stats_operedup()` (`modules/m_stats.c`) lists every currently-opered
   client network-wide, which includes pseudoclient bots (e.g. cncheck,
   vhost `chatnet/bot/*`) alongside real staff. Skips any opered client
   whose displayed host matches `chatnet/bot*` before it's counted or
   printed, so `/STATS p` shows real staff, not bots. Harmless to keep
   even if your network has no bots under that vhost pattern -- it's
   simply never a match.

5. **Services-set hosts may carry any nick character** -- ChatNet-specific.
   `clean_host()` in `m_chghost.c`, `m_signon.c` and `m_nick.c` only
   accepted hostname characters, so a services cloak like
   `user/Gabiy[a]n` got mangled. They now accept hostname *or* nick
   characters (`IsCloakHostChar()`); client-supplied hostnames are still
   checked with `IsHostChar()`. If you take only some of these three
   files, take `m_nick.c` too, or the hub will KILL such users on every
   relink burst.

## Extensions bundled in `extensions/`

Not part of upstream, loaded by the bundled config:

- `cap_sts.c` -- IRCv3 STS, advertises the real TLS port.
- `cn_ip_cloak.c` -- the `CN-` anonymous IP/host cloak (`+x`).
- `cn_whois_notify.c` -- notifies on WHOIS (`+W`), staff and bots excluded.

`extb_account`, `sno_globaloper`, `invite_notify` and `chm_operonly`
are stock Solanum extensions that every ChatNet server loads.

Each patch is its own commit with a full explanation in the commit
message -- `git log` for the details, this file is just the index.

## Building

Same as upstream Solanum -- see `INSTALL.md`. If you're containerizing
it, watch Docker's default `nofile` ulimit: it's often high enough
that Solanum's fd-indexed table sizing tries to allocate a huge amount
of memory and segfaults at startup. Cap it explicitly (ChatNet uses
`65536`).

## Staying in sync with upstream

Run `./sync-upstream.sh` to rebase these patches onto the latest
upstream Solanum -- it stops for you to resolve by hand if a patch no
longer applies cleanly. A GitHub Action can also run this on a
schedule and open a PR automatically; see the repo settings if one
isn't already configured.

Note that a patch can become obsolete rather than conflict -- e.g. the
original "real build date" patch here was dropped entirely once
upstream shipped its own proper fix for the same `__DATE__` placeholder
issue (see commit history around 2026-08-20's sync). Always check
*why* a patch no longer applies, not just whether it does.

## ChatNet Development

- **sh** (abcx@chatnet.gg) -- maintainer

Thanks to the ChatNet staff for testing these patches on real linked
leaves before they landed here:

- **w0od** (w0od@chatnet.gg)
- **TGS** (tgs@chatnet.gg)
- **Astro** (astro@chatnet.gg)
- **Slogan** (slogan@chatnet.gg)
