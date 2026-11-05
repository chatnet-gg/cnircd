/*
 * Solanum: a slightly advanced ircd
 * cn_uplink.c: preferred uplink with ordered fallbacks, failover and failback
 *
 * The stock autoconn rotates its connect{} blocks (a tried block goes to the end of the list), has no notion of a
 * preferred uplink and never moves a server back once the preferred one returns. This module replaces it for the
 * servers named in etc/uplink.plan:
 *
 *     interval 10        seconds between ticks / probes
 *     fail 3             consecutive failed probes before an uplink counts as down
 *     ok 6               consecutive good probes before it counts as up again
 *     cooldown 600       seconds to wait after a failed move back
 *     unstable_drops 3   link drops in unstable_window seconds that make an uplink "unstable"
 *     unstable_window 1800
 *     unstable_hold 600  clean seconds required before moving back to an unstable uplink
 *     uplink hub.example.net      first = preferred
 *     uplink backup.example.net   then the fallbacks, in order
 *
 * The plan is a local file: a server keeps working with services down. The autoconn flag of the planned uplinks is
 * switched off every tick (a rehash turns it back on), so the module is the only one creating those links.
 *
 *  - Not linked to any planned uplink: connect to the first one that is not down (an unstable uplink is skipped
 *    until it has been clean for unstable_hold seconds).
 *  - Linked to a fallback while a better uplink answers `ok` probes in a row: close the link to the fallback and connect
 *    to the better one at once (a tree allows one uplink, so it is break-then-make). If the new link is not up
 *    25 seconds later, go back to the fallback and wait `cooldown` seconds.
 *  - Probes are plain TCP connects to the uplink's port, only toward uplinks we are NOT linked to and that are
 *    better than the one we are on (all of them when isolated). The peer's connection throttle counts them: the
 *    peer needs an exempt{} for this server's address.
 *
 * Oper command: UPLINK STATUS (any oper) | FREEZE ON|OFF | RELOAD (need the oper:routing privilege).
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "hash.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "defaults.h"
#include "rb_event.h"
#include "logger.h"

static const char cwu_desc[] = "Preferred uplink with ordered fallbacks: failover and failback, no autoconn rotation.";

#define CWU_FILE   "uplink.plan"
#define CWU_MAX    8
#define CWU_DROPS  8

struct cwu_up
{
	char name[64];
	int fails, oks;
	bool down, probing, linked, was_linked;
	int strikes;                 /* consecutive link attempts that did not come up (it answers probes but refuses us) */
	time_t bad_until;            /* do not pick it as a target before this time */
	time_t drops[CWU_DROPS];
	int ndrops;
};

static struct cwu_up cwu_ups[CWU_MAX];
static int cwu_n;
static int cfg_interval = 10, cfg_fail = 3, cfg_ok = 6, cfg_cooldown = 600;
static int cfg_unstable_drops = 3, cfg_unstable_window = 1800, cfg_unstable_hold = 600;
static bool cwu_frozen;
static time_t cwu_connecting_until, cwu_cooldown_until, cwu_fb_deadline, cwu_ready_since, cwu_att_deadline;
static int cwu_att_idx = -1;   /* uplink we are currently trying to link to when isolated */
static int cwu_att_oks;        /* its good-probe count when the attempt started: >0 means it looked reachable */
static int cwu_fb_target = -1, cwu_fb_rollback = -1;
static int cwu_last_state = -2;      /* -1 isolated, 0 preferred, k fallback k */
static bool cwu_last_unstable;
static struct ev_entry *cwu_ev;

static void mo_uplink(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message uplink_msgtab = {
	"UPLINK", 0, 0, 0, 0,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, mg_ignore, {mo_uplink, 2}}
};
mapi_clist_av1 cwu_clist[] = { &uplink_msgtab, NULL };

static void cwu_tick(void *);
static bool cwu_load_plan(void);
static void cwu_conf_hook(void *);

mapi_hfn_list_av1 cwu_hfnlist[] = {
	{ "conf_read_end", cwu_conf_hook },
	{ NULL, NULL }
};

static int
modinit(void)
{
	(void) cwu_load_plan();
	cwu_ev = rb_event_add("cn_uplink_tick", cwu_tick, NULL, cfg_interval);
	return 0;
}

static void
moddeinit(void)
{
	if (cwu_ev != NULL)
		rb_event_delete(cwu_ev);
	cwu_ev = NULL;
}

DECLARE_MODULE_AV2(cn_uplink, modinit, moddeinit, cwu_clist, NULL, cwu_hfnlist, NULL, NULL, cwu_desc);

static void
cwu_note(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	sendto_realops_snomask(SNO_GENERAL, L_ALL, "cn_uplink: %s", buf);
	ilog(L_SERVER, "cn_uplink: %s", buf);
}

static bool
cwu_load_plan(void)
{
	char path[PATH_MAX], line[256];
	FILE *f;
	int n = 0;

	if (getenv("CN_UPLINK_PLAN") != NULL)       /* test labs: one plan per server sharing one install */
		rb_strlcpy(path, getenv("CN_UPLINK_PLAN"), sizeof path);
	else
		snprintf(path, sizeof path, "%s/%s", ircd_paths[IRCD_PATH_ETC], CWU_FILE);
	f = fopen(path, "r");
	if (f == NULL)
		return false;

	memset(cwu_ups, 0, sizeof cwu_ups);
	while (fgets(line, sizeof line, f) != NULL)
	{
		char key[32], val[64];
		char *save = NULL, *k, *w;
		int v;

		if (line[0] == '#')
			continue;
		k = strtok_r(line, " \t\r\n", &save);        /* no sscanf: its C23 variant needs glibc >= 2.38 */
		w = k != NULL ? strtok_r(NULL, " \t\r\n", &save) : NULL;
		if (k == NULL || w == NULL || strlen(k) >= sizeof key || strlen(w) >= sizeof val)
			continue;
		rb_strlcpy(key, k, sizeof key);
		rb_strlcpy(val, w, sizeof val);
		v = atoi(val);
		if (!strcmp(key, "uplink") && n < CWU_MAX && strlen(val) < sizeof cwu_ups[0].name)
			rb_strlcpy(cwu_ups[n++].name, val, sizeof cwu_ups[0].name);
		else if (!strcmp(key, "interval") && v >= 1)
			cfg_interval = v;
		else if (!strcmp(key, "fail") && v >= 1)
			cfg_fail = v;
		else if (!strcmp(key, "ok") && v >= 1)
			cfg_ok = v;
		else if (!strcmp(key, "cooldown") && v >= 0)
			cfg_cooldown = v;
		else if (!strcmp(key, "unstable_drops") && v >= 1)
			cfg_unstable_drops = v;
		else if (!strcmp(key, "unstable_window") && v >= 1)
			cfg_unstable_window = v;
		else if (!strcmp(key, "unstable_hold") && v >= 0)
			cfg_unstable_hold = v;
	}
	fclose(f);
	cwu_n = n;
	return true;
}

static bool
cwu_is_direct(const char *name)
{
	struct Client *c = find_server(NULL, name);

	return c != NULL && IsServer(c) && MyConnect(c);
}

/* The stock autoconn must never run for the planned uplinks, not even in the first seconds after startup or
 * after a rehash: switch it off as soon as the configuration has been read (and again every tick). */
static void
cwu_disable_autoconn(void)
{
	int i;

	for (i = 0; i < cwu_n; i++)
	{
		struct server_conf *sc = find_server_conf(cwu_ups[i].name);

		if (sc != NULL)
			sc->flags &= ~SERVER_AUTOCONN;
	}
}

static void
cwu_conf_hook(void *unused)
{
	(void) unused;
	cwu_disable_autoconn();
}

static int
cwu_recent_drops(const struct cwu_up *u, time_t now)
{
	int i, c = 0;

	for (i = 0; i < u->ndrops && i < CWU_DROPS; i++)
		if (now - u->drops[i] <= cfg_unstable_window)
			c++;
	return c;
}

static time_t
cwu_last_drop(const struct cwu_up *u)
{
	time_t last = 0;
	int i;

	for (i = 0; i < u->ndrops && i < CWU_DROPS; i++)
		if (u->drops[i] > last)
			last = u->drops[i];
	return last;
}

static bool
cwu_unstable(const struct cwu_up *u, time_t now)
{
	return cwu_recent_drops(u, now) >= cfg_unstable_drops;
}

/* Clean enough to move back to: enough good probes, and (if it has been flapping) quiet for unstable_hold. */
static bool
cwu_ready(const struct cwu_up *u, time_t now)
{
	if (u->oks < cfg_ok)
		return false;
	return !cwu_unstable(u, now) || now - cwu_last_drop(u) >= cfg_unstable_hold;
}

static void
cwu_probe_cb(rb_fde_t *F, int status, void *data)
{
	struct cwu_up *u = data;

	u->probing = false;
	if (status == RB_OK)
	{
		u->oks++;
		u->fails = 0;
		if (u->oks >= cfg_ok)
			u->down = false;
	}
	else
	{
		u->fails++;
		u->oks = 0;
		if (u->fails >= cfg_fail)
			u->down = true;
	}
	rb_close(F);
}

static void
cwu_probe(struct cwu_up *u)
{
	struct server_conf *sc = find_server_conf(u->name);
	struct rb_sockaddr_storage ss;
	rb_fde_t *F;
	int fam;

	if (sc == NULL || u->probing)
		return;

	if (sc->aftype == AF_INET6 || (sc->aftype != AF_INET && GET_SS_FAMILY(&sc->connect4) != AF_INET))
		ss = sc->connect6;
	else
		ss = sc->connect4;
	fam = GET_SS_FAMILY(&ss);
	if (fam != AF_INET && fam != AF_INET6)
		return;                    /* address not resolved yet: no verdict, no counting */

	SET_SS_PORT(&ss, htons(sc->port));
	F = rb_socket(fam, SOCK_STREAM, 0, "uplink probe");
	if (F == NULL)
		return;
	u->probing = true;
	rb_connect_tcp(F, (struct sockaddr *)&ss, NULL, cwu_probe_cb, u, 5);
}

static void
cwu_connect(int idx)
{
	struct server_conf *sc = find_server_conf(cwu_ups[idx].name);

	if (sc != NULL)
		(void) serv_connect(sc, NULL);
}

static void
cwu_state_note(int li, time_t now)
{
	if (li != cwu_last_state)
	{
		if (li == 0)
			cwu_note("linked to preferred uplink %s", cwu_ups[0].name);
		else if (li > 0)
			cwu_note("linked to fallback %s", cwu_ups[li].name);
		else if (cwu_last_state != -2)
			cwu_note("not linked to any planned uplink");
		cwu_last_state = li;
	}
	if (cwu_n > 0)
	{
		bool u = cwu_unstable(&cwu_ups[0], now);

		if (u != cwu_last_unstable)
		{
			cwu_note(u ? "%s is unstable (%d drops in %d s), staying on fallback until it is quiet for %d s"
			           : "%s is stable again", cwu_ups[0].name, cwu_recent_drops(&cwu_ups[0], now),
			         cfg_unstable_window, cfg_unstable_hold);
			cwu_last_unstable = u;
		}
	}
}

static void
cwu_tick(void *unused)
{
	time_t now = rb_current_time();
	int i, j, li = -1;

	(void) unused;
	if (cwu_frozen || cwu_n == 0)
		return;

	cwu_disable_autoconn();

	for (i = 0; i < cwu_n; i++)
	{
		struct cwu_up *u = &cwu_ups[i];

		u->linked = cwu_is_direct(u->name);
		if (u->was_linked && !u->linked)
		{
			u->drops[u->ndrops % CWU_DROPS] = now;
			u->ndrops++;
			u->oks = 0;
		}
		u->was_linked = u->linked;
		if (u->linked && li < 0)
			li = i;
		if (u->linked)
		{
			u->fails = 0;
			u->oks = cfg_ok;
			u->down = false;
		}
	}

	/* Probe only what can matter: every unlinked uplink when we have none, otherwise only the ones better than the
	 * one we are on. Worse uplinks are left alone: each probe is a connection the peer's throttle counts. */
	for (i = 0; i < cwu_n; i++)
		if (!cwu_ups[i].linked && (li < 0 || i < li))
			cwu_probe(&cwu_ups[i]);

	cwu_state_note(li, now);

	for (i = 0; i < cwu_n; i++)
		if (cwu_ups[i].linked)
			cwu_ups[i].strikes = 0;
	if (cwu_att_idx >= 0)
	{
		struct cwu_up *a = &cwu_ups[cwu_att_idx];

		if (a->linked)
			cwu_att_idx = -1;
		else if (now >= cwu_att_deadline && cwu_att_oks < 1)
			cwu_att_idx = -1;      /* it was simply unreachable (probe logic handles that): no penalty, retry soon */
		else if (now >= cwu_att_deadline)
		{
			a->strikes++;
			a->bad_until = now + (a->strikes >= 3 ? cfg_cooldown : 30 * a->strikes);
			cwu_note("link attempt to %s did not come up (strike %d): skipping it for %d s", a->name, a->strikes,
			         (int)(a->bad_until - now));
			cwu_att_idx = -1;
		}
	}

	if (cwu_fb_target >= 0)
	{
		if (cwu_ups[cwu_fb_target].linked)
			cwu_fb_target = -1;                  /* move completed */
		else if (now >= cwu_fb_deadline)
		{
			cwu_note("move back to %s failed, returning to %s, next try in %d s", cwu_ups[cwu_fb_target].name,
			         cwu_ups[cwu_fb_rollback].name, cfg_cooldown);
			cwu_ups[cwu_fb_target].oks = 0;
			cwu_ups[cwu_fb_target].bad_until = now + cfg_cooldown;
			cwu_cooldown_until = now + cfg_cooldown;
			cwu_connect(cwu_fb_rollback);
			cwu_connecting_until = now + 20;
			cwu_fb_target = -1;
		}
		return;
	}

	if (li < 0)
	{
		int t = -1;

		cwu_ready_since = 0;
		if (now < cwu_connecting_until)
			return;
		for (i = 0; i < cwu_n && t < 0; i++)
			if (!cwu_ups[i].down && now >= cwu_ups[i].bad_until &&
			    (!cwu_unstable(&cwu_ups[i], now) || now - cwu_last_drop(&cwu_ups[i]) >= cfg_unstable_hold))
				t = i;
		for (i = 0; i < cwu_n && t < 0; i++)
			if (!cwu_ups[i].down && now >= cwu_ups[i].bad_until)
				t = i;
		for (i = 0; i < cwu_n && t < 0; i++)
			if (now >= cwu_ups[i].bad_until)
				t = i;
		if (t < 0)
			return;                              /* every uplink is in its penalty time: wait */
		cwu_connect(t);
		cwu_att_idx = t;
		cwu_att_oks = cwu_ups[t].oks;
		cwu_att_deadline = now + 20;
		cwu_connecting_until = now + 20;
		return;
	}

	if (li == 0 || now < cwu_cooldown_until)
	{
		cwu_ready_since = 0;
		return;
	}

	for (j = 0; j < li; j++)
		if (cwu_ready(&cwu_ups[j], now))
			break;
	if (j >= li)
	{
		cwu_ready_since = 0;
		return;
	}

	/* Same stagger for every server of a split island: a fixed delay from the server name, so they do not all
	 * leave their fallback in the same second. */
	{
		unsigned int h = 0;
		const char *p;

		for (p = me.name; *p != '\0'; p++)
			h = h * 31 + (unsigned char)*p;
		if (cwu_ready_since == 0)
			cwu_ready_since = now;
		if (now - cwu_ready_since < (time_t)((h % 4) * 10))
			return;
	}

	{
		struct Client *old = find_server(NULL, cwu_ups[li].name);

		cwu_note("%s answered %d probes in a row: moving from %s to %s", cwu_ups[j].name, cwu_ups[j].oks,
		         cwu_ups[li].name, cwu_ups[j].name);
		cwu_fb_target = j;
		cwu_fb_rollback = li;
		cwu_fb_deadline = now + 25;
		cwu_ready_since = 0;
		if (old != NULL)
			exit_client(old, old, &me, "uplink change");
		cwu_connect(j);
	}
}

static void
mo_uplink(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	time_t now = rb_current_time();
	int i;

	/* STATUS is for any oper; FREEZE and RELOAD change what the server does with its links. */
	if ((!irccmp(parv[1], "FREEZE") || !irccmp(parv[1], "RELOAD")) && !HasPrivilege(source_p, "oper:routing"))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "routing");
		return;
	}

	if (!irccmp(parv[1], "FREEZE") && parc >= 3)
	{
		cwu_frozen = !irccmp(parv[2], "ON");
		cwu_note("%s by %s", cwu_frozen ? "FROZEN: no link changes" : "unfrozen", get_oper_name(source_p));
	}
	else if (!irccmp(parv[1], "RELOAD"))
	{
		sendto_one_notice(source_p, ":UPLINK: plan %s", cwu_load_plan() ? "reloaded" : "file not found");
	}
	else if (!irccmp(parv[1], "STATUS"))
	{
		sendto_one_notice(source_p, ":UPLINK%s: interval %d fail %d ok %d cooldown %d s", cwu_frozen ? " (FROZEN)" : "",
		                  cfg_interval, cfg_fail, cfg_ok, cfg_cooldown);
		for (i = 0; i < cwu_n; i++)
		{
			const struct cwu_up *u = &cwu_ups[i];

			sendto_one_notice(source_p, ":UPLINK %d %s: %s%s fails=%d oks=%d drops=%d%s", i, u->name,
			                  u->linked ? "LINKED" : (u->down ? "down" : "up?"), i == 0 ? " (preferred)" : "",
			                  u->fails, u->oks, cwu_recent_drops(u, now),
			                  cwu_unstable(u, now) ? " UNSTABLE" : "");
		}
	}
	else
		sendto_one_notice(source_p, ":Syntax: UPLINK STATUS | FREEZE ON|OFF | RELOAD");
}
