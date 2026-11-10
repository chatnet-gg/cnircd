/*
 * Solanum: a slightly advanced ircd
 * cn_uplink.c: preferred uplink with ordered fallbacks, failover and failback
 *
 * The stock autoconn rotates its connect{} blocks (a tried block goes to the end of the list), has no notion of a
 * preferred uplink and never moves a server back once the preferred one returns. This module replaces it for the
 * servers named in uplink.plan (next to the running ircd.conf):
 *
 *     interval 10        seconds between ticks / probes
 *     fail 3             consecutive failed probes before an uplink counts as down
 *     ok 6               consecutive good probes before it counts as up again
 *     cooldown 600       seconds to wait after a failed move back
 *     unstable_drops 3   link drops in unstable_window seconds that make an uplink "unstable"
 *     unstable_window 1800
 *     unstable_hold 600  clean seconds required before moving back to an unstable uplink
 *     accept_push no     yes = ChatWorld may set the uplink lines (ENCAP UPLINKPLAN), see below
 *     uplink hub.example.net      first = preferred
 *     uplink backup.example.net   then the fallbacks, in order
 *
 * The plan is a local file: a server keeps working with services down. The autoconn flag of the planned uplinks is
 * switched off every tick (a rehash turns it back on), so the module is the only one creating those links.
 *
 *  - Not linked to any planned uplink: connect to the first one that is not down (an unstable uplink is skipped
 *    until it has been clean for unstable_hold seconds).
 *  - Linked to a fallback while a better uplink answers `ok` probes in a row: close the link to the fallback and connect
 *    to the better one (a tree allows one uplink, so it is break-then-make). The connect starts one tick after the
 *    split, so the better uplink has seen it and does not refuse a duplicate server or count a burst of connects
 *    against its connection throttle; if it is not up 20 seconds later it is tried once more. If the move has not
 *    completed 60 seconds after the split, go back to the fallback and wait `cooldown` seconds.
 *  - Probes are plain TCP connects to the uplink's port, only toward uplinks we are NOT linked to and that are
 *    better than the one we are on (all of them when isolated). The peer's connection throttle counts them: the
 *    peer needs an exempt{} for this server's address.
 *
 * Services can also set the plan: ChatWorld's ROUTING PUSH sends `ENCAP <server> UPLINKPLAN <name,name,...>`. A server
 * only takes it if its own plan file says `accept_push yes` (default no), the sender is a services client (+S), every name
 * is one of its own connect{} blocks, and it is not itself. The plan file is rewritten (uplink lines only, the other
 * directives and comments stay) and reloaded; opers see one notice.
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
	struct timeval probe_start;
	time_t last_probe;           /* when the last probe finished, 0 = never */
	bool last_probe_ok;
	long last_probe_ms;
	unsigned long probes_ok, probes_fail;
};

static struct cwu_up cwu_ups[CWU_MAX];
static int cwu_n;
static int cfg_interval = 10, cfg_fail = 3, cfg_ok = 6, cfg_cooldown = 600;
static int cfg_unstable_drops = 3, cfg_unstable_window = 1800, cfg_unstable_hold = 600;
static bool cwu_frozen;
static time_t cwu_freeze_until;      /* 0 = no expiry */
static time_t cwu_override_until;    /* a temporary plan (UPLINK SET) is active until then; 0 = the plan file rules */
static time_t cwu_debug_until;       /* UPLINK DEBUG: every probe and decision goes to the log and the history file */
static char cwu_last_event[160];
static time_t cwu_last_event_t;
static bool cfg_accept_push;
#define CWU_REMOTE 8
static char cwu_remote_from[CWU_REMOTE][64];   /* servers whose opers may run UPLINK RELOAD/STATUS here by ENCAP */
static int cwu_nremote;
static char cwu_last_push[160];      /* who/what/when of the last accepted push, for UPLINK STATUS */
static time_t cwu_connecting_until, cwu_cooldown_until, cwu_fb_deadline, cwu_ready_since, cwu_att_deadline;
static int cwu_att_idx = -1;   /* uplink we are currently trying to link to when isolated */
static int cwu_att_oks;        /* its good-probe count when the attempt started: >0 means it looked reachable */
static int cwu_fb_target = -1, cwu_fb_rollback = -1;
static bool cwu_fb_pending;     /* the old link is gone: the connect to the better uplink starts at the next tick */
static int cwu_fb_tries;       /* connects made to the better uplink in this move (it gets one retry) */
static int cwu_last_state = -2;      /* -1 isolated, 0 preferred, k fallback k */
static bool cwu_last_unstable;
static struct ev_entry *cwu_ev;

static void mo_uplink(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_uplink(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_uplinkplan(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

struct Message uplink_msgtab = {
	"UPLINK", 0, 0, 0, 0,
	{mg_ignore, mg_not_oper, mg_ignore, mg_ignore, {me_uplink, 2}, {mo_uplink, 2}}
};
/* ENCAP <this server> UPLINKPLAN <name,name,...> from services */
struct Message uplinkplan_msgtab = {
	"UPLINKPLAN", 0, 0, 0, 0,
	{mg_ignore, mg_ignore, mg_ignore, mg_ignore, {me_uplinkplan, 2}, mg_ignore}
};

mapi_clist_av1 cwu_clist[] = { &uplink_msgtab, &uplinkplan_msgtab, NULL };

static void cwu_tick(void *);
static bool cwu_load_plan(bool keep, bool may_generate);
static void cwu_conf_hook(void *);

mapi_hfn_list_av1 cwu_hfnlist[] = {
	{ "conf_read_end", cwu_conf_hook },
	{ NULL, NULL }
};

static int
modinit(void)
{
	(void) cwu_load_plan(false, false);          /* the connect{} blocks may not be read yet: no automatic plan here */
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

/* Long-lived history of the decisions, one line per event, in a file of its own next to the plan (rotated at 1 MiB,
 * one old generation kept). Format: YYYY-MM-DD HH:MM:SS text. */
#define CWU_HIST     "uplink.history"
#define CWU_HIST_MAX (1024 * 1024)

static void cwu_confdir(char *buf, size_t len);

static void
cwu_hist(const char *text)
{
	char dir[PATH_MAX], path[PATH_MAX], old[PATH_MAX + 4], ts[32];
	struct stat st;
	time_t t = rb_current_time();
	FILE *f;

	cwu_confdir(dir, sizeof dir);
	snprintf(path, sizeof path, "%s/%s", dir, CWU_HIST);
	if (stat(path, &st) == 0 && st.st_size > CWU_HIST_MAX)
	{
		snprintf(old, sizeof old, "%s.1", path);
		(void) rename(path, old);
	}
	f = fopen(path, "a");
	if (f == NULL)
		return;
	strftime(ts, sizeof ts, "%Y-%m-%d %H:%M:%S", localtime(&t));
	fprintf(f, "%s %s\n", ts, text);
	fclose(f);
}

static void
cwu_note(const char *fmt, ...)
{
	char buf[256];
	va_list ap;

	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	sendto_realops_snomask(SNO_GENERAL, L_ALL | L_NETWIDE, "cn_uplink: %s", buf);   /* every oper on the network sees who changed what */
	ilog(L_SERVER, "cn_uplink: %s", buf);
	cwu_hist(buf);
	rb_strlcpy(cwu_last_event, buf, sizeof cwu_last_event);
	cwu_last_event_t = rb_current_time();
}

/* Detail for UPLINK DEBUG: log and history only, never the opers' screens. */
static void
cwu_dbg(const char *fmt, ...)
{
	char buf[256], line[280];
	va_list ap;

	if (cwu_debug_until == 0)
		return;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof buf, fmt, ap);
	va_end(ap);
	ilog(L_SERVER, "cn_uplink: debug: %s", buf);
	snprintf(line, sizeof line, "debug: %s", buf);
	cwu_hist(line);
}

/* Directory of the running ircd.conf (e.g. etc-live): the plan and the generated file live next to the live config,
 * whatever prefix this build was installed with. */
static void
cwu_confdir(char *buf, size_t len)
{
	const char *cf = ConfigFileEntry.configfile;
	const char *slash = cf != NULL ? strrchr(cf, '/') : NULL;

	if (slash == NULL)
		rb_strlcpy(buf, ircd_paths[IRCD_PATH_ETC], len);
	else
	{
		size_t n = (size_t)(slash - cf) < len - 1 ? (size_t)(slash - cf) : len - 1;

		memcpy(buf, cf, n);
		buf[n] = '\0';
	}
}

static void
cwu_plan_path(char *path, size_t len)
{
	if (getenv("CN_UPLINK_PLAN") != NULL)       /* test labs: one plan per server sharing one install */
		rb_strlcpy(path, getenv("CN_UPLINK_PLAN"), len);
	else
	{
		char dir[PATH_MAX];

		cwu_confdir(dir, sizeof dir);
		snprintf(path, len, "%s/%s", dir, CWU_FILE);
	}
}

/* No uplink.plan: build one from the connect{} blocks that have autoconn on, in the order they appear in ircd.conf,
 * and write it. Only blocks the admin already marked "connect out to this one" count, so a hub does not turn its
 * leaves into uplinks. Whoever wants another order or accept_push creates or edits the file. */
static bool
cwu_auto_plan(void)
{
	char path[PATH_MAX], list[256] = "";
	rb_dlink_node *ptr;
	FILE *f;
	int n = 0;

	cwu_plan_path(path, sizeof path);
	for (ptr = server_conf_list.tail; ptr != NULL && n < CWU_MAX; ptr = ptr->prev)       /* the list is newest-first */
	{
		const struct server_conf *sc = ptr->data;

		if (!ServerConfAutoconn(sc) || ServerConfIllegal(sc) || !irccmp(sc->name, me.name))
			continue;
		if (strlen(sc->name) >= sizeof cwu_ups[0].name)
			continue;
		n++;
		rb_strlcat(list, n > 1 ? " > " : "", sizeof list);
		rb_strlcat(list, sc->name, sizeof list);
	}
	if (n == 0)
		return false;
	f = fopen(path, "w");
	if (f == NULL)
		return false;
	fprintf(f, "# uplink.plan written by cn_uplink because none existed: the connect{} blocks with autoconn, in the order of ircd.conf.\n"
	           "# Edit it or replace it freely; a rehash or UPLINK RELOAD reads it. accept_push is off unless you add it.\n");
	for (ptr = server_conf_list.tail; ptr != NULL; ptr = ptr->prev)
	{
		const struct server_conf *sc = ptr->data;

		if (ServerConfAutoconn(sc) && !ServerConfIllegal(sc) && irccmp(sc->name, me.name) &&
		    strlen(sc->name) < sizeof cwu_ups[0].name && n-- > 0)
			fprintf(f, "uplink %s\n", sc->name);
	}
	fclose(f);
	cwu_note("no uplink.plan here: wrote one from the autoconn connect{} blocks: %s", list);
	return true;
}

/* keep: carry the probe counters and drops of entries that are still in the plan (a rehash must not reset them). */
static bool
cwu_load_plan(bool keep, bool may_generate)
{
	char path[PATH_MAX], line[256];
	struct cwu_up old[CWU_MAX];
	int oldn = cwu_n;
	FILE *f;
	int n = 0, k, m;

	cwu_plan_path(path, sizeof path);
	f = fopen(path, "r");
	if (f == NULL && may_generate && cwu_auto_plan())
		f = fopen(path, "r");
	if (f == NULL)
		return false;

	memcpy(old, cwu_ups, sizeof old);
	memset(cwu_ups, 0, sizeof cwu_ups);
	cwu_override_until = 0;                     /* reading the file ends any temporary plan */
	cwu_att_idx = cwu_fb_target = cwu_fb_rollback = -1;
	cwu_fb_pending = false;
	cfg_accept_push = false;                    /* the file is the truth: no line, no push */
	cwu_nremote = 0;                            /* same for remote_from: none listed, no remote control */
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
		else if (!strcmp(key, "remote_from") && cwu_nremote < CWU_REMOTE)
			rb_strlcpy(cwu_remote_from[cwu_nremote++], val, sizeof cwu_remote_from[0]);
		else if (!strcmp(key, "accept_push"))
			cfg_accept_push = !strcmp(val, "yes") || !strcmp(val, "1") || !strcmp(val, "on");
	}
	fclose(f);
	cwu_n = n;
	if (keep)
		for (k = 0; k < n; k++)
			for (m = 0; m < oldn; m++)
				if (!irccmp(cwu_ups[k].name, old[m].name))
					cwu_ups[k] = old[m];
	return true;
}

/* Every name in the plan must be one of this server's own connect{} blocks, or it is never probed or connected and,
 * when we are isolated, can be picked again and again without a penalty. Say so loudly. */
static void
cwu_check_names(void)
{
	int i;

	for (i = 0; i < cwu_n; i++)
	{
		if (!irccmp(cwu_ups[i].name, me.name))
			cwu_note("WARNING: uplink %s in uplink.plan is this server itself", cwu_ups[i].name);
		else if (find_server_conf(cwu_ups[i].name) == NULL)
			cwu_note("WARNING: uplink %s in uplink.plan has no connect{} block here: it is never probed or connected", cwu_ups[i].name);
	}
}

static void
cwu_plan_str(char *buf, size_t len)
{
	int i;

	buf[0] = '\0';
	for (i = 0; i < cwu_n; i++)
	{
		rb_strlcat(buf, i ? " > " : "", len);
		rb_strlcat(buf, cwu_ups[i].name, len);
	}
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

/* conf_read_end (start-up and every REHASH): the plan is read again here, so a rehash is enough; the connect{} blocks
 * are known now, so the names are checked and a missing plan can be written. Probe counters are kept. */
static void
cwu_conf_hook(void *unused)
{
	char before[256], after[256];

	(void) unused;
	cwu_plan_str(before, sizeof before);
	if (cwu_load_plan(true, true))
	{
		cwu_plan_str(after, sizeof after);
		if (strcmp(before, after))
			cwu_note("plan read at rehash: %s", after[0] ? after : "(empty)");
		cwu_check_names();
	}
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
	const struct timeval *tv = rb_current_time_tv();

	u->probing = false;
	u->last_probe = rb_current_time();
	u->last_probe_ok = (status == RB_OK);
	u->last_probe_ms = (tv->tv_sec - u->probe_start.tv_sec) * 1000 + (tv->tv_usec - u->probe_start.tv_usec) / 1000;
	if (status == RB_OK)
		u->probes_ok++;
	else
		u->probes_fail++;
	cwu_dbg("probe %s: %s in %ld ms (oks=%d fails=%d)", u->name, status == RB_OK ? "ok" : "FAILED", u->last_probe_ms,
	        status == RB_OK ? u->oks + 1 : 0, status == RB_OK ? 0 : u->fails + 1);
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
	u->probe_start = *rb_current_time_tv();
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
	if (cwu_debug_until != 0 && now >= cwu_debug_until)
	{
		cwu_note("debug off (time is up)");
		cwu_debug_until = 0;
	}
	if (cwu_freeze_until != 0 && now >= cwu_freeze_until)
	{
		cwu_frozen = false;
		cwu_freeze_until = 0;
		cwu_note("freeze expired: link management resumed");
	}
	if (cwu_override_until != 0 && now >= cwu_override_until)
	{
		cwu_note("temporary plan expired: back to the plan file");
		(void) cwu_load_plan(true, false);
		cwu_check_names();
	}
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
		else if (cwu_fb_pending)
		{
			/* Break-then-make with a pause: the better uplink may still see this server in its tree for a moment
			 * after the old link dropped and then closes the handshake (a duplicate server), so the connect starts
			 * one tick after the split. */
			cwu_fb_pending = false;
			cwu_fb_tries = 1;
			cwu_connect(cwu_fb_target);
			cwu_fb_deadline = now + 20;
		}
		else if (now >= cwu_fb_deadline && cwu_fb_tries <= 1)
		{
			cwu_note("attempt to link to %s did not come up, trying once more", cwu_ups[cwu_fb_target].name);
			cwu_fb_tries++;
			cwu_connect(cwu_fb_target);
			cwu_fb_deadline = now + 20;
		}
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
		cwu_dbg("isolated: trying %s (%s, fails=%d oks=%d strikes=%d)", cwu_ups[t].name,
		        cwu_ups[t].down ? "marked down, nothing better left" : "first uplink not down and not in penalty",
		        cwu_ups[t].fails, cwu_ups[t].oks, cwu_ups[t].strikes);
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
		cwu_fb_pending = true;
		cwu_fb_tries = 0;
		cwu_fb_deadline = now + 60;
		cwu_ready_since = 0;
		if (old != NULL)
			exit_client(old, old, &me, "uplink change");
	}
}


/* A name is accepted only if it is a plain server name and one of OUR connect{} blocks (and not this server). */
static bool
cwu_push_name_ok(const char *name, char *why, size_t whylen)
{
	const char *p;

	if (*name == '\0' || strlen(name) >= sizeof cwu_ups[0].name)
	{
		snprintf(why, whylen, "bad name length");
		return false;
	}
	for (p = name; *p != '\0'; p++)
		if (!(isalnum((unsigned char)*p) || *p == '.' || *p == '-' || *p == '_'))
		{
			snprintf(why, whylen, "bad character in %s", name);
			return false;
		}
	if (!irccmp(name, me.name))
	{
		snprintf(why, whylen, "%s is this server", name);
		return false;
	}
	if (find_server_conf(name) == NULL)
	{
		snprintf(why, whylen, "%s is not a connect{} block here", name);
		return false;
	}
	return true;
}

/* Rewrite the plan file keeping everything except the uplink lines, then append the new uplink lines. */
static bool
cwu_write_plan(const char names[][64], int count)
{
	char path[PATH_MAX], tmp[PATH_MAX], line[512];
	FILE *in, *out;
	int i;

	cwu_plan_path(path, sizeof path);
	snprintf(tmp, sizeof tmp, "%s.tmp", path);
	in = fopen(path, "r");
	out = fopen(tmp, "w");
	if (out == NULL)
	{
		if (in != NULL)
			fclose(in);
		return false;
	}
	while (in != NULL && fgets(line, sizeof line, in) != NULL)
		if (strncmp(line, "uplink ", 7) != 0 && strncmp(line, "uplink\t", 7) != 0)
			fputs(line, out);
	if (in != NULL)
		fclose(in);
	for (i = 0; i < count; i++)
		fprintf(out, "uplink %s\n", names[i]);
	if (fclose(out) != 0 || rename(tmp, path) != 0)
		return false;
	return true;
}

static void
me_uplinkplan(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	char names[CWU_MAX][64], why[128], list[512], shown[400];
	char *tok, *save = NULL;
	int count = 0, i, j;

	if (!IsPerson(source_p) || !IsService(source_p))
		return;                                     /* only the services pseudo-clients (+S) may set a plan */

	if (!cfg_accept_push)
	{
		cwu_note("plan from %s ignored (accept_push is off here)", source_p->name);
		return;
	}

	rb_strlcpy(list, parv[1], sizeof list);
	for (tok = strtok_r(list, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save))
	{
		if (count >= CWU_MAX)
		{
			snprintf(why, sizeof why, "more than %d uplinks", CWU_MAX);
			goto refused;
		}
		if (!cwu_push_name_ok(tok, why, sizeof why))
			goto refused;
		for (j = 0; j < count; j++)
			if (!irccmp(names[j], tok))
			{
				snprintf(why, sizeof why, "%s listed twice", tok);
				goto refused;
			}
		rb_strlcpy(names[count++], tok, sizeof names[0]);
	}
	if (count == 0)
	{
		snprintf(why, sizeof why, "empty plan");
		goto refused;
	}
	if (!cwu_write_plan(names, count))
	{
		snprintf(why, sizeof why, "cannot write the plan file");
		goto refused;
	}
	(void) cwu_load_plan(true, false);

	shown[0] = '\0';
	for (i = 0; i < count; i++)
	{
		rb_strlcat(shown, i ? " > " : "", sizeof shown);
		rb_strlcat(shown, names[i], sizeof shown);
	}
	snprintf(cwu_last_push, sizeof cwu_last_push, "%s at %ld", source_p->name, (long) rb_current_time());
	cwu_note("uplink plan set by %s: %s", source_p->name, shown);
	return;

refused:
	cwu_note("uplink plan from %s REFUSED: %s", source_p->name, why);
}

static void
cwu_status(struct Client *source_p)
{
	time_t now = rb_current_time();
	char extra[200] = "", rem[200] = "";
	int i;

	if (cwu_frozen && cwu_freeze_until != 0)
		snprintf(extra, sizeof extra, " (FROZEN, %ld min left)", (long)((cwu_freeze_until - now + 59) / 60));
	else if (cwu_frozen)
		rb_strlcpy(extra, " (FROZEN)", sizeof extra);
	for (i = 0; i < cwu_nremote; i++)
	{
		rb_strlcat(rem, i ? "," : "", sizeof rem);
		rb_strlcat(rem, cwu_remote_from[i], sizeof rem);
	}
	sendto_one_notice(source_p, ":UPLINK%s: interval %d fail %d ok %d cooldown %d s, accept_push %s, remote_from %s%s%s",
	                  extra, cfg_interval, cfg_fail, cfg_ok, cfg_cooldown, cfg_accept_push ? "yes" : "no",
	                  rem[0] ? rem : "(none)", cwu_last_push[0] ? ", last plan from " : "", cwu_last_push);
	if (cwu_override_until != 0)
		sendto_one_notice(source_p, ":UPLINK: TEMPORARY plan, %ld min left, then back to the plan file",
		                  (long)((cwu_override_until - now + 59) / 60));
	if (cwu_debug_until != 0)
		sendto_one_notice(source_p, ":UPLINK: DEBUG on, %ld min left (log and %s)",
		                  (long)((cwu_debug_until - now + 59) / 60), CWU_HIST);
	if (cwu_last_event[0] != '\0')
		sendto_one_notice(source_p, ":UPLINK: last event %ld s ago: %s", (long)(now - cwu_last_event_t), cwu_last_event);
	for (i = 0; i < cwu_n; i++)
	{
		const struct cwu_up *u = &cwu_ups[i];
		char pr[96] = "no probe yet", pen[48] = "";

		if (u->last_probe != 0)
			snprintf(pr, sizeof pr, "last probe %ld s ago %s %ld ms", (long)(now - u->last_probe),
			         u->last_probe_ok ? "ok" : "FAILED", u->last_probe_ms);
		if (u->bad_until > now)
			snprintf(pen, sizeof pen, " skipped for %ld s (strikes=%d)", (long)(u->bad_until - now), u->strikes);
		sendto_one_notice(source_p, ":UPLINK %d %s: %s%s fails=%d oks=%d drops=%d%s | %s, probes ok=%lu failed=%lu%s",
		                  i, u->name, u->linked ? "LINKED" : (u->down ? "down" : "up?"), i == 0 ? " (preferred)" : "",
		                  u->fails, u->oks, cwu_recent_drops(u, now), cwu_unstable(u, now) ? " UNSTABLE" : "",
		                  pr, u->probes_ok, u->probes_fail, pen);
	}
}

/* One parsed UPLINK command.  RELOAD|STATUS [mask]   FREEZE ON [min] [mask] | FREEZE OFF [mask]
 * SET <name,name,..> [min] [mask]   DEBUG ON [min] [mask] | DEBUG OFF [mask].  A number right after the required
 * arguments is the duration in minutes; whatever follows is the server mask (absent = this server only). */
struct cwu_cmd
{
	char sub[16];
	bool on;
	char list[512];
	int minutes;                 /* 0 = not given */
	const char *mask;
};

static bool
cwu_all_digits(const char *s)
{
	return *s != '\0' && strspn(s, "0123456789") == strlen(s) && strlen(s) < 6;
}

static bool
cwu_parse(int parc, const char *parv[], struct cwu_cmd *c)
{
	int i;

	memset(c, 0, sizeof *c);
	rb_strlcpy(c->sub, parv[1], sizeof c->sub);
	if (!irccmp(c->sub, "RELOAD") || !irccmp(c->sub, "STATUS"))
	{
		c->mask = parc > 2 ? parv[2] : NULL;
		return true;
	}
	if (!irccmp(c->sub, "FREEZE") || !irccmp(c->sub, "DEBUG"))
	{
		if (parc < 3 || (irccmp(parv[2], "ON") && irccmp(parv[2], "OFF")))
			return false;
		c->on = !irccmp(parv[2], "ON");
		i = 3;
	}
	else if (!irccmp(c->sub, "SET"))
	{
		if (parc < 3)
			return false;
		rb_strlcpy(c->list, parv[2], sizeof c->list);
		i = 3;
	}
	else
		return false;
	if (parc > i && cwu_all_digits(parv[i]))
		c->minutes = atoi(parv[i++]);
	c->mask = parc > i ? parv[i] : NULL;
	return true;
}

static int
cwu_clamp(int minutes, int dflt, int max)
{
	if (minutes <= 0)
		return dflt;
	return minutes > max ? max : minutes;
}

/* Does the work of a parsed command on THIS server. remote = it came by ENCAP from a server in remote_from. */
static void
cwu_exec(struct Client *source_p, const struct cwu_cmd *c, bool remote)
{
	time_t now = rb_current_time();
	char who[160];

	if (remote)
		snprintf(who, sizeof who, "%s from %s", source_p->name, source_p->servptr->name);
	else
		rb_strlcpy(who, get_oper_name(source_p), sizeof who);

	if (!irccmp(c->sub, "STATUS"))
	{
		if (remote)
			sendto_one_notice(source_p, ":UPLINK: status of %s", me.name);
		cwu_status(source_p);
	}
	else if (!irccmp(c->sub, "RELOAD"))
	{
		char before[256], after[256];
		bool loaded;

		cwu_plan_str(before, sizeof before);
		loaded = cwu_load_plan(false, true);
		cwu_plan_str(after, sizeof after);
		cwu_note("plan reload %s by %s%s%s", loaded ? "done" : "FAILED (file not found)", who,
		         loaded ? ": " : "", loaded ? after : "");
		if (loaded)
			cwu_check_names();
		sendto_one_notice(source_p, ":UPLINK: %s plan %s", me.name, loaded ? "reloaded" : "file not found");
	}
	else if (!irccmp(c->sub, "FREEZE"))
	{
		if (c->on)
		{
			int m = remote ? cwu_clamp(c->minutes, 30, 120) : (c->minutes > 0 ? cwu_clamp(c->minutes, 0, 1440) : 0);

			cwu_frozen = true;
			cwu_freeze_until = m > 0 ? now + m * 60 : 0;
			if (m > 0)
				cwu_note("FROZEN for %d min by %s: no link changes", m, who);
			else
				cwu_note("FROZEN by %s: no link changes, until UPLINK FREEZE OFF", who);
		}
		else
		{
			cwu_frozen = false;
			cwu_freeze_until = 0;
			cwu_note("unfrozen by %s", who);
		}
		sendto_one_notice(source_p, ":UPLINK: %s %s", me.name, cwu_frozen ? "frozen" : "unfrozen");
	}
	else if (!irccmp(c->sub, "DEBUG"))
	{
		if (c->on)
		{
			int m = cwu_clamp(c->minutes, 30, 240);

			cwu_debug_until = now + m * 60;
			cwu_note("debug on for %d min by %s: every probe and decision goes to the log and %s", m, who, CWU_HIST);
		}
		else
		{
			cwu_debug_until = 0;
			cwu_note("debug off by %s", who);
		}
		sendto_one_notice(source_p, ":UPLINK: %s debug %s", me.name, cwu_debug_until != 0 ? "on" : "off");
	}
	else if (!irccmp(c->sub, "SET"))
	{
		char names[CWU_MAX][64], why[128], list[512], shown[400];
		char *tok, *save = NULL;
		int count = 0, i, j, m = cwu_clamp(c->minutes, 120, 240);

		rb_strlcpy(list, c->list, sizeof list);
		for (tok = strtok_r(list, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save))
		{
			if (count >= CWU_MAX)
			{
				snprintf(why, sizeof why, "more than %d uplinks", CWU_MAX);
				goto refused;
			}
			if (!cwu_push_name_ok(tok, why, sizeof why))
				goto refused;
			for (j = 0; j < count; j++)
				if (!irccmp(names[j], tok))
				{
					snprintf(why, sizeof why, "%s listed twice", tok);
					goto refused;
				}
			rb_strlcpy(names[count++], tok, sizeof names[0]);
		}
		if (count == 0)
		{
			snprintf(why, sizeof why, "empty list");
			goto refused;
		}
		memset(cwu_ups, 0, sizeof cwu_ups);
		for (i = 0; i < count; i++)
			rb_strlcpy(cwu_ups[i].name, names[i], sizeof cwu_ups[0].name);
		cwu_n = count;
		cwu_att_idx = cwu_fb_target = cwu_fb_rollback = -1;
		cwu_fb_pending = false;
		cwu_override_until = now + m * 60;
		cwu_plan_str(shown, sizeof shown);
		cwu_note("TEMPORARY plan set by %s for %d min: %s (then back to the plan file)", who, m, shown);
		sendto_one_notice(source_p, ":UPLINK: %s temporary plan set for %d min", me.name, m);
		return;
refused:
		cwu_note("temporary plan from %s REFUSED: %s", who, why);
		sendto_one_notice(source_p, ":UPLINK: %s refused: %s", me.name, why);
	}
}

/* The same command, sent on to the servers matching the mask. Duration and ON/OFF are written out so every server
 * reads the same thing; the receiving server applies its own limits. */
static void
cwu_relay(struct Client *source_p, const struct cwu_cmd *c)
{
	char args[600];

	if (!irccmp(c->sub, "FREEZE") || !irccmp(c->sub, "DEBUG"))
		snprintf(args, sizeof args, "%s %s %d", c->sub, c->on ? "ON" : "OFF", c->minutes);
	else if (!irccmp(c->sub, "SET"))
		snprintf(args, sizeof args, "SET %s %d", c->list, c->minutes);
	else
		snprintf(args, sizeof args, "%s", c->sub);
	sendto_match_servs(source_p, c->mask, CAP_ENCAP, NOCAPS, "ENCAP %s UPLINK %s", c->mask, args);
}

/* From a remote oper by ENCAP: the origin server checked oper:routing; here we trust only the servers the local plan
 * lists in remote_from (default: none). Always announced to every oper, with who and from where. */
static void
me_uplink(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct cwu_cmd c;
	bool ok = false;
	int i;

	if (!IsPerson(source_p) || !IsOper(source_p) || source_p->servptr == NULL)
		return;
	for (i = 0; i < cwu_nremote; i++)
		if (!irccmp(cwu_remote_from[i], source_p->servptr->name))
			ok = true;
	if (!ok)
	{
		cwu_note("remote UPLINK %s by %s refused: %s is not in remote_from here", parv[1], source_p->name, source_p->servptr->name);
		sendto_one_notice(source_p, ":UPLINK: %s refuses remote control from %s (not in remote_from)", me.name, source_p->servptr->name);
		return;
	}
	if (!cwu_parse(parc, parv, &c))
	{
		sendto_one_notice(source_p, ":UPLINK: %s could not read the command", me.name);
		return;
	}
	cwu_exec(source_p, &c, true);
}

static void
mo_uplink(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	struct cwu_cmd c;

	if (!cwu_parse(parc, parv, &c))
	{
		sendto_one_notice(source_p, ":Syntax: UPLINK STATUS|RELOAD [server]  |  FREEZE ON [min] [server] | FREEZE OFF [server]  |  "
		                            "SET <name,name,..> [min] [server]  |  DEBUG ON [min] [server] | DEBUG OFF [server]");
		return;
	}
	/* STATUS is for any oper; everything else changes what the server does with its links. */
	if (irccmp(c.sub, "STATUS") && !HasPrivilege(source_p, "oper:routing"))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "routing");
		return;
	}
	if (c.mask != NULL)
	{
		cwu_relay(source_p, &c);
		if (match(c.mask, me.name) == 0)
			return;
	}
	cwu_exec(source_p, &c, false);
}
