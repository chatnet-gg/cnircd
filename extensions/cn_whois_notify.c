/*
 * Solanum: a slightly advanced ircd
 * cn_whois_notify.c: user mode +W, notifies you when someone /WHOIS's you
 *
 * abcX remembered this from the real old ChatNet network (Bahamut-
 * based CNIRCd); not present in either the released CNIRCd 6.1.0
 * source or upstream DALnet/bahamut, so it was likely a private
 * ChatNet-only patch never published -- same situation as the "CN-"
 * cloak prefix (see cn_ip_cloak.c). Reimplemented here as a small
 * umode-gated extension, same shape as stock extensions/
 * umode_noctcp.c: a new user mode ('W') plus one hook callback.
 *
 * Hooks solanum's own "doing_whois" hook point (declared in
 * modules/m_whois.c as doing_whois_hook, exported under the string
 * name "doing_whois" via that file's mapi_hlist_av1) rather than
 * patching core WHOIS handling directly.
 *
 * Staff-only (2026-08-13, abcX): also hooks "umode_changed" (same hook
 * cn_ip_cloak.c uses for a different purpose) to strip +W back off
 * immediately if a non-oper sets it, same enforcement shape as core's
 * own IsOper() gate on UMODE_ADMIN in ircd/s_user.c.
 *
 * Service/bot nicks excluded (2026-08-13, abcX): a network helper bot
 * polls WHOIS on abcX's nick every 90s to detect away status, which
 * floods +W with noise from a known bot rather than the "someone is
 * looking you up" signal +W exists for. The list below is the set of
 * service/bot nicks that stay silent.
 *
 * Staff-on-staff excluded too (2026-08-18, abcX: "vedo cncheck che mi
 * fa i whois" -> generalized to "staff cloak chatnet/staff* non deve
 * vedere i whois dei bot di ChatNet" -> "anche tra staff non si
 * dovrebbe vedere" -- confirmed both directions, "se faccio un whois
 * ad astro astro non dovrebbe vederlo stessa cosa vale per me"). +W's
 * real purpose is flagging a stranger/rando looking you up, not routine
 * staff-on-staff or bot-on-staff traffic. Checked by real staff cloak
 * (chatnet/staff/*, applied on IDENTIFY/SASL -- same field
 * cn_ip_cloak.c itself writes) on BOTH sides: source WHOISing a staffer
 * still notifies unless the source is also staff-cloaked (or a listed
 * service nick, existing check above).
 */

#include "stdinc.h"
#include "modules.h"
#include "hook.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "s_user.h"
#include "numeric.h"
#include "match.h"

static const char cn_whois_notify_desc[] =
	"Adds user mode +W: notifies you when someone /WHOIS's you.";

/* Service/bot nicks that never trigger +W notifications */
static const char *cn_whois_notify_service_nicks[] = {
	"NickServ", "ChanServ", "K9", "OS", "ChatWorld", "CW", "Global",
	"MemoServ", "InfoServ", "SaslServ", "GroupServ", "HostServ",
	"BotServ", "GameServ", "RPGServ", "HelpServ", "StatServ", "ALIS",
	"ozone", "teleirc", "telegram", "MatrixBridge", "Scout",
	"Claude", "Claude-abcX", "cncheck",
	NULL
};

/* Real staff cloak prefix, as written by cn_ip_cloak.c */
static const char cn_whois_notify_staff_host_prefix[] = "chatnet/staff/";

static void whois_notify_process(void *);
static void whois_notify_umode_check(void *);

static bool
cn_whois_notify_is_service_nick(const char *nick)
{
	const char **p;

	for (p = cn_whois_notify_service_nicks; *p != NULL; p++)
		if (!irccmp(nick, *p))
			return true;

	return false;
}

static bool
cn_whois_notify_is_staff_host(const char *host)
{
	return !strncmp(host, cn_whois_notify_staff_host_prefix,
			sizeof(cn_whois_notify_staff_host_prefix) - 1);
}

mapi_hfn_list_av1 cn_whois_notify_hfnlist[] = {
	{ "doing_whois", whois_notify_process },
	{ "umode_changed", whois_notify_umode_check },
	{ NULL, NULL }
};

static void
whois_notify_process(void *data_)
{
	hook_data_client *data = data_;
	struct Client *source_p = data->client;
	struct Client *target_p = data->target;

	if (!MyClient(target_p))
		return;

	if (source_p == target_p)
		return;

	if (cn_whois_notify_is_service_nick(source_p->name))
		return;

	if (cn_whois_notify_is_staff_host(target_p->host) && cn_whois_notify_is_staff_host(source_p->host))
		return;

	if (target_p->umodes & user_modes['W'])
	{
		sendto_one_notice(target_p, ":*** %s (%s@%s) is doing a /WHOIS on you",
			source_p->name, source_p->username, source_p->host);
	}
}

static void
whois_notify_umode_check(void *vdata)
{
	hook_data_umode_changed *data = (hook_data_umode_changed *)vdata;
	struct Client *source_p = data->client;

	if (!MyClient(source_p))
		return;

	/* Just opered up this call: auto-enable +W, abcX wants notifications
	 * on by default the moment someone becomes staff rather than opt-in
	 * per session. oper_up() sets UMODE_OPER on source_p before calling
	 * this hook, so IsOper() is already true here; oldumodes still
	 * reflects pre-oper state. */
	if (IsOper(source_p) && !(data->oldumodes & UMODE_OPER)
			&& !(source_p->umodes & user_modes['W']))
	{
		source_p->umodes |= user_modes['W'];
		sendto_one_notice(source_p, ":*** Auto-enabling +W (WHOIS notifications)");
	}

	/* +W newly set this call, and not (yet, or ever) an oper */
	if ((source_p->umodes & user_modes['W']) && !(data->oldumodes & user_modes['W'])
			&& !IsOper(source_p))
	{
		source_p->umodes &= ~user_modes['W'];
		sendto_one_numeric(source_p, ERR_NOPRIVILEGES, form_str(ERR_NOPRIVILEGES));
	}
}

static int
_modinit(void)
{
	user_modes['W'] = find_umode_slot();
	construct_umodebuf();

	return 0;
}

static void
_moddeinit(void)
{
	user_modes['W'] = 0;
	construct_umodebuf();
}

DECLARE_MODULE_AV2(cn_whois_notify, _modinit, _moddeinit, NULL, NULL,
			cn_whois_notify_hfnlist, NULL, NULL, cn_whois_notify_desc);
