/* modules/m_chants.c
 *
 * CHANTS -- admin-only, trusted override of a channel's TS6 timestamp.
 *
 * TS6's collision rule (ms_sjoin, m_join.c) only ever lets a channel's
 * TS go down or stay the same. Once something (a service, an
 * accidental TS 0 SJOIN, ...) has lowered it, there is no protocol-level
 * way to raise it again short of every server forgetting the channel
 * (0 members everywhere) so that it is recreated fresh. For a channel
 * that is never empty, that isn't practical.
 *
 * CHANTS is an explicit admin escape hatch for that situation: it sets
 * chptr->channelts directly on this server, with no comparison against
 * the old value, then relays the same assignment to every other linked
 * server so the whole network agrees again. Unlike an SJOIN it carries
 * no member list and never touches modes, bans or membership.
 *
 * Gated on IsOperAdmin() (the privilege RESTART and DIE already need):
 * it rewrites network-wide state unconditionally, and is trusted only
 * because only admin opers can reach it.
 *
 * Notes on the implementation:
 *
 *  - It uses get_or_create_channel() rather than find_channel(). A server
 *    only allocates a Channel struct for channels it has local members
 *    in, so a server with none would never see the update, and its next
 *    local JOIN would create the channel at the TS6 default (0) and
 *    broadcast that network-wide, undoing the change.
 *
 *  - A channel created here gets MODE_PERMANENT. channel.c destroys a
 *    channel when `!(chptr->mode.mode & MODE_PERMANENT) && members <= 0`
 *    (channel.c:295/330), and a freshly allocated copy has mode.mode ==
 *    0, so without the flag it would be destroyed again right away and
 *    the next real JOIN would recreate it at TS 0. For a channel that is
 *    already +P network-wide this only makes the new local copy match
 *    what the channel already is; it grants nothing new.
 */

#include "stdinc.h"
#include "client.h"
#include "channel.h"
#include "hash.h"
#include "ircd.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "send.h"
#include "numeric.h"
#include "msg.h"
#include "parse.h"
#include "modules.h"

static const char chants_desc[] =
	"Provides the CHANTS command, an admin-only trusted override of a channel's TS6 timestamp";

static void mo_chants(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void ms_chants(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[]);
static void do_chants(struct Client *source_p, struct Client *client_p, const char *chname, time_t newts, bool from_oper);

struct Message chants_msgtab = {
	"CHANTS", 0, 0, 0, 0,
	{mg_unreg, mg_not_oper, mg_ignore, {ms_chants, 3}, mg_ignore, {mo_chants, 3}}
};

mapi_clist_av1 chants_clist[] = { &chants_msgtab, NULL };

DECLARE_MODULE_AV2(chants, NULL, NULL, chants_clist, NULL, NULL, NULL, NULL, chants_desc);

static void
do_chants(struct Client *source_p, struct Client *client_p, const char *chname, time_t newts, bool from_oper)
{
	bool isnew;
	struct Channel *chptr = get_or_create_channel(source_p, chname, &isnew);

	if (chptr == NULL)
	{
		sendto_one_notice(source_p, ":CHANTS: %s isn't a valid channel name", chname);
		return;
	}

	if (isnew)
		chptr->mode.mode |= MODE_PERMANENT;

	sendto_realops_snomask(SNO_GENERAL, L_NETWIDE,
			     "%s used CHANTS on %s: TS %ld -> %ld%s",
			     source_p->name, chptr->chname,
			     (long) chptr->channelts, (long) newts,
			     isnew ? " (no local members here yet, marked +P so it sticks)" : "");

	chptr->channelts = newts;

	sendto_server(client_p, chptr, CAP_TS6, NOCAPS,
		      ":%s CHANTS %s %ld",
		      from_oper ? source_p->name : use_id(source_p),
		      chptr->chname, (long) newts);
}

static void
mo_chants(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	time_t newts;
	char *endptr;

	if (!IsOperAdmin(source_p))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return;
	}

	if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
	{
		sendto_one_notice(source_p, ":usage: CHANTS <channel> <new-ts>");
		return;
	}

	if (!IsChannelName(parv[1]))
	{
		sendto_one_notice(source_p, ":CHANTS: %s isn't a channel name", parv[1]);
		return;
	}

	newts = strtol(parv[2], &endptr, 10);
	if (*endptr != '\0' || newts < 0 || newts > rb_current_time())
	{
		sendto_one_notice(source_p, ":CHANTS: <new-ts> must be a whole number of seconds since 1970, not in the future");
		return;
	}

	do_chants(source_p, NULL, parv[1], newts, true);
}

static void
ms_chants(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	time_t newts;

	if (parc < 3 || EmptyString(parv[1]) || EmptyString(parv[2]))
		return;

	newts = atol(parv[2]);
	if (newts < 0)
		return;

	do_chants(source_p, client_p, parv[1], newts, false);
}
