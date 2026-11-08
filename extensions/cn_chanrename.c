/*
 * cn_chanrename.c: RENAME <#old> <#new> [:reason]
 *
 * Changes only the capitalisation of a channel name (#chatnet -> #ChatNet) while people are inside, which is
 * otherwise impossible: the server keeps the name the first user typed when the channel was created.
 * The channel keeps its members, modes, topic, bans and timestamp. Only names that are equal when case is ignored
 * are accepted, so it can never move a channel onto another one.
 *
 * Who: opers with oper:admin (RENAME), and services (by ENCAP, so a services command can follow). The rename is sent
 * to every server by ENCAP * RENAME; servers without this module ignore it and keep the old capitalisation until
 * the channel is recreated. Members who asked for draft/channel-rename get
 *     :nick!user@host RENAME #old #new :reason
 * and everybody else gets a channel notice, so nobody sees the name change behind their back.
 */

#include "stdinc.h"
#include "modules.h"
#include "client.h"
#include "ircd.h"
#include "send.h"
#include "msg.h"
#include "parse.h"
#include "hash.h"
#include "channel.h"
#include "numeric.h"
#include "s_conf.h"
#include "s_newconf.h"
#include "s_serv.h"
#include "logger.h"

static const char cn_chanrename_desc[] = "RENAME: change the capitalisation of a channel name while it is in use.";

static void mo_rename(struct MsgBuf *, struct Client *, struct Client *, int, const char **);
static void me_rename(struct MsgBuf *, struct Client *, struct Client *, int, const char **);

static uint64_t CLICAP_CHANRENAME;

struct Message rename_msgtab = {
	"RENAME", 0, 0, 0, 0,
	{mg_unreg, mg_not_oper, mg_ignore, mg_ignore, {me_rename, 3}, {mo_rename, 3}}
};

mapi_clist_av1 cn_chanrename_clist[] = { &rename_msgtab, NULL };
mapi_cap_list_av2 cn_chanrename_caps[] = {
	{ MAPI_CAP_CLIENT, "draft/channel-rename", NULL, &CLICAP_CHANRENAME },
	{ 0, NULL, NULL, NULL },
};

DECLARE_MODULE_AV2(cn_chanrename, NULL, NULL, cn_chanrename_clist, NULL, NULL, cn_chanrename_caps, NULL, cn_chanrename_desc);

/* Checks and applies the rename on this server and tells the local members. Returns false with a reason if refused. */
static bool
cn_rename_apply(struct Client *source_p, const char *oldname, const char *newname, const char *reason, const char **why)
{
	struct Channel *chptr = find_channel(oldname);
	char *copy;

	if (chptr == NULL)
	{
		*why = "no such channel";
		return false;
	}
	if (!IsChannelName(newname) || !check_channel_name(newname) || strlen(newname) > CHANNELLEN)
	{
		*why = "not a valid channel name";
		return false;
	}
	if (irccmp(chptr->chname, newname) != 0)
	{
		*why = "only the capitalisation can change";
		return false;
	}
	if (!strcmp(chptr->chname, newname))
	{
		*why = "the channel already has that name";
		return false;
	}

	/* members that know the cap get the real thing, the others a notice (they keep working: names are case-blind) */
	sendto_channel_local_with_capability(source_p, ALL_MEMBERS, CLICAP_CHANRENAME, 0, chptr, ":%s!%s@%s RENAME %s %s :%s",
	                                     source_p->name, source_p->username, source_p->host, chptr->chname, newname, reason);
	sendto_channel_local_with_capability(&me, ALL_MEMBERS, 0, CLICAP_CHANRENAME, chptr, ":%s NOTICE %s :%s renamed this channel to %s (%s)",
	                                     me.name, chptr->chname, source_p->name, newname, reason);

	copy = rb_strdup(newname);
	rb_free(chptr->chname);
	chptr->chname = copy;
	return true;
}

static void
mo_rename(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *why = NULL, *reason = parc > 3 && !EmptyString(parv[3]) ? parv[3] : "capitalisation";

	if (!HasPrivilege(source_p, "oper:admin"))
	{
		sendto_one(source_p, form_str(ERR_NOPRIVS), me.name, source_p->name, "admin");
		return;
	}
	if (find_channel(parv[1]) == NULL)
	{
		sendto_one_numeric(source_p, ERR_NOSUCHCHANNEL, form_str(ERR_NOSUCHCHANNEL), parv[1]);
		return;
	}
	if (!cn_rename_apply(source_p, parv[1], parv[2], reason, &why))
	{
		sendto_one_notice(source_p, ":RENAME: %s", why);
		return;
	}
	sendto_match_servs(source_p, "*", CAP_ENCAP, NOCAPS, "ENCAP * RENAME %s %s :%s", parv[1], parv[2], reason);
	sendto_realops_snomask(SNO_GENERAL, L_ALL | L_NETWIDE, "%s renamed channel %s to %s", get_oper_name(source_p), parv[1], parv[2]);
	ilog(L_MAIN, "RENAME %s -> %s by %s", parv[1], parv[2], get_oper_name(source_p));
}

/* ENCAP * RENAME <old> <new> :reason, from an oper or from services */
static void
me_rename(struct MsgBuf *msgbuf_p, struct Client *client_p, struct Client *source_p, int parc, const char *parv[])
{
	const char *why = NULL, *reason = parc > 3 && !EmptyString(parv[3]) ? parv[3] : "capitalisation";

	if (!IsPerson(source_p) || !(IsOper(source_p) || IsService(source_p)))
		return;
	(void) cn_rename_apply(source_p, parv[1], parv[2], reason, &why);
}
