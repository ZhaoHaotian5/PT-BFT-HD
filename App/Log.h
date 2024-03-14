#ifndef LOG_H
#define LOG_H

#include <iostream>
#include <map>
#include <set>
#include <stdint.h>
#include <stdio.h>
#include "config.h"
#include "message.h"
#include "Justification.h"
#include "Proposal.h"

class Log
{
private:
	// Basic Hotstuff
	std::map<View, std::set<MsgNewviewHotstuff>> newviewsHotstuff;
	std::map<View, std::set<MsgLdrprepareHotstuff>> ldrpreparesHotstuff;
	std::map<View, std::set<MsgPrepareHotstuff>> preparesHotstuff;
	std::map<View, std::set<MsgPrecommitHotstuff>> precommitsHotstuff;
	std::map<View, std::set<MsgCommitHotstuff>> commitsHotstuff;

	// Basic Damysus
	std::map<View, std::set<MsgNewviewDamysus>> newviewsDamysus;
	std::map<View, std::set<MsgLdrprepareDamysus>> ldrpreparesDamysus;
	std::map<View, std::set<MsgPrepareDamysus>> preparesDamysus;
	std::map<View, std::set<MsgPrecommitDamysus>> precommitsDamysus;

	// Basic Ptbft
	std::map<View, std::set<MsgNewviewPtbft>> newviewsPtbft;
	std::map<View, std::set<MsgLdrpreparePtbft>> ldrpreparesPtbft;
	std::map<View, std::set<MsgPreparePtbft>> preparesPtbft;
	std::map<View, std::set<MsgPrecommitPtbft>> precommitsPtbft;
	std::map<View, std::set<MsgExnewviewPtbft>> exnewviewsPtbft;
	std::map<View, std::set<MsgExldrpreparePtbft>> exldrpreparesPtbft;
	std::map<View, std::set<MsgExpreparePtbft>> expreparesPtbft;
	std::map<View, std::set<MsgExprecommitPtbft>> exprecommitsPtbft;
	std::map<View, std::set<MsgExcommitPtbft>> excommitsPtbft;

public:
	Log();

	// Basic Hotstuff
	// Return the number of signatures
	unsigned int storeMsgNewviewHotstuff(MsgNewviewHotstuff msgNewview);
	unsigned int storeMsgLdrprepareHotstuff(MsgLdrprepareHotstuff msgLdrprepare);
	unsigned int storeMsgPrepareHotstuff(MsgPrepareHotstuff msgPrepare);
	unsigned int storeMsgPrecommitHotstuff(MsgPrecommitHotstuff msgPrecommit);
	unsigned int storeMsgCommitHotstuff(MsgCommitHotstuff msgCommit);

	// Collect [n] signatures of the messages
	Signs getMsgNewviewHotstuff(View view, unsigned int n);
	Signs getMsgPrepareHotstuff(View view, unsigned int n);
	Signs getMsgPrecommitHotstuff(View view, unsigned int n);
	Signs getMsgCommitHotstuff(View view, unsigned int n);

	// Find the justification of the highest message
	Justification findHighestMsgNewviewHotstuff(View view);

	// Find the first justification of the all messages
	MsgLdrprepareHotstuff firstMsgLdrprepareHotstuff(View view);
	Justification firstMsgPrepareHotstuff(View view);
	Justification firstMsgPrecommitHotstuff(View view);
	Justification firstMsgCommitHotstuff(View view);

	// Basic Damysus
	// Return the number of signatures
	unsigned int storeMsgNewviewDamysus(MsgNewviewDamysus msgNewview);
	unsigned int storeMsgLdrprepareDamysus(MsgLdrprepareDamysus msgLdrprepare);
	unsigned int storeMsgPrepareDamysus(MsgPrepareDamysus msgPrepare);
	unsigned int storeMsgPrecommitDamysus(MsgPrecommitDamysus msgPrecommit);

	// Collect [n] signatures of the messages
	std::set<MsgNewviewDamysus> getMsgNewviewDamysus(View view, unsigned int n);
	Signs getMsgPrepareDamysus(View view, unsigned int n);
	Signs getMsgPrecommitDamysus(View view, unsigned int n);

	// Find the first message
	MsgLdrprepareDamysus firstMsgLdrprepareDamysus(View view);
	Justification firstMsgPrepareDamysus(View view);
	Justification firstMsgPrecommitDamysus(View view);

	// Basic Ptbft
	// Return the number of signatures
	unsigned int storeMsgNewviewPtbft(MsgNewviewPtbft msgNewview);
	unsigned int storeMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare);
	unsigned int storeMsgPreparePtbft(MsgPreparePtbft msgPrepare);
	unsigned int storeMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit);
	unsigned int storeMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview);
	unsigned int storeMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare);
	unsigned int storeMsgExpreparePtbft(MsgExpreparePtbft msgExprepare);
	unsigned int storeMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit);
	unsigned int storeMsgExcommitPtbft(MsgExcommitPtbft msgExcommit);

	// Collect [n] signatures of the messages
	std::set<MsgNewviewPtbft> getMsgNewviewPtbft(View view, unsigned int n);
	Signs getMsgPreparePtbft(View view, unsigned int n);
	Signs getMsgPrecommitPtbft(View view, unsigned int n);
	Signs getMsgExnewviewPtbft(View view, unsigned int n);
	Signs getMsgExpreparePtbft(View view, unsigned int n);
	Signs getMsgExprecommitPtbft(View view, unsigned int n);
	Signs getMsgExcommitPtbft(View view, unsigned int n);

	// Find the justification of the highest message
	Justification findHighestMsgExnewviewPtbft(View view);

	// Find the first message
	MsgLdrpreparePtbft firstMsgLdrpreparePtbft(View view);
	Justification firstMsgPreparePtbft(View view);
	Justification firstMsgPrecommitPtbft(View view);
	MsgExldrpreparePtbft firstMsgExldrpreparePtbft(View view);
	Justification firstMsgExpreparePtbft(View view);
	Justification firstMsgExprecommitPtbft(View view);
	Justification firstMsgExcommitPtbft(View view);

	// Print
	std::string toPrint();
};

#endif
