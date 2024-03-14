#include "Log.h"

Log::Log() {}

// Basic Hotstuff
bool msgNewviewHotstuffFrom(std::set<MsgNewviewHotstuff> msgNewviews, std::set<ReplicaID> signers)
{
	for (std::set<MsgNewviewHotstuff>::iterator itMsg = msgNewviews.begin(); itMsg != msgNewviews.end(); itMsg++)
	{
		MsgNewviewHotstuff msgNewview = *itMsg;
		std::set<ReplicaID> allSigners = msgNewview.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgNewviewHotstuff(MsgNewviewHotstuff msgNewview)
{
	RoundData roundData_MsgNewview = msgNewview.roundData;
	View proposeView_MsgNewview = roundData_MsgNewview.getProposeView();
	std::set<ReplicaID> signers = msgNewview.signs.getSigners();
	std::map<View, std::set<MsgNewviewHotstuff>>::iterator itView = this->newviewsHotstuff.find(proposeView_MsgNewview);
	if (itView != this->newviewsHotstuff.end())
	{
		std::set<MsgNewviewHotstuff> msgNewviews = itView->second;
		if (!msgNewviewHotstuffFrom(msgNewviews, signers))
		{
			msgNewviews.insert(msgNewview);
			this->newviewsHotstuff[proposeView_MsgNewview] = msgNewviews;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: " << msgNewviews.size() << COLOUR_NORMAL << std::endl;
			}
			return msgNewviews.size();
		}
	}
	else
	{
		std::set<MsgNewviewHotstuff> msgNewviews = {msgNewview};
		this->newviewsHotstuff[proposeView_MsgNewview] = msgNewviews;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgLdrprepareHotstuffFrom(std::set<MsgLdrprepareHotstuff> msgLdrprepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgLdrprepareHotstuff>::iterator itMsg = msgLdrprepares.begin(); itMsg != msgLdrprepares.end(); itMsg++)
	{
		MsgLdrprepareHotstuff msgLdrprepare = *itMsg;
		std::set<ReplicaID> allSigners = msgLdrprepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgLdrprepareHotstuff(MsgLdrprepareHotstuff msgLdrprepare)
{
	Proposal<Justification> proposal_MsgLdrprepare = msgLdrprepare.proposal;
	View proposeView_MsgLdrprepare = proposal_MsgLdrprepare.getCertification().getRoundData().getProposeView();
	std::set<ReplicaID> signers = msgLdrprepare.signs.getSigners();
	std::map<View, std::set<MsgLdrprepareHotstuff>>::iterator itView = this->ldrpreparesHotstuff.find(proposeView_MsgLdrprepare);
	if (itView != this->ldrpreparesHotstuff.end())
	{
		std::set<MsgLdrprepareHotstuff> msgLdrprepares = itView->second;
		if (!msgLdrprepareHotstuffFrom(msgLdrprepares, signers))
		{
			msgLdrprepares.insert(msgLdrprepare);
			this->ldrpreparesHotstuff[proposeView_MsgLdrprepare] = msgLdrprepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: " << msgLdrprepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgLdrprepares.size();
		}
	}
	else
	{
		std::set<MsgLdrprepareHotstuff> msgLdrprepares = {msgLdrprepare};
		this->ldrpreparesHotstuff[proposeView_MsgLdrprepare] = msgLdrprepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPrepareHotstuffFrom(std::set<MsgPrepareHotstuff> msgPrepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgPrepareHotstuff>::iterator itMsg = msgPrepares.begin(); itMsg != msgPrepares.end(); itMsg++)
	{
		MsgPrepareHotstuff msgPrepare = *itMsg;
		std::set<ReplicaID> allSigners = msgPrepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPrepareHotstuff(MsgPrepareHotstuff msgPrepare)
{
	RoundData roundData_MsgPrepare = msgPrepare.roundData;
	View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
	std::set<ReplicaID> signers = msgPrepare.signs.getSigners();
	std::map<View, std::set<MsgPrepareHotstuff>>::iterator itView = this->preparesHotstuff.find(proposeView_MsgPrepare);
	if (itView != this->preparesHotstuff.end())
	{
		std::set<MsgPrepareHotstuff> msgPrepares = itView->second;
		if (!msgPrepareHotstuffFrom(msgPrepares, signers))
		{
			msgPrepares.insert(msgPrepare);
			this->preparesHotstuff[proposeView_MsgPrepare] = msgPrepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: " << msgPrepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrepares.size();
		}
	}
	else
	{
		std::set<MsgPrepareHotstuff> msgPrepares = {msgPrepare};
		this->preparesHotstuff[proposeView_MsgPrepare] = msgPrepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPrecommitHotstuffFrom(std::set<MsgPrecommitHotstuff> msgPrecommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgPrecommitHotstuff>::iterator itMsg = msgPrecommits.begin(); itMsg != msgPrecommits.end(); itMsg++)
	{
		MsgPrecommitHotstuff msgPrecommit = *itMsg;
		std::set<ReplicaID> allSigners = msgPrecommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPrecommitHotstuff(MsgPrecommitHotstuff msgPrecommit)
{
	RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
	View proposeView_MsgPrecommit = roundData_MsgPrecommit.getProposeView();
	std::set<ReplicaID> signers = msgPrecommit.signs.getSigners();
	std::map<View, std::set<MsgPrecommitHotstuff>>::iterator itView = this->precommitsHotstuff.find(proposeView_MsgPrecommit);
	if (itView != this->precommitsHotstuff.end())
	{
		std::set<MsgPrecommitHotstuff> msgPrecommits = itView->second;
		if (!msgPrecommitHotstuffFrom(msgPrecommits, signers))
		{
			msgPrecommits.insert(msgPrecommit);
			this->precommitsHotstuff[proposeView_MsgPrecommit] = msgPrecommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: " << msgPrecommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrecommits.size();
		}
	}
	else
	{
		std::set<MsgPrecommitHotstuff> msgPrecommits = {msgPrecommit};
		this->precommitsHotstuff[proposeView_MsgPrecommit] = msgPrecommits;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgCommitHotstuffFrom(std::set<MsgCommitHotstuff> msgCommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgCommitHotstuff>::iterator itMsg = msgCommits.begin(); itMsg != msgCommits.end(); itMsg++)
	{
		MsgCommitHotstuff msgCommit = *itMsg;
		std::set<ReplicaID> allSigners = msgCommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgCommitHotstuff(MsgCommitHotstuff msgCommit)
{
	RoundData roundData_MsgCommit = msgCommit.roundData;
	View proposeView_MsgCommit = roundData_MsgCommit.getProposeView();
	std::set<ReplicaID> signers = msgCommit.signs.getSigners();
	std::map<View, std::set<MsgCommitHotstuff>>::iterator itView = this->commitsHotstuff.find(proposeView_MsgCommit);
	if (itView != this->commitsHotstuff.end())
	{
		std::set<MsgCommitHotstuff> msgCommits = itView->second;
		if (!msgCommitHotstuffFrom(msgCommits, signers))
		{
			msgCommits.insert(msgCommit);
			this->commitsHotstuff[proposeView_MsgCommit] = msgCommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgCommit in view " << proposeView_MsgCommit << " and the number of MsgCommit is: " << msgCommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgCommits.size();
		}
	}
	else
	{
		std::set<MsgCommitHotstuff> msgCommits = {msgCommit};
		this->commitsHotstuff[proposeView_MsgCommit] = msgCommits;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgCommit in view " << proposeView_MsgCommit << " and the number of MsgCommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

Signs Log::getMsgNewviewHotstuff(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgNewviewHotstuff>>::iterator itView = this->newviewsHotstuff.find(view);
	if (itView != this->newviewsHotstuff.end())
	{
		std::set<MsgNewviewHotstuff> msgNewviews = itView->second;
		for (std::set<MsgNewviewHotstuff>::iterator itMsg = msgNewviews.begin(); signs.getSize() < n && itMsg != msgNewviews.end(); itMsg++)
		{
			MsgNewviewHotstuff msgNewview = *itMsg;
			Signs signs_MsgNewview = msgNewview.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgNewview.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgNewview, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgPrepareHotstuff(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPrepareHotstuff>>::iterator itView = this->preparesHotstuff.find(view);
	if (itView != this->preparesHotstuff.end())
	{
		std::set<MsgPrepareHotstuff> msgPrepares = itView->second;
		for (std::set<MsgPrepareHotstuff>::iterator itMsg = msgPrepares.begin(); signs.getSize() < n && itMsg != msgPrepares.end(); itMsg++)
		{
			MsgPrepareHotstuff msgPrepare = *itMsg;
			Signs signs_MsgPrepare = msgPrepare.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrepare, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgPrecommitHotstuff(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPrecommitHotstuff>>::iterator itView = this->precommitsHotstuff.find(view);
	if (itView != this->precommitsHotstuff.end())
	{
		std::set<MsgPrecommitHotstuff> msgPrecommits = itView->second;
		for (std::set<MsgPrecommitHotstuff>::iterator itMsg = msgPrecommits.begin(); signs.getSize() < n && itMsg != msgPrecommits.end(); itMsg++)
		{
			MsgPrecommitHotstuff msgPrecommit = *itMsg;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrecommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgCommitHotstuff(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgCommitHotstuff>>::iterator itView = this->commitsHotstuff.find(view);
	if (itView != this->commitsHotstuff.end())
	{
		std::set<MsgCommitHotstuff> msgCommits = itView->second;
		for (std::set<MsgCommitHotstuff>::iterator itMsg = msgCommits.begin(); signs.getSize() < n && itMsg != msgCommits.end(); itMsg++)
		{
			MsgCommitHotstuff msgCommit = *itMsg;
			Signs signs_MsgCommit = msgCommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgCommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgCommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Justification Log::findHighestMsgNewviewHotstuff(View view)
{
	std::map<View, std::set<MsgNewviewHotstuff>>::iterator itView = this->newviewsHotstuff.find(view);
	Justification justification_MsgNewview = Justification();
	if (itView != this->newviewsHotstuff.end())
	{
		std::set<MsgNewviewHotstuff> msgNewviews = itView->second;
		View highView = 0;
		for (std::set<MsgNewviewHotstuff>::iterator itMsg = msgNewviews.begin(); itMsg != msgNewviews.end(); itMsg++)
		{
			MsgNewviewHotstuff msgNewview = *itMsg;
			RoundData roundData_MsgNewview = msgNewview.roundData;
			Signs signs_MsgNewview = msgNewview.signs;
			View justifyView_MsgNewview = roundData_MsgNewview.getJustifyView();
			if (justifyView_MsgNewview >= highView)
			{
				highView = justifyView_MsgNewview;
				justification_MsgNewview = Justification(roundData_MsgNewview, signs_MsgNewview);
			}
		}
	}
	return justification_MsgNewview;
}

MsgLdrprepareHotstuff Log::firstMsgLdrprepareHotstuff(View view)
{
	std::map<View, std::set<MsgLdrprepareHotstuff>>::iterator itView = this->ldrpreparesHotstuff.find(view);
	if (itView != this->ldrpreparesHotstuff.end())
	{
		std::set<MsgLdrprepareHotstuff> msgLdrprepares = itView->second;
		if (msgLdrprepares.size() > 0)
		{
			std::set<MsgLdrprepareHotstuff>::iterator itMsg = msgLdrprepares.begin();
			MsgLdrprepareHotstuff msgLdrprepare = *itMsg;
			return msgLdrprepare;
		}
	}
	Proposal<Justification> proposal;
	Signs signs;
	MsgLdrprepareHotstuff msgLdrprepare = MsgLdrprepareHotstuff(proposal, signs);
	return msgLdrprepare;
}

Justification Log::firstMsgPrepareHotstuff(View view)
{
	std::map<View, std::set<MsgPrepareHotstuff>>::iterator itView = this->preparesHotstuff.find(view);
	if (itView != this->preparesHotstuff.end())
	{
		std::set<MsgPrepareHotstuff> msgPrepares = itView->second;
		if (msgPrepares.size() > 0)
		{
			std::set<MsgPrepareHotstuff>::iterator itMsg = msgPrepares.begin();
			MsgPrepareHotstuff msgPrepare = *itMsg;
			RoundData roundData_MsgPrepare = msgPrepare.roundData;
			Signs signs_MsgPrepare = msgPrepare.signs;
			Justification justification_MsgPrepare = Justification(roundData_MsgPrepare, signs_MsgPrepare);
			return justification_MsgPrepare;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgPrecommitHotstuff(View view)
{
	std::map<View, std::set<MsgPrecommitHotstuff>>::iterator itView = this->precommitsHotstuff.find(view);
	if (itView != this->precommitsHotstuff.end())
	{
		std::set<MsgPrecommitHotstuff> msgPrecommits = itView->second;
		if (msgPrecommits.size() > 0)
		{
			std::set<MsgPrecommitHotstuff>::iterator itMsg = msgPrecommits.begin();
			MsgPrecommitHotstuff msgPrecommit = *itMsg;
			RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			Justification justification_MsgPrecommit = Justification(roundData_MsgPrecommit, signs_MsgPrecommit);
			return justification_MsgPrecommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgCommitHotstuff(View view)
{
	std::map<View, std::set<MsgCommitHotstuff>>::iterator itView = this->commitsHotstuff.find(view);
	if (itView != this->commitsHotstuff.end())
	{
		std::set<MsgCommitHotstuff> msgCommits = itView->second;
		if (msgCommits.size() > 0)
		{
			std::set<MsgCommitHotstuff>::iterator itMsg = msgCommits.begin();
			MsgCommitHotstuff msgCommit = *itMsg;
			RoundData roundData_MsgCommit = msgCommit.roundData;
			Signs signs_MsgCommit = msgCommit.signs;
			Justification justification_MsgCommit = Justification(roundData_MsgCommit, signs_MsgCommit);
			return justification_MsgCommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

// Basic Damysus
bool msgNewviewDamysusFrom(std::set<MsgNewviewDamysus> msgNewviews, std::set<ReplicaID> signers)
{
	for (std::set<MsgNewviewDamysus>::iterator itMsg = msgNewviews.begin(); itMsg != msgNewviews.end(); itMsg++)
	{
		MsgNewviewDamysus msgNewview = *itMsg;
		std::set<ReplicaID> allSigners = msgNewview.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgNewviewDamysus(MsgNewviewDamysus msgNewview)
{
	RoundData roundData_MsgNewview = msgNewview.roundData;
	View proposeView_MsgNewview = roundData_MsgNewview.getProposeView();
	std::set<ReplicaID> signers = msgNewview.signs.getSigners();

	std::map<View, std::set<MsgNewviewDamysus>>::iterator itView = this->newviewsDamysus.find(proposeView_MsgNewview);
	if (itView != this->newviewsDamysus.end())
	{
		std::set<MsgNewviewDamysus> msgNewviews = itView->second;
		if (!msgNewviewDamysusFrom(msgNewviews, signers))
		{
			msgNewviews.insert(msgNewview);
			this->newviewsDamysus[proposeView_MsgNewview] = msgNewviews;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: " << msgNewviews.size() << COLOUR_NORMAL << std::endl;
			}
			return msgNewviews.size();
		}
	}
	else
	{
		std::set<MsgNewviewDamysus> msgNewviews = {msgNewview};
		this->newviewsDamysus[proposeView_MsgNewview] = msgNewviews;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgLdrprepareDamysusFrom(std::set<MsgLdrprepareDamysus> msgLdrprepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgLdrprepareDamysus>::iterator itMsg = msgLdrprepares.begin(); itMsg != msgLdrprepares.end(); itMsg++)
	{
		MsgLdrprepareDamysus msgLdrprepare = *itMsg;
		std::set<ReplicaID> allSigners = msgLdrprepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgLdrprepareDamysus(MsgLdrprepareDamysus msgLdrprepare)
{
	Accumulator accumulator_MsgLdrprepare = msgLdrprepare.proposal.getCertification();
	View proposeView_MsgLdrprepare = accumulator_MsgLdrprepare.getProposeView();
	std::set<ReplicaID> signers = msgLdrprepare.signs.getSigners();

	std::map<View, std::set<MsgLdrprepareDamysus>>::iterator itView = this->ldrpreparesDamysus.find(proposeView_MsgLdrprepare);
	if (itView != this->ldrpreparesDamysus.end())
	{
		std::set<MsgLdrprepareDamysus> msgLdrprepares = itView->second;
		if (!msgLdrprepareDamysusFrom(msgLdrprepares, signers))
		{
			msgLdrprepares.insert(msgLdrprepare);
			this->ldrpreparesDamysus[proposeView_MsgLdrprepare] = msgLdrprepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: " << msgLdrprepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgLdrprepares.size();
		}
	}
	else
	{
		std::set<MsgLdrprepareDamysus> msgLdrprepares = {msgLdrprepare};
		this->ldrpreparesDamysus[proposeView_MsgLdrprepare] = msgLdrprepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPrepareDamysusFrom(std::set<MsgPrepareDamysus> msgPrepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgPrepareDamysus>::iterator itMsg = msgPrepares.begin(); itMsg != msgPrepares.end(); itMsg++)
	{
		MsgPrepareDamysus msgPrepare = *itMsg;
		std::set<ReplicaID> allSigners = msgPrepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPrepareDamysus(MsgPrepareDamysus msgPrepare)
{
	RoundData roundData_MsgPrepare = msgPrepare.roundData;
	View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
	std::set<ReplicaID> signers = msgPrepare.signs.getSigners();

	std::map<View, std::set<MsgPrepareDamysus>>::iterator itView = this->preparesDamysus.find(proposeView_MsgPrepare);
	if (itView != this->preparesDamysus.end())
	{
		std::set<MsgPrepareDamysus> msgPrepares = itView->second;
		if (!msgPrepareDamysusFrom(msgPrepares, signers))
		{
			msgPrepares.insert(msgPrepare);
			this->preparesDamysus[proposeView_MsgPrepare] = msgPrepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: " << msgPrepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrepares.size();
		}
	}
	else
	{
		std::set<MsgPrepareDamysus> msgPrepares = {msgPrepare};
		this->preparesDamysus[proposeView_MsgPrepare] = msgPrepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPrecommitDamysusFrom(std::set<MsgPrecommitDamysus> msgPrecommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgPrecommitDamysus>::iterator itMsg = msgPrecommits.begin(); itMsg != msgPrecommits.end(); itMsg++)
	{
		MsgPrecommitDamysus msgPrecommit = *itMsg;
		std::set<ReplicaID> allSigners = msgPrecommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPrecommitDamysus(MsgPrecommitDamysus msgPrecommit)
{
	RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
	View proposeView_MsgPrecommit = roundData_MsgPrecommit.getProposeView();
	std::set<ReplicaID> signers = msgPrecommit.signs.getSigners();

	std::map<View, std::set<MsgPrecommitDamysus>>::iterator itView = this->precommitsDamysus.find(proposeView_MsgPrecommit);
	if (itView != this->precommitsDamysus.end())
	{
		std::set<MsgPrecommitDamysus> msgPrecommits = itView->second;
		if (!msgPrecommitDamysusFrom(msgPrecommits, signers))
		{
			msgPrecommits.insert(msgPrecommit);
			this->precommitsDamysus[proposeView_MsgPrecommit] = msgPrecommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: " << msgPrecommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrecommits.size();
		}
	}
	else
	{
		std::set<MsgPrecommitDamysus> msgPrecommits = {msgPrecommit};
		this->precommitsDamysus[proposeView_MsgPrecommit] = {msgPrecommit};
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

std::set<MsgNewviewDamysus> Log::getMsgNewviewDamysus(View view, unsigned int n)
{
	std::set<MsgNewviewDamysus> msgNewview;
	std::map<View, std::set<MsgNewviewDamysus>>::iterator itView = this->newviewsDamysus.find(view);
	if (itView != this->newviewsDamysus.end())
	{
		std::set<MsgNewviewDamysus> msgNewviews = itView->second;
		for (std::set<MsgNewviewDamysus>::iterator itMsg = msgNewviews.begin(); msgNewview.size() < n && itMsg != msgNewviews.end(); itMsg++)
		{
			MsgNewviewDamysus msg = *itMsg;
			msgNewview.insert(msg);
		}
	}
	return msgNewview;
}

Signs Log::getMsgPrepareDamysus(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPrepareDamysus>>::iterator itView = this->preparesDamysus.find(view);
	if (itView != this->preparesDamysus.end())
	{
		std::set<MsgPrepareDamysus> msgPrepares = itView->second;
		for (std::set<MsgPrepareDamysus>::iterator itMsg = msgPrepares.begin(); signs.getSize() < n && itMsg != msgPrepares.end(); itMsg++)
		{
			MsgPrepareDamysus msgPrepare = *itMsg;
			Signs signs_MsgPrepare = msgPrepare.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrepare, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgPrecommitDamysus(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPrecommitDamysus>>::iterator itView = this->precommitsDamysus.find(view);
	if (itView != this->precommitsDamysus.end())
	{
		std::set<MsgPrecommitDamysus> msgPrecommits = itView->second;
		for (std::set<MsgPrecommitDamysus>::iterator itMsg = msgPrecommits.begin(); signs.getSize() < n && itMsg != msgPrecommits.end(); itMsg++)
		{
			MsgPrecommitDamysus msgPrecommit = *itMsg;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrecommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

MsgLdrprepareDamysus Log::firstMsgLdrprepareDamysus(View view)
{
	std::map<View, std::set<MsgLdrprepareDamysus>>::iterator itView = this->ldrpreparesDamysus.find(view);
	if (itView != this->ldrpreparesDamysus.end())
	{
		std::set<MsgLdrprepareDamysus> msgLdrprepares = itView->second;
		if (msgLdrprepares.size() > 0)
		{
			std::set<MsgLdrprepareDamysus>::iterator itMsg = msgLdrprepares.begin();
			MsgLdrprepareDamysus msgLdrprepare = *itMsg;
			return msgLdrprepare;
		}
	}
	Proposal<Accumulator> proposal;
	Signs signs;
	MsgLdrprepareDamysus msgLdrprepare = MsgLdrprepareDamysus(proposal, signs);
	return msgLdrprepare;
}

Justification Log::firstMsgPrepareDamysus(View view)
{
	std::map<View, std::set<MsgPrepareDamysus>>::iterator itView = this->preparesDamysus.find(view);
	if (itView != this->preparesDamysus.end())
	{
		std::set<MsgPrepareDamysus> msgPrepares = itView->second;
		if (msgPrepares.size() > 0)
		{
			std::set<MsgPrepareDamysus>::iterator itMsg = msgPrepares.begin();
			MsgPrepareDamysus msgPrepare = *itMsg;
			RoundData roundData_MsgPrepare = msgPrepare.roundData;
			Signs signs_MsgPrepare = msgPrepare.signs;
			Justification justification_MsgPrepare = Justification(roundData_MsgPrepare, signs_MsgPrepare);
			return justification_MsgPrepare;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgPrecommitDamysus(View view)
{
	std::map<View, std::set<MsgPrecommitDamysus>>::iterator itView = this->precommitsDamysus.find(view);
	if (itView != this->precommitsDamysus.end())
	{
		std::set<MsgPrecommitDamysus> msgPrecommits = itView->second;
		if (msgPrecommits.size() > 0)
		{
			std::set<MsgPrecommitDamysus>::iterator itMsg = msgPrecommits.begin();
			MsgPrecommitDamysus msgPrecommit = *itMsg;
			RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			Justification justification_MsgPrecommit = Justification(roundData_MsgPrecommit, signs_MsgPrecommit);
			return justification_MsgPrecommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

// Basic Ptbft
bool msgNewviewPtbftFrom(std::set<MsgNewviewPtbft> msgNewviews, std::set<ReplicaID> signers)
{
	for (std::set<MsgNewviewPtbft>::iterator itMsg = msgNewviews.begin(); itMsg != msgNewviews.end(); itMsg++)
	{
		MsgNewviewPtbft msgNewview = *itMsg;
		std::set<ReplicaID> allSigners = msgNewview.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgNewviewPtbft(MsgNewviewPtbft msgNewview)
{
	RoundData roundData_MsgNewview = msgNewview.roundData;
	View proposeView_MsgNewview = roundData_MsgNewview.getProposeView();
	std::set<ReplicaID> signers = msgNewview.signs.getSigners();
	std::map<View, std::set<MsgNewviewPtbft>>::iterator itView = this->newviewsPtbft.find(proposeView_MsgNewview);
	if (itView != this->newviewsPtbft.end())
	{
		std::set<MsgNewviewPtbft> msgNewviews = itView->second;
		if (!msgNewviewPtbftFrom(msgNewviews, signers))
		{
			msgNewviews.insert(msgNewview);
			this->newviewsPtbft[proposeView_MsgNewview] = msgNewviews;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: " << msgNewviews.size() << COLOUR_NORMAL << std::endl;
			}
			return msgNewviews.size();
		}
	}
	else
	{
		std::set<MsgNewviewPtbft> msgNewviews = {msgNewview};
		this->newviewsPtbft[proposeView_MsgNewview] = msgNewviews;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgNewview in view " << proposeView_MsgNewview << " and the number of MsgNewview is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgLdrpreparePtbftFrom(std::set<MsgLdrpreparePtbft> msgLdrprepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgLdrpreparePtbft>::iterator itMsg = msgLdrprepares.begin(); itMsg != msgLdrprepares.end(); itMsg++)
	{
		MsgLdrpreparePtbft msgLdrprepare = *itMsg;
		std::set<ReplicaID> allSigners = msgLdrprepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare)
{
	Accumulator accumulator_MsgLdrprepare = msgLdrprepare.proposal.getCertification();
	View proposeView_MsgLdrprepare = accumulator_MsgLdrprepare.getProposeView();
	std::set<ReplicaID> signers = msgLdrprepare.signs.getSigners();

	std::map<View, std::set<MsgLdrpreparePtbft>>::iterator itView = this->ldrpreparesPtbft.find(proposeView_MsgLdrprepare);
	if (itView != this->ldrpreparesPtbft.end())
	{
		std::set<MsgLdrpreparePtbft> msgLdrprepares = itView->second;
		if (!msgLdrpreparePtbftFrom(msgLdrprepares, signers))
		{
			msgLdrprepares.insert(msgLdrprepare);
			this->ldrpreparesPtbft[proposeView_MsgLdrprepare] = msgLdrprepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: " << msgLdrprepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgLdrprepares.size();
		}
	}
	else
	{
		std::set<MsgLdrpreparePtbft> msgLdrprepares = {msgLdrprepare};
		this->ldrpreparesPtbft[proposeView_MsgLdrprepare] = msgLdrprepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgLdrprepare in view " << proposeView_MsgLdrprepare << " and the number of MsgLdrprepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPreparePtbftFrom(std::set<MsgPreparePtbft> msgPrepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgPreparePtbft>::iterator itMsg = msgPrepares.begin(); itMsg != msgPrepares.end(); itMsg++)
	{
		MsgPreparePtbft msgPrepare = *itMsg;
		std::set<ReplicaID> allSigners = msgPrepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPreparePtbft(MsgPreparePtbft msgPrepare)
{
	RoundData roundData_MsgPrepare = msgPrepare.roundData;
	View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
	std::set<ReplicaID> signers = msgPrepare.signs.getSigners();

	std::map<View, std::set<MsgPreparePtbft>>::iterator itView = this->preparesPtbft.find(proposeView_MsgPrepare);
	if (itView != this->preparesPtbft.end())
	{
		std::set<MsgPreparePtbft> msgPrepares = itView->second;
		if (!msgPreparePtbftFrom(msgPrepares, signers))
		{
			msgPrepares.insert(msgPrepare);
			this->preparesPtbft[proposeView_MsgPrepare] = msgPrepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: " << msgPrepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrepares.size();
		}
	}
	else
	{
		std::set<MsgPreparePtbft> msgPrepares = {msgPrepare};
		this->preparesPtbft[proposeView_MsgPrepare] = msgPrepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrepare in view " << proposeView_MsgPrepare << " and the number of MsgPrepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgPrecommitPtbftFrom(std::set<MsgPrecommitPtbft> msgPrecommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgPrecommitPtbft>::iterator itMsg = msgPrecommits.begin(); itMsg != msgPrecommits.end(); itMsg++)
	{
		MsgPrecommitPtbft msgPrecommit = *itMsg;
		std::set<ReplicaID> allSigners = msgPrecommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigners = allSigners.begin(); itSigners != allSigners.end(); itSigners++)
		{
			signers.erase(*itSigners);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit)
{
	RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
	View proposeView_MsgPrecommit = roundData_MsgPrecommit.getProposeView();
	std::set<ReplicaID> signers = msgPrecommit.signs.getSigners();

	std::map<View, std::set<MsgPrecommitPtbft>>::iterator itView = this->precommitsPtbft.find(proposeView_MsgPrecommit);
	if (itView != this->precommitsPtbft.end())
	{
		std::set<MsgPrecommitPtbft> msgPrecommits = itView->second;
		if (!msgPrecommitPtbftFrom(msgPrecommits, signers))
		{
			msgPrecommits.insert(msgPrecommit);
			this->precommitsPtbft[proposeView_MsgPrecommit] = msgPrecommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: " << msgPrecommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgPrecommits.size();
		}
	}
	else
	{
		std::set<MsgPrecommitPtbft> msgPrecommits = {msgPrecommit};
		this->precommitsPtbft[proposeView_MsgPrecommit] = {msgPrecommit};
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgPrecommit in view " << proposeView_MsgPrecommit << " and the number of MsgPrecommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgExnewviewPtbftFrom(std::set<MsgExnewviewPtbft> msgExnewviews, std::set<ReplicaID> signers)
{
	for (std::set<MsgExnewviewPtbft>::iterator itMsg = msgExnewviews.begin(); itMsg != msgExnewviews.end(); itMsg++)
	{
		MsgExnewviewPtbft msgExnewview = *itMsg;
		std::set<ReplicaID> allSigners = msgExnewview.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview)
{
	RoundData roundData_MsgExnewview = msgExnewview.roundData;
	View proposeView_MsgExnewview = roundData_MsgExnewview.getProposeView();
	std::set<ReplicaID> signers = msgExnewview.signs.getSigners();
	std::map<View, std::set<MsgExnewviewPtbft>>::iterator itView = this->exnewviewsPtbft.find(proposeView_MsgExnewview);
	if (itView != this->exnewviewsPtbft.end())
	{
		std::set<MsgExnewviewPtbft> msgExnewviews = itView->second;
		if (!msgExnewviewPtbftFrom(msgExnewviews, signers))
		{
			msgExnewviews.insert(msgExnewview);
			this->exnewviewsPtbft[proposeView_MsgExnewview] = msgExnewviews;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgExnewview in view " << proposeView_MsgExnewview << " and the number of MsgExnewview is: " << msgExnewviews.size() << COLOUR_NORMAL << std::endl;
			}
			return msgExnewviews.size();
		}
	}
	else
	{
		std::set<MsgExnewviewPtbft> msgExnewviews = {msgExnewview};
		this->exnewviewsPtbft[proposeView_MsgExnewview] = msgExnewviews;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgExnewview in view " << proposeView_MsgExnewview << " and the number of MsgExnewview is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgExldrpreparePtbftFrom(std::set<MsgExldrpreparePtbft> msgExldrprepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgExldrpreparePtbft>::iterator itMsg = msgExldrprepares.begin(); itMsg != msgExldrprepares.end(); itMsg++)
	{
		MsgExldrpreparePtbft msgExldrprepare = *itMsg;
		std::set<ReplicaID> allSigners = msgExldrprepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare)
{
	Proposal<Justification> proposal_MsgExldrprepare = msgExldrprepare.proposal;
	View proposeView_MsgExldrprepare = proposal_MsgExldrprepare.getCertification().getRoundData().getProposeView();
	std::set<ReplicaID> signers = msgExldrprepare.signs.getSigners();
	std::map<View, std::set<MsgExldrpreparePtbft>>::iterator itView = this->exldrpreparesPtbft.find(proposeView_MsgExldrprepare);
	if (itView != this->exldrpreparesPtbft.end())
	{
		std::set<MsgExldrpreparePtbft> msgExldrprepares = itView->second;
		if (!msgExldrpreparePtbftFrom(msgExldrprepares, signers))
		{
			msgExldrprepares.insert(msgExldrprepare);
			this->exldrpreparesPtbft[proposeView_MsgExldrprepare] = msgExldrprepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgExldrprepare in view " << proposeView_MsgExldrprepare << " and the number of MsgExldrprepare is: " << msgExldrprepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgExldrprepares.size();
		}
	}
	else
	{
		std::set<MsgExldrpreparePtbft> msgExldrprepares = {msgExldrprepare};
		this->exldrpreparesPtbft[proposeView_MsgExldrprepare] = msgExldrprepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgExldrprepare in view " << proposeView_MsgExldrprepare << " and the number of MsgExldrprepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgExpreparePtbftFrom(std::set<MsgExpreparePtbft> msgExprepares, std::set<ReplicaID> signers)
{
	for (std::set<MsgExpreparePtbft>::iterator itMsg = msgExprepares.begin(); itMsg != msgExprepares.end(); itMsg++)
	{
		MsgExpreparePtbft msgExprepare = *itMsg;
		std::set<ReplicaID> allSigners = msgExprepare.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgExpreparePtbft(MsgExpreparePtbft msgExprepare)
{
	RoundData roundData_MsgExprepare = msgExprepare.roundData;
	View proposeView_MsgExprepare = roundData_MsgExprepare.getProposeView();
	std::set<ReplicaID> signers = msgExprepare.signs.getSigners();
	std::map<View, std::set<MsgExpreparePtbft>>::iterator itView = this->expreparesPtbft.find(proposeView_MsgExprepare);
	if (itView != this->expreparesPtbft.end())
	{
		std::set<MsgExpreparePtbft> msgExprepares = itView->second;
		if (!msgExpreparePtbftFrom(msgExprepares, signers))
		{
			msgExprepares.insert(msgExprepare);
			this->expreparesPtbft[proposeView_MsgExprepare] = msgExprepares;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgExprepare in view " << proposeView_MsgExprepare << " and the number of MsgExprepare is: " << msgExprepares.size() << COLOUR_NORMAL << std::endl;
			}
			return msgExprepares.size();
		}
	}
	else
	{
		std::set<MsgExpreparePtbft> msgExprepares = {msgExprepare};
		this->expreparesPtbft[proposeView_MsgExprepare] = msgExprepares;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgExprepare in view " << proposeView_MsgExprepare << " and the number of MsgExprepare is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgExprecommitPtbftFrom(std::set<MsgExprecommitPtbft> msgExprecommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgExprecommitPtbft>::iterator itMsg = msgExprecommits.begin(); itMsg != msgExprecommits.end(); itMsg++)
	{
		MsgExprecommitPtbft msgExprecommit = *itMsg;
		std::set<ReplicaID> allSigners = msgExprecommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit)
{
	RoundData roundData_MsgExprecommit = msgExprecommit.roundData;
	View proposeView_MsgExprecommit = roundData_MsgExprecommit.getProposeView();
	std::set<ReplicaID> signers = msgExprecommit.signs.getSigners();
	std::map<View, std::set<MsgExprecommitPtbft>>::iterator itView = this->exprecommitsPtbft.find(proposeView_MsgExprecommit);
	if (itView != this->exprecommitsPtbft.end())
	{
		std::set<MsgExprecommitPtbft> msgExprecommits = itView->second;
		if (!msgExprecommitPtbftFrom(msgExprecommits, signers))
		{
			msgExprecommits.insert(msgExprecommit);
			this->exprecommitsPtbft[proposeView_MsgExprecommit] = msgExprecommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgExprecommit in view " << proposeView_MsgExprecommit << " and the number of MsgExprecommit is: " << msgExprecommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgExprecommits.size();
		}
	}
	else
	{
		std::set<MsgExprecommitPtbft> msgExprecommits = {msgExprecommit};
		this->exprecommitsPtbft[proposeView_MsgExprecommit] = msgExprecommits;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgExprecommit in view " << proposeView_MsgExprecommit << " and the number of MsgExprecommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

bool msgExcommitPtbftFrom(std::set<MsgExcommitPtbft> msgExcommits, std::set<ReplicaID> signers)
{
	for (std::set<MsgExcommitPtbft>::iterator itMsg = msgExcommits.begin(); itMsg != msgExcommits.end(); itMsg++)
	{
		MsgExcommitPtbft msgExcommit = *itMsg;
		std::set<ReplicaID> allSigners = msgExcommit.signs.getSigners();
		for (std::set<ReplicaID>::iterator itSigner = allSigners.begin(); itSigner != allSigners.end(); itSigner++)
		{
			signers.erase(*itSigner);
			if (signers.empty())
			{
				return true;
			}
		}
	}
	return false;
}

unsigned int Log::storeMsgExcommitPtbft(MsgExcommitPtbft msgExcommit)
{
	RoundData roundData_MsgExcommit = msgExcommit.roundData;
	View proposeView_MsgExcommit = roundData_MsgExcommit.getProposeView();
	std::set<ReplicaID> signers = msgExcommit.signs.getSigners();
	std::map<View, std::set<MsgExcommitPtbft>>::iterator itView = this->excommitsPtbft.find(proposeView_MsgExcommit);
	if (itView != this->excommitsPtbft.end())
	{
		std::set<MsgExcommitPtbft> msgExcommits = itView->second;
		if (!msgExcommitPtbftFrom(msgExcommits, signers))
		{
			msgExcommits.insert(msgExcommit);
			this->excommitsPtbft[proposeView_MsgExcommit] = msgExcommits;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Updated entry for MsgExcommit in view " << proposeView_MsgExcommit << " and the number of MsgExcommit is: " << msgExcommits.size() << COLOUR_NORMAL << std::endl;
			}
			return msgExcommits.size();
		}
	}
	else
	{
		std::set<MsgExcommitPtbft> msgExcommits = {msgExcommit};
		this->excommitsPtbft[proposeView_MsgExcommit] = msgExcommits;
		if (DEBUG_LOG)
		{
			std::cout << COLOUR_GREEN << "No entry for MsgExcommit in view " << proposeView_MsgExcommit << " and the number of MsgExcommit is: 1" << COLOUR_NORMAL << std::endl;
		}
		return 1;
	}
	return 0;
}

std::set<MsgNewviewPtbft> Log::getMsgNewviewPtbft(View view, unsigned int n)
{
	std::set<MsgNewviewPtbft> msgNewview;
	std::map<View, std::set<MsgNewviewPtbft>>::iterator itView = this->newviewsPtbft.find(view);
	if (itView != this->newviewsPtbft.end())
	{
		std::set<MsgNewviewPtbft> msgNewviews = itView->second;
		for (std::set<MsgNewviewPtbft>::iterator itMsg = msgNewviews.begin(); msgNewview.size() < n && itMsg != msgNewviews.end(); itMsg++)
		{
			MsgNewviewPtbft msg = *itMsg;
			msgNewview.insert(msg);
		}
	}
	return msgNewview;
}

Signs Log::getMsgPreparePtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPreparePtbft>>::iterator itView = this->preparesPtbft.find(view);
	if (itView != this->preparesPtbft.end())
	{
		std::set<MsgPreparePtbft> msgPrepares = itView->second;
		for (std::set<MsgPreparePtbft>::iterator itMsg = msgPrepares.begin(); signs.getSize() < n && itMsg != msgPrepares.end(); itMsg++)
		{
			MsgPreparePtbft msgPrepare = *itMsg;
			Signs signs_MsgPrepare = msgPrepare.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrepare, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgPrecommitPtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgPrecommitPtbft>>::iterator itView = this->precommitsPtbft.find(view);
	if (itView != this->precommitsPtbft.end())
	{
		std::set<MsgPrecommitPtbft> msgPrecommits = itView->second;
		for (std::set<MsgPrecommitPtbft>::iterator itMsg = msgPrecommits.begin(); signs.getSize() < n && itMsg != msgPrecommits.end(); itMsg++)
		{
			MsgPrecommitPtbft msgPrecommit = *itMsg;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgPrecommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgExnewviewPtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgExnewviewPtbft>>::iterator itView = this->exnewviewsPtbft.find(view);
	if (itView != this->exnewviewsPtbft.end())
	{
		std::set<MsgExnewviewPtbft> msgExnewviews = itView->second;
		for (std::set<MsgExnewviewPtbft>::iterator itMsg = msgExnewviews.begin(); signs.getSize() < n && itMsg != msgExnewviews.end(); itMsg++)
		{
			MsgExnewviewPtbft msgExnewview = *itMsg;
			Signs signs_MsgExnewview = msgExnewview.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgExnewview, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgExpreparePtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgExpreparePtbft>>::iterator itView = this->expreparesPtbft.find(view);
	if (itView != this->expreparesPtbft.end())
	{
		std::set<MsgExpreparePtbft> msgExprepares = itView->second;
		for (std::set<MsgExpreparePtbft>::iterator itMsg = msgExprepares.begin(); signs.getSize() < n && itMsg != msgExprepares.end(); itMsg++)
		{
			MsgExpreparePtbft msgExprepare = *itMsg;
			Signs signs_MsgExprepare = msgExprepare.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgExprepare, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgExprecommitPtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgExprecommitPtbft>>::iterator itView = this->exprecommitsPtbft.find(view);
	if (itView != this->exprecommitsPtbft.end())
	{
		std::set<MsgExprecommitPtbft> msgExprecommits = itView->second;
		for (std::set<MsgExprecommitPtbft>::iterator itMsg = msgExprecommits.begin(); signs.getSize() < n && itMsg != msgExprecommits.end(); itMsg++)
		{
			MsgExprecommitPtbft msgExprecommit = *itMsg;
			Signs signs_MsgExprecommit = msgExprecommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgExprecommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Signs Log::getMsgExcommitPtbft(View view, unsigned int n)
{
	Signs signs;
	std::map<View, std::set<MsgExcommitPtbft>>::iterator itView = this->excommitsPtbft.find(view);
	if (itView != this->excommitsPtbft.end())
	{
		std::set<MsgExcommitPtbft> msgExcommits = itView->second;
		for (std::set<MsgExcommitPtbft>::iterator itMsg = msgExcommits.begin(); signs.getSize() < n && itMsg != msgExcommits.end(); itMsg++)
		{
			MsgExcommitPtbft msgExcommit = *itMsg;
			Signs signs_MsgExcommit = msgExcommit.signs;
			if (DEBUG_LOG)
			{
				std::cout << COLOUR_GREEN << "Adding signatures: " << signs_MsgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			signs.addUpto(signs_MsgExcommit, n);
		}
	}
	if (DEBUG_LOG)
	{
		std::cout << COLOUR_GREEN << "Log signatures: " << signs.toPrint() << COLOUR_NORMAL << std::endl;
	}
	return signs;
}

Justification Log::findHighestMsgExnewviewPtbft(View view)
{
	std::map<View, std::set<MsgExnewviewPtbft>>::iterator itView = this->exnewviewsPtbft.find(view);
	Justification justification_MsgExnewview = Justification();
	if (itView != this->exnewviewsPtbft.end())
	{
		std::set<MsgExnewviewPtbft> msgExnewviews = itView->second;
		View highView = 0;
		for (std::set<MsgExnewviewPtbft>::iterator itMsg = msgExnewviews.begin(); itMsg != msgExnewviews.end(); itMsg++)
		{
			MsgExnewviewPtbft msgExnewview = *itMsg;
			RoundData roundData_MsgExnewview = msgExnewview.roundData;
			Signs signs_MsgExnewview = msgExnewview.signs;
			View justifyView_MsgExnewview = roundData_MsgExnewview.getJustifyView();
			if (justifyView_MsgExnewview >= highView)
			{
				highView = justifyView_MsgExnewview;
				justification_MsgExnewview = Justification(roundData_MsgExnewview, signs_MsgExnewview);
			}
		}
	}
	return justification_MsgExnewview;
}

MsgLdrpreparePtbft Log::firstMsgLdrpreparePtbft(View view)
{
	std::map<View, std::set<MsgLdrpreparePtbft>>::iterator itView = this->ldrpreparesPtbft.find(view);
	if (itView != this->ldrpreparesPtbft.end())
	{
		std::set<MsgLdrpreparePtbft> msgLdrprepares = itView->second;
		if (msgLdrprepares.size() > 0)
		{
			std::set<MsgLdrpreparePtbft>::iterator itMsg = msgLdrprepares.begin();
			MsgLdrpreparePtbft msgLdrprepare = *itMsg;
			return msgLdrprepare;
		}
	}
	Proposal<Accumulator> proposal;
	Signs signs;
	MsgLdrpreparePtbft msgLdrprepare = MsgLdrpreparePtbft(proposal, signs);
	return msgLdrprepare;
}

Justification Log::firstMsgPreparePtbft(View view)
{
	std::map<View, std::set<MsgPreparePtbft>>::iterator itView = this->preparesPtbft.find(view);
	if (itView != this->preparesPtbft.end())
	{
		std::set<MsgPreparePtbft> msgPrepares = itView->second;
		if (msgPrepares.size() > 0)
		{
			std::set<MsgPreparePtbft>::iterator itMsg = msgPrepares.begin();
			MsgPreparePtbft msgPrepare = *itMsg;
			RoundData roundData_MsgPrepare = msgPrepare.roundData;
			Signs signs_MsgPrepare = msgPrepare.signs;
			Justification justification_MsgPrepare = Justification(roundData_MsgPrepare, signs_MsgPrepare);
			return justification_MsgPrepare;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgPrecommitPtbft(View view)
{
	std::map<View, std::set<MsgPrecommitPtbft>>::iterator itView = this->precommitsPtbft.find(view);
	if (itView != this->precommitsPtbft.end())
	{
		std::set<MsgPrecommitPtbft> msgPrecommits = itView->second;
		if (msgPrecommits.size() > 0)
		{
			std::set<MsgPrecommitPtbft>::iterator itMsg = msgPrecommits.begin();
			MsgPrecommitPtbft msgPrecommit = *itMsg;
			RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
			Signs signs_MsgPrecommit = msgPrecommit.signs;
			Justification justification_MsgPrecommit = Justification(roundData_MsgPrecommit, signs_MsgPrecommit);
			return justification_MsgPrecommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

MsgExldrpreparePtbft Log::firstMsgExldrpreparePtbft(View view)
{
	std::map<View, std::set<MsgExldrpreparePtbft>>::iterator itView = this->exldrpreparesPtbft.find(view);
	if (itView != this->exldrpreparesPtbft.end())
	{
		std::set<MsgExldrpreparePtbft> msgExldrprepares = itView->second;
		if (msgExldrprepares.size() > 0)
		{
			std::set<MsgExldrpreparePtbft>::iterator itMsg = msgExldrprepares.begin();
			MsgExldrpreparePtbft msgExldrprepare = *itMsg;
			return msgExldrprepare;
		}
	}
	Proposal<Justification> proposal;
	Signs signs;
	MsgExldrpreparePtbft msgExldrprepare = MsgExldrpreparePtbft(proposal, signs);
	return msgExldrprepare;
}

Justification Log::firstMsgExpreparePtbft(View view)
{
	std::map<View, std::set<MsgExpreparePtbft>>::iterator itView = this->expreparesPtbft.find(view);
	if (itView != this->expreparesPtbft.end())
	{
		std::set<MsgExpreparePtbft> msgExprepares = itView->second;
		if (msgExprepares.size() > 0)
		{
			std::set<MsgExpreparePtbft>::iterator itMsg = msgExprepares.begin();
			MsgExpreparePtbft msgExprepare = *itMsg;
			RoundData roundData_MsgExprepare = msgExprepare.roundData;
			Signs signs_MsgExprepare = msgExprepare.signs;
			Justification justification_MsgExprepare = Justification(roundData_MsgExprepare, signs_MsgExprepare);
			return justification_MsgExprepare;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgExprecommitPtbft(View view)
{
	std::map<View, std::set<MsgExprecommitPtbft>>::iterator itView = this->exprecommitsPtbft.find(view);
	if (itView != this->exprecommitsPtbft.end())
	{
		std::set<MsgExprecommitPtbft> msgExprecommits = itView->second;
		if (msgExprecommits.size() > 0)
		{
			std::set<MsgExprecommitPtbft>::iterator itMsg = msgExprecommits.begin();
			MsgExprecommitPtbft msgExprecommit = *itMsg;
			RoundData roundData_MsgExprecommit = msgExprecommit.roundData;
			Signs signs_MsgExprecommit = msgExprecommit.signs;
			Justification justification_MsgExprecommit = Justification(roundData_MsgExprecommit, signs_MsgExprecommit);
			return justification_MsgExprecommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

Justification Log::firstMsgExcommitPtbft(View view)
{
	std::map<View, std::set<MsgExcommitPtbft>>::iterator itView = this->excommitsPtbft.find(view);
	if (itView != this->excommitsPtbft.end())
	{
		std::set<MsgExcommitPtbft> msgExcommits = itView->second;
		if (msgExcommits.size() > 0)
		{
			std::set<MsgExcommitPtbft>::iterator itMsg = msgExcommits.begin();
			MsgExcommitPtbft msgExcommit = *itMsg;
			RoundData roundData_MsgExcommit = msgExcommit.roundData;
			Signs signs_MsgExcommit = msgExcommit.signs;
			Justification justification_MsgExcommit = Justification(roundData_MsgExcommit, signs_MsgExcommit);
			return justification_MsgExcommit;
		}
	}
	Justification justification = Justification();
	return justification;
}

std::string Log::toPrint()
{
	std::string text = "";

#if defined(BASIC_HOTSTUFF)
	// MsgNewviewHotstuff
	for (std::map<View, std::set<MsgNewviewHotstuff>>::iterator itView = this->newviewsHotstuff.begin(); itView != this->newviewsHotstuff.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgNewviewHotstuff> msgs = itView->second;
		text += "MsgNewviewHotstuff: View = " + std::to_string(view) + "; The number of MsgNewviewHotstuff is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgLdrprepareHotstuff
	for (std::map<View, std::set<MsgLdrprepareHotstuff>>::iterator itView = this->ldrpreparesHotstuff.begin(); itView != this->ldrpreparesHotstuff.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgLdrprepareHotstuff> msgs = itView->second;
		text += "MsgLdrprepareHotstuff: View = " + std::to_string(view) + "; The number of MsgLdrprepareHotstuff is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPrepareHotstuff
	for (std::map<View, std::set<MsgPrepareHotstuff>>::iterator itView = this->preparesHotstuff.begin(); itView != this->preparesHotstuff.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPrepareHotstuff> msgs = itView->second;
		text += "MsgPrepareHotstuff: View = " + std::to_string(view) + "; The number of MsgPrepareHotstuff is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPrecommitHotstuff
	for (std::map<View, std::set<MsgPrecommitHotstuff>>::iterator itView = this->precommitsHotstuff.begin(); itView != this->precommitsHotstuff.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPrecommitHotstuff> msgs = itView->second;
		text += "MsgPrecommitHotstuff: View = " + std::to_string(view) + "; The number of MsgPrecommitHotstuff is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgCommitHotstuff
	for (std::map<View, std::set<MsgCommitHotstuff>>::iterator itView = this->commitsHotstuff.begin(); itView != this->commitsHotstuff.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgCommitHotstuff> msgs = itView->second;
		text += "MsgCommitHotstuff: View = " + std::to_string(view) + "; The number of MsgCommitHotstuff is: " + std::to_string(msgs.size()) + "\n";
	}
#elif defined(BASIC_DAMYSUS)
	// MsgNewviewDamysus
	for (std::map<View, std::set<MsgNewviewDamysus>>::iterator itView = this->newviewsDamysus.begin(); itView != this->newviewsDamysus.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgNewviewDamysus> msgs = itView->second;
		text += "MsgNewviewDamysus: View = " + std::to_string(view) + "; The number of MsgNewviewDamysus is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgLdrprepareDamysus
	for (std::map<View, std::set<MsgLdrprepareDamysus>>::iterator itView = this->ldrpreparesDamysus.begin(); itView != this->ldrpreparesDamysus.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgLdrprepareDamysus> msgs = itView->second;
		text += "MsgLdrprepareDamysus: View = " + std::to_string(view) + "; The number of MsgLdrprepareDamysus is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPrepareDamysus
	for (std::map<View, std::set<MsgPrepareDamysus>>::iterator itView = this->preparesDamysus.begin(); itView != this->preparesDamysus.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPrepareDamysus> msgs = itView->second;
		text += "MsgPrepareDamysus: View = " + std::to_string(view) + "; The number of MsgPrepareDamysus is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPrecommitDamysus
	for (std::map<View, std::set<MsgPrecommitDamysus>>::iterator itView = this->precommitsDamysus.begin(); itView != this->precommitsDamysus.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPrecommitDamysus> msgs = itView->second;
		text += "MsgPrecommitDamysus: View = " + std::to_string(view) + "; The number of MsgPrecommitDamysus is: " + std::to_string(msgs.size()) + "\n";
	}
#elif defined(BASIC_PTBFT)
	// MsgNewviewPtbft
	for (std::map<View, std::set<MsgNewviewPtbft>>::iterator itView = this->newviewsPtbft.begin(); itView != this->newviewsPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgNewviewPtbft> msgs = itView->second;
		text += "MsgNewviewPtbft: View = " + std::to_string(view) + "; The number of MsgNewviewPtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgLdrpreparePtbft
	for (std::map<View, std::set<MsgLdrpreparePtbft>>::iterator itView = this->ldrpreparesPtbft.begin(); itView != this->ldrpreparesPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgLdrpreparePtbft> msgs = itView->second;
		text += "MsgLdrpreparePtbft: View = " + std::to_string(view) + "; The number of MsgLdrpreparePtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPreparePtbft
	for (std::map<View, std::set<MsgPreparePtbft>>::iterator itView = this->preparesPtbft.begin(); itView != this->preparesPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPreparePtbft> msgs = itView->second;
		text += "MsgPreparePtbft: View = " + std::to_string(view) + "; The number of MsgPreparePtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgPrecommitPtbft
	for (std::map<View, std::set<MsgPrecommitPtbft>>::iterator itView = this->precommitsPtbft.begin(); itView != this->precommitsPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgPrecommitPtbft> msgs = itView->second;
		text += "MsgPrecommitPtbft: View = " + std::to_string(view) + "; The number of MsgPrecommitPtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgExnewviewPtbft
	for (std::map<View, std::set<MsgExnewviewPtbft>>::iterator itView = this->exnewviewsPtbft.begin(); itView != this->exnewviewsPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgExnewviewPtbft> msgs = itView->second;
		text += "MsgExnewviewPtbft: View = " + std::to_string(view) + "; The number of MsgExnewviewPtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgExldrpreparePtbft
	for (std::map<View, std::set<MsgExldrpreparePtbft>>::iterator itView = this->exldrpreparesPtbft.begin(); itView != this->exldrpreparesPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgExldrpreparePtbft> msgs = itView->second;
		text += "MsgExldrpreparePtbft: View = " + std::to_string(view) + "; The number of MsgExldrpreparePtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgExpreparePtbft
	for (std::map<View, std::set<MsgExpreparePtbft>>::iterator itView = this->expreparesPtbft.begin(); itView != this->expreparesPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgExpreparePtbft> msgs = itView->second;
		text += "MsgExpreparePtbft: View = " + std::to_string(view) + "; The number of MsgExpreparePtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgExprecommitPtbft
	for (std::map<View, std::set<MsgExprecommitPtbft>>::iterator itView = this->exprecommitsPtbft.begin(); itView != this->exprecommitsPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgExprecommitPtbft> msgs = itView->second;
		text += "MsgExprecommitPtbft: View = " + std::to_string(view) + "; The number of MsgExprecommitPtbft is: " + std::to_string(msgs.size()) + "\n";
	}
	// MsgExcommitPtbft
	for (std::map<View, std::set<MsgExcommitPtbft>>::iterator itView = this->excommitsPtbft.begin(); itView != this->excommitsPtbft.end(); itView++)
	{
		View view = itView->first;
		std::set<MsgExcommitPtbft> msgs = itView->second;
		text += "MsgExcommitPtbft: View = " + std::to_string(view) + "; The number of MsgExcommitPtbft is: " + std::to_string(msgs.size()) + "\n";
	}
#endif

	return text;
}