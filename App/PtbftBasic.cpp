#include "PtbftBasic.h"

void PtbftBasic::increment()
{
	if (this->phase == PHASE_NEWVIEW)
	{
		this->phase = PHASE_PREPARE;
	}
	else if (this->phase == PHASE_PREPARE)
	{
		this->phase = PHASE_PRECOMMIT;
	}
	else if (this->phase == PHASE_PRECOMMIT)
	{
		this->phase = PHASE_COMMIT;
	}
	else if (this->phase == PHASE_COMMIT)
	{
		this->phase = PHASE_NEWVIEW;
		this->view++;
	}
}

void PtbftBasic::feedback()
{
	this->phase = PHASE_EXNEWVIEW;
	this->view--;
}

void PtbftBasic::incrementExtra()
{
	if (this->phase == PHASE_EXNEWVIEW)
	{
		this->phase = PHASE_EXPREPARE;
	}
	else if (this->phase == PHASE_EXPREPARE)
	{
		this->phase = PHASE_EXPRECOMMIT;
	}
	else if (this->phase == PHASE_EXPRECOMMIT)
	{
		this->phase = PHASE_EXCOMMIT;
	}
	else if (this->phase == PHASE_EXCOMMIT)
	{
		this->phase = PHASE_NEWVIEW;
		this->view++;
	}
}

Sign PtbftBasic::signText(std::string text)
{
	Sign sign = Sign(this->privateKey, this->replicaId, text);
	return sign;
}

Justification PtbftBasic::updateRoundData(Hash hash1, Hash hash2, View view)
{
	RoundData roundData = RoundData(hash1, this->view, hash2, view, this->phase);
	Sign sign = this->signText(roundData.toString());
	Justification justification = Justification(roundData, sign);
	this->increment();
	return justification;
}

Justification PtbftBasic::updateExtraRoundData(Hash hash1, Hash hash2, View view)
{
	RoundData roundData = RoundData(hash1, this->view, hash2, view, this->phase);
	Sign sign = this->signText(roundData.toString());
	Justification justification = Justification(roundData, sign);
	this->incrementExtra();
	return justification;
}

bool PtbftBasic::verifySigns(Signs signs, ReplicaID replicaId, Nodes nodes, std::string text)
{
	bool b = signs.verify(replicaId, nodes, text);
	return b;
}

PtbftBasic::PtbftBasic()
{
	this->prepareHash = Hash(true); // The genesis block
	this->prepareView = 0;
	this->preprepareHash = Hash(true); // The genesis block
	this->preprepareView = 0;
	this->view = 0;
	this->phase = PHASE_NEWVIEW;
	this->generalQuorumSize = 0;
	this->trustedQuorumSize = 0;
}

PtbftBasic::PtbftBasic(ReplicaID replicaId, Key privateKey, unsigned int generalQuorumSize, unsigned int trustedQuorumSize)
{
	this->prepareHash = Hash(true); // The genesis block
	this->prepareView = 0;
	this->preprepareHash = Hash(true); // The genesis block
	this->preprepareView = 0;
	this->view = 0;
	this->phase = PHASE_NEWVIEW;
	this->replicaId = replicaId;
	this->privateKey = privateKey;
	this->generalQuorumSize = generalQuorumSize;
	this->trustedQuorumSize = trustedQuorumSize;
}

bool PtbftBasic::verifyJustification(Nodes nodes, Justification justification)
{
	bool b = this->verifySigns(justification.getSigns(), this->replicaId, nodes, justification.getRoundData().toString());
	return b;
}

bool PtbftBasic::verifyProposal(Nodes nodes, Proposal<Accumulator> proposal, Signs signs)
{
	bool b = this->verifySigns(signs, this->replicaId, nodes, proposal.toString());
	return b;
}

bool PtbftBasic::verifyExproposal(Nodes nodes, Proposal<Justification> exproposal, Signs signs)
{
	bool b = this->verifySigns(signs, this->replicaId, nodes, exproposal.toString());
	return b;
}

Justification PtbftBasic::initializeMsgNewview()
{
	Justification justification_MsgNewview = this->updateRoundData(Hash(false), this->prepareHash, this->prepareView);
	return justification_MsgNewview;
}

Justification PtbftBasic::respondProposal(Nodes nodes, Hash proposeHash, Accumulator accumulator_MsgLdrprepare)
{
	View proposeView_MsgLdrprepare = accumulator_MsgLdrprepare.getProposeView();
	Hash prepareHash_MsgLdrprepare = accumulator_MsgLdrprepare.getPrepareHash();
	View prepareView_MsgLdrprepare = accumulator_MsgLdrprepare.getPrepareView();
	unsigned size_MsgLdrprepare = accumulator_MsgLdrprepare.getSize();
	if (this->view == proposeView_MsgLdrprepare && size_MsgLdrprepare == MAX_NUM_SIGNATURES)
	{
		Justification justification_MsgPrepare = this->updateRoundData(proposeHash, prepareHash_MsgLdrprepare, prepareView_MsgLdrprepare);
		RoundData roundData_MsgPrepare = justification_MsgPrepare.getRoundData();
		Hash proposeHash_MsgPrepare = roundData_MsgPrepare.getProposeHash();
		View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
		this->preprepareHash = this->prepareHash;
		this->preprepareView = this->prepareView;
		this->prepareHash = proposeHash_MsgPrepare;
		this->prepareView = proposeView_MsgPrepare;
		return justification_MsgPrepare;
	}
	else
	{
		if (DEBUG_MODULES)
		{
			std::cout << COLOUR_CYAN << this->replicaId << " fail to respond proposal" << COLOUR_NORMAL << std::endl;
		}
		return Justification();
	}
}

void PtbftBasic::skipRound()
{
	this->phase = PHASE_NEWVIEW;
	this->view++;
}

Justification PtbftBasic::initializeMsgExnewview()
{
	this->feedback();
	Justification justification_MsgExnewview = this->updateExtraRoundData(Hash(false), this->preprepareHash, this->preprepareView);
	return justification_MsgExnewview;
}

Justification PtbftBasic::respondExproposal(Nodes nodes, Hash proposeHash, Justification justification_MsgExnewview)
{
	RoundData roundData_MsgExnewview = justification_MsgExnewview.getRoundData();
	View proposeView_MsgExnewview = roundData_MsgExnewview.getProposeView();
	Hash justifyHash_MsgExnewview = roundData_MsgExnewview.getJustifyHash();
	View justifyView_MsgExnewview = roundData_MsgExnewview.getJustifyView();
	Phase phase_MsgExnewview = roundData_MsgExnewview.getPhase();
	if (this->verifyJustification(nodes, justification_MsgExnewview) && this->view == proposeView_MsgExnewview && phase_MsgExnewview == PHASE_EXNEWVIEW)
	{
		Justification justification_MsgExprepare = this->updateExtraRoundData(proposeHash, justifyHash_MsgExnewview, justifyView_MsgExnewview);
		return justification_MsgExprepare;
	}
	else
	{
		if (DEBUG_MODULES)
		{
			std::cout << COLOUR_CYAN << this->replicaId << " fail to respond proposal" << COLOUR_NORMAL << std::endl;
		}
		return Justification();
	}
}

Justification PtbftBasic::saveMsgExprepare(Nodes nodes, Justification justification_MsgExprepare)
{
	RoundData roundData_MsgExprepare = justification_MsgExprepare.getRoundData();
	Hash proposeHash_MsgExprepare = roundData_MsgExprepare.getProposeHash();
	View proposeView_MsgExprepare = roundData_MsgExprepare.getProposeView();
	Phase phase_MsgExprepare = roundData_MsgExprepare.getPhase();
	if (this->verifyJustification(nodes, justification_MsgExprepare) && justification_MsgExprepare.getSigns().getSize() == this->generalQuorumSize && this->view == proposeView_MsgExprepare && phase_MsgExprepare == PHASE_EXPREPARE)
	{
		this->prepareHash = proposeHash_MsgExprepare;
		this->prepareView = proposeView_MsgExprepare;
		Justification justification_MsgExprecommit = this->updateExtraRoundData(proposeHash_MsgExprepare, Hash(), View());
		return justification_MsgExprecommit;
	}
	else
	{
		if (DEBUG_MODULES)
		{
			std::cout << COLOUR_CYAN << this->replicaId << " fail to store in MsgExprepare" << COLOUR_NORMAL << std::endl;
		}
		return Justification();
	}
}

Justification PtbftBasic::lockMsgExprecommit(Nodes nodes, Justification justification_MsgExprecommit)
{
	RoundData roundData_MsgExprecommit = justification_MsgExprecommit.getRoundData();
	Hash proposeHash_MsgExprecommit = roundData_MsgExprecommit.getProposeHash();
	View proposeView_MsgExprecommit = roundData_MsgExprecommit.getProposeView();
	Phase phase_MsgExprecommit = roundData_MsgExprecommit.getPhase();
	if (this->verifyJustification(nodes, justification_MsgExprecommit) && justification_MsgExprecommit.getSigns().getSize() == this->generalQuorumSize && this->view == proposeView_MsgExprecommit && phase_MsgExprecommit == PHASE_EXPRECOMMIT)
	{
		this->prepareHash = proposeHash_MsgExprecommit;
		this->prepareView = proposeView_MsgExprecommit;
		Justification justification_MsgExcommit = this->updateExtraRoundData(proposeHash_MsgExprecommit, Hash(), View());
		return justification_MsgExcommit;
	}
	else
	{
		if (DEBUG_MODULES)
		{
			std::cout << COLOUR_CYAN << this->replicaId << " fail to lock in MsgExprecommit" << COLOUR_NORMAL << std::endl;
		}
		return Justification();
	}
}