#ifndef PTBFTBASIC_H
#define PTBFTBASIC_H

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <string>
#include "Hash.h"
#include "Proposal.h"
#include "Justification.h"

class PtbftBasic
{
private:
	Hash prepareHash;				// Hash of the last prepared block
	View prepareView;				// View of [prepareHash]
	Hash preprepareHash;			// Copy of [prepareHash]
	View preprepareView;			// Copy of [prepareView]
	View view;						// Current view
	Phase phase;					// Current phase
	ReplicaID replicaId;			// Unique identifier
	Key privateKey;					// Private key
	unsigned int generalQuorumSize; // General quorum size
	unsigned int trustedQuorumSize; // Trusted quorum size

	void increment();
	void feedback();
	void incrementExtra();
	Sign signText(std::string text);
	Justification updateRoundData(Hash hash1, Hash hash2, View view);
	Justification updateExtraRoundData(Hash hash1, Hash hash2, View view);
	bool verifySigns(Signs signs, ReplicaID replicaId, Nodes nodes, std::string text);

public:
	PtbftBasic();
	PtbftBasic(ReplicaID replicaId, Key privateKey, unsigned int generalQuorumSize, unsigned int trustedQuorumSize);

	bool verifyJustification(Nodes nodes, Justification justification);
	bool verifyProposal(Nodes nodes, Proposal<Accumulator> proposal, Signs signs);
	bool verifyExproposal(Nodes nodes, Proposal<Justification> exproposal, Signs signs);

	Justification initializeMsgNewview();
	Justification respondProposal(Nodes nodes, Hash proposeHash, Accumulator accumulator_MsgLdrprepare);
	void skipRound();
	Justification initializeMsgExnewview();
	Justification respondExproposal(Nodes nodes, Hash proposeHash, Justification justification_MsgExnewview);
	Justification saveMsgExprepare(Nodes nodes, Justification justification_MsgExprepare);
	Justification lockMsgExprecommit(Nodes nodes, Justification justification_MsgExprecommit);
};

#endif
