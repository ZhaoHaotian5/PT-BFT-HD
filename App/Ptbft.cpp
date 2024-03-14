#include "Ptbft.h"

// Local variables
Time startTime = std::chrono::steady_clock::now();
Time startView = std::chrono::steady_clock::now();
Time currentTime;
std::string statisticsValues;
std::string statisticsDone;
Statistics statistics;
PtbftBasic ptbftBasic;
sgx_enclave_id_t global_eid = 0;

// Opcodes
const uint8_t MsgNewviewPtbft::opcode;
const uint8_t MsgLdrpreparePtbft::opcode;
const uint8_t MsgPreparePtbft::opcode;
const uint8_t MsgPrecommitPtbft::opcode;
const uint8_t MsgExnewviewPtbft::opcode;
const uint8_t MsgExldrpreparePtbft::opcode;
const uint8_t MsgExpreparePtbft::opcode;
const uint8_t MsgExprecommitPtbft::opcode;
const uint8_t MsgExcommitPtbft::opcode;
const uint8_t MsgTransaction::opcode;
const uint8_t MsgReply::opcode;
const uint8_t MsgStart::opcode;

// Converts between classes and simpler structures used in enclaves
// Store [transaction] in [transaction_t]
void setTransaction(Transaction transaction, Transaction_t *transaction_t)
{
	transaction_t->clientId = transaction.getClientId();
	transaction_t->transactionId = transaction.getTransactionId();
	memcpy(transaction_t->transactionData, transaction.getTransactionData(), PAYLOAD_SIZE);
}

// Store [hash] in [hash_t]
void setHash(Hash hash, Hash_t *hash_t)
{
	memcpy(hash_t->hash, hash.getHash(), SHA256_DIGEST_LENGTH);
	hash_t->set = hash.getSet();
}

// Load [hash] from [hash_t]
Hash getHash(Hash_t *hash_t)
{
	bool set = hash_t->set;
	unsigned char *hash = hash_t->hash;
	Hash hash_ = Hash(set, hash);
	return hash_;
}

// Store [block] in [block_t]
void setBlock(Block block, Block_t *block_t)
{
	block_t->set = block.getSet();
	setHash(block.getPreviousHash(), &(block_t->previousHash));
	block_t->size = block.getSize();
	for (int i = 0; i < block.getSize(); i++)
	{
		setTransaction(block.get(i), &(block_t->transactions[i]));
	}
}

// Store [roundData] in [roundData_t]
void setRoundData(RoundData roundData, RoundData_t *roundData_t)
{
	setHash(roundData.getProposeHash(), &(roundData_t->proposeHash));
	roundData_t->proposeView = roundData.getProposeView();
	setHash(roundData.getJustifyHash(), &(roundData_t->justifyHash));
	roundData_t->justifyView = roundData.getJustifyView();
	roundData_t->phase = roundData.getPhase();
}

// Load [roundData] from [roundData_t]
RoundData getRoundData(RoundData_t *roundData_t)
{
	Hash proposeHash = getHash(&(roundData_t->proposeHash));
	View proposeView = roundData_t->proposeView;
	Hash justifyHash = getHash(&(roundData_t->justifyHash));
	View justifyView = roundData_t->justifyView;
	Phase phase = roundData_t->phase;
	RoundData roundData = RoundData(proposeHash, proposeView, justifyHash, justifyView, phase);
	return roundData;
}

// Store [sign] in [sign_t]
void setSign(Sign sign, Sign_t *sign_t)
{
	sign_t->set = sign.isSet();
	sign_t->signer = sign.getSigner();
	memcpy(sign_t->signtext, sign.getSigntext(), SIGN_LEN);
}

// Load [sign] from [sign_t]
Sign getSign(Sign_t *sign_t)
{
	bool b = sign_t->set;
	ReplicaID signer = sign_t->signer;
	unsigned char *signtext = sign_t->signtext;
	Sign sign = Sign(b, signer, signtext);
	return sign;
}

// Store [signs] in [signs_t]
void setSigns(Signs signs, Signs_t *signs_t)
{
	signs_t->size = signs.getSize();
	for (int i = 0; i < signs.getSize(); i++)
	{
		setSign(signs.get(i), &(signs_t->signs[i]));
	}
}

// Load [signs] from [signs_t]
Signs getSigns(Signs_t *signs_t)
{
	unsigned int size = signs_t->size;
	Sign signs[MAX_NUM_SIGNATURES];
	for (int i = 0; i < size; i++)
	{
		signs[i] = getSign(&(signs_t->signs[i]));
	}
	Signs signs_ = Signs(size, signs);
	return signs_;
}

// Store [justification] in [justification_t]
void setJustification(Justification justification, Justification_t *justification_t)
{
	justification_t->set = justification.isSet();
	setRoundData(justification.getRoundData(), &(justification_t->roundData));
	setSigns(justification.getSigns(), &(justification_t->signs));
}

// Store [justifications] in [justifications_t]
void setJustifications(Justification justifications[MAX_NUM_SIGNATURES], Justifications_t *justifications_t)
{
	for (int i = 0; i < MAX_NUM_SIGNATURES; i++)
	{
		setJustification(justifications[i], &(justifications_t->justifications[i]));
	}
}

// Load [justification] from [justification_t]
Justification getJustification(Justification_t *justification_t)
{
	bool set = justification_t->set;
	RoundData roundData = getRoundData(&(justification_t->roundData));
	Sign sign[MAX_NUM_SIGNATURES];
	for (int i = 0; i < MAX_NUM_SIGNATURES; i++)
	{
		sign[i] = Sign(justification_t->signs.signs[i].set, justification_t->signs.signs[i].signer, justification_t->signs.signs[i].signtext);
	}
	Signs signs(justification_t->signs.size, sign);
	Justification justification = Justification(set, roundData, signs);
	return justification;
}

// Store [accumulator] in [accumulator_t]
void setAccumulator(Accumulator accumulator, Accumulator_t *accumulator_t)
{
	accumulator_t->set = accumulator.isSet();
	accumulator_t->proposeView = accumulator.getProposeView();
	accumulator_t->prepareHash.set = accumulator.getPrepareHash().getSet();
	memcpy(accumulator_t->prepareHash.hash, accumulator.getPrepareHash().getHash(), SHA256_DIGEST_LENGTH);
	accumulator_t->prepareView = accumulator.getPrepareView();
	accumulator_t->size = accumulator.getSize();
}

// Load [accumulator] from [accumulator_t]
Accumulator getAccumulator(Accumulator_t *accumulator_t)
{
	bool set = accumulator_t->set;
	View proposeView = accumulator_t->proposeView;
	Hash prepareHash = getHash(&(accumulator_t->prepareHash));
	View prepareView = accumulator_t->prepareView;
	unsigned int size = accumulator_t->size;
	Accumulator accumulator = Accumulator(set, proposeView, prepareHash, prepareView, size);
	return accumulator;
}

// Store [proposal] in [proposal_t]
void setProposal(Proposal<Accumulator> proposal, Proposal_t *proposal_t)
{
	setAccumulator(proposal.getCertification(), &(proposal_t->accumulator));
	setBlock(proposal.getBlock(), &(proposal_t->block));
}

// Store [exproposal] in [exproposal_t]
void setExproposal(Proposal<Justification> exproposal, Exproposal_t *exproposal_t)
{
	setJustification(exproposal.getCertification(), &(exproposal_t->justification));
	setBlock(exproposal.getBlock(), &(exproposal_t->block));
}

void TEE_Print(const char *text)
{
	printf("%s\n", text);
}

// Print functions
std::string Ptbft::printReplicaId()
{
	return "[" + std::to_string(this->replicaId) + "-" + std::to_string(this->view) + "]";
}

void Ptbft::printNowTime(std::string msg)
{
	auto now = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(now - startView).count();
	double etime = (statistics.getTotalViewTime().total + time) / (1000 * 1000);
	std::cout << COLOUR_BLUE << this->printReplicaId() << msg << " @ " << etime << COLOUR_NORMAL << std::endl;
}

void Ptbft::printClientInfo()
{
	for (Clients::iterator it = this->clients.begin(); it != this->clients.end(); it++)
	{
		ClientID clientId = it->first;
		ClientInformation clientInfo = it->second;
		bool running = std::get<0>(clientInfo);
		unsigned int received = std::get<1>(clientInfo);
		unsigned int replied = std::get<2>(clientInfo);
		ClientNet::conn_t conn = std::get<3>(clientInfo);
		if (DEBUG_BASIC)
		{
			std::cout << COLOUR_RED
					  << this->printReplicaId() << "CLIENT[id: "
					  << clientId << ", running: "
					  << running << ", numbers of received: "
					  << received << ", numbers of replied: "
					  << replied << "]" << COLOUR_NORMAL << std::endl;
		}
	}
}

std::string Ptbft::recipients2string(Peers recipients)
{
	std::string text = "";
	for (Peers::iterator it = recipients.begin(); it != recipients.end(); it++)
	{
		Peer peer = *it;
		text += std::to_string(std::get<0>(peer)) + " ";
	}
	return text;
}

// Setting functions
unsigned int Ptbft::getLeaderOf(View view)
{
	unsigned int leader = this->view % this->numTrustedReplicas + this->numGeneralReplicas;
	return leader;
}

unsigned int Ptbft::getCurrentLeader()
{
	unsigned int leader = this->getLeaderOf(this->view);
	return leader;
}

bool Ptbft::amLeaderOf(View view)
{
	if (this->replicaId == this->getLeaderOf(view))
	{
		return true;
	}
	else
	{
		return false;
	}
}

bool Ptbft::amCurrentLeader()
{
	if (this->replicaId == this->getCurrentLeader())
	{
		return true;
	}
	else
	{
		return false;
	}
}

std::vector<ReplicaID> Ptbft::getGeneralReplicaIds()
{
	std::vector<ReplicaID> generalNodeIds;
	for (unsigned int i = 0; i < this->numGeneralReplicas; i++)
	{
		generalNodeIds.push_back(i);
	}
	return generalNodeIds;
}

bool Ptbft::amGeneralReplicaIds()
{
	std::vector<ReplicaID> generalNodeIds = this->getGeneralReplicaIds();
	for (std::vector<ReplicaID>::iterator itReplica = generalNodeIds.begin(); itReplica != generalNodeIds.end(); itReplica++)
	{
		ReplicaID replicaId = *itReplica;
		if (this->replicaId == replicaId)
		{
			return true;
		}
	}
	return false;
}

Peers Ptbft::removeFromPeers(ReplicaID replicaId)
{
	Peers peers;
	for (Peers::iterator itPeers = this->peers.begin(); itPeers != this->peers.end(); itPeers++)
	{
		Peer peer = *itPeers;
		if (std::get<0>(peer) != replicaId)
		{
			peers.push_back(peer);
		}
	}
	return peers;
}

Peers Ptbft::removeFromPeers(std::vector<ReplicaID> generalNodeIds)
{
	Peers peers;
	for (Peers::iterator itPeers = this->peers.begin(); itPeers != this->peers.end(); itPeers++)
	{
		Peer peer = *itPeers;
		bool tag = true;
		for (std::vector<ReplicaID>::iterator itReplica = generalNodeIds.begin(); itReplica != generalNodeIds.end(); itReplica++)
		{
			ReplicaID replicaId = *itReplica;
			if (std::get<0>(peer) == replicaId)
			{
				tag = false;
			}
		}
		if (tag)
		{
			peers.push_back(peer);
		}
	}
	return peers;
}

Peers Ptbft::keepFromPeers(ReplicaID replicaId)
{
	Peers peers;
	for (Peers::iterator itPeers = this->peers.begin(); itPeers != this->peers.end(); itPeers++)
	{
		Peer peer = *itPeers;
		if (std::get<0>(peer) == replicaId)
		{
			peers.push_back(peer);
		}
	}
	return peers;
}

std::vector<salticidae::PeerId> Ptbft::getPeerIds(Peers recipients)
{
	std::vector<salticidae::PeerId> returnPeerId;
	for (Peers::iterator it = recipients.begin(); it != recipients.end(); it++)
	{
		Peer peer = *it;
		returnPeerId.push_back(std::get<1>(peer));
	}
	return returnPeerId;
}

void Ptbft::setTimer()
{
	this->timer.del();
	this->timer.add(this->leaderChangeTime);
	this->timerView = this->view;
}

// Reply to clients
void Ptbft::replyTransactions(Transaction *transactions)
{
	for (int i = 0; i < MAX_NUM_TRANSACTIONS; i++)
	{
		Transaction transaction = transactions[i];
		ClientID clientId = transaction.getClientId();
		TransactionID transactionId = transaction.getTransactionId(); // TransactionID 0 is for dummy transactions
		if (transactionId != 0)
		{
			Clients::iterator itClient = this->clients.find(clientId);
			if (itClient != this->clients.end())
			{
				this->executionQueue.enqueue(std::make_pair(transactionId, clientId));
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending reply to " << clientId << ": " << transactionId << COLOUR_NORMAL << std::endl;
				}
			}
			else
			{
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Unknown client: " << clientId << COLOUR_NORMAL << std::endl;
				}
			}
		}
	}
}

void Ptbft::replyHash(Hash hash)
{
	std::map<View, Block>::iterator it = this->blocks.find(this->view);
	if (it != this->blocks.end())
	{
		Block block = it->second;
		if (hash == block.hash())
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Found block for view " << this->view << ": " << block.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->replyTransactions(block.getTransactions());
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Recorded block but incorrect hash for view " << this->view << COLOUR_NORMAL << std::endl;
			}
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Checking hash: " << hash.toString() << COLOUR_NORMAL << std::endl;
			}
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "No block recorded for view " << this->view << COLOUR_NORMAL << std::endl;
		}
	}
}

// Call TEE functions
bool Ptbft::verifyJustificationPtbft(Justification justification)
{
	bool b;
	if (!this->amGeneralReplicaIds())
	{
		Justification_t justification_t;
		setJustification(justification, &justification_t);
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_verifyJustificationPtbft(global_eid, &extra_t, &justification_t, &b);
	}
	else
	{
		b = ptbftBasic.verifyJustification(this->nodes, justification);
	}
	return b;
}

bool Ptbft::verifyProposalPtbft(Proposal<Accumulator> proposal, Signs signs)
{
	bool b;
	if (!this->amGeneralReplicaIds())
	{
		Proposal_t proposal_t;
		setProposal(proposal, &proposal_t);
		Signs_t signs_t;
		setSigns(signs, &signs_t);
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_verifyProposalPtbft(global_eid, &extra_t, &proposal_t, &signs_t, &b);
	}
	else
	{
		b = ptbftBasic.verifyProposal(this->nodes, proposal, signs);
	}
	return b;
}

bool Ptbft::verifyExproposalPtbft(Proposal<Justification> exproposal, Signs signs)
{
	bool b;
	if (!this->amGeneralReplicaIds())
	{
		Exproposal_t exproposal_t;
		setExproposal(exproposal, &exproposal_t);
		Signs_t signs_t;
		setSigns(signs, &signs_t);
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_verifyExproposalPtbft(global_eid, &extra_t, &exproposal_t, &signs_t, &b);
	}
	else
	{
		b = ptbftBasic.verifyExproposal(this->nodes, exproposal, signs);
	}
	return b;
}

Justification Ptbft::initializeMsgNewviewPtbft()
{
	Justification justification_MsgNewview = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Justification_t justification_MsgNewview_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_initializeMsgNewviewPtbft(global_eid, &extra_t, &justification_MsgNewview_t);
		justification_MsgNewview = getJustification(&justification_MsgNewview_t);
	}
	else
	{
		justification_MsgNewview = ptbftBasic.initializeMsgNewview();
	}
	return justification_MsgNewview;
}

Accumulator Ptbft::initializeAccumulatorPtbft(Justification justifications_MsgNewview[MAX_NUM_SIGNATURES])
{
	Justifications_t justifications_MsgNewview_t;
	setJustifications(justifications_MsgNewview, &justifications_MsgNewview_t);
	Accumulator_t accumulator_MsgLdrprepare_t;
	sgx_status_t extra_t;
	sgx_status_t status_t;
	status_t = TEE_initializeAccumulatorPtbft(global_eid, &extra_t, &justifications_MsgNewview_t, &accumulator_MsgLdrprepare_t);
	Accumulator accumulator_MsgLdrprepare = getAccumulator(&accumulator_MsgLdrprepare_t);
	return accumulator_MsgLdrprepare;
}

Signs Ptbft::initializeMsgLdrpreparePtbft(Proposal<Accumulator> proposal_MsgLdrprepare)
{
	Proposal_t proposal_MsgLdrprepare_t;
	setProposal(proposal_MsgLdrprepare, &proposal_MsgLdrprepare_t);
	Signs_t signs_MsgLdrprepare_t;
	sgx_status_t extra_t;
	sgx_status_t status_t;
	status_t = TEE_initializeMsgLdrpreparePtbft(global_eid, &extra_t, &proposal_MsgLdrprepare_t, &signs_MsgLdrprepare_t);
	Signs signs_MsgLdrprepare = getSigns(&signs_MsgLdrprepare_t);
	return signs_MsgLdrprepare;
}

Justification Ptbft::respondMsgLdrprepareProposalPtbft(Hash proposeHash, Accumulator accumulator_MsgLdrprepare)
{
	Justification justification_MsgPrepare = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Accumulator_t accumulator_MsgLdrprepare_t;
		setAccumulator(accumulator_MsgLdrprepare, &accumulator_MsgLdrprepare_t);
		Hash_t proposeHash_t;
		setHash(proposeHash, &proposeHash_t);
		Justification_t justification_MsgPrepare_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_respondProposalPtbft(global_eid, &extra_t, &proposeHash_t, &accumulator_MsgLdrprepare_t, &justification_MsgPrepare_t);
		justification_MsgPrepare = getJustification(&justification_MsgPrepare_t);
	}
	else
	{
		justification_MsgPrepare = ptbftBasic.respondProposal(this->nodes, proposeHash, accumulator_MsgLdrprepare);
	}
	return justification_MsgPrepare;
}

Justification Ptbft::saveMsgPreparePtbft(Justification justification_MsgPrepare)
{
	Justification_t justification_MsgPrepare_t;
	setJustification(justification_MsgPrepare, &justification_MsgPrepare_t);
	Justification_t justification_MsgPrecommit_t;
	sgx_status_t extra;
	sgx_status_t status_t;
	status_t = TEE_saveMsgPreparePtbft(global_eid, &extra, &justification_MsgPrepare_t, &justification_MsgPrecommit_t);
	Justification justification_MsgPrecommit = getJustification(&justification_MsgPrecommit_t);
	return justification_MsgPrecommit;
}

void Ptbft::skipRoundPtbft()
{
	ptbftBasic.skipRound();
}

Justification Ptbft::initializeMsgExnewviewPtbft()
{
	Justification justification_MsgExnewview = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Justification_t justification_MsgExnewview_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_initializeMsgExnewviewPtbft(global_eid, &extra_t, &justification_MsgExnewview_t);
		justification_MsgExnewview = getJustification(&justification_MsgExnewview_t);
	}
	else
	{
		justification_MsgExnewview = ptbftBasic.initializeMsgExnewview();
	}
	return justification_MsgExnewview;
}

Justification Ptbft::respondMsgExnewviewProposalPtbft(Hash proposeHash, Justification justification_MsgExnewview)
{
	Hash_t proposeHash_t;
	setHash(proposeHash, &proposeHash_t);
	Justification_t justification_MsgExnewview_t;
	setJustification(justification_MsgExnewview, &justification_MsgExnewview_t);
	Justification_t justification_MsgExprepare_t;
	sgx_status_t extra_t;
	sgx_status_t status_t;
	status_t = TEE_respondExproposalPtbft(global_eid, &extra_t, &proposeHash_t, &justification_MsgExnewview_t, &justification_MsgExprepare_t);
	Justification justification_MsgExprepare = getJustification(&justification_MsgExprepare_t);
	return justification_MsgExprepare;
}

Signs Ptbft::initializeMsgExldrpreparePtbft(Proposal<Justification> proposal_MsgExldrprepare)
{
	Exproposal_t proposal_MsgExldrprepare_t;
	setExproposal(proposal_MsgExldrprepare, &proposal_MsgExldrprepare_t);
	Signs_t signs_MsgExldrprepare_t;
	sgx_status_t extra_t;
	sgx_status_t status_t;
	status_t = TEE_initializeMsgExldrpreparePtbft(global_eid, &extra_t, &proposal_MsgExldrprepare_t, &signs_MsgExldrprepare_t);
	Signs signs_MsgExldrprepare = getSigns(&signs_MsgExldrprepare_t);
	return signs_MsgExldrprepare;
}

Justification Ptbft::respondMsgExldrprepareProposalPtbft(Hash proposeHash, Justification justification_MsgExnewview)
{
	Justification justification_MsgExprepare = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Hash_t proposeHash_t;
		setHash(proposeHash, &proposeHash_t);
		Justification_t justification_MsgExnewview_t;
		setJustification(justification_MsgExnewview, &justification_MsgExnewview_t);
		Justification_t justification_MsgExprepare_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_respondExproposalPtbft(global_eid, &extra_t, &proposeHash_t, &justification_MsgExnewview_t, &justification_MsgExprepare_t);
		justification_MsgExprepare = getJustification(&justification_MsgExprepare_t);
	}
	else
	{
		justification_MsgExprepare = ptbftBasic.respondExproposal(this->nodes, proposeHash, justification_MsgExnewview);
	}
	return justification_MsgExprepare;
}

Justification Ptbft::saveMsgExpreparePtbft(Justification justification_MsgExprepare)
{
	Justification justification_MsgExprecommit = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Justification_t justification_MsgExprepare_t;
		setJustification(justification_MsgExprepare, &justification_MsgExprepare_t);
		Justification_t justification_MsgExprecommit_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_saveMsgExpreparePtbft(global_eid, &extra_t, &justification_MsgExprepare_t, &justification_MsgExprecommit_t);
		justification_MsgExprecommit = getJustification(&justification_MsgExprecommit_t);
	}
	else
	{
		Justification justification_MsgExprecommit = ptbftBasic.saveMsgExprepare(this->nodes, justification_MsgExprepare);
	}
	return justification_MsgExprecommit;
}

Justification Ptbft::lockMsgExprecommitPtbft(Justification justification_MsgExprecommit)
{
	Justification justification_MsgExcommit = Justification();
	if (!this->amGeneralReplicaIds())
	{
		Justification_t justification_MsgExprecommit_t;
		setJustification(justification_MsgExprecommit, &justification_MsgExprecommit_t);
		Justification_t justification_MsgExcommit_t;
		sgx_status_t extra_t;
		sgx_status_t status_t;
		status_t = TEE_lockMsgExprecommitPtbft(global_eid, &extra_t, &justification_MsgExprecommit_t, &justification_MsgExcommit_t);
		justification_MsgExcommit = getJustification(&justification_MsgExcommit_t);
	}
	else
	{
		justification_MsgExcommit = ptbftBasic.lockMsgExprecommit(this->nodes, justification_MsgExprecommit);
	}
	return justification_MsgExcommit;
}

Accumulator Ptbft::initializeAccumulator(std::set<MsgNewviewPtbft> msgNewviews)
{
	Justification justifications_MsgNewview[MAX_NUM_SIGNATURES];
	unsigned int i = 0;
	for (std::set<MsgNewviewPtbft>::iterator it = msgNewviews.begin(); it != msgNewviews.end() && i < MAX_NUM_SIGNATURES; it++, i++)
	{
		MsgNewviewPtbft msgNewview = *it;
		RoundData roundData_MsgNewview = msgNewview.roundData;
		Signs signs_MsgNewview = msgNewview.signs;
		Justification justification_MsgNewview = Justification(roundData_MsgNewview, signs_MsgNewview);
		justifications_MsgNewview[i] = justification_MsgNewview;
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgNewview[" << i << "]: " << msgNewview.toPrint() << COLOUR_NORMAL << std::endl;
		}
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Justification of MsgNewview[" << i << "]: " << justifications_MsgNewview[i].toPrint() << COLOUR_NORMAL << std::endl;
		}
	}

	Accumulator accumulator_MsgLdrprepare;
	accumulator_MsgLdrprepare = this->initializeAccumulatorPtbft(justifications_MsgNewview);
	return accumulator_MsgLdrprepare;
}

// Receive messages
void Ptbft::receiveMsgStartPtbft(MsgStart msgStart, const ClientNet::conn_t &conn)
{
	ClientID clientId = msgStart.clientId;
	if (this->clients.find(clientId) == this->clients.end())
	{
		(this->clients)[clientId] = std::make_tuple(true, 0, 0, conn);
	}
	if (!this->started)
	{
		this->started = true;
		this->getStarted();
	}
}

void Ptbft::receiveMsgTransactionPtbft(MsgTransaction msgTransaction, const ClientNet::conn_t &conn)
{
	this->handleMsgTransaction(msgTransaction);
}

void Ptbft::receiveMsgNewviewPtbft(MsgNewviewPtbft msgNewview, const PeerNet::conn_t &conn)
{
	this->handleMsgNewviewPtbft(msgNewview);
}

void Ptbft::receiveMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare, const PeerNet::conn_t &conn)
{
	this->handleMsgLdrpreparePtbft(msgLdrprepare);
}

void Ptbft::receiveMsgPreparePtbft(MsgPreparePtbft msgPrepare, const PeerNet::conn_t &conn)
{
	this->handleMsgPreparePtbft(msgPrepare);
}

void Ptbft::receiveMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit, const PeerNet::conn_t &conn)
{
	this->handleMsgPrecommitPtbft(msgPrecommit);
}

void Ptbft::receiveMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview, const PeerNet::conn_t &conn)
{
	this->handleMsgExnewviewPtbft(msgExnewview);
}

void Ptbft::receiveMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare, const PeerNet::conn_t &conn)
{
	this->handleMsgExldrpreparePtbft(msgExldrprepare);
}

void Ptbft::receiveMsgExpreparePtbft(MsgExpreparePtbft msgExprepare, const PeerNet::conn_t &conn)
{
	this->handleMsgExpreparePtbft(msgExprepare);
}

void Ptbft::receiveMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit, const PeerNet::conn_t &conn)
{
	this->handleMsgExprecommitPtbft(msgExprecommit);
}

void Ptbft::receiveMsgExcommitPtbft(MsgExcommitPtbft msgExcommit, const PeerNet::conn_t &conn)
{
	this->handleMsgExcommitPtbft(msgExcommit);
}

// Send messages
void Ptbft::sendMsgNewviewPtbft(MsgNewviewPtbft msgNewview, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgNewview.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgNewview, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgNewviewPtbft");
	}
}

void Ptbft::sendMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgLdrprepare.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgLdrprepare, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgLdrpreparePtbft");
	}
}

void Ptbft::sendMsgPreparePtbft(MsgPreparePtbft msgPrepare, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgPrepare.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgPrepare, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgPreparePtbft");
	}
}

void Ptbft::sendMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgPrecommit.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgPrecommit, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgPrecommitPtbft");
	}
}

void Ptbft::sendMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgExnewview.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgExnewview, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgExnewviewPtbft");
	}
}

void Ptbft::sendMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgExldrprepare.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgExldrprepare, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgExldrpreparePtbft");
	}
}

void Ptbft::sendMsgExpreparePtbft(MsgExpreparePtbft msgExprepare, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgExprepare.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgExprepare, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgExpreparePtbft");
	}
}

void Ptbft::sendMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgExprecommit.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgExprecommit, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgExprecommitPtbft");
	}
}

void Ptbft::sendMsgExcommitPtbft(MsgExcommitPtbft msgExcommit, Peers recipients)
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending: " << msgExcommit.toPrint() << " -> " << this->recipients2string(recipients) << COLOUR_NORMAL << std::endl;
	}
	this->peerNet.multicast_msg(msgExcommit, getPeerIds(recipients));
	if (DEBUG_TIME)
	{
		this->printNowTime("Sending MsgExcommitPtbft");
	}
}

// Handle messages
void Ptbft::handleMsgTransaction(MsgTransaction msgTransaction)
{
	std::lock_guard<std::mutex> guard(mutexTransaction);
	auto start = std::chrono::steady_clock::now();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgTransaction: " << msgTransaction.toPrint() << COLOUR_NORMAL << std::endl;
	}

	Transaction transaction = msgTransaction.transaction;
	ClientID clientId = transaction.getClientId();
	Clients::iterator it = this->clients.find(clientId);
	if (it != this->clients.end()) // Found an entry for [clientId]
	{
		ClientInformation clientInformation = it->second;
		bool running = std::get<0>(clientInformation);
		if (running)
		{
			// Got a new transaction from a live client
			if (this->transactions.size() < this->transactions.max_size())
			{
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Pushing transaction: " << transaction.toPrint() << COLOUR_NORMAL << std::endl;
				}
				(this->clients)[clientId] = std::make_tuple(true, std::get<1>(clientInformation) + 1, std::get<2>(clientInformation), std::get<3>(clientInformation));
				this->transactions.push_back(transaction);
			}
			else
			{
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Too many transactions (" << this->transactions.size() << "/" << this->transactions.max_size() << ")" << clientId << COLOUR_NORMAL << std::endl;
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Transaction rejected from stopped client: " << clientId << COLOUR_NORMAL << std::endl;
			}
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Transaction rejected from unknown client: " << clientId << COLOUR_NORMAL << std::endl;
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleEarlierMessagesPtbft()
{
	// Check if there are enough messages to start the next view
	if (this->amCurrentLeader())
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Leader handling earlier messages" << COLOUR_NORMAL << std::endl;
		}
		std::set<MsgNewviewPtbft> msgNewviews = this->log.getMsgNewviewPtbft(this->view, this->generalQuorumSize);
		if (msgNewviews.size() == this->generalQuorumSize)
		{
			this->initiateMsgNewviewPtbft();
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Replica handling earlier messages" << COLOUR_NORMAL << std::endl;
		}
		// Check if the view has already been locked
		Signs signs_MsgPrecommit = this->log.getMsgPrecommitPtbft(this->view, this->trustedQuorumSize);
		if (signs_MsgPrecommit.getSize() == this->trustedQuorumSize)
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Catching up using MsgPrecommit certificate" << COLOUR_NORMAL << std::endl;
			}

			// Skip the prepare phase and pre-commit phase
			this->initializeMsgNewviewPtbft();
			this->initializeMsgNewviewPtbft();

			// Execute the block
			Justification justification_MsgPrecommit = this->log.firstMsgPrecommitPtbft(this->view);
			RoundData roundData_MsgPrecommit = justification_MsgPrecommit.getRoundData();
			Signs signs_MsgPrecommit = justification_MsgPrecommit.getSigns();
			if (signs_MsgPrecommit.getSize() == this->trustedQuorumSize && this->verifyJustificationPtbft(justification_MsgPrecommit))
			{
				this->executeBlockPtbft(roundData_MsgPrecommit);
			}
		}
		else
		{
			Signs signs_MsgPrepare = this->log.getMsgPreparePtbft(this->view, this->trustedQuorumSize);
			if (signs_MsgPrepare.getSize() == this->trustedQuorumSize)
			{
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Catching up using MsgPrepare certificate" << COLOUR_NORMAL << std::endl;
				}
				Justification justification_MsgPrepare = this->log.firstMsgPreparePtbft(this->view);

				// Skip the prepare phase
				this->initializeMsgNewviewPtbft();

				// Store [justification_MsgPrepare]
				this->respondMsgPreparePtbft(justification_MsgPrepare);
			}
			else
			{
				MsgLdrpreparePtbft msgLdrprepare = this->log.firstMsgLdrpreparePtbft(this->view);

				// Check if the proposal has been stored
				if (msgLdrprepare.signs.getSize() == 1)
				{
					if (DEBUG_HELP)
					{
						std::cout << COLOUR_BLUE << this->printReplicaId() << "Catching up using MsgLdrprepare proposal" << COLOUR_NORMAL << std::endl;
					}
					Proposal<Accumulator> proposal = msgLdrprepare.proposal;
					Accumulator accumulator_MsgLdrprepare = proposal.getCertification();
					Block block = proposal.getBlock();
					this->respondMsgLdrpreparePtbft(accumulator_MsgLdrprepare, block);
				}
			}
		}
	}
}

void Ptbft::handleMsgNewviewPtbft(MsgNewviewPtbft msgNewview)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgNewview: " << msgNewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgNewview = msgNewview.roundData;
	Hash proposeHash_MsgNewview = roundData_MsgNewview.getProposeHash();
	View proposeView_MsgNewview = roundData_MsgNewview.getProposeView();
	Phase phase_MsgNewview = roundData_MsgNewview.getPhase();

	if (proposeHash_MsgNewview.isDummy() && proposeView_MsgNewview >= this->view && phase_MsgNewview == PHASE_NEWVIEW)
	{
		if (proposeView_MsgNewview == this->view)
		{
			if (this->log.storeMsgNewviewPtbft(msgNewview) == this->generalQuorumSize)
			{
				this->initiateMsgNewviewPtbft();
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgNewview: " << msgNewview.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgNewviewPtbft(msgNewview);
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Discarded MsgNewview: " << msgNewview.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgLdrprepare: " << msgLdrprepare.toPrint() << COLOUR_NORMAL << std::endl;
	}
	Proposal<Accumulator> proposal_MsgLdrprepare = msgLdrprepare.proposal;
	Signs signs_MsgLdrprepare = msgLdrprepare.signs;
	Accumulator accumulator_MsgLdrprepare = proposal_MsgLdrprepare.getCertification();
	View proposeView_MsgLdrprepare = accumulator_MsgLdrprepare.getProposeView();
	Hash prepareHash_MsgLdrprepare = accumulator_MsgLdrprepare.getPrepareHash();
	Block block = proposal_MsgLdrprepare.getBlock();

	// Verify the [signs_MsgLdrprepare] in [msgLdrprepare]
	if (this->verifyProposalPtbft(proposal_MsgLdrprepare, signs_MsgLdrprepare) && block.extends(prepareHash_MsgLdrprepare) && proposeView_MsgLdrprepare >= this->view)
	{
		if (proposeView_MsgLdrprepare == this->view)
		{
			this->respondMsgLdrpreparePtbft(accumulator_MsgLdrprepare, block);
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgLdrprepare: " << msgLdrprepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgLdrpreparePtbft(msgLdrprepare);
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgPreparePtbft(MsgPreparePtbft msgPrepare)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgPrepare: " << msgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgPrepare = msgPrepare.roundData;
	Signs signs_MsgPrepare = msgPrepare.signs;
	View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
	Phase phase_MsgPrepare = roundData_MsgPrepare.getPhase();
	Justification justification_MsgPrepare = Justification(roundData_MsgPrepare, signs_MsgPrepare);

	if (proposeView_MsgPrepare >= this->view && phase_MsgPrepare == PHASE_PREPARE)
	{
		if (proposeView_MsgPrepare == this->view)
		{
			if (this->amCurrentLeader())
			{
				if (this->log.storeMsgPreparePtbft(msgPrepare) == this->trustedQuorumSize)
				{
					this->initiateMsgPreparePtbft(roundData_MsgPrepare);
				}
			}
			else
			{
				if (signs_MsgPrepare.getSize() == this->trustedQuorumSize)
				{
					this->respondMsgPreparePtbft(justification_MsgPrepare);
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgPrepare: " << msgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgPreparePtbft(msgPrepare);
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgPrecommit: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgPrecommit = msgPrecommit.roundData;
	Signs signs_MsgPrecommit = msgPrecommit.signs;
	View proposeView_MsgPrecommit = roundData_MsgPrecommit.getProposeView();
	Phase phase_MsgPrecommit = roundData_MsgPrecommit.getPhase();
	Justification justification_MsgPrecommit = Justification(roundData_MsgPrecommit, signs_MsgPrecommit);

	if (proposeView_MsgPrecommit >= this->view && phase_MsgPrecommit == PHASE_PRECOMMIT)
	{
		if (proposeView_MsgPrecommit == this->view)
		{
			if (this->amCurrentLeader())
			{
				if (this->log.storeMsgPrecommitPtbft(msgPrecommit) == this->trustedQuorumSize)
				{
					this->initiateMsgPrecommitPtbft(roundData_MsgPrecommit);
				}
			}
			else
			{
				if (signs_MsgPrecommit.getSize() == this->trustedQuorumSize && this->verifyJustificationPtbft(justification_MsgPrecommit))
				{
					if (this->amGeneralReplicaIds())
					{
						this->skipRoundPtbft();
					}
					this->executeBlockPtbft(roundData_MsgPrecommit);
				}
				else
				{
					this->getExtraStarted();
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgPrecommit: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			if (this->amLeaderOf(proposeView_MsgPrecommit))
			{
				this->log.storeMsgPrecommitPtbft(msgPrecommit);
			}
			else
			{
				if (this->verifyJustificationPtbft(justification_MsgPrecommit))
				{
					this->log.storeMsgPrecommitPtbft(msgPrecommit);
				}
			}
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgExnewview: " << msgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgExnewview = msgExnewview.roundData;
	Hash proposeHash_MsgExnewview = roundData_MsgExnewview.getProposeHash();
	View proposeView_MsgExnewview = roundData_MsgExnewview.getProposeView();
	Phase phase_MsgExnewview = roundData_MsgExnewview.getPhase();

	if (proposeHash_MsgExnewview.isDummy() && proposeView_MsgExnewview >= this->view && phase_MsgExnewview == PHASE_EXNEWVIEW)
	{
		if (proposeView_MsgExnewview == this->view)
		{
			if (this->log.storeMsgExnewviewPtbft(msgExnewview) == this->generalQuorumSize)
			{
				this->initiateMsgExnewviewPtbft();
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgExnewview: " << msgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgExnewviewPtbft(msgExnewview);
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Discarded MsgExnewview: " << msgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgExldrprepare: " << msgExldrprepare.toPrint() << COLOUR_NORMAL << std::endl;
	}
	Proposal<Justification> proposal_MsgExldrprepare = msgExldrprepare.proposal;
	Signs signs_MsgExldrprepare = msgExldrprepare.signs;
	Justification justification_MsgExnewview = proposal_MsgExldrprepare.getCertification();
	RoundData roundData_MsgExnewview = justification_MsgExnewview.getRoundData();
	View proposeView_MsgExnewview = roundData_MsgExnewview.getProposeView();
	Hash justifyHash_MsgExnewview = roundData_MsgExnewview.getJustifyHash();
	Block block = proposal_MsgExldrprepare.getBlock();

	// Verify the [signs_MsgExldrprepare] in [msgExldrprepare]
	if (this->verifyExproposalPtbft(proposal_MsgExldrprepare, signs_MsgExldrprepare) && block.extends(justifyHash_MsgExnewview) && proposeView_MsgExnewview >= this->view)
	{
		if (proposeView_MsgExnewview == this->view)
		{
			this->respondMsgExldrpreparePtbft(justification_MsgExnewview, block);
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgExldrprepare: " << msgExldrprepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgExldrpreparePtbft(msgExldrprepare);
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgExpreparePtbft(MsgExpreparePtbft msgExprepare)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgExprepare: " << msgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgExprepare = msgExprepare.roundData;
	Signs signs_MsgExprepare = msgExprepare.signs;
	View proposeView_MsgExprepare = roundData_MsgExprepare.getProposeView();
	Phase phase_MsgExprepare = roundData_MsgExprepare.getPhase();
	Justification justification_MsgExprepare = Justification(roundData_MsgExprepare, signs_MsgExprepare);

	if (proposeView_MsgExprepare >= this->view && phase_MsgExprepare == PHASE_EXPREPARE)
	{
		if (proposeView_MsgExprepare == this->view)
		{
			if (this->amCurrentLeader())
			{
				if (this->log.storeMsgExpreparePtbft(msgExprepare) == this->generalQuorumSize)
				{
					this->initiateMsgExpreparePtbft(roundData_MsgExprepare);
				}
			}
			else
			{
				if (signs_MsgExprepare.getSize() == this->generalQuorumSize)
				{
					this->respondMsgExpreparePtbft(justification_MsgExprepare);
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgExprepare: " << msgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgExpreparePtbft(msgExprepare);
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgExprecommit: " << msgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgExprecommit = msgExprecommit.roundData;
	Signs signs_MsgExprecommit = msgExprecommit.signs;
	View proposeView_MsgExprecommit = roundData_MsgExprecommit.getProposeView();
	Phase phase_MsgExprecommit = roundData_MsgExprecommit.getPhase();
	Justification justification_MsgExprecommit = Justification(roundData_MsgExprecommit, signs_MsgExprecommit);

	if (proposeView_MsgExprecommit >= this->view && phase_MsgExprecommit == PHASE_EXPRECOMMIT)
	{
		if (proposeView_MsgExprecommit == this->view)
		{
			if (this->amCurrentLeader())
			{
				if (this->log.storeMsgExprecommitPtbft(msgExprecommit) == this->generalQuorumSize)
				{
					this->initiateMsgExprecommitPtbft(roundData_MsgExprecommit);
				}
			}
			else
			{
				if (signs_MsgExprecommit.getSize() == this->generalQuorumSize)
				{
					this->respondMsgExprecommitPtbft(justification_MsgExprecommit);
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgExprecommit: " << msgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			this->log.storeMsgExprecommitPtbft(msgExprecommit);
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

void Ptbft::handleMsgExcommitPtbft(MsgExcommitPtbft msgExcommit)
{
	auto start = std::chrono::steady_clock::now();

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgExcommit: " << msgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgExcommit = msgExcommit.roundData;
	Signs signs_MsgExcommit = msgExcommit.signs;
	View proposeView_MsgExcommit = roundData_MsgExcommit.getProposeView();
	Phase phase_MsgExcommit = roundData_MsgExcommit.getPhase();
	Justification justification_MsgExcommit = Justification(roundData_MsgExcommit, signs_MsgExcommit);

	if (proposeView_MsgExcommit >= this->view && phase_MsgExcommit == PHASE_EXCOMMIT)
	{
		if (proposeView_MsgExcommit == this->view)
		{
			if (this->amCurrentLeader())
			{
				if (this->log.storeMsgExcommitPtbft(msgExcommit) == this->generalQuorumSize)
				{
					this->initiateMsgExcommitPtbft(roundData_MsgExcommit);
				}
			}
			else
			{
				if (signs_MsgExcommit.getSize() == this->generalQuorumSize && this->verifyJustificationPtbft(justification_MsgExcommit))
				{
					this->executeBlockPtbft(roundData_MsgExcommit);
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing MsgExcommit: " << msgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
			}
			if (this->amLeaderOf(proposeView_MsgExcommit))
			{
				this->log.storeMsgExcommitPtbft(msgExcommit);
			}
			else
			{
				if (this->verifyJustificationPtbft(justification_MsgExcommit))
				{
					this->log.storeMsgExcommitPtbft(msgExcommit);
				}
			}
		}
	}

	auto end = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
	statistics.addHandleTime(time);
}

// Initiate messages
void Ptbft::initiateMsgNewviewPtbft()
{
	std::set<MsgNewviewPtbft> msgNewviews = this->log.getMsgNewviewPtbft(this->view, this->generalQuorumSize);
	if (msgNewviews.size() == this->generalQuorumSize)
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Handling MsgNewview to accumulator" << COLOUR_NORMAL << std::endl;
		}
		Accumulator accumulator_MsgLdrprepare = this->initializeAccumulator(msgNewviews);

		if (accumulator_MsgLdrprepare.isSet())
		{
			// Create [block] extends the highest prepared block
			Hash prepareHash_MsgLdrprepare = accumulator_MsgLdrprepare.getPrepareHash();
			Block block = this->createNewBlockPtbft(prepareHash_MsgLdrprepare);

			// Create [justification_MsgPrepare] for that [block]
			Justification justification_MsgPrepare = this->respondMsgLdrprepareProposalPtbft(block.hash(), accumulator_MsgLdrprepare);
			if (justification_MsgPrepare.isSet())
			{
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing block for view " << this->view << ": " << block.toPrint() << COLOUR_NORMAL << std::endl;
				}
				this->blocks[this->view] = block;

				// Create [msgLdrprepare] out of [block]
				Proposal<Accumulator> proposal_MsgLdrprepare = Proposal<Accumulator>(accumulator_MsgLdrprepare, block);
				Signs signs_MsgLdrprepare = this->initializeMsgLdrpreparePtbft(proposal_MsgLdrprepare);
				MsgLdrpreparePtbft msgLdrprepare = MsgLdrpreparePtbft(proposal_MsgLdrprepare, signs_MsgLdrprepare);

				// Send [msgLdrprepare] to replicas
				Peers recipients = this->removeFromPeers(this->replicaId);
				this->sendMsgLdrpreparePtbft(msgLdrprepare, recipients);
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgLdrprepare to replicas: " << msgLdrprepare.toPrint() << COLOUR_NORMAL << std::endl;
				}

				// Create [msgPrepare]
				RoundData roundData_MsgPrepare = justification_MsgPrepare.getRoundData();
				Signs signs_MsgPrepare = justification_MsgPrepare.getSigns();
				MsgPreparePtbft msgPrepare = MsgPreparePtbft(roundData_MsgPrepare, signs_MsgPrepare);
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Hold on MsgPrepare to its own: " << msgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
				}

				// Store own [msgPrepare] in the log
				if (this->log.storeMsgPreparePtbft(msgPrepare) == this->trustedQuorumSize)
				{
					this->initiateMsgPreparePtbft(msgPrepare.roundData);
				}
			}
		}
		else
		{
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Bad accumulator for MsgLdrprepare: " << accumulator_MsgLdrprepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
		}
	}
}

void Ptbft::initiateMsgPreparePtbft(RoundData roundData_MsgPrepare)
{
	View proposeView_MsgPrepare = roundData_MsgPrepare.getProposeView();
	Signs signs_MsgPrepare = this->log.getMsgPreparePtbft(proposeView_MsgPrepare, this->trustedQuorumSize);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgPrepare signatures: " << signs_MsgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
	}

	Justification justification_MsgPrepare = Justification(roundData_MsgPrepare, signs_MsgPrepare);
	if (signs_MsgPrepare.getSize() == this->trustedQuorumSize)
	{
		// Create [msgPrepare]
		MsgPreparePtbft msgPrepare = MsgPreparePtbft(roundData_MsgPrepare, signs_MsgPrepare);

		// Send [msgPrepare] to replicas
		Peers recipients = this->removeFromPeers(this->getGeneralReplicaIds());
		this->sendMsgPreparePtbft(msgPrepare, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgPrepare to replicas: " << msgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Create [msgPrecommit]
		Justification justification_MsgPrecommit = this->saveMsgPreparePtbft(justification_MsgPrepare);
		RoundData roundData_MsgPrecommit = justification_MsgPrecommit.getRoundData();
		Signs signs_MsgPrecommit = justification_MsgPrecommit.getSigns();
		MsgPrecommitPtbft msgPrecommit = MsgPrecommitPtbft(roundData_MsgPrecommit, signs_MsgPrecommit);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Hold on MsgPrecommit to its own: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Store own [msgPrecommit] in the log
		if (this->log.storeMsgPrecommitPtbft(msgPrecommit) >= this->trustedQuorumSize)
		{
			this->initiateMsgPrecommitPtbft(justification_MsgPrecommit.getRoundData());
		}
	}
}

void Ptbft::initiateMsgPrecommitPtbft(RoundData roundData_MsgPrecommit)
{
	View proposeView_MsgPrecommit = roundData_MsgPrecommit.getProposeView();
	Signs signs_MsgPrecommit = this->log.getMsgPrecommitPtbft(proposeView_MsgPrecommit, this->trustedQuorumSize);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgPrecommit signatures: " << signs_MsgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}

	if (signs_MsgPrecommit.getSize() == this->trustedQuorumSize)
	{
		// Create [msgPrecommit]
		MsgPrecommitPtbft msgPrecommit = MsgPrecommitPtbft(roundData_MsgPrecommit, signs_MsgPrecommit);

		// Send [msgPrecommit] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgPrecommitPtbft(msgPrecommit, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgPrecommit to replicas: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Execute the block
		this->executeBlockPtbft(roundData_MsgPrecommit);
	}
	else
	{
		// Create [msgPrecommit]
		MsgPrecommitPtbft msgPrecommit = MsgPrecommitPtbft(roundData_MsgPrecommit, signs_MsgPrecommit);

		// Send [msgPrecommit] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgPrecommitPtbft(msgPrecommit, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgPrecommit to replicas: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
		}

		this->getExtraStarted();
	}
}

void Ptbft::initiateMsgExnewviewPtbft()
{
	// Create [block] extends the highest prepared block
	Justification justification_MsgExnewview = this->log.findHighestMsgExnewviewPtbft(this->view);
	RoundData roundData_MsgExnewview = justification_MsgExnewview.getRoundData();
	Hash justifyHash_MsgExnewview = roundData_MsgExnewview.getJustifyHash();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Highest Newview for view " << this->view << ": " << justification_MsgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	Block block = createNewBlockPtbft(justifyHash_MsgExnewview);

	// Create [justification_MsgExprepare] for that [block]
	Justification justification_MsgExprepare = this->respondMsgExnewviewProposalPtbft(block.hash(), justification_MsgExnewview);
	if (justification_MsgExprepare.isSet())
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing block for view " << this->view << ": " << block.toPrint() << COLOUR_NORMAL << std::endl;
		}
		this->blocks[this->view] = block;

		// Create [msgExldrprepare] out of [block]
		Proposal<Justification> proposal_MsgExldrprepare = Proposal<Justification>(justification_MsgExnewview, block);
		Signs signs_MsgExldrprepare = this->initializeMsgExldrpreparePtbft(proposal_MsgExldrprepare);
		MsgExldrpreparePtbft msgExldrprepare = MsgExldrpreparePtbft(proposal_MsgExldrprepare, signs_MsgExldrprepare);

		// Send [msgExldrprepare] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgExldrpreparePtbft(msgExldrprepare, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExldrprepare to replicas: " << msgExldrprepare.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Create [msgExprepare]
		RoundData roundData_MsgExprepare = justification_MsgExprepare.getRoundData();
		Signs signs_MsgExprepare = justification_MsgExprepare.getSigns();
		MsgExpreparePtbft msgExprepare = MsgExpreparePtbft(roundData_MsgExprepare, signs_MsgExprepare);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Hold on MsgExprepare to its own: " << msgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Bad justification of MsgExprepare" << justification_MsgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}
}

void Ptbft::initiateMsgExpreparePtbft(RoundData roundData_MsgExprepare)
{
	View proposeView_MsgExprepare = roundData_MsgExprepare.getProposeView();
	Signs signs_MsgExprepare = this->log.getMsgExpreparePtbft(proposeView_MsgExprepare, this->generalQuorumSize);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgExprepare signatures: " << signs_MsgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
	}

	Justification justification_MsgExprepare = Justification(roundData_MsgExprepare, signs_MsgExprepare);
	if (signs_MsgExprepare.getSize() == this->generalQuorumSize)
	{
		// Create [msgExprepare]
		MsgExpreparePtbft msgExprepare = MsgExpreparePtbft(roundData_MsgExprepare, signs_MsgExprepare);

		// Send [msgExprepare] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgExpreparePtbft(msgExprepare, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExprepare to replicas: " << msgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Create [msgExprecommit]
		Justification justification_MsgExprecommit = this->saveMsgExpreparePtbft(justification_MsgExprepare);
		RoundData roundData_MsgExprecommit = justification_MsgExprecommit.getRoundData();
		Signs signs_MsgExprecommit = justification_MsgExprecommit.getSigns();
		MsgExprecommitPtbft msgExprecommit = MsgExprecommitPtbft(roundData_MsgExprecommit, signs_MsgExprecommit);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Hold on MsgExprecommit to its own: " << msgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}
}

void Ptbft::initiateMsgExprecommitPtbft(RoundData roundData_MsgExprecommit)
{
	View proposeView_MsgExprecommit = roundData_MsgExprecommit.getProposeView();
	Signs signs_MsgExprecommit = this->log.getMsgExprecommitPtbft(proposeView_MsgExprecommit, this->generalQuorumSize);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgExprecommit signatures: " << signs_MsgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}

	Justification justification_MsgExprecommit = Justification(roundData_MsgExprecommit, signs_MsgExprecommit);
	if (signs_MsgExprecommit.getSize() == this->generalQuorumSize)
	{
		// Create [msgExprecommit]
		MsgExprecommitPtbft msgExprecommit = MsgExprecommitPtbft(roundData_MsgExprecommit, signs_MsgExprecommit);

		// Send [msgExprecommit] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgExprecommitPtbft(msgExprecommit, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExprecommit to replicas: " << msgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Create [msgExcommit]
		Justification justification_MsgExcommit = this->lockMsgExprecommitPtbft(justification_MsgExprecommit);
		RoundData roundData_MsgExcommit = justification_MsgExcommit.getRoundData();
		Signs signs_MsgExcommit = justification_MsgExcommit.getSigns();
		MsgExcommitPtbft msgExcommit = MsgExcommitPtbft(roundData_MsgExcommit, signs_MsgExcommit);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Hold on MsgExcommit to its own: " << msgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}
}

void Ptbft::initiateMsgExcommitPtbft(RoundData roundData_MsgExcommit)
{
	View proposeView_MsgExcommit = roundData_MsgExcommit.getProposeView();
	Signs signs_MsgExcommit = this->log.getMsgExcommitPtbft(proposeView_MsgExcommit, this->generalQuorumSize);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "MsgExcommit signatures: " << signs_MsgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
	}

	if (signs_MsgExcommit.getSize() == this->generalQuorumSize)
	{
		// Create [msgExcommit]
		MsgExcommitPtbft msgExcommit = MsgExcommitPtbft(roundData_MsgExcommit, signs_MsgExcommit);

		// Send [msgExcommit] to replicas
		Peers recipients = this->removeFromPeers(this->replicaId);
		this->sendMsgExcommitPtbft(msgExcommit, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExcommit to replicas: " << msgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
		}

		// Execute the block
		this->executeBlockPtbft(roundData_MsgExcommit);
	}
}

// Respond messages
void Ptbft::respondMsgLdrpreparePtbft(Accumulator accumulator_MsgLdrprepare, Block block)
{
	// Create own [justification_MsgPrepare] for that [block]
	Justification justification_MsgPrepare = this->respondMsgLdrprepareProposalPtbft(block.hash(), accumulator_MsgLdrprepare);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "justification_MsgPrepare: " << justification_MsgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
	}
	if (justification_MsgPrepare.isSet())
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing block for view " << this->view << ": " << block.toPrint() << COLOUR_NORMAL << std::endl;
		}
		this->blocks[this->view] = block;

		// Create [msgPrepare] out of [block]
		RoundData roundData_MsgPrepare = justification_MsgPrepare.getRoundData();
		Signs signs_MsgPrepare = justification_MsgPrepare.getSigns();
		MsgPreparePtbft msgPrepare = MsgPreparePtbft(justification_MsgPrepare.getRoundData(), justification_MsgPrepare.getSigns());

		// Send [msgPrepare] to leader
		if (!this->amGeneralReplicaIds())
		{
			Peers recipients = this->keepFromPeers(this->getCurrentLeader());
			this->sendMsgPreparePtbft(msgPrepare, recipients);
			if (DEBUG_HELP)
			{
				std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgPrepare to leader: " << msgPrepare.toPrint() << COLOUR_NORMAL << std::endl;
			}
		}
	}
}

void Ptbft::respondMsgPreparePtbft(Justification justification_MsgPrepare)
{
	// Create [justification_MsgPrecommit]
	Justification justification_MsgPrecommit = this->saveMsgPreparePtbft(justification_MsgPrepare);

	// Create [msgPrecommit]
	RoundData roundData_MsgPrecommit = justification_MsgPrecommit.getRoundData();
	Signs signs_MsgPrecommit = justification_MsgPrecommit.getSigns();
	MsgPrecommitPtbft msgPrecommit = MsgPrecommitPtbft(roundData_MsgPrecommit, signs_MsgPrecommit);

	// Send [msgPrecommit] to leader
	Peers recipients = this->keepFromPeers(this->getCurrentLeader());
	this->sendMsgPrecommitPtbft(msgPrecommit, recipients);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgPrecommit to leader: " << msgPrecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
}

void Ptbft::respondMsgExldrpreparePtbft(Justification justification_MsgExnewview, Block block)
{
	// Create own [justification_MsgExprepare] for that [block]
	Justification justification_MsgExprepare = this->respondMsgExldrprepareProposalPtbft(block.hash(), justification_MsgExnewview);
	if (justification_MsgExprepare.isSet())
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Storing block for view " << this->view << ": " << block.toPrint() << COLOUR_NORMAL << std::endl;
		}
		this->blocks[this->view] = block;

		// Create [msgExprepare] out of [block]
		RoundData roundData_MsgExprepare = justification_MsgExprepare.getRoundData();
		Signs signs_MsgExprepare = justification_MsgExprepare.getSigns();
		MsgExpreparePtbft msgExprepare = MsgExpreparePtbft(roundData_MsgExprepare, signs_MsgExprepare);

		// Send [msgExprepare] to leader
		Peers recipients = this->keepFromPeers(this->getCurrentLeader());
		this->sendMsgExpreparePtbft(msgExprepare, recipients);
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExprepare to leader: " << msgExprepare.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}
}

void Ptbft::respondMsgExpreparePtbft(Justification justification_MsgExprepare)
{
	// Create [justification_MsgExprecommit]
	Justification justification_MsgExprecommit = this->saveMsgExpreparePtbft(justification_MsgExprepare);

	// Create [msgExprecommit]
	RoundData roundData_MsgExprecommit = justification_MsgExprecommit.getRoundData();
	Signs signs_MsgExprecommit = justification_MsgExprecommit.getSigns();
	MsgExprecommitPtbft msgExprecommit = MsgExprecommitPtbft(roundData_MsgExprecommit, signs_MsgExprecommit);

	// Send [msgExprecommit] to leader
	Peers recipients = this->keepFromPeers(this->getCurrentLeader());
	this->sendMsgExprecommitPtbft(msgExprecommit, recipients);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExprecommit to leader: " << msgExprecommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
}

void Ptbft::respondMsgExprecommitPtbft(Justification justification_MsgExprecommit)
{
	// Create [justification_MsgExcommit]
	Justification justification_MsgExcommit = this->lockMsgExprecommitPtbft(justification_MsgExprecommit);

	// Create [msgExcommit]
	RoundData roundData_MsgExcommit = justification_MsgExcommit.getRoundData();
	Signs signs_MsgExcommit = justification_MsgExcommit.getSigns();
	MsgExcommitPtbft msgExcommit = MsgExcommitPtbft(roundData_MsgExcommit, signs_MsgExcommit);

	// Send [msgExcommit] to leader
	Peers recipients = this->keepFromPeers(this->getCurrentLeader());
	this->sendMsgExcommitPtbft(msgExcommit, recipients);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExcommit to leader: " << msgExcommit.toPrint() << COLOUR_NORMAL << std::endl;
	}
}

// Main functions
int Ptbft::initializeSGX()
{
	// Initializing enclave
	if (initialize_enclave(&global_eid, "enclave.token", "enclave.signed.so") < 0)
	{
		std::cout << this->printReplicaId() << "Failed to initialize enclave" << std::endl;
		return 1;
	}
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Initialized enclave" << COLOUR_NORMAL << std::endl;
	}

	// Initializing variables
	std::set<ReplicaID> replicaIds = this->nodes.getReplicaIds();
	unsigned int num = replicaIds.size();
	Pids_t others;
	others.num_nodes = num;
	unsigned int i = 0;
	for (std::set<ReplicaID>::iterator it = replicaIds.begin(); it != replicaIds.end(); it++, i++)
	{
		others.pids[i] = *it;
	}

	sgx_status_t extra;
	sgx_status_t status_t;
	status_t = initializeVariables_t(global_eid, &extra, &(this->replicaId), &others, &(this->generalQuorumSize), &(this->trustedQuorumSize));
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Enclave variables are initialized." << COLOUR_NORMAL << std::endl;
	}
	return 0;
}

void Ptbft::getStarted()
{
	if (DEBUG_BASIC)
	{
		std::cout << COLOUR_RED << this->printReplicaId() << "Starting" << COLOUR_NORMAL << std::endl;
	}
	startTime = std::chrono::steady_clock::now();
	startView = std::chrono::steady_clock::now();

	// Send [msgNewview] to the leader of the current view
	ReplicaID leader = this->getCurrentLeader();
	Peers recipients = this->keepFromPeers(leader);

	Justification justification_MsgNewview = this->initializeMsgNewviewPtbft();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Initial justification: " << justification_MsgNewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgNewview = justification_MsgNewview.getRoundData();
	Signs signs_MsgNewview = justification_MsgNewview.getSigns();
	MsgNewviewPtbft msgNewview = MsgNewviewPtbft(roundData_MsgNewview, signs_MsgNewview);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Starting with: " << msgNewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	if (this->amCurrentLeader())
	{
		this->handleMsgNewviewPtbft(msgNewview);
	}
	else
	{
		this->sendMsgNewviewPtbft(msgNewview, recipients);
	}
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgNewview to leader[" << leader << "]" << COLOUR_NORMAL << std::endl;
	}
}

void Ptbft::getExtraStarted()
{
	if (DEBUG_BASIC)
	{
		std::cout << COLOUR_RED << this->printReplicaId() << "Starting extra round" << COLOUR_NORMAL << std::endl;
	}

	// Send [msgExnewview] to the leader of the current view
	ReplicaID leader = this->getCurrentLeader();
	Peers recipients = this->keepFromPeers(leader);

	Justification justification_MsgExnewview = this->initializeMsgExnewviewPtbft();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Initial justification: " << justification_MsgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	RoundData roundData_MsgExnewview = justification_MsgExnewview.getRoundData();
	Signs signs_MsgExnewview = justification_MsgExnewview.getSigns();
	MsgExnewviewPtbft msgExnewview = MsgExnewviewPtbft(roundData_MsgExnewview, signs_MsgExnewview);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Starting with: " << msgExnewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	if (this->amCurrentLeader())
	{
		this->handleMsgExnewviewPtbft(msgExnewview);
	}
	else
	{
		this->sendMsgExnewviewPtbft(msgExnewview, recipients);
	}
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Sent MsgExnewview to leader[" << leader << "]" << COLOUR_NORMAL << std::endl;
	}
}

void Ptbft::startNewViewPtbft()
{
	// Generate [justification_MsgNewview] until one for the next view
	Justification justification_MsgNewview = this->initializeMsgNewviewPtbft();
	View proposeView_MsgNewview = justification_MsgNewview.getRoundData().getProposeView();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Generating justification: " << justification_MsgNewview.toPrint() << COLOUR_NORMAL << std::endl;
	}
	while (proposeView_MsgNewview <= this->view)
	{
		justification_MsgNewview = this->initializeMsgNewviewPtbft();
		proposeView_MsgNewview = justification_MsgNewview.getRoundData().getProposeView();
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Generating justification: " << justification_MsgNewview.toPrint() << COLOUR_NORMAL << std::endl;
		}
	}

	// Increase the view
	this->view++;

	// Start the timer
	this->setTimer();

	RoundData roundData_MsgNewview = justification_MsgNewview.getRoundData();
	Phase phase_MsgNewview = roundData_MsgNewview.getPhase();
	Signs signs_MsgNewview = justification_MsgNewview.getSigns();
	if (proposeView_MsgNewview == this->view && phase_MsgNewview == PHASE_NEWVIEW)
	{
		MsgNewviewPtbft msgNewview = MsgNewviewPtbft(roundData_MsgNewview, signs_MsgNewview);
		if (this->amCurrentLeader())
		{
			this->handleEarlierMessagesPtbft();
			this->handleMsgNewviewPtbft(msgNewview);
		}
		else
		{
			ReplicaID leader = this->getCurrentLeader();
			Peers recipients = this->keepFromPeers(leader);
			this->sendMsgNewviewPtbft(msgNewview, recipients);
			this->handleEarlierMessagesPtbft();
		}
	}
	else
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Failed to start" << COLOUR_NORMAL << std::endl;
		}
	}
}

Block Ptbft::createNewBlockPtbft(Hash hash)
{
	std::lock_guard<std::mutex> guard(mutexTransaction);
	Transaction transaction[MAX_NUM_TRANSACTIONS];
	unsigned int i = 0;

	// We fill the block we have with transactions we have received so far
	while (i < MAX_NUM_TRANSACTIONS && !this->transactions.empty())
	{
		transaction[i] = this->transactions.front();
		this->transactions.pop_front();
		i++;
	}

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Filled block with " << i << " transactions" << COLOUR_NORMAL << std::endl;
	}

	unsigned int size = i;
	// We fill the rest with dummy transactions
	while (i < MAX_NUM_TRANSACTIONS)
	{
		transaction[i] = Transaction();
		i++;
	}
	Block block = Block(hash, size, transaction);
	return block;
}

void Ptbft::executeBlockPtbft(RoundData roundData_MsgPrecommit)
{
	auto endView = std::chrono::steady_clock::now();
	double time = std::chrono::duration_cast<std::chrono::microseconds>(endView - startView).count();
	startView = endView;
	statistics.increaseExecuteViews();
	statistics.addViewTime(time);

	if (this->transactions.empty())
	{
		this->viewsWithoutNewTrans++;
	}
	else
	{
		this->viewsWithoutNewTrans = 0;
	}

	// Execute
	if (DEBUG_BASIC)
	{
		std::cout << COLOUR_RED << this->printReplicaId()
				  << "PTBFT-EXECUTE(" << this->view << "/" << std::to_string(this->numViews - 1) << ":" << time << ") "
				  << statistics.toString() << COLOUR_NORMAL << std::endl;
	}

	this->replyHash(roundData_MsgPrecommit.getProposeHash());
	if (this->timeToStop())
	{
		this->recordStatisticsPtbft();
	}
	else
	{
		this->startNewViewPtbft();
	}
}

bool Ptbft::timeToStop()
{
	bool b = this->numViews > 0 && this->numViews <= this->view + 1;
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE
				  << this->printReplicaId()
				  << "timeToStop = " << b
				  << "; numViews = " << this->numViews
				  << "; viewsWithoutNewTrans = " << this->viewsWithoutNewTrans
				  << "; Transaction sizes = " << this->transactions.size()
				  << COLOUR_NORMAL << std::endl;
	}
	if (DEBUG_HELP)
	{
		if (b)
		{
			std::cout << COLOUR_BLUE
					  << this->printReplicaId()
					  << "numViews = " << this->numViews
					  << "; viewsWithoutNewTrans = " << this->viewsWithoutNewTrans
					  << "; Transaction sizes = " << this->transactions.size()
					  << COLOUR_NORMAL << std::endl;
		}
	}
	return b;
}

void Ptbft::recordStatisticsPtbft()
{
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "DONE - Printing statistics" << COLOUR_NORMAL << std::endl;
	}

	unsigned int quant1 = 0;
	unsigned int quant2 = 10;

	// Throughput
	Times totalView = statistics.getTotalViewTime();
	double kopsView = ((totalView.num) * (MAX_NUM_TRANSACTIONS) * 1.0) / 1000;
	double secsView = totalView.total / (1000 * 1000);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId()
				  << "VIEW| View = " << this->view
				  << "; Kops = " << kopsView
				  << "; Secs = " << secsView
				  << "; num = " << totalView.num
				  << COLOUR_NORMAL << std::endl;
	}
	double throughputView = kopsView / secsView;

	// Handle
	Times totalHandle = statistics.getTotalHandleTime();
	double kopsHandle = ((totalHandle.num) * (MAX_NUM_TRANSACTIONS) * 1.0) / 1000;
	double secsHandle = totalHandle.total / (1000 * 1000);
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId()
				  << "HANDLE| View = " << this->view
				  << "; Kops = " << kopsHandle
				  << "; Secs = " << secsHandle
				  << "; num = " << totalHandle.num
				  << COLOUR_NORMAL << std::endl;
	}

	// Latency
	double latencyView = (totalView.total / totalView.num / 1000); // milli-seconds spent on views

	// Handle
	double handle = (totalHandle.total / 1000); // milli-seconds spent on handling messages

	std::ofstream fileVals(statisticsValues);
	fileVals << std::to_string(throughputView)
			 << " " << std::to_string(latencyView)
			 << " " << std::to_string(handle);
	fileVals.close();

	// Done
	std::ofstream fileDone(statisticsDone);
	fileDone.close();
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Printing DONE file: " << statisticsDone << COLOUR_NORMAL << std::endl;
	}
}

// Constuctor
Ptbft::Ptbft(KeysFunctions keysFunctions, ReplicaID replicaId, unsigned int numGeneralReplicas, unsigned int numTrustedReplicas, unsigned int numReplicas, unsigned int numViews, unsigned int numFaults, double leaderChangeTime, Nodes nodes, Key privateKey, PeerNet::Config peerNetConfig, ClientNet::Config clientNetConfig) : peerNet(peerEventContext, peerNetConfig), clientNet(requestEventContext, clientNetConfig)
{
	this->keysFunction = keysFunctions;
	this->replicaId = replicaId;
	this->numGeneralReplicas = numGeneralReplicas;
	this->numTrustedReplicas = numTrustedReplicas;
	this->numReplicas = numReplicas;
	this->numViews = numViews;
	this->numFaults = numFaults;
	this->leaderChangeTime = leaderChangeTime;
	this->nodes = nodes;
	this->privateKey = privateKey;
	this->generalQuorumSize = this->numReplicas - this->numFaults;
	this->trustedQuorumSize = floor(this->numTrustedReplicas / 2) + 1;
	this->view = 0;

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Starting handler" << COLOUR_NORMAL << std::endl;
	}
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "General quorum size: " << this->generalQuorumSize << COLOUR_NORMAL << std::endl;
	}
	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Trusted quorum size: " << this->trustedQuorumSize << COLOUR_NORMAL << std::endl;
	}

	// Trusted Functions
	if (!this->amGeneralReplicaIds())
	{
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Initializing TEE" << COLOUR_NORMAL << std::endl;
		}
		this->initializeSGX();
		if (DEBUG_HELP)
		{
			std::cout << COLOUR_BLUE << this->printReplicaId() << "Initialized TEE" << COLOUR_NORMAL << std::endl;
		}
	}
	else
	{
		ptbftBasic = PtbftBasic(this->replicaId, this->privateKey, this->generalQuorumSize, this->trustedQuorumSize);
	}

	// Salticidae
	this->requestCall = new salticidae::ThreadCall(this->requestEventContext);

	// The client event context handles replies through [executionQueue]
	this->executionQueue.reg_handler(this->requestEventContext, [this](ExecutionQueue &executionQueue)
									 {
										std::pair<TransactionID,ClientID> transactionPair;
										while (executionQueue.try_dequeue(transactionPair))
										{
											TransactionID transactionId = transactionPair.first;
											ClientID clientId = transactionPair.second;
											Clients::iterator itClient = this->clients.find(clientId);
											if (itClient != this->clients.end())
											{
												ClientInformation clientInformation = itClient->second;
												MsgReply msgReply = MsgReply(transactionId);
												ClientNet::conn_t recipient = std::get<3>(clientInformation);
												if (DEBUG_HELP)
												{
													std::cout << COLOUR_BLUE << this->printReplicaId() << "Sending reply to " << clientId << ": " << msgReply.toPrint() << COLOUR_NORMAL << std::endl;
												}
												try
												{
													this->clientNet.send_msg(msgReply,recipient);
													(this->clients)[clientId]=std::make_tuple(std::get<0>(clientInformation),std::get<1>(clientInformation),std::get<2>(clientInformation)+1,std::get<3>(clientInformation));
												}
												catch(std::exception &error)
												{
													if (DEBUG_HELP)
													{
														std::cout << COLOUR_BLUE << this->printReplicaId() << "Couldn't send reply to " << clientId << ": " << msgReply.toPrint() << "; " << error.what() << COLOUR_NORMAL << std::endl;
													}
												}
											}
											else
											{
												if (DEBUG_HELP)
												{
													std::cout << COLOUR_BLUE << this->printReplicaId() << "Couldn't reply to unknown client: " << clientId << COLOUR_NORMAL << std::endl;
												}
											}
										}
										return false; });

	this->timer = salticidae::TimerEvent(peerEventContext, [this](salticidae::TimerEvent &)
										 {
                                                if (DEBUG_HELP)
												{
													std::cout << COLOUR_BLUE << this->printReplicaId() << "timer ran out" << COLOUR_NORMAL << std::endl;
													this->startNewViewPtbft();
													this->timer.del();
													this->timer.add(this->leaderChangeTime);
												} });

	Host host = "127.0.0.1";
	PortID replicaPort = 8760 + this->replicaId;
	PortID clientPort = 9760 + this->replicaId;

	Node *thisNode = nodes.find(this->replicaId);
	if (thisNode != NULL)
	{
		host = thisNode->getHost();
		replicaPort = thisNode->getReplicaPort();
		clientPort = thisNode->getClientPort();
	}
	else
	{
		std::cout << COLOUR_RED << this->printReplicaId() << "Couldn't find own information among nodes" << COLOUR_NORMAL << std::endl;
	}

	salticidae::NetAddr peerAddress = salticidae::NetAddr(host + ":" + std::to_string(replicaPort));
	this->peerNet.start();
	this->peerNet.listen(peerAddress);

	salticidae::NetAddr clientAddress = salticidae::NetAddr(host + ":" + std::to_string(clientPort));
	this->clientNet.start();
	this->clientNet.listen(clientAddress);

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Connecting..." << COLOUR_NORMAL << std::endl;
	}

	for (size_t j = 0; j < this->numReplicas; j++)
	{
		if (this->replicaId != j)
		{
			Node *otherNode = nodes.find(j);
			if (otherNode != NULL)
			{
				salticidae::NetAddr otherNodeAddress = salticidae::NetAddr(otherNode->getHost() + ":" + std::to_string(otherNode->getReplicaPort()));
				salticidae::PeerId otherPeerId{otherNodeAddress};
				this->peerNet.add_peer(otherPeerId);
				this->peerNet.set_peer_addr(otherPeerId, otherNodeAddress);
				this->peerNet.conn_peer(otherPeerId);
				if (DEBUG_HELP)
				{
					std::cout << COLOUR_BLUE << this->printReplicaId() << "Added peer: " << j << COLOUR_NORMAL << std::endl;
				}
				this->peers.push_back(std::make_pair(j, otherPeerId));
			}
			else
			{
				std::cout << COLOUR_RED << this->printReplicaId() << "Couldn't find " << j << "'s information among nodes" << COLOUR_NORMAL << std::endl;
			}
		}
	}

	this->clientNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgStartPtbft, this, _1, _2));
	this->clientNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgTransactionPtbft, this, _1, _2));

	this->peerNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgNewviewPtbft, this, _1, _2));
	this->peerNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgLdrpreparePtbft, this, _1, _2));
	this->peerNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgPreparePtbft, this, _1, _2));
	this->peerNet.reg_handler(salticidae::generic_bind(&Ptbft::receiveMsgPrecommitPtbft, this, _1, _2));

	// Statistics
	auto timeNow = std::chrono::system_clock::now();
	std::time_t time = std::chrono::system_clock::to_time_t(timeNow);
	struct tm y2k = {0};
	double seconds = difftime(time, mktime(&y2k));
	statisticsValues = "results/vals-" + std::to_string(this->replicaId) + "-" + std::to_string(seconds);
	statisticsDone = "results/done-" + std::to_string(this->replicaId) + "-" + std::to_string(seconds);
	statistics.setReplicaId(this->replicaId);

	auto peerShutDown = [&](int)
	{ peerEventContext.stop(); };
	salticidae::SigEvent peerSigTerm = salticidae::SigEvent(peerEventContext, peerShutDown);
	peerSigTerm.add(SIGTERM);

	auto clientShutDown = [&](int)
	{ requestEventContext.stop(); };
	salticidae::SigEvent clientSigTerm = salticidae::SigEvent(requestEventContext, clientShutDown);
	clientSigTerm.add(SIGTERM);

	requestThread = std::thread([this]()
								{ requestEventContext.dispatch(); });

	if (DEBUG_HELP)
	{
		std::cout << COLOUR_BLUE << this->printReplicaId() << "Dispatching" << COLOUR_NORMAL << std::endl;
	}
	peerEventContext.dispatch();
}