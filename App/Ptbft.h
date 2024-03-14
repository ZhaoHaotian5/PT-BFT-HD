#ifndef PTBFT_H
#define PTBFT_H

#include <fstream>
#include <functional>
#include <iostream>
#include <list>
#include <math.h>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <stdio.h>
#include <stdlib.h>
#include <string>
#include <thread>
#include <unistd.h>
#include <vector>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/pem.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <sys/socket.h>
#include "../Enclave/EnclaveUsertypes.h"
#include "salticidae/event.h"
#include "salticidae/msg.h"
#include "salticidae/network.h"
#include "salticidae/stream.h"
#include "sgx_urts.h"
#include "sgx_utils/sgx_utils.h"
#include "Enclave_u.h"
#include "Nodes.h"
#include "KeysFunctions.h"
#include "Log.h"
#include "Proposal.h"
#include "PtbftBasic.h"
#include "Statistics.h"
#include "Transaction.h"

using std::placeholders::_1;
using std::placeholders::_2;
using Peer = std::tuple<ReplicaID, salticidae::PeerId>;
using Peers = std::vector<Peer>;
using PeerNet = salticidae::PeerNetwork<uint8_t>;
using ClientNet = salticidae::ClientNetwork<uint8_t>;
using ClientInformation = std::tuple<bool, unsigned int, unsigned int, ClientNet::conn_t>; // [bool] is true if the client hasn't stopped, 1st [int] is the number of transactions received from clients, 2nd [int] is the number of transactions replied to
using Clients = std::map<ClientID, ClientInformation>;
using MessageNet = salticidae::MsgNetwork<uint8_t>;
using ExecutionQueue = salticidae::MPSCQueueEventDriven<std::pair<TransactionID, ClientID>>;
using Time = std::chrono::time_point<std::chrono::steady_clock>;

class Ptbft
{
private:
	// Basic settings
	KeysFunctions keysFunction;
	ReplicaID replicaId;
	unsigned int numGeneralReplicas;
	unsigned int numTrustedReplicas;
	unsigned int numReplicas;
	unsigned int numViews;
	unsigned int numFaults;
	double leaderChangeTime;
	Nodes nodes;
	Key privateKey;
	unsigned int generalQuorumSize;
	unsigned int trustedQuorumSize;
	View view;

	// Message handlers
	salticidae::EventContext peerEventContext;	  // Peer event context
	salticidae::EventContext requestEventContext; // Request event context
	Peers peers;
	PeerNet peerNet;
	Clients clients;
	ClientNet clientNet;
	std::thread requestThread;
	salticidae::BoxObj<salticidae::ThreadCall> requestCall;
	salticidae::TimerEvent timer;
	ExecutionQueue executionQueue;

	// State variables
	std::list<Transaction> transactions; // Current transactions waiting to be processed
	std::map<View, Block> blocks;		 // Blocks received in each view
	std::mutex mutexTransaction;
	std::mutex mutexHandle;
	unsigned int viewsWithoutNewTrans = 0;
	bool started = false;
	bool stopped = false;
	View timerView; // View at which the timer was started
	Log log;

	// Print functions
	std::string printReplicaId();
	void printNowTime(std::string msg);
	void printClientInfo();
	std::string recipients2string(Peers recipients);

	// Setting functions
	unsigned int getLeaderOf(View view);
	unsigned int getCurrentLeader();
	bool amLeaderOf(View view);
	bool amCurrentLeader();
	std::vector<ReplicaID> getGeneralReplicaIds();
	bool amGeneralReplicaIds();
	Peers removeFromPeers(ReplicaID replicaId);
	Peers removeFromPeers(std::vector<ReplicaID> generalNodeIds);
	Peers keepFromPeers(ReplicaID replicaId);
	std::vector<salticidae::PeerId> getPeerIds(Peers recipients);
	void setTimer();

	// Reply to clients
	void replyTransactions(Transaction *transactions);
	void replyHash(Hash hash);

	// Call TEE functions
	bool verifyJustificationPtbft(Justification justification);
	bool verifyProposalPtbft(Proposal<Accumulator> proposal, Signs signs);
	bool verifyExproposalPtbft(Proposal<Justification> exproposal, Signs signs);

	Justification initializeMsgNewviewPtbft();
	Accumulator initializeAccumulatorPtbft(Justification justifications_MsgNewview[MAX_NUM_SIGNATURES]);
	Signs initializeMsgLdrpreparePtbft(Proposal<Accumulator> proposal_MsgLdrprepare);
	Justification respondMsgLdrprepareProposalPtbft(Hash proposeHash, Accumulator accumulator_MsgLdrprepare);
	Justification saveMsgPreparePtbft(Justification justification_MsgPrepare);
	void skipRoundPtbft();
	Justification initializeMsgExnewviewPtbft();
	Justification respondMsgExnewviewProposalPtbft(Hash proposeHash, Justification justification_MsgExnewview);
	Signs initializeMsgExldrpreparePtbft(Proposal<Justification> proposal_MsgExldrprepare);
	Justification respondMsgExldrprepareProposalPtbft(Hash proposeHash, Justification justification_MsgExnewview);
	Justification saveMsgExpreparePtbft(Justification justification_MsgExprepare);
	Justification lockMsgExprecommitPtbft(Justification justification_MsgExprecommit);

	Accumulator initializeAccumulator(std::set<MsgNewviewPtbft> msgNewviews);

	// Receive messages
	void receiveMsgStartPtbft(MsgStart msgStart, const ClientNet::conn_t &conn);
	void receiveMsgTransactionPtbft(MsgTransaction msgTransaction, const ClientNet::conn_t &conn);
	void receiveMsgNewviewPtbft(MsgNewviewPtbft msgNewview, const PeerNet::conn_t &conn);
	void receiveMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare, const PeerNet::conn_t &conn);
	void receiveMsgPreparePtbft(MsgPreparePtbft msgPrepare, const PeerNet::conn_t &conn);
	void receiveMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit, const PeerNet::conn_t &conn);
	void receiveMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview, const PeerNet::conn_t &conn);
	void receiveMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare, const PeerNet::conn_t &conn);
	void receiveMsgExpreparePtbft(MsgExpreparePtbft msgExprepare, const PeerNet::conn_t &conn);
	void receiveMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit, const PeerNet::conn_t &conn);
	void receiveMsgExcommitPtbft(MsgExcommitPtbft msgExcommit, const PeerNet::conn_t &conn);

	// Send messages
	void sendMsgNewviewPtbft(MsgNewviewPtbft msgNewview, Peers recipients);
	void sendMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare, Peers recipients);
	void sendMsgPreparePtbft(MsgPreparePtbft msgPrepare, Peers recipients);
	void sendMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit, Peers recipients);
	void sendMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview, Peers recipients);
	void sendMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare, Peers recipients);
	void sendMsgExpreparePtbft(MsgExpreparePtbft msgExprepare, Peers recipients);
	void sendMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit, Peers recipients);
	void sendMsgExcommitPtbft(MsgExcommitPtbft msgExcommit, Peers recipients);

	// Handle messages
	void handleMsgTransaction(MsgTransaction msgTransaction);
	void handleEarlierMessagesPtbft();									   // For replicas to process messages they have already received for in new view
	void handleMsgNewviewPtbft(MsgNewviewPtbft msgNewview);				   // Once the leader has received [msgNewview], it creates [msgLdrprepare] out of the highest prepared block
	void handleMsgLdrpreparePtbft(MsgLdrpreparePtbft msgLdrprepare);	   // Once the replicas have received [msgLdrprepare], it creates [msgPrepare] out of the proposal
	void handleMsgPreparePtbft(MsgPreparePtbft msgPrepare);				   // For both the leader and replicas process [msgPrepare]
	void handleMsgPrecommitPtbft(MsgPrecommitPtbft msgPrecommit);		   // For both the leader and replicas process [msgPrecommit]
	void handleMsgExnewviewPtbft(MsgExnewviewPtbft msgExnewview);		   // Once the leader has received [msgExnewview], it creates [msgExldrprepare] out of the highest prepared block
	void handleMsgExldrpreparePtbft(MsgExldrpreparePtbft msgExldrprepare); // Once the replicas have received [msgExldrprepare], it creates [msgExprepare] out of the proposal
	void handleMsgExpreparePtbft(MsgExpreparePtbft msgExprepare);		   // For both the leader and replicas process [msgExprepare]
	void handleMsgExprecommitPtbft(MsgExprecommitPtbft msgExprecommit);	   // For both the leader and replicas process [msgExprecommit]
	void handleMsgExcommitPtbft(MsgExcommitPtbft msgExcommit);			   // For both the leader and replicas process [msgExcommit]

	// Initiate messages
	void initiateMsgNewviewPtbft();										  // Leader send [msgLdrprepare] to others and hold its own [msgPrepare]
	void initiateMsgPreparePtbft(RoundData roundData_MsgPrepare);		  // Leader send [msgPrepare] to others and hold its own [msgPrecommit]
	void initiateMsgPrecommitPtbft(RoundData roundData_MsgPrecommit);	  // Leader send [msgPrecommit] to others and execute the block
	void initiateMsgExnewviewPtbft();									  // Leader send [msgExldrprepare] to others and hold its own [msgExprepare]
	void initiateMsgExpreparePtbft(RoundData roundData_MsgExprepare);	  // Leader send [msgExprepare] to others and hold its own [msgExprecommit]
	void initiateMsgExprecommitPtbft(RoundData roundData_MsgExprecommit); // Leader send [msgExprecommit] to others and hold its own [msgExcommit]
	void initiateMsgExcommitPtbft(RoundData roundData_MsgExcommit);		  // Leader send [msgExcommit] to others and execute the block

	// Respond messages
	void respondMsgLdrpreparePtbft(Accumulator accumulator_MsgLdrprepare, Block block);		 // Replicas respond to [msgLdrprepare] and send [msgPrepare] to the leader
	void respondMsgPreparePtbft(Justification justification_MsgPrepare);					 // Replicas respond to [msgPrepare] and send [msgPrecommit] to the leader
	void respondMsgExldrpreparePtbft(Justification justification_MsgExnewview, Block block); // Replicas respond to [msgExldrprepare] and send [msgExprepare] to the leader
	void respondMsgExpreparePtbft(Justification justification_MsgExprepare);				 // Replicas respond to [msgExprepare] and send [msgExprecommit] to the leader
	void respondMsgExprecommitPtbft(Justification justification_MsgExprecommit);			 // Replicas respond to [msgExprecommit] and send [msgExcommit] to the leader

	// Main functions
	int initializeSGX();
	void getStarted();
	void getExtraStarted();
	void startNewViewPtbft();
	Block createNewBlockPtbft(Hash hash);
	void executeBlockPtbft(RoundData roundData_MsgPrecommit);
	bool timeToStop();
	void recordStatisticsPtbft();

public:
	Ptbft(KeysFunctions keysFunctions, ReplicaID replicaId, unsigned int numGeneralReplicas, unsigned int numTrustedReplicas, unsigned int numReplicas, unsigned int numViews, unsigned int numFaults, double leaderChangeTime, Nodes nodes, Key privateKey, PeerNet::Config peerNetConfig, ClientNet::Config clientNetConfig);
};

#endif
