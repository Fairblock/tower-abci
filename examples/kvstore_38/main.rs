//! Example ABCI application, an in-memory key-value store.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
    str,
};

use bytes::Bytes;
use futures::future::FutureExt;
use structopt::StructOpt;
use tower::{Service, ServiceBuilder};
use tracing::{info, error};
// use bls12_381::{G1Projective, Scalar};

use tendermint::{
    abci::{
        response::{self},
        Event, EventAttributeIndexExt,
    },
    v0_38::abci::request,
};

use tower_abci::{
    v038::{split, Server},
    BoxError,
};

use tendermint::abci::types::ExecTxResult;
use tendermint::v0_38::abci::{Request, Response};

/// In-memory, hashmap-backed key-value store ABCI application.
#[derive(Clone, Debug, Default)]
pub struct KVStore {
    store: HashMap<String, String>,
    height: u32,
    app_hash: [u8; 8],
}

impl Service<Request> for KVStore {
    type Response = Response;
    type Error = BoxError;
    type Future = Pin<Box<dyn Future<Output = Result<Response, BoxError>> + Send + 'static>>;

    fn poll_ready(&mut self, _cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        Poll::Ready(Ok(()))
    }

    fn call(&mut self, req: Request) -> Self::Future {
        tracing::info!(?req);

        let rsp = match req {
            // handled messages
            Request::Info(_) => Response::Info(self.info()),
            Request::Query(query) => Response::Query(self.query(query.data)),
            Request::PrepareProposal(prepare_prop) => {
                Response::PrepareProposal(self.prepare_proposal(prepare_prop))
            }
            Request::ProcessProposal(proposal) => {
                Response::ProcessProposal(self.process_proposal(proposal))
            }
            Request::ExtendVote(vote) => Response::ExtendVote(self.extend_vote(vote)),
            Request::VerifyVoteExtension(vote) => {
                Response::VerifyVoteExtension(self.verify_vote(vote))
            }
            Request::FinalizeBlock(block) => Response::FinalizeBlock(self.finalize_block(block)),
            Request::Commit => Response::Commit(self.commit()),

            // unhandled messages
            Request::Flush => Response::Flush,
            Request::Echo(_) => Response::Echo(Default::default()),
            Request::InitChain(_) => Response::InitChain(Default::default()),
            Request::CheckTx(_) => Response::CheckTx(Default::default()),
            Request::ListSnapshots => Response::ListSnapshots(Default::default()),
            Request::OfferSnapshot(_) => Response::OfferSnapshot(Default::default()),
            Request::LoadSnapshotChunk(_) => Response::LoadSnapshotChunk(Default::default()),
            Request::ApplySnapshotChunk(_) => Response::ApplySnapshotChunk(Default::default()),
        };
        tracing::info!(?rsp);
        async move { Ok(rsp) }.boxed()
    }
}

impl KVStore {
    fn info(&self) -> response::Info {
        response::Info {
            data: "tower-abci-kvstore-example".to_string(),
            version: "0.1.0".to_string(),
            app_version: 1,
            last_block_height: self.height.into(),
            last_block_app_hash: self.app_hash.to_vec().try_into().unwrap(),
        }
    }

    fn query(&self, query: Bytes) -> response::Query {
        println!("\n\n\n\n Processing query \n\n\n\n");
        let key = String::from_utf8(query.to_vec()).unwrap();
        println!("{}", key);
        let (value, log) = match self.store.get(&key) {
            Some(value) => (value.clone(), "exists".to_string()),
            None => ("".to_string(), "does not exist".to_string()),
        };

        response::Query {
            log,
            key: key.into_bytes().into(),
            value: value.into_bytes().into(),
            ..Default::default()
        }
    }

    fn execute_tx(&mut self, tx: Bytes) -> ExecTxResult {
        let tx = String::from_utf8(tx.to_vec()).unwrap();
        let tx_parts = tx.split('=').collect::<Vec<_>>();
        let (key, value) = match (tx_parts.first(), tx_parts.get(1)) {
            (Some(key), Some(value)) => (*key, *value),
            _ => (tx.as_ref(), tx.as_ref()),
        };
        self.store.insert(key.to_string(), value.to_string());

        ExecTxResult {
            events: vec![Event::new(
                "app",
                vec![
                    ("key", key).index(),
                    ("index_key", "index is working").index(),
                    ("noindex_key", "noindex is working").no_index(),
                ],
            )],
            ..Default::default()
        }
    }

    // Custom prepare_proposal function
    fn prepare_proposal(&self, prepare_prop: request::PrepareProposal) -> response::PrepareProposal {
        // Implement your custom logic here
        info!("Preparing proposal with {} transactions", prepare_prop.txs.len());

        let mut new_tx: Vec<Bytes> = Vec::new();
        let mut aggr_ve = vec![String::new(); 126];


        let last_commit = &prepare_prop.local_last_commit;
        if let Some(extended_info) = last_commit {
            for vote in &extended_info.votes {
                let bytes_vec = vote.vote_extension.to_vec();
                let s = match str::from_utf8(&bytes_vec) {
                    Ok(v) => v,
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
                aggr_ve.push(s.to_string());
            }
        }
        // append ves at the top of the proposal
        new_tx.push(Bytes::from(aggr_ve));

        // Append the original transactions
        new_tx.extend(prepare_prop.txs);

        response::PrepareProposal {
            txs: new_tx,
        }
    }

    fn process_proposal(&mut self, proposal: request::ProcessProposal) -> response::ProcessProposal {
        // Implement your custom logic here
        info!("Processing proposal with {} transactions", proposal.txs.len());

        response::ProcessProposal::Accept
    }

    // Simulated BeginBlock
    fn begin_block(&mut self, block: &request::FinalizeBlock) {
        info!("Begin block");
        // Place any logic here that should happen at the beginning of a block
        let ext = &block.txs[0];
        let ve_bytes = ext.to_vec();
        let aggr_ve = match str::from_utf8(&ve_bytes) {
            Ok(v) => v,
            Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
        };

        let mut key = "aggr_ks_".to_owned();
        let ht = block.height.to_string();
        key.push_str(&ht);
        

        self.store.insert(key, aggr_ve.to_string());
    }

    fn finalize_block(&mut self, block: request::FinalizeBlock) -> response::FinalizeBlock {
        // Simulate BeginBlock
        self.begin_block(&block);
        
        let mut tx_results = Vec::new();
        for tx in block.txs {
            tx_results.push(self.execute_tx(tx));
        }
        response::FinalizeBlock {
            events: vec![Event::new(
                "app",
                vec![("num_tx", format!("{}", tx_results.len())).index()],
            )],
            tx_results,
            validator_updates: vec![],
            consensus_param_updates: None,
            app_hash: self
                .compute_apphash()
                .to_vec()
                .try_into()
                .expect("vec to `AppHash` conversion is actually infaillible."),
        }
    }

    fn commit(&mut self) -> response::Commit {
        let retain_height = self.height.into();
        // As in the other kvstore examples, just use store.len() as the "hash"
        self.app_hash = self.compute_apphash();
        self.height += 1;

        response::Commit {
            // This field is ignored for CometBFT >= 0.38
            data: Bytes::default(),
            retain_height,
        }
    }

    // Extend Vote Function
    fn extend_vote(&self, _vote: request::ExtendVote) -> response::ExtendVote {
        info!("Extending vote");
        response::ExtendVote {
            vote_extension: Bytes::from("VE"),
        }
    }

    // Verify Vote Extension Function
    fn verify_vote(&self, vote: request::VerifyVoteExtension) -> response::VerifyVoteExtension {
        info!("Verifying extended vote");

        // Convert vote_extension from Bytes to String
        if let Ok(vote_extension_str) = str::from_utf8(&vote.vote_extension) {
            // Check if the vote_extension contains the string "VE"
            if vote_extension_str.contains("VE") {
                info!("Vote extension accepted");
                response::VerifyVoteExtension::Accept
            } else {
                info!("Vote extension rejected");
                response::VerifyVoteExtension::Reject  
            }
        } else {
            // If conversion fails, reject the vote
            error!("Failed to convert vote extension to string");
            response::VerifyVoteExtension::Reject
        }
    }

    fn compute_apphash(&self) -> [u8; 8] {
        (self.store.len() as u64).to_be_bytes()
    }
}

#[derive(Debug, StructOpt)]
struct Opt {
    /// Bind the TCP server to this host.
    #[structopt(short, long, default_value = "127.0.0.1")]
    host: String,

    /// Bind the TCP server to this port.
    #[structopt(short, long, default_value = "26658")]
    port: u16,

    /// Bind the UDS server to this path
    #[structopt(long)]
    uds: Option<String>,
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();
    let opt = Opt::from_args();

    // Construct our ABCI application.
    let service = KVStore::default();

    // Split it into components.
    let (consensus, mempool, snapshot, info) = split::service(service, 1);

    // Hand those components to the ABCI server, but customize request behavior
    // for each category -- for instance, apply load-shedding only to mempool
    // and info requests, but not to consensus requests.
    // Note that this example use synchronous execution in `Service::call`, wrapping the end result in a ready future.
    // If `Service::call` did the actual request handling inside the `async` block as well, then the `consensus` service
    // below should be wrapped with a `ServiceBuilder::concurrency_limit` to avoid any unintended reordering of message effects.
    let server_builder = Server::builder()
        .consensus(consensus)
        .snapshot(snapshot)
        .mempool(
            ServiceBuilder::new()
                .load_shed()
                .buffer(10)
                .service(mempool),
        )
        .info(
            ServiceBuilder::new()
                .load_shed()
                .buffer(100)
                .rate_limit(50, std::time::Duration::from_secs(1))
                .service(info),
        );

    let server = server_builder.finish().unwrap();

    if let Some(uds_path) = opt.uds {
        server.listen_unix(uds_path).await.unwrap();
    } else {
        server
            .listen_tcp(format!("{}:{}", opt.host, opt.port))
            .await
            .unwrap();
    }
}


struct ExtractedKey {
    sk: G2Projective,
    index: u32,
}

struct Commitment {
    index: u32,
    commitment: G2Projective,
}

// Assuming HashablePoint trait is defined like this
trait HashablePoint {
    fn hash(&self, id: &[u8]) -> G2Projective;
}

impl HashablePoint for G2Projective {
    fn hash(&self, id: &[u8]) -> G2Projective {
        let mut hasher = Sha256::new();
        hasher.update(id);
        let result = hasher.finalize();

        // Hash to G2 using the result
        G2Projective::hash_to_curve(&result)
    }
}

fn verify_share(suite: &G2Projective, commitment: &Commitment, received_share: &ExtractedKey, qid: &G2Projective) -> bool {
    // Implement the verification logic here
    true // Placeholder
}

fn lagrange_coefficient(index: u32, s: &[u32]) -> Scalar {
    // Implement Lagrange coefficient calculation here
    Scalar::one() // Placeholder
}

fn aggregate(sk_shares: Vec<G2Projective>) -> G2Projective {
    sk_shares.into_iter().reduce(|acc, share| acc + share).unwrap()
}

fn process_sk(suite: &G2Projective, share: &ExtractedKey, s: &[u32]) -> ExtractedKey {
    let lagrange_coef = lagrange_coefficient(share.index, s);
    let identity_key = share.sk * lagrange_coef;
    ExtractedKey {
        sk: identity_key,
        index: share.index,
    }
}

fn aggregate_sk(
    suite: &G2Projective,
    received_shares: Vec<ExtractedKey>,
    commitments: Vec<Commitment>,
    id: &[u8],
) -> (G2Projective, Vec<u32>) {
    let mut sk_shares = vec![];
    let mut invalid = vec![];
    let mut valid = vec![];
    let mut valid_share = vec![];

    for i in 0..received_shares.len() {
        let received_share = &received_shares[i];
        let commitment = &commitments[i];

        let h_g2: &dyn HashablePoint = suite;  // Using the suite as the HashablePoint trait
        let qid = h_g2.hash(id);

        if verify_share(suite, commitment, received_share, &qid) {
            valid.push(received_share.index);
            valid_share.push(received_share.clone());
        } else {
            invalid.push(commitment.index);
        }
    }

    for r in valid_share.iter() {
        let processed_share = process_sk(suite, r, &valid);
        sk_shares.push(processed_share.sk);
    }

    let sk = aggregate(sk_shares);
    (sk, invalid)
}