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
use tracing::info;
use bls12_381::{pairing, G1Projective, G2Affine, G2Projective, Scalar};
use serde::{Serialize, Deserialize};
use hex::decode;
use group::GroupEncoding;

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
        let mut valid_shares: Vec<ExtractedKey> = Vec::new();

        let mut sk_shares: Vec<G2Projective> = Vec::new();
        let mut sk = G2Projective::identity();

        let last_commit = &prepare_prop.local_last_commit;

        let mut valid_indices: Vec<u64> = Vec::new();
        if let Some(extended_info) = last_commit {
            for vote in &extended_info.votes {
                let bytes_vec = vote.vote_extension.to_vec();

                // Deserialize from JSON bytes
                let deserialized_json: VEdata = serde_json::from_slice(&bytes_vec).unwrap();
                println!("Deserialized from JSON: {:?}", deserialized_json);

                // convert keyshare to bytes from hex
                let keyshare_hex = deserialized_json.data;
                let keyshare_byte = match decode(keyshare_hex) {
                    Ok(bytes) => bytes,
                    Err(_) => todo!(),
                };

                //====================================//
                // aggregate VE data with black magic //
                //====================================//
                
                // Convert `Vec<u8>` to a reference to a fixed-size array
                let mut new_share_point_projective = G2Projective::default();
                if keyshare_byte.len() == 96 {
                    if let Ok(array_ref) = <&[u8; 96]>::try_from(keyshare_byte.as_slice()) {
                        let new_share_point_option = G2Affine::from_compressed(array_ref);
            
                        // Unwrap the CtOption safely
                        if new_share_point_option.is_some().into() {
                            let new_share_point = new_share_point_option.unwrap();
                            new_share_point_projective = G2Projective::from(new_share_point);
            
                            println!("Successfully converted to G2Projective: {:?}", new_share_point_projective);
                        } else {
                            eprintln!("Failed to unmarshal binary key into a valid G2Affine point");
                        }
                    } else {
                        eprintln!("Failed to convert Vec<u8> to &[u8; 96]");
                    }
                } else {
                    eprintln!("Error: The byte key is not exactly 96 bytes long.");
                }


                let new_extracted_key = ExtractedKey {
                    index: deserialized_json.index.into(),
                    sk: new_share_point_projective
                };

                valid_shares.push(new_extracted_key);
                valid_indices.push(deserialized_json.index)
                
            }

            for share in valid_shares {
                let processed_share = process_sk( &share, &valid_indices);
                sk_shares.push(processed_share.sk);
            }

            sk = aggregate(sk_shares);
        }

        let aggr_ks = Bytes::from(sk.to_bytes().as_ref().to_vec());

        // append aggregated keyshare at the top of the proposal
        new_tx.push(aggr_ks);

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
    fn extend_vote(&self, vote: request::ExtendVote) -> response::ExtendVote {
        info!("Extending vote");
        
        // generate keyshare of validator with black magic
        // keyshare = generate_keyshare()

        // get index from validator config

        let vedata = VEdata {
            data: "VE data".to_string(),
            height: vote.height.into(),
            index: 1,
        };
    
        // Serialize to JSON bytes
        let json_bytes = serde_json::to_vec(&vedata).unwrap();
        println!("JSON Bytes: {:?}", json_bytes);

        response::ExtendVote {
            vote_extension: json_bytes.into(),
        }
    }

    // Verify Vote Extension Function
    fn verify_vote(&self, _vote: request::VerifyVoteExtension) -> response::VerifyVoteExtension {
        info!("Verifying extended vote");
        response::VerifyVoteExtension::Accept

        // Skip all verification for now
        // TODO: Add verification
        // // Convert vote_extension from Bytes to String
        // if let Ok(vote_extension_str) = str::from_utf8(&vote.vote_extension) {
        //     // Check if the vote_extension contains the string "VE"
        //     if vote_extension_str.contains("VE") {
        //         info!("Vote extension accepted");
        //         response::VerifyVoteExtension::Accept
        //     } else {
        //         info!("Vote extension rejected");
        //         response::VerifyVoteExtension::Reject  
        //     }
        // } else {
        //     // If conversion fails, reject the vote
        //     error!("Failed to convert vote extension to string");
        //     response::VerifyVoteExtension::Reject
        // }
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
    index: u64,
}

// struct Commitment {
//     index: u32,
//     commitment: G2Projective,
// }

#[derive(Serialize, Deserialize, Debug)]
pub struct VEdata {
    data: String,
    height: u64,
    index: u64
}

// fn verify_share(suite: &G2Projective, commitment: &Commitment, received_share: &ExtractedKey, qid: &G2Projective) -> bool {
//     // Implement the verification logic here
//     true // Placeholder
// }

fn lagrange_coefficient(index: u64, s: &[u64]) -> Scalar {
    // Implement Lagrange coefficient calculation here
    let mut nominator = Scalar::one();
    let mut denominator = Scalar::one();
    let mut temp: Scalar;
    let mut temp1: Scalar;

    for &si in s {
        if si != index {
            // nominator *= s
            temp = Scalar::from(si as u64);
            nominator *= temp;

            // denominator *= (s - signer)
            temp = Scalar::from(si as u64);
            temp1 = Scalar::from(index);
            denominator *= temp - temp1;
        }
    }

    // outScalar = nominator / denominator
    nominator * denominator.invert().unwrap_or(Scalar::zero()) // Handling division by zero case
}

fn aggregate(sk_shares: Vec<G2Projective>) -> G2Projective {
    sk_shares.into_iter().reduce(|acc, share| acc + share).unwrap()
}

fn process_sk(share: &ExtractedKey, s: &[u64]) -> ExtractedKey {
    let lagrange_coef = lagrange_coefficient(share.index, s);
    let identity_key = share.sk * lagrange_coef;
    ExtractedKey {
        sk: identity_key,
        index: share.index,
    }
}
