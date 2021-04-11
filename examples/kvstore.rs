use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

use futures::future::FutureExt;
use structopt::StructOpt;
use tendermint_proto::abci as pb;
use tower::{Service, ServiceBuilder};

use tower_abci::{split, BoxError, Request, Response, Server};

#[derive(Clone, Debug)]
pub struct KVStore {
    store: HashMap<String, String>,
    height: u64,
    app_hash: [u8; 8],
}

impl Default for KVStore {
    fn default() -> Self {
        Self {
            store: HashMap::default(),
            height: 0,
            app_hash: [0; 8],
        }
    }

}

impl KVStore {
    fn info(&self) -> pb::ResponseInfo {
        pb::ResponseInfo {
            data: "tower-abci-kvstore-example".to_string(),
            version: "0.1.0".to_string(),
            app_version: 1,
            last_block_height: self.height as i64,
            last_block_app_hash: self.app_hash.to_vec(),
        }
    }

    fn query(&self, query: Vec<u8>) -> pb::ResponseQuery {
        let key = String::from_utf8(query).unwrap();
        let (value, log) = match self.store.get(&key) {
            Some(value) => (value.clone(), "exists".to_string()),
            None => ("".to_string(), "does not exist".to_string()),
        };
        pb::ResponseQuery {
            code: 0,
            log,
            info: "".to_string(),
            index: 0,
            key: key.into_bytes(),
            value: value.into_bytes(),
            proof_ops: None,
            height: self.height as i64,
            codespace: "".to_string(),
        }
    }

    fn deliver_tx(&mut self, tx: Vec<u8>) -> pb::ResponseDeliverTx {
        let tx = String::from_utf8(tx).unwrap();
        let tx_parts = tx.split('=').collect::<Vec<_>>();
        let (key, value) = match (tx_parts.get(0), tx_parts.get(1)) {
            (Some(key), Some(value)) => (*key, *value),
            _ => (tx.as_ref(), tx.as_ref()),
        };
        self.store.insert(key.to_string(), value.to_string());
        pb::ResponseDeliverTx {
            code: 0,
            data: vec![],
            log: "".to_string(),
            info: "".to_string(),
            gas_wanted: 0,
            gas_used: 0,
            events: vec![pb::Event {
                r#type: "app".to_string(),
                attributes: vec![
                    pb::EventAttribute {
                        key: "key".as_bytes().to_owned(),
                        value: key.as_bytes().to_owned(),
                        index: true,
                    },
                    pb::EventAttribute {
                        key: "index_key".as_bytes().to_owned(),
                        value: "index is working".as_bytes().to_owned(),
                        index: true,
                    },
                    pb::EventAttribute {
                        key: "noindex_key".as_bytes().to_owned(),
                        value: "index is working".as_bytes().to_owned(),
                        index: false,
                    },
                ],
            }],
            codespace: "".to_string(),
        }
    }

    fn commit(&mut self) -> pb::ResponseCommit {
        let retain_height = self.height as i64;
        // As in the other kvstore examples, just use store.len() as the "hash"
        self.app_hash = (self.store.len() as u64).to_be_bytes();
        self.height += 1;
        pb::ResponseCommit {
            data: self.app_hash.to_vec(),
            retain_height,
        }
    }
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
            Request::Info(_) => Response::Info(self.info()),
            Request::Query(query) => Response::Query(self.query(query.data)),
            Request::DeliverTx(pb::RequestDeliverTx { tx }) => {
                Response::DeliverTx(self.deliver_tx(tx))
            }
            Request::Commit(_) => Response::Commit(self.commit()),

            Request::Echo(_) => Response::Echo(Default::default()),
            Request::Flush(_) => Response::Flush(Default::default()),
            Request::SetOption(_) => Response::SetOption(Default::default()),
            Request::InitChain(_) => Response::InitChain(Default::default()),
            Request::BeginBlock(_) => Response::BeginBlock(Default::default()),
            Request::CheckTx(_) => Response::CheckTx(Default::default()),
            Request::EndBlock(_) => Response::EndBlock(Default::default()),
            Request::ListSnapshots(_) => Response::ListSnapshots(Default::default()),
            Request::OfferSnapshot(_) => Response::OfferSnapshot(Default::default()),
            Request::LoadSnapshotChunk(_) => Response::LoadSnapshotChunk(Default::default()),
            Request::ApplySnapshotChunk(_) => Response::ApplySnapshotChunk(Default::default()),
        };
        tracing::info!(?rsp);
        async move { Ok(rsp) }.boxed()
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
}

#[tokio::main]
async fn main() {
    tracing_subscriber::fmt::init();

    let opt = Opt::from_args();
    let (consensus, mempool, snapshot, info) = split::service(KVStore::default(), 1);

    Server::builder()
        .consensus(consensus)
        .snapshot(snapshot)
        .mempool(
            ServiceBuilder::new()
                .load_shed()
                .buffer(10)
                .service(mempool),
        )
        .info(ServiceBuilder::new().load_shed().buffer(100).service(info))
        .finish()
        .unwrap()
        .listen(format!("{}:{}", opt.host, opt.port))
        .await
        .unwrap();
}
