use core::fmt;
use std::{borrow::Cow, collections::HashMap, str::FromStr};

use crate::{content::ServiceError, utils::BASE64_RELAXED};
use base64::prelude::*;
use libsignal_core::{DeviceId, E164};
use libsignal_protocol::PublicKey;
use serde::{Deserialize, Serialize};
use url::Url;
use zkgroup::ServerPublicParams;

use crate::push_service::{HttpAuth, DEFAULT_DEVICE_ID};

#[derive(Clone)]
pub struct ServiceConfiguration {
    service_url: Url,
    storage_url: Url,
    cdn_urls: HashMap<u32, Url>,
    pub certificate_authority: String,
    pub unidentified_sender_trust_roots: Vec<PublicKey>,
    pub zkgroup_server_public_params: ServerPublicParams,
}

#[derive(Clone)]
pub struct ServiceCredentials {
    pub aci: Option<uuid::Uuid>,
    pub pni: Option<uuid::Uuid>,
    pub phonenumber: E164,
    pub password: Option<String>,
    pub device_id: Option<DeviceId>,
}

impl ServiceCredentials {
    pub fn authorization(&self) -> Option<HttpAuth> {
        self.password.as_ref().map(|password| HttpAuth {
            username: self.login(),
            password: password.clone(),
        })
    }

    pub fn e164(&self) -> String {
        self.phonenumber.to_string()
    }

    pub fn login(&self) -> String {
        let identifier = {
            if let Some(uuid) = self.aci.as_ref() {
                uuid.to_string()
            } else {
                self.e164()
            }
        };

        match self.device_id {
            None => identifier,
            Some(device_id) if device_id == *DEFAULT_DEVICE_ID => identifier,
            Some(id) => format!("{}.{}", identifier, id),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum SignalServers {
    Staging,
    Production,
}

#[cfg(feature = "cdsi")]
impl From<SignalServers> for libsignal_net::env::Env<'static> {
    fn from(servers: SignalServers) -> Self {
        match servers {
            SignalServers::Staging => libsignal_net::env::STAGING,
            SignalServers::Production => libsignal_net::env::PROD,
        }
    }
}

#[derive(Debug)]
pub enum Endpoint<'a> {
    Absolute(Url),
    Service {
        path: Cow<'a, str>,
    },
    Storage {
        path: Cow<'a, str>,
    },
    Cdn {
        cdn_id: u32,
        path: Cow<'a, str>,
        query: Option<Cow<'a, str>>,
    },
}

impl fmt::Display for Endpoint<'_> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Endpoint::Absolute(url) => write!(f, "absolute URL {url}"),
            Endpoint::Service { path } => {
                write!(f, "service API call to {path}")
            },
            Endpoint::Storage { path } => {
                write!(f, "storage API call to {path}")
            },
            Endpoint::Cdn { cdn_id, path, .. } => {
                write!(f, "CDN{cdn_id} call to {path}")
            },
        }
    }
}

impl<'a> Endpoint<'a> {
    pub fn service(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Service { path: path.into() }
    }

    pub fn cdn(cdn_id: u32, path: impl Into<Cow<'a, str>>) -> Self {
        Self::Cdn {
            cdn_id,
            path: path.into(),
            query: None,
        }
    }

    pub fn cdn_url(cdn_id: u32, url: &'a Url) -> Self {
        Self::Cdn {
            cdn_id,
            path: url.path().into(),
            query: url.query().map(Into::into),
        }
    }

    pub fn storage(path: impl Into<Cow<'a, str>>) -> Self {
        Self::Storage { path: path.into() }
    }

    pub fn into_url(
        self,
        service_configuration: &ServiceConfiguration,
    ) -> Result<Url, ServiceError> {
        match self {
            Endpoint::Service { path } => {
                Ok(service_configuration.service_url.join(&path)?)
            },
            Endpoint::Storage { path } => {
                Ok(service_configuration.storage_url.join(&path)?)
            },
            Endpoint::Cdn {
                cdn_id,
                path,
                query,
            } => {
                let Some(mut url) =
                    service_configuration.cdn_urls.get(&cdn_id).cloned()
                else {
                    tracing::warn!(%cdn_id, "Unknown CDN");
                    return Err(ServiceError::UnknownCdnVersion(cdn_id));
                };
                url.set_path(&path);
                url.set_query(query.as_deref());
                Ok(url)
            },
            Endpoint::Absolute(url) => Ok(url),
        }
    }
}

impl FromStr for SignalServers {
    type Err = std::io::Error;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use std::io::ErrorKind;
        match s {
            "staging" => Ok(Self::Staging),
            "production" => Ok(Self::Production),
            _ => Err(Self::Err::new(
                ErrorKind::InvalidInput,
                "invalid signal servers, can be either: staging or production",
            )),
        }
    }
}

impl fmt::Display for SignalServers {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Staging => f.write_str("staging"),
            Self::Production => f.write_str("production"),
        }
    }
}

impl From<SignalServers> for ServiceConfiguration {
    fn from(val: SignalServers) -> Self {
        ServiceConfiguration::from(&val)
    }
}

impl From<&SignalServers> for ServiceConfiguration {
    fn from(val: &SignalServers) -> Self {
        // base configuration from https://github.com/signalapp/Signal-Desktop/blob/development/config/default.json
        match val {
            // e2 A1 wiring — REPOINTED. `SignalServers::Staging` is repurposed to point
            // at the personas ISOLATED self-hosted Signal-Server *test-server* (fronted by
            // a local TLS-terminating proxy on :8443 → the cleartext :8080 connector; see
            // deploy/signal-test-server/tls-proxy.sh). This is NOT Signal's staging network
            // — it is our own single-tenant staging server, the sanctioned venue for the
            // account-gated A1 send/receive wiring (docs/SERVERLESS_SIGNAL_DESIGN.md §8,
            // signal-server-selfhost-route). Values below are the checked-in test secrets
            // from the Signal-Server `test-server` profile (test.yml / test-secrets-bundle.yml).
            SignalServers::Staging => ServiceConfiguration {
                service_url: "https://127.0.0.1:8443".parse().unwrap(),
                // No storage-service / CDN is started by the test-server profile, and A1
                // records ride inline (no attachments, no GroupV2 storage). These are
                // pointed at the proxy so the config is well-formed but are unused in A1.
                storage_url: "https://127.0.0.1:8443".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://127.0.0.1:8443".parse().unwrap());
                    map.insert(2, "https://127.0.0.1:8443".parse().unwrap());
                    map.insert(3, "https://127.0.0.1:8443".parse().unwrap());
                    map
                },
                // Our proxy's self-signed CA (deploy/signal-test-server/.local/tls/ca.crt).
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/personas-test-server-ca.pem")).to_string(),
                // Sealed-sender trust root from test-secrets-bundle.yml ("Trust root for the
                // certificate in test.yml"). Single root (the test profile does not rotate).
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BS/lfaNHzWJDFSjarF+7KQcw//aEr8TPwu2QmV9Yyzt0").unwrap()).unwrap(),
                ],
                // zkgroup serverPublic from test.yml (`chatZkConfig.serverPublic` /
                // `groupsZkConfig` share it). Needed so the config deserialises even though
                // A1 delivery does not exercise GroupV2 credentials (per-member 1:1 fan-out).
                zkgroup_server_public_params: bincode::deserialize(&BASE64_RELAXED.decode("AAp8oB0D4EV2q7hSue3Kxzh1Vc88/nmLuRR9G3EefC0+CMcxJFQwDMgjFvFBKx3o6m9gJLevYiKcm/NxXX9WtnFMDHgDgfqHxbCi2rm20SgoHnuoph6XArmEOX6a1xLJVxgDtgfm1IbcyyqROXYxe9v2RvMUAnjbLI/fm0rXXhldjszlVR/wRpybX90RUjFyL/2Achttf3IC/ShWKkB6mWXwuFCcNfzeCCQ+w7cNnDbWscBcrhuou7HZvbt16/YdCXLyp+WdwS8ZkelpITvyK2hsPvf4oxaRLQfVRYXUMX55xpapbKH6PthuOzMVRkf+I3Xz3/bNjiQSlQkmAXlgB1YujgABYnJ6yJXQKP2mR4UJ3UYoGroYoafWycDa+vUYYozaUmzFjsBYWpYE+HyPJlJ2QaFTrpVqxX7NXsSbg8t35IvfWfZME9YBZ2eErDunwkaE4iDQhHl5IXAhbHDrr2QaJ68YIkn7lJSgFDKGFB2kb6BvDUGzcpI/CTHQi6WlCqQidQLJWDFFdlYjrUCQM2vvJtgyGrSc89jdXTFjM31aqmtcPWgWL0qv+RmK/BC392Nsu8WoSJcAE4yhccQuRSemtolgwewnjasoOFBNOPh4+pX55SwhyTVgtwl+NTNVNFydxGp9Me8ogRWElzwA9BFtNAgQtlfgIyZRTetFqLkYmIBDxwMcpizDKES5lPhV2uJJuzcMq/06mVQz2OrXgglWk01uN8U59pfNFpTZhcGQv+MHjwEAudq5eLpt3aFrdxJ7D26Fwl5j215SJ0yZo7vmSEML1vf7FaGh0IL57bRpCvdebB5WapSChUX+PPvCXohVjGrERFvQpeET6pydGGlEKYLWuWa3zFGmPvJJYZ/QfcmIP9zyhqzQT/7a7RIqFA==").unwrap()).unwrap(),
            },
            // configuration with the Signal API production endpoints
            // https://github.com/signalapp/Signal-Desktop/blob/master/config/production.json
            SignalServers::Production => ServiceConfiguration {
                service_url:
                    "https://chat.signal.org".parse().unwrap(),
                storage_url: "https://storage.signal.org".parse().unwrap(),
                cdn_urls: {
                    let mut map = HashMap::new();
                    map.insert(0, "https://cdn.signal.org".parse().unwrap());
                    map.insert(2, "https://cdn2.signal.org".parse().unwrap());
                    map.insert(3, "https://cdn3.signal.org".parse().unwrap());
                    map
                },
                certificate_authority: include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/certs/production-root-ca.pem")).to_string(),
                unidentified_sender_trust_roots: vec![
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BXu6QIKVz5MA8gstzfOgRQGqyLqOwNKHL6INkv3IHWMF").unwrap()).unwrap(),
                    PublicKey::deserialize(&BASE64_RELAXED.decode("BUkY0I+9+oPgDCn4+Ac6Iu813yvqkDr/ga8DzLxFxuk6").unwrap()).unwrap(),
                ],
                zkgroup_server_public_params: bincode::deserialize(
                    &BASE64_RELAXED.decode("AMhf5ywVwITZMsff/eCyudZx9JDmkkkbV6PInzG4p8x3VqVJSFiMvnvlEKWuRob/1eaIetR31IYeAbm0NdOuHH8Qi+Rexi1wLlpzIo1gstHWBfZzy1+qHRV5A4TqPp15YzBPm0WSggW6PbSn+F4lf57VCnHF7p8SvzAA2ZZJPYJURt8X7bbg+H3i+PEjH9DXItNEqs2sNcug37xZQDLm7X36nOoGPs54XsEGzPdEV+itQNGUFEjY6X9Uv+Acuks7NpyGvCoKxGwgKgE5XyJ+nNKlyHHOLb6N1NuHyBrZrgtY/JYJHRooo5CEqYKBqdFnmbTVGEkCvJKxLnjwKWf+fEPoWeQFj5ObDjcKMZf2Jm2Ae69x+ikU5gBXsRmoF94GXTLfN0/vLt98KDPnxwAQL9j5V1jGOY8jQl6MLxEs56cwXN0dqCnImzVH3TZT1cJ8SW1BRX6qIVxEzjsSGx3yxF3suAilPMqGRp4ffyopjMD1JXiKR2RwLKzizUe5e8XyGOy9fplzhw3jVzTRyUZTRSZKkMLWcQ/gv0E4aONNqs4P+NameAZYOD12qRkxosQQP5uux6B2nRyZ7sAV54DgFyLiRcq1FvwKw2EPQdk4HDoePrO/RNUbyNddnM/mMgj4FW65xCoT1LmjrIjsv/Ggdlx46ueczhMgtBunx1/w8k8V+l8LVZ8gAT6wkU5J+DPQalQguMg12Jzug3q4TbdHiGCmD9EunCwOmsLuLJkz6EcSYXtrlDEnAM+hicw7iergYLLlMXpfTdGxJCWJmP4zqUFeTTmsmhsjGBt7NiEB/9pFFEB3pSbf4iiUukw63Eo8Aqnf4iwob6X1QviCWuc8t0LUlT9vALgh/f2DPVOOmR0RW6bgRvc7DSF20V/omg+YBw==").unwrap()).unwrap(),
            },
        }
    }
}
