use trafficserver::{
    log_debug, Action, CacheEntry, CacheLookupState, CacheStatus, GlobalPlugin, Hook, Plugin,
    ReadRequestState, SendResponseState, Transaction,
};

const PLUGIN: &str = "plugin";

fn init(_args: Vec<String>) {
    trafficserver::register_plugin("ExamplePlugin", "example", "mail@example.com");

    let handler = Box::new(GlobalHandler {});
    trafficserver::register_global_hooks(vec![Hook::HttpReadRequestHeaders], handler);
}

trafficserver::plugin_init!(init);

struct GlobalHandler {}

impl GlobalPlugin for GlobalHandler {
    fn read_request_headers(&self, transaction: &mut Transaction<ReadRequestState>) -> Action {
        log_debug!(PLUGIN, "global plugin: read request headers");

        let plugin = Box::new(TransactionHandler {});
        transaction.add_plugin(
            vec![Hook::HttpSendResponseHeaders, Hook::HttpCacheLookup],
            plugin,
        );
        Action::Resume
    }
}

struct TransactionHandler {}

impl Plugin for TransactionHandler {
    fn cache_lookup(&mut self, transaction: &mut Transaction<CacheLookupState>) -> Action {
        match &mut transaction.cache_status() {
            CacheStatus::HitFresh(cached) => log_cache_hit(cached),
            CacheStatus::HitStale(cached) => log_cache_hit(cached),
            CacheStatus::Miss => {
                log_debug!(PLUGIN, "cache miss");
            }
            CacheStatus::Skipped => {
                log_debug!(PLUGIN, "cache lookup skipped");
            }
            CacheStatus::None => {
                log_debug!(PLUGIN, "no cache lookup status");
            }
        };
        Action::Resume
    }

    fn send_response_headers(
        &mut self,
        transaction: &mut Transaction<SendResponseState>,
    ) -> Action {
        log_debug!(PLUGIN, "transaction plugin: send response headers");

        let req = transaction.client_request_mut();

        log_debug!(PLUGIN, "-- received {} headers", req.headers.len());

        log_debug!(PLUGIN, "-- mutating the request headers");
        req.headers.remove("x-foo");
        req.headers.set("x-bar", "1");
        req.headers.append("x-bar", "2");

        log_debug!(PLUGIN, "-- iterating over all header fields");
        for field in req.headers.iter() {
            log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
        }
        log_debug!(PLUGIN, "-- check if header field is present");
        log_debug!(PLUGIN, "  -- x-foo: {}", req.headers.contains_key("x-foo"));
        log_debug!(PLUGIN, "  -- x-bar: {}", req.headers.contains_key("x-bar"));

        log_debug!(PLUGIN, "-- iterating over header fields with name");
        for field in req.headers.find("x-bar") {
            log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
        }

        log_debug!(PLUGIN, "-- printing response headers");
        let resp = &transaction.client_response();
        for field in resp.headers.iter() {
            log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
        }

        Action::Resume
    }
}

fn log_cache_hit(cached: &mut CacheEntry) {
    let status = cached.response.status();
    let cache_control = cached
        .response
        .headers
        .find("cache-control")
        .next()
        .map(|h| h.value().to_string());

    log_debug!(
        PLUGIN,
        "found a cached {:?} response with cache control '{}'",
        status,
        cache_control.unwrap_or("".into())
    );
}
