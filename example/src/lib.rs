use trafficserver::{
    log_debug, Action, CacheEntry, CacheLookupState, CacheStatus, HttpEvent, HttpHook, Plugin,
    PluginMut, SendResponseState, Transaction,
};

const PLUGIN: &str = "plugin";

fn init(_args: Vec<String>) {
    trafficserver::register_plugin("ExamplePlugin", "example", "mail@example.com");
    trafficserver::add_http_hooks([HttpHook::ReadRequestHeaders].into(), GlobalHandler {});
}

trafficserver::plugin_init!(init);

struct GlobalHandler {}

impl Plugin for GlobalHandler {
    fn handle_event(&self, event: HttpEvent) -> Action {
        if let HttpEvent::ReadRequestHeader(mut tx) = event {
            let url = tx.effective_url();
            log_debug!(PLUGIN, "global plugin: received request for {}", url);
            tx.set_cache_url(url.trim_end_matches('/'));
            tx.add_plugin(
                [HttpHook::SendResponseHeaders, HttpHook::CacheLookup].into(),
                TransactionHandler {},
            );
        }
        Action::Resume
    }
}

struct TransactionHandler {}

impl PluginMut for TransactionHandler {
    fn handle_event(&mut self, event: HttpEvent) -> Action {
        match event {
            HttpEvent::SendResponseHeader(mut tx) => self.send_response_headers(&mut tx),
            HttpEvent::CacheLookupComplete(mut tx) => self.cache_lookup(&mut tx),
            _ => Action::Resume,
        }
    }
}

impl TransactionHandler {
    fn cache_lookup(&mut self, transaction: &mut Transaction<CacheLookupState>) -> Action {
        match transaction.cache_status() {
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

fn log_cache_hit(cached: &CacheEntry) {
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
