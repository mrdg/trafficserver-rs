use trafficserver::{log_debug, Action, GlobalPlugin, Hook, Plugin, Transaction};

const PLUGIN: &str = "plugin";

fn init(_args: Vec<String>) {
    trafficserver::register_plugin("ExamplePlugin", "example", "mail@example.com");

    let handler = Box::new(GlobalHandler {});
    trafficserver::register_global_hooks(vec![Hook::HttpReadRequestHeaders], handler);
}

trafficserver::plugin_init!(init);

struct GlobalHandler {}

impl GlobalPlugin for GlobalHandler {
    fn handle_read_request_headers(&self, transaction: &mut Transaction) -> Action {
        log_debug!(PLUGIN, "global plugin: read request headers");

        let plugin = Box::new(TransactionHandler {});
        transaction.add_plugin(vec![Hook::HttpSendResponseHeaders], plugin);
        Action::Resume
    }
}

struct TransactionHandler {}

impl Plugin for TransactionHandler {
    fn handle_send_response_headers(&mut self, transaction: &mut Transaction) -> Action {
        log_debug!(PLUGIN, "transaction plugin: send response headers");

        let headers = &mut transaction.client_request.headers;

        log_debug!(PLUGIN, "-- received {} headers", headers.len());

        log_debug!(PLUGIN, "-- mutating the request headers");
        headers.remove("x-foo");
        headers.set("x-bar", "1");
        headers.append("x-bar", "2");

        log_debug!(PLUGIN, "-- iterating over all header fields");
        for field in headers.iter() {
            log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
        }
        log_debug!(PLUGIN, "-- check if header field is present");
        log_debug!(PLUGIN, "  -- x-foo: {}", headers.contains_key("x-foo"));
        log_debug!(PLUGIN, "  -- x-bar: {}", headers.contains_key("x-bar"));

        log_debug!(PLUGIN, "-- iterating over header fields with name");
        for field in headers.find("x-bar") {
            log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
        }

        let req = &mut transaction.client_request;

        log_debug!(PLUGIN, "-- printing response headers");
        if let Some(resp) = transaction.client_response.as_mut() {
            for field in resp.headers.iter() {
                log_debug!(PLUGIN, "  -- {}: {}", field.key(), field.value());
            }
        }

        for _field in req.headers.iter() {}

        Action::Resume
    }
}
