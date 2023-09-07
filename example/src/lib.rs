use trafficserver::{log_debug, Hook, Plugin, Transaction};

const PLUGIN: &str = "plugin";

fn init(_args: Vec<String>) {
    trafficserver::register_plugin("ExamplePlugin", "example", "mail@example.com");

    let plugin = Box::new(ExamplePlugin {});
    trafficserver::register_global_hooks(vec![Hook::HttpReadRequestHeaders], plugin);
}

trafficserver::plugin_init!(init);

struct ExamplePlugin {}

impl Plugin for ExamplePlugin {
    fn handle_read_request_headers(&mut self, transaction: &mut Transaction) {
        log_debug!(PLUGIN, "global plugin: read request headers");

        let plugin = Box::new(TransactionPlugin {});
        transaction.add_plugin(vec![Hook::HttpSendResponseHeaders], plugin);
        transaction.resume();
    }
}

struct TransactionPlugin {}

impl Plugin for TransactionPlugin {
    fn handle_send_response_headers(&mut self, transaction: &mut Transaction) {
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

        transaction.resume();
    }
}
