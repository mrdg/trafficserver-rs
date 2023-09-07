use std::{
    ffi::{self, CStr, CString},
    ptr,
    rc::Rc,
};

pub use trafficserver_sys::TSDebug;

use trafficserver_sys::{
    TSCont, TSContCreate, TSContDataGet, TSContDataSet, TSContDestroy, TSEvent,
    TSEvent_TS_EVENT_HTTP_CONTINUE, TSEvent_TS_EVENT_HTTP_READ_REQUEST_HDR,
    TSEvent_TS_EVENT_HTTP_SEND_RESPONSE_HDR, TSEvent_TS_EVENT_HTTP_TXN_CLOSE, TSHandleMLocRelease,
    TSHttpHookAdd, TSHttpHookID_TS_HTTP_READ_REQUEST_HDR_HOOK,
    TSHttpHookID_TS_HTTP_SEND_RESPONSE_HDR_HOOK, TSHttpHookID_TS_HTTP_TXN_CLOSE_HOOK, TSHttpTxn,
    TSHttpTxnClientReqGet, TSHttpTxnClientRespGet, TSHttpTxnHookAdd, TSHttpTxnReenable, TSMBuffer,
    TSMLoc, TSMimeHdrFieldAppend, TSMimeHdrFieldCreate, TSMimeHdrFieldDestroy, TSMimeHdrFieldFind,
    TSMimeHdrFieldGet, TSMimeHdrFieldNameGet, TSMimeHdrFieldNameSet, TSMimeHdrFieldNext,
    TSMimeHdrFieldNextDup, TSMimeHdrFieldValueStringGet, TSMimeHdrFieldValueStringInsert,
    TSMimeHdrFieldsCount, TSPluginRegister, TSPluginRegistrationInfo, TSReturnCode,
    TSReturnCode_TS_ERROR, TSReturnCode_TS_SUCCESS,
};

pub struct Response {
    pub headers: Headers,
}

pub struct Request {
    pub headers: Headers,
}

pub struct Headers {
    buf: TSMBuffer,
    loc: TSMLoc,
}

impl Headers {
    fn new(buf: TSMBuffer, loc: TSMLoc) -> Self {
        Self { buf, loc }
    }

    // Returns the number of fields in the header.
    pub fn len(&self) -> usize {
        let len = unsafe { TSMimeHdrFieldsCount(self.buf, self.loc) };
        len as usize
    }

    pub fn contains_key(&self, key: &str) -> bool {
        self.find(key).count() > 0
    }

    pub fn remove(&mut self, key: &str) {
        for field in self.find(key) {
            unsafe {
                TSMimeHdrFieldDestroy(self.buf, self.loc, field.handle.field);
            }
        }
    }

    // Adds a new header field with key and value. If an existing header field with this key
    // already exists, this will add an additional field, not append to the previous one.
    pub fn append(&mut self, key: &str, value: &str) {
        let mut field_loc: TSMLoc = ptr::null_mut();
        let res = unsafe { TSMimeHdrFieldCreate(self.buf, self.loc, &mut field_loc) };
        if res != TSReturnCode_TS_SUCCESS {
            return;
        }
        unsafe {
            TSMimeHdrFieldNameSet(
                self.buf,
                self.loc,
                field_loc,
                key.as_ptr() as *const i8,
                key.len() as i32,
            );
            TSMimeHdrFieldAppend(self.buf, self.loc, field_loc);
            TSMimeHdrFieldValueStringInsert(
                self.buf,
                self.loc,
                field_loc,
                0,
                value.as_ptr() as *const i8,
                value.len() as i32,
            );
        }
    }

    // Set overwrites any existing any existing header fields with the same key
    pub fn set(&mut self, key: &str, value: &str) {
        self.remove(key);
        self.append(key, value);
    }

    // Iterates over all header fields
    pub fn iter<'a>(&'a self) -> impl Iterator<Item = HeaderField> + 'a {
        let field_loc = unsafe { TSMimeHdrFieldGet(self.buf, self.loc, 0) };
        let handle = Rc::new(HeaderFieldHandle::new(self, field_loc));
        HeaderIter::new(handle, TSMimeHdrFieldNext)
    }

    // Iterates over all header fields with the specified key. The key comparison is case
    // insensitive
    pub fn find<'a>(&'a self, key: &str) -> impl Iterator<Item = HeaderField> + 'a {
        let len = key.len() as i32;
        let key = key.as_ptr() as *const ffi::c_char;
        let field_loc = unsafe { TSMimeHdrFieldFind(self.buf, self.loc, key, len) };
        let handle = Rc::new(HeaderFieldHandle::new(self, field_loc));
        HeaderIter::new(handle, TSMimeHdrFieldNextDup)
    }
}

pub struct HeaderField<'a> {
    handle: Rc<HeaderFieldHandle<'a>>,
}

impl<'a> HeaderField<'a> {
    pub fn key(&self) -> &str {
        let mut length: ffi::c_int = 0;
        let c_str = unsafe {
            let value = TSMimeHdrFieldNameGet(
                self.handle.headers.buf,
                self.handle.headers.loc,
                self.handle.field,
                &mut length,
            );
            if value.is_null() {
                return "";
            }
            CStr::from_ptr(value)
        };
        let str = c_str.to_str().unwrap();
        &str[0..length as usize]
    }

    pub fn value(&self) -> &str {
        let mut length: ffi::c_int = 0;
        let c_str = unsafe {
            let value = TSMimeHdrFieldValueStringGet(
                self.handle.headers.buf,
                self.handle.headers.loc,
                self.handle.field,
                -1,
                &mut length,
            );
            if value.is_null() {
                return "";
            }
            CStr::from_ptr(value)
        };
        let str = c_str.to_str().unwrap();
        &str[0..length as usize]
    }
}

// This wraps a TSMLoc so it can be freed when both the HeaderField and HeaderIter using it are dropped.
struct HeaderFieldHandle<'a> {
    headers: &'a Headers,
    field: TSMLoc,
}

impl<'a> HeaderFieldHandle<'a> {
    fn new(headers: &'a Headers, field: TSMLoc) -> Self {
        Self { headers, field }
    }
}

impl<'a> Drop for HeaderFieldHandle<'a> {
    fn drop(&mut self) {
        if self.field.is_null() {
            return;
        }
        unsafe { TSHandleMLocRelease(self.headers.buf, self.headers.loc, self.field) };
    }
}

type IterNext = unsafe extern "C" fn(bufp: TSMBuffer, hdr: TSMLoc, field: TSMLoc) -> TSMLoc;

struct HeaderIter<'a> {
    iter_next: IterNext,
    handle: Rc<HeaderFieldHandle<'a>>,
}

impl<'a> HeaderIter<'a> {
    fn new(handle: Rc<HeaderFieldHandle<'a>>, iter_next: IterNext) -> Self {
        Self { iter_next, handle }
    }
}

impl<'a> Iterator for HeaderIter<'a> {
    type Item = HeaderField<'a>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.handle.field.is_null() {
            return None;
        }
        let header_field = HeaderField {
            handle: self.handle.clone(),
        };
        let field_loc = unsafe {
            (self.iter_next)(
                self.handle.headers.buf,
                self.handle.headers.loc,
                self.handle.field,
            )
        };
        self.handle = Rc::new(HeaderFieldHandle {
            field: field_loc,
            headers: self.handle.headers,
        });
        Some(header_field)
    }
}

pub struct Transaction {
    txn: TSHttpTxn,
    pub client_request: Request,
    pub client_response: Option<Response>,
}

impl Transaction {
    fn new(txn: TSHttpTxn) -> Self {
        Self {
            // I think this needs to be initialized lazily, like the C++ plugin does it.
            client_request: Request {
                headers: init_headers(txn, TSHttpTxnClientReqGet).unwrap(),
            },
            client_response: init_headers(txn, TSHttpTxnClientRespGet)
                .map(|headers| Response { headers }),
            txn,
        }
    }

    pub fn resume(&self) {
        unsafe { TSHttpTxnReenable(self.txn, TSEvent_TS_EVENT_HTTP_CONTINUE) }
    }

    pub fn add_plugin(&self, hooks: Vec<Hook>, plugin: Box<dyn Plugin>) {
        // Passing a null mutex here, same as the TransactionPlugin constructor in cppapi.
        let cont = unsafe { TSContCreate(Some(handle_event), ptr::null_mut()) };
        let state = Box::new(PluginState::new(plugin));
        let cont_data = Box::into_raw(state) as *mut ffi::c_void;
        unsafe { TSContDataSet(cont, cont_data) }
        for hook in hooks {
            unsafe { TSHttpTxnHookAdd(self.txn, hook as u32, cont) };
        }
        // TODO: make sure we don't register this twice
        unsafe { TSHttpTxnHookAdd(self.txn, TSHttpHookID_TS_HTTP_TXN_CLOSE_HOOK, cont) };
    }
}

type HeaderInitFn = unsafe extern "C" fn(
    txnp: TSHttpTxn,
    bufp: *mut TSMBuffer,
    offset: *mut TSMLoc,
) -> TSReturnCode;

fn init_headers(txn: TSHttpTxn, init: HeaderInitFn) -> Option<Headers> {
    let mut buf: TSMBuffer = ptr::null_mut();
    let mut loc: TSMLoc = ptr::null_mut();
    if unsafe { init(txn, &mut buf, &mut loc) } != TSReturnCode_TS_SUCCESS {
        return None;
    }
    Some(Headers::new(buf, loc))
}

pub enum Action {
    Resume,
}

pub trait Plugin {
    fn handle_read_request_headers(&mut self, _transaction: &mut Transaction) -> Action {
        Action::Resume
    }

    fn handle_send_response_headers(&mut self, _transaction: &mut Transaction) -> Action {
        Action::Resume
    }
}

#[macro_export]
macro_rules! plugin_init {
    ($init: ident) => {
        use std::ffi::{self, CStr};

        #[no_mangle]
        #[allow(non_snake_case)]
        pub unsafe extern "C" fn TSPluginInit(argc: ffi::c_int, argv: *const *const ffi::c_char) {
            let mut args = Vec::with_capacity(argc as usize);
            for i in 0..argc {
                let ptr = argv.offset(i as isize);
                let arg = CStr::from_ptr(*ptr).to_str().unwrap().to_string();
                args.push(arg);
            }
            $init(args);
        }
    };
}

#[macro_export]
macro_rules! log_debug {
    ($tag:expr, $($arg:tt)*) => {
        let msg = format!($($arg)*);
        let tag_str = std::ffi::CString::new($tag).unwrap();
        let msg_str = std::ffi::CString::new(msg).unwrap();
        unsafe { $crate::TSDebug(tag_str.as_ptr(), msg_str.as_ptr()) };
    }
}

#[repr(i32)]
pub enum TsReturnCode {
    Success = TSReturnCode_TS_SUCCESS,
    Error = TSReturnCode_TS_ERROR,
}

pub fn register_plugin(name: &str, vendor: &str, email: &str) -> TsReturnCode {
    let name = CString::new(name.to_string()).unwrap();
    let vendor = CString::new(vendor.to_string()).unwrap();
    let email = CString::new(email.to_string()).unwrap();
    let info = TSPluginRegistrationInfo {
        plugin_name: name.as_ptr(),
        vendor_name: vendor.as_ptr(),
        support_email: email.as_ptr(),
    };
    if unsafe { TSPluginRegister(&info) } == TSReturnCode_TS_ERROR {
        return TsReturnCode::Error;
    }
    TsReturnCode::Success
}

pub fn register_global_hooks(hooks: Vec<Hook>, plugin: Box<dyn Plugin>) {
    // Create global continuation with a null mutex, because otherwise this will be
    // locked by every ATS thread.
    let cont = unsafe { TSContCreate(Some(handle_event), ptr::null_mut()) };
    let state = Box::new(PluginState::new(plugin));
    let cont_data = Box::into_raw(state) as *mut ffi::c_void;
    unsafe { TSContDataSet(cont, cont_data) }
    for hook in hooks {
        unsafe { TSHttpHookAdd(hook as u32, cont) };
    }
}

#[repr(u32)]
pub enum Hook {
    HttpReadRequestHeaders = TSHttpHookID_TS_HTTP_READ_REQUEST_HDR_HOOK,
    HttpSendResponseHeaders = TSHttpHookID_TS_HTTP_SEND_RESPONSE_HDR_HOOK,
}

struct PluginState {
    plugin: Box<dyn Plugin>,
}

impl PluginState {
    fn new(plugin: Box<dyn Plugin>) -> Self {
        Self { plugin }
    }

    fn invoke_plugin(&mut self, event: TSEvent, transaction: &mut Transaction) {
        let action = match event as u32 {
            TSEvent_TS_EVENT_HTTP_READ_REQUEST_HDR => {
                self.plugin.handle_read_request_headers(transaction)
            }
            TSEvent_TS_EVENT_HTTP_SEND_RESPONSE_HDR => {
                self.plugin.handle_send_response_headers(transaction)
            }
            _ => unreachable!(),
        };
        match action {
            Action::Resume => transaction.resume(),
        }
    }
}

unsafe extern "C" fn handle_event(contp: TSCont, event: TSEvent, edata: *mut ffi::c_void) -> i32 {
    let cont_data = TSContDataGet(contp);
    if event == TSEvent_TS_EVENT_HTTP_TXN_CLOSE {
        TSContDestroy(contp);
        let _ = Box::from_raw(cont_data); // drop the plugin
        unsafe { TSHttpTxnReenable(edata as TSHttpTxn, TSEvent_TS_EVENT_HTTP_CONTINUE) }
        return 0;
    }

    let state: &mut PluginState = &mut *(cont_data as *mut PluginState);
    let mut transaction = Transaction::new(edata as TSHttpTxn);
    state.invoke_plugin(event, &mut transaction);

    return 0;
}
