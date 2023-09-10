use std::{
    ffi::{self, CString},
    ptr,
    rc::Rc,
    slice, str,
};

pub use trafficserver_sys::TSDebug;
pub use trafficserver_sys::TSHttpStatus as HttpStatus;

use trafficserver_sys::{
    TSCacheLookupResult, TSCont, TSContCreate, TSContDataGet, TSContDataSet, TSContDestroy,
    TSEvent, TSHandleMLocRelease, TSHttpHdrStatusGet, TSHttpHookAdd, TSHttpHookID, TSHttpTxn,
    TSHttpTxnCacheLookupStatusGet, TSHttpTxnCacheLookupStatusSet, TSHttpTxnCachedReqGet,
    TSHttpTxnCachedRespGet, TSHttpTxnClientReqGet, TSHttpTxnClientRespGet, TSHttpTxnHookAdd,
    TSHttpTxnReenable, TSMBuffer, TSMLoc, TSMimeHdrFieldAppend, TSMimeHdrFieldCreate,
    TSMimeHdrFieldDestroy, TSMimeHdrFieldFind, TSMimeHdrFieldGet, TSMimeHdrFieldNameGet,
    TSMimeHdrFieldNameSet, TSMimeHdrFieldNext, TSMimeHdrFieldNextDup, TSMimeHdrFieldValueStringGet,
    TSMimeHdrFieldValueStringInsert, TSMimeHdrFieldsCount, TSPluginRegister,
    TSPluginRegistrationInfo, TSReturnCode,
};

pub struct Response {
    pub status: HttpStatus,
    pub headers: Headers,
}

impl Response {
    fn new(txn: TSHttpTxn, header_init: HeaderInitFn) -> Self {
        let headers = init_headers(txn, header_init).unwrap();
        let status = unsafe { TSHttpHdrStatusGet(headers.buf, headers.loc) };
        Self { status, headers }
    }
}

pub struct Request {
    pub headers: Headers,
}

impl Request {
    fn new(txn: TSHttpTxn, header_init: HeaderInitFn) -> Self {
        let headers = init_headers(txn, header_init).unwrap();
        Self { headers }
    }
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
        if res != TSReturnCode::TS_SUCCESS {
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
        unsafe {
            let value = TSMimeHdrFieldNameGet(
                self.handle.headers.buf,
                self.handle.headers.loc,
                self.handle.field,
                &mut length,
            );
            if value.is_null() {
                return "";
            }
            let s = slice::from_raw_parts::<u8>(value as *const u8, length as usize);
            str::from_utf8(s).ok().unwrap_or_default()
        }
    }

    pub fn value(&self) -> &str {
        let mut length: ffi::c_int = 0;
        unsafe {
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
            let s = slice::from_raw_parts::<u8>(value as *const u8, length as usize);
            str::from_utf8(s).ok().unwrap_or_default()
        }
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

// TODO: use sealed traits
pub trait State {}
impl State for ReadRequestState {}
impl State for CacheLookupState {}
impl State for SendResponseState {}

pub trait PreCacheState {}
impl PreCacheState for ReadRequestState {}

pub struct ReadRequestState {
    pub client_request: Request,
}

impl ReadRequestState {
    fn new(txn: TSHttpTxn) -> Self {
        Self {
            client_request: Request::new(txn, TSHttpTxnClientReqGet),
        }
    }
}

pub struct CacheLookupState {
    pub client_request: Request,
    pub cache_status: CacheStatus,
}

impl CacheLookupState {
    fn new(txn: TSHttpTxn) -> Self {
        Self {
            client_request: Request::new(txn, TSHttpTxnClientReqGet),
            cache_status: cache_lookup_status(txn),
        }
    }
}

pub struct SendResponseState {
    pub client_request: Request,
    pub client_response: Response,
}

impl SendResponseState {
    fn new(txn: TSHttpTxn) -> Self {
        Self {
            client_request: Request::new(txn, TSHttpTxnClientReqGet),
            client_response: Response::new(txn, TSHttpTxnClientRespGet),
        }
    }
}

pub struct Transaction<S: State> {
    txn: TSHttpTxn,
    pub state: S,
}

impl<S: State> Transaction<S> {
    fn new(txn: TSHttpTxn, state: S) -> Transaction<S> {
        Self { txn, state }
    }

    pub fn add_plugin(&self, hooks: Vec<Hook>, plugin: Box<dyn Plugin>) {
        // Passing a null mutex here, same as the TransactionPlugin constructor in cppapi.
        let cont = unsafe { TSContCreate(Some(handle_event), ptr::null_mut()) };
        let state = Box::new(PluginState::new(plugin));
        let cont_data = Box::into_raw(state) as *mut ffi::c_void;
        unsafe { TSContDataSet(cont, cont_data) }
        for hook in hooks {
            unsafe { TSHttpTxnHookAdd(self.txn, hook.into(), cont) };
        }
        unsafe { TSHttpTxnHookAdd(self.txn, TSHttpHookID::TS_HTTP_TXN_CLOSE_HOOK, cont) };
    }
}

impl<S: State + PreCacheState> Transaction<S> {
    pub fn set_cache_url(&mut self) {
        todo!()
    }
}

impl Transaction<CacheLookupState> {
    pub fn set_cache_status(&mut self, status: CacheStatusOverride) -> ReturnCode {
        set_cache_status(self.txn, &self.state.cache_status, status)
    }
}

pub struct CacheEntry {
    pub request: Request,
    pub response: Response,
}

impl CacheEntry {
    fn new(txn: TSHttpTxn) -> Self {
        Self {
            request: Request::new(txn, TSHttpTxnCachedReqGet),
            response: Response::new(txn, TSHttpTxnCachedRespGet),
        }
    }
}

pub enum CacheStatus {
    HitFresh(CacheEntry),
    HitStale(CacheEntry),
    Miss,
    Skipped,
    None,
}

impl CacheStatus {
    fn has_cache_entry(&self) -> bool {
        matches!(self, Self::HitFresh(_) | Self::HitStale(_))
    }
}

pub enum CacheStatusOverride {
    HitFresh,
    HitStale,
    Miss,
}

fn set_cache_status(txn: TSHttpTxn, current: &CacheStatus, new: CacheStatusOverride) -> ReturnCode {
    use CacheStatusOverride::*;
    let status = match new {
        HitFresh | HitStale if !current.has_cache_entry() => {
            return ReturnCode::Error;
        }
        HitStale => TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_STALE,
        HitFresh => TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_FRESH,
        Miss => TSCacheLookupResult::TS_CACHE_LOOKUP_MISS,
    };
    let res = unsafe { TSHttpTxnCacheLookupStatusSet(txn, status.0 as i32) };
    if res == TSReturnCode::TS_ERROR {
        return ReturnCode::Error;
    }

    ReturnCode::Success
}

fn cache_lookup_status(txn: TSHttpTxn) -> CacheStatus {
    let mut cache_status: ffi::c_int = 0;
    let res = unsafe { TSHttpTxnCacheLookupStatusGet(txn, &mut cache_status) };
    if res == TSReturnCode::TS_ERROR {
        return CacheStatus::None;
    }

    match TSCacheLookupResult(cache_status as u32) {
        TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_FRESH => {
            CacheStatus::HitFresh(CacheEntry::new(txn))
        }
        TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_STALE => {
            CacheStatus::HitStale(CacheEntry::new(txn))
        }
        TSCacheLookupResult::TS_CACHE_LOOKUP_MISS => CacheStatus::Miss,
        TSCacheLookupResult::TS_CACHE_LOOKUP_SKIPPED => CacheStatus::Skipped,
        _ => CacheStatus::None,
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
    if unsafe { init(txn, &mut buf, &mut loc) } != TSReturnCode::TS_SUCCESS {
        return None;
    }
    Some(Headers::new(buf, loc))
}

pub enum Action {
    Resume,
}

pub trait Plugin {
    fn read_request_headers(&mut self, _transaction: &mut Transaction<ReadRequestState>) -> Action {
        Action::Resume
    }

    fn cache_lookup(&mut self, _transaction: &mut Transaction<CacheLookupState>) -> Action {
        Action::Resume
    }

    fn send_response_headers(
        &mut self,
        _transaction: &mut Transaction<SendResponseState>,
    ) -> Action {
        Action::Resume
    }
}

pub trait GlobalPlugin {
    fn read_request_headers(&self, _transaction: &mut Transaction<ReadRequestState>) -> Action {
        Action::Resume
    }

    fn cache_lookup(&self, _transaction: &mut Transaction<CacheLookupState>) -> Action {
        Action::Resume
    }

    fn send_response_headers(&self, _transaction: &mut Transaction<SendResponseState>) -> Action {
        Action::Resume
    }
}

impl<T: GlobalPlugin> Plugin for T {
    fn read_request_headers(&mut self, transaction: &mut Transaction<ReadRequestState>) -> Action {
        T::read_request_headers(self, transaction)
    }

    fn cache_lookup(&mut self, transaction: &mut Transaction<CacheLookupState>) -> Action {
        T::cache_lookup(self, transaction)
    }

    fn send_response_headers(
        &mut self,
        transaction: &mut Transaction<SendResponseState>,
    ) -> Action {
        T::send_response_headers(self, transaction)
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

pub enum ReturnCode {
    Success,
    Error,
}

pub fn register_plugin(name: &str, vendor: &str, email: &str) -> ReturnCode {
    let name = CString::new(name.to_string()).unwrap();
    let vendor = CString::new(vendor.to_string()).unwrap();
    let email = CString::new(email.to_string()).unwrap();
    let info = TSPluginRegistrationInfo {
        plugin_name: name.as_ptr(),
        vendor_name: vendor.as_ptr(),
        support_email: email.as_ptr(),
    };
    if unsafe { TSPluginRegister(&info) } == TSReturnCode::TS_ERROR {
        return ReturnCode::Error;
    }
    ReturnCode::Success
}

pub fn register_global_hooks(hooks: Vec<Hook>, plugin: Box<dyn Plugin>) {
    // Create global continuation with a null mutex, because otherwise this will be
    // locked by every ATS thread.
    let cont = unsafe { TSContCreate(Some(handle_event), ptr::null_mut()) };
    let state = Box::new(PluginState::new(plugin));
    let cont_data = Box::into_raw(state) as *mut ffi::c_void;
    unsafe { TSContDataSet(cont, cont_data) }
    for hook in hooks {
        unsafe { TSHttpHookAdd(hook.into(), cont) };
    }
}

pub enum Hook {
    HttpReadRequestHeaders,
    HttpCacheLookup,
    HttpSendResponseHeaders,
}

impl Into<TSHttpHookID> for Hook {
    fn into(self) -> TSHttpHookID {
        match self {
            Hook::HttpReadRequestHeaders => TSHttpHookID::TS_HTTP_READ_REQUEST_HDR_HOOK,
            Hook::HttpCacheLookup => TSHttpHookID::TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK,
            Hook::HttpSendResponseHeaders => TSHttpHookID::TS_HTTP_SEND_RESPONSE_HDR_HOOK,
        }
    }
}

struct PluginState {
    plugin: Box<dyn Plugin>,
}

impl PluginState {
    fn new(plugin: Box<dyn Plugin>) -> Self {
        Self { plugin }
    }

    fn invoke_plugin(&mut self, event: TSEvent, txn: TSHttpTxn) {
        let action = match event {
            TSEvent::TS_EVENT_HTTP_READ_REQUEST_HDR => {
                let mut transaction = Transaction::new(txn, ReadRequestState::new(txn));
                self.plugin.read_request_headers(&mut transaction)
            }
            TSEvent::TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE => {
                let mut transaction = Transaction::new(txn, CacheLookupState::new(txn));
                self.plugin.cache_lookup(&mut transaction)
            }
            TSEvent::TS_EVENT_HTTP_SEND_RESPONSE_HDR => {
                let mut transaction = Transaction::new(txn, SendResponseState::new(txn));
                self.plugin.send_response_headers(&mut transaction)
            }
            _ => panic!("unknown event type: {:?}", event),
        };
        match action {
            Action::Resume => unsafe { TSHttpTxnReenable(txn, TSEvent::TS_EVENT_HTTP_CONTINUE) },
        }
    }
}

unsafe extern "C" fn handle_event(contp: TSCont, event: TSEvent, edata: *mut ffi::c_void) -> i32 {
    let cont_data = TSContDataGet(contp);
    if event == TSEvent::TS_EVENT_HTTP_TXN_CLOSE {
        TSContDestroy(contp);
        let _ = Box::from_raw(cont_data); // drop the plugin
        unsafe { TSHttpTxnReenable(edata as TSHttpTxn, TSEvent::TS_EVENT_HTTP_CONTINUE) }
        return 0;
    }

    let state: &mut PluginState = &mut *(cont_data as *mut PluginState);
    state.invoke_plugin(event, edata as TSHttpTxn);

    return 0;
}
