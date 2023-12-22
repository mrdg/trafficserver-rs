use std::{
    any::Any,
    cell::OnceCell,
    collections::HashSet,
    ffi::{self, CString},
    marker::PhantomData,
    ptr,
    rc::Rc,
    slice, str,
};

pub use trafficserver_sys::TSDebug;
pub use trafficserver_sys::TSHttpStatus as HttpStatus;

use trafficserver_sys::{
    TSCacheLookupResult, TSCacheUrlSet, TSCont, TSContCreate, TSContDataGet, TSContDataSet,
    TSContDestroy, TSEvent, TSHandleMLocRelease, TSHttpHdrStatusGet, TSHttpHookAdd, TSHttpHookID,
    TSHttpTxn, TSHttpTxnCacheLookupStatusGet, TSHttpTxnCacheLookupStatusSet, TSHttpTxnCachedReqGet,
    TSHttpTxnCachedRespGet, TSHttpTxnClientReqGet, TSHttpTxnClientRespGet,
    TSHttpTxnEffectiveUrlStringGet, TSHttpTxnHookAdd, TSHttpTxnReenable, TSHttpTxnServerRespGet,
    TSMBuffer, TSMLoc, TSMimeHdrFieldAppend, TSMimeHdrFieldCreate, TSMimeHdrFieldDestroy,
    TSMimeHdrFieldFind, TSMimeHdrFieldGet, TSMimeHdrFieldNameGet, TSMimeHdrFieldNameSet,
    TSMimeHdrFieldNext, TSMimeHdrFieldNextDup, TSMimeHdrFieldValueStringGet,
    TSMimeHdrFieldValueStringInsert, TSMimeHdrFieldsCount, TSPluginRegister,
    TSPluginRegistrationInfo, TSReturnCode, _TSfree,
};

type EventHandler = fn(Cont, TSEvent, *mut ffi::c_void) -> ReturnCode;

unsafe extern "C" fn handle_event(contp: TSCont, event: TSEvent, edata: *mut ffi::c_void) -> i32 {
    let ptr = TSContDataGet(contp);
    let cont_data = &mut *(ptr as *mut ContData);
    let cont = Cont::from_raw(contp);
    (cont_data.handler)(cont, event, edata).into()
}

struct ContData {
    handler: EventHandler,
    user_data: Option<Box<dyn Any>>,
}

struct Cont {
    ptr: TSCont,
}

impl Cont {
    fn from_raw(ptr: TSCont) -> Self {
        Self { ptr }
    }

    fn new<T: 'static>(handler: EventHandler, data: T) -> Self {
        let cont_data = Box::new(ContData {
            handler,
            user_data: Some(Box::new(data)),
        });
        let contp = unsafe {
            let ptr = TSContCreate(Some(handle_event), ptr::null_mut());
            TSContDataSet(ptr, Box::into_raw(cont_data) as *mut ffi::c_void);
            ptr
        };
        Self::from_raw(contp)
    }

    fn data<T: 'static>(&mut self) -> Option<&mut T> {
        let cont_data = unsafe {
            let ptr = TSContDataGet(self.ptr);
            &mut *(ptr as *mut ContData)
        };
        cont_data.user_data.as_mut().and_then(|d| d.downcast_mut())
    }

    fn destroy(self) {
        unsafe {
            let ptr = TSContDataGet(self.ptr);
            let _ = Box::from_raw(ptr as *mut ContData);
            TSContDestroy(self.ptr);
        }
    }
}

pub struct Response {
    status: HttpStatus,
    pub headers: Headers,
}

impl Response {
    fn new(txn: TxHandle, header_init: HeaderInitFn) -> Self {
        let headers = init_headers(txn, header_init).unwrap();
        let status = unsafe { TSHttpHdrStatusGet(headers.buf, headers.loc) };
        Self { status, headers }
    }

    pub fn status(&self) -> HttpStatus {
        self.status
    }
}

pub struct Request {
    pub headers: Headers,
}

impl Request {
    fn new(txn: TxHandle, header_init: HeaderInitFn) -> Self {
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
    pub fn iter(&self) -> impl Iterator<Item = HeaderField> {
        let field_loc = unsafe { TSMimeHdrFieldGet(self.buf, self.loc, 0) };
        let handle = Rc::new(HeaderFieldHandle::new(self, field_loc));
        HeaderIter::new(handle, TSMimeHdrFieldNext)
    }

    // Iterates over all header fields with the specified key. The key comparison is case
    // insensitive
    pub fn find(&self, key: &str) -> impl Iterator<Item = HeaderField> {
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

mod private {
    pub trait State {}
}

pub trait State: private::State {}

macro_rules! define_states {
    ($($s:ident),* $(,)?) => {
        $(
            pub struct $s;
            impl private::State for $s {}
            impl State for $s {}
        )*
    }
}

macro_rules! group_states {
    ($name:ident, [$($x:ident),*]) => {
        pub trait $name: State {}
        $(impl $name for $x {})*
    };
}

define_states![
    ReadRequestState,
    ReadRequestPreRemap,
    ReadRequestPostRemap,
    CacheLookupState,
    ReadCachedHeaderState,
    SendRequestState,
    OsDnsState,
    ReadResponseState,
    SendResponseState,
    TransactionCloseState,
];

group_states!(
    PreCache,
    [ReadRequestState, ReadRequestPreRemap, ReadRequestPostRemap]
);
group_states!(
    PostCache,
    [
        CacheLookupState,
        ReadCachedHeaderState,
        OsDnsState,
        SendRequestState,
        ReadResponseState,
        SendResponseState,
        TransactionCloseState
    ]
);

#[derive(Clone, Copy, Debug)]
pub struct TxHandle(TSHttpTxn);

impl TxHandle {
    fn resume(&mut self) {
        unsafe { TSHttpTxnReenable(self.0, TSEvent::TS_EVENT_HTTP_CONTINUE) };
    }

    fn add_hook(&mut self, hook: HttpHook, cont: &Cont) {
        unsafe { TSHttpTxnHookAdd(self.0, hook.into(), cont.ptr) }
    }
}

pub struct Transaction<'a, S: State> {
    txn: TxHandle,
    inner: &'a mut TransactionInner,
    state: PhantomData<S>,
}

impl<'a, S: State> Transaction<'a, S> {
    fn new(txn: TxHandle, inner: &'a mut TransactionInner) -> Transaction<'a, S> {
        Self {
            txn,
            inner,
            state: Default::default(),
        }
    }

    pub fn add_plugin<P: PluginMut + 'static>(&mut self, mut hooks: HashSet<HttpHook>, plugin: P) {
        let mut plugin_state = PluginState::new(Box::new(plugin));
        plugin_state.txn_close_hook = hooks.contains(&HttpHook::TransactionClose);
        hooks.insert(HttpHook::TransactionClose);
        let cont = Cont::new(handle_transaction_event, plugin_state);
        for hook in hooks {
            self.txn.add_hook(hook, &cont);
        }
    }

    pub fn client_request(&self) -> &Request {
        self.inner.set_client_request(self.txn);
        self.inner.client_request.get().unwrap()
    }

    pub fn client_request_mut(&mut self) -> &mut Request {
        self.inner.set_client_request(self.txn);
        self.inner.client_request.get_mut().unwrap()
    }

    pub fn effective_url(&self) -> String {
        let mut length: ffi::c_int = 0;
        let bytes = unsafe {
            let buf = TSHttpTxnEffectiveUrlStringGet(self.txn.0, &mut length);
            let bytes = slice::from_raw_parts::<u8>(buf as *const u8, length as usize).to_owned();
            _TSfree(buf as *mut ffi::c_void);
            bytes
        };
        String::from_utf8(bytes).ok().unwrap()
    }
}

fn handle_transaction_event(mut cont: Cont, event: TSEvent, edata: *mut ffi::c_void) -> ReturnCode {
    let state = cont.data::<PluginState>().unwrap();
    let mut tx_handle = TxHandle(edata as TSHttpTxn);

    if event == TSEvent::TS_EVENT_HTTP_TXN_CLOSE {
        if state.txn_close_hook {
            state.plugin.handle_event(HttpEvent::TransactionClose);
        }
        tx_handle.resume();
        cont.destroy();
        return ReturnCode::Success;
    }

    let event = match event {
        TSEvent::TS_EVENT_HTTP_READ_REQUEST_HDR => {
            let tx = Transaction::new(tx_handle, &mut state.tx_inner);
            HttpEvent::ReadRequestHeader(tx)
        }
        TSEvent::TS_EVENT_HTTP_SEND_RESPONSE_HDR => {
            let tx = Transaction::new(tx_handle, &mut state.tx_inner);
            HttpEvent::SendResponseHeader(tx)
        }
        TSEvent::TS_EVENT_HTTP_CACHE_LOOKUP_COMPLETE => {
            let tx = Transaction::new(tx_handle, &mut state.tx_inner);
            HttpEvent::CacheLookupComplete(tx)
        }
        _ => panic!("unhandled event {:?}", event),
    };

    match state.plugin.handle_event(event) {
        Action::Resume => tx_handle.resume(),
    }
    ReturnCode::Success
}

impl<S: PreCache> Transaction<'_, S> {
    pub fn set_cache_url(&mut self, url: &str) -> ReturnCode {
        let res = unsafe { TSCacheUrlSet(self.txn.0, url.as_ptr() as *const i8, url.len() as i32) };
        res.into()
    }
}

impl<S: PostCache> Transaction<'_, S> {
    pub fn cache_status(&self) -> &CacheStatus {
        self.inner.set_cache_status(self.txn);
        self.inner.cache_status.get().unwrap()
    }
}

impl Transaction<'_, CacheLookupState> {
    pub fn set_cache_status(&mut self, status: CacheStatusOverride) -> ReturnCode {
        self.inner.set_cache_status(self.txn);
        let cache_status = self.inner.cache_status.get_mut().unwrap();
        set_cache_status(self.txn, cache_status, status)
    }
}

impl Transaction<'_, ReadResponseState> {
    pub fn server_response(&self) -> &Response {
        self.inner.set_server_response(self.txn);
        self.inner.server_response.get().unwrap()
    }

    pub fn server_response_mut(&mut self) -> &mut Response {
        self.inner.set_server_response(self.txn);
        self.inner.server_response.get_mut().unwrap()
    }
}

impl Transaction<'_, SendResponseState> {
    pub fn client_response(&self) -> &Response {
        self.inner.set_client_response(self.txn);
        self.inner.client_response.get().unwrap()
    }

    pub fn client_response_mut(&mut self) -> &mut Response {
        self.inner.set_client_response(self.txn);
        self.inner.client_response.get_mut().unwrap()
    }
}

struct TransactionInner {
    client_request: OnceCell<Request>,
    client_response: OnceCell<Response>,
    server_response: OnceCell<Response>,
    cache_status: OnceCell<CacheStatus>,
}

impl TransactionInner {
    fn new() -> Self {
        TransactionInner {
            client_request: OnceCell::new(),
            client_response: OnceCell::new(),
            server_response: OnceCell::new(),
            cache_status: OnceCell::new(),
        }
    }

    fn set_client_request(&self, txn: TxHandle) {
        self.client_request
            .get_or_init(|| Request::new(txn, TSHttpTxnClientReqGet));
    }

    fn set_client_response(&self, txn: TxHandle) {
        self.client_response
            .get_or_init(|| Response::new(txn, TSHttpTxnClientRespGet));
    }

    fn set_server_response(&self, txn: TxHandle) {
        self.server_response
            .get_or_init(|| Response::new(txn, TSHttpTxnServerRespGet));
    }

    fn set_cache_status(&self, txn: TxHandle) {
        self.cache_status.get_or_init(|| cache_lookup_status(txn));
    }
}

pub struct CacheEntry {
    pub request: Request,
    pub response: Response,
}

impl CacheEntry {
    fn new(txn: TxHandle) -> Self {
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

fn set_cache_status(txn: TxHandle, current: &CacheStatus, new: CacheStatusOverride) -> ReturnCode {
    use CacheStatusOverride::*;
    let status = match new {
        HitFresh | HitStale if !current.has_cache_entry() => {
            return ReturnCode::Error;
        }
        HitStale => TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_STALE,
        HitFresh => TSCacheLookupResult::TS_CACHE_LOOKUP_HIT_FRESH,
        Miss => TSCacheLookupResult::TS_CACHE_LOOKUP_MISS,
    };
    let res = unsafe { TSHttpTxnCacheLookupStatusSet(txn.0, status.0 as i32) };
    res.into()
}

fn cache_lookup_status(txn: TxHandle) -> CacheStatus {
    let mut cache_status: ffi::c_int = 0;
    let res = unsafe { TSHttpTxnCacheLookupStatusGet(txn.0, &mut cache_status) };
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

fn init_headers(txn: TxHandle, init: HeaderInitFn) -> Option<Headers> {
    let mut buf: TSMBuffer = ptr::null_mut();
    let mut loc: TSMLoc = ptr::null_mut();
    if unsafe { init(txn.0, &mut buf, &mut loc) } != TSReturnCode::TS_SUCCESS {
        return None;
    }
    Some(Headers::new(buf, loc))
}

pub enum Action {
    Resume,
}

pub enum HttpEvent<'a> {
    ReadRequestHeader(Transaction<'a, ReadRequestState>),
    CacheLookupComplete(Transaction<'a, CacheLookupState>),
    SendResponseHeader(Transaction<'a, SendResponseState>),
    TransactionClose,
}

pub trait PluginMut: Sync + Send {
    fn handle_event(&mut self, event: HttpEvent) -> Action;
}

pub trait Plugin: Sync + Send {
    fn handle_event(&self, event: HttpEvent) -> Action;
}

impl<T: Plugin> PluginMut for T {
    fn handle_event(&mut self, event: HttpEvent) -> Action {
        T::handle_event(self, event)
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

impl From<ReturnCode> for TSReturnCode {
    fn from(value: ReturnCode) -> Self {
        match value {
            ReturnCode::Success => TSReturnCode::TS_SUCCESS,
            ReturnCode::Error => TSReturnCode::TS_ERROR,
        }
    }
}

impl From<TSReturnCode> for ReturnCode {
    fn from(value: TSReturnCode) -> Self {
        match value {
            TSReturnCode::TS_ERROR => ReturnCode::Error,
            TSReturnCode::TS_SUCCESS => ReturnCode::Success,
            _ => unreachable!(),
        }
    }
}

impl From<ReturnCode> for i32 {
    fn from(value: ReturnCode) -> Self {
        match value {
            ReturnCode::Success => 0,
            ReturnCode::Error => 1,
        }
    }
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

pub fn add_http_hooks<P: Plugin + 'static>(hooks: HashSet<HttpHook>, plugin: P) {
    let plugin_state = PluginState::new(Box::new(plugin));
    let cont = Cont::new(handle_transaction_event, plugin_state);
    for hook in hooks {
        unsafe { TSHttpHookAdd(hook.into(), cont.ptr) };
    }
}

#[derive(PartialEq, Eq, Hash)]
pub enum HttpHook {
    ReadRequestHeaders,
    CacheLookup,
    SendResponseHeaders,
    TransactionClose,
}

impl From<HttpHook> for TSHttpHookID {
    fn from(hook: HttpHook) -> Self {
        match hook {
            HttpHook::ReadRequestHeaders => TSHttpHookID::TS_HTTP_READ_REQUEST_HDR_HOOK,
            HttpHook::CacheLookup => TSHttpHookID::TS_HTTP_CACHE_LOOKUP_COMPLETE_HOOK,
            HttpHook::SendResponseHeaders => TSHttpHookID::TS_HTTP_SEND_RESPONSE_HDR_HOOK,
            HttpHook::TransactionClose => TSHttpHookID::TS_HTTP_TXN_CLOSE_HOOK,
        }
    }
}

struct PluginState {
    plugin: Box<dyn PluginMut>,
    tx_inner: TransactionInner,
    txn_close_hook: bool,
}

impl PluginState {
    fn new(plugin: Box<dyn PluginMut>) -> Self {
        Self {
            plugin,
            tx_inner: TransactionInner::new(),
            txn_close_hook: false,
        }
    }
}
