//! WASM request-filter plugins (B-I5/B-E4) — ADR-0031.
//!
//! One module per listener, compiled once when the configuration is resolved.
//! Every request gets a **fresh store and instance**: plugins are stateless
//! request filters in ABI v1, and no guest memory survives an exchange.
//!
//! The guest may import only the two header functions below; there is no WASI
//! and no host function that performs I/O, so network and filesystem are
//! denied by construction. Fuel bounds instructions, the epoch ticker bounds
//! wall-clock time (an infinite loop is interrupted), and `StoreLimits` bounds
//! linear memory. See ADR-0031 for the full contract.

use std::fmt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::thread::JoinHandle;
use std::time::Duration;

use wasmtime::{
    Caller, Config, Engine, Linker, Memory, Module, Store, StoreLimits, StoreLimitsBuilder, Trap,
    ValType,
};

/// Version of the guest ABI (`eqproxy_on_request` contract).
pub const ABI_VERSION: u32 = 1;
/// Largest accepted `.wasm` file, before compilation.
pub const MAX_MODULE_BYTES: u64 = 4 * 1024 * 1024;
/// Largest request head a plugin can be handed. A listener with a plugin must
/// keep `limits.max_head_bytes` at or below this value (validated).
pub const MAX_PLUGIN_INPUT: usize = 64 * 1024;

const MAX_NAME_BYTES: usize = 64;
const MAX_VALUE_BYTES: usize = 2048;
const MAX_OP_BYTES: usize = 8 * 1024;
const MAX_OPS: usize = 64;
const EPOCH_TICK: Duration = Duration::from_millis(1);

/// Framing and connection headers a plugin may not touch: rewriting them
/// after the proxy validated framing would reintroduce request smuggling.
pub const RESERVED_HEADERS: &[&str] = &[
    "content-length",
    "transfer-encoding",
    "connection",
    "host",
    "upgrade",
    "expect",
    "te",
    "trailer",
    "proxy-connection",
];

/// What happens when a plugin fails at runtime (ADR-0031 §5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum FailurePolicy {
    /// Answer 503 and never forward the request (default).
    #[default]
    Closed,
    /// Forward the request unchanged and count the failure.
    Open,
}

/// Validated plugin settings, resolved from `[listener.<name>.plugin]`.
#[derive(Debug, Clone)]
pub struct PluginSettings {
    /// Module path (relative to the configuration file's directory).
    pub path: PathBuf,
    /// Instruction budget per invocation.
    pub fuel: u64,
    /// Wall-clock bound per invocation (epoch resolution: 1 ms).
    pub timeout: Duration,
    /// Maximum linear memory per instance.
    pub memory_bytes: usize,
    /// Maximum header mutations per invocation.
    pub max_header_ops: usize,
    /// Runtime failure policy.
    pub on_error: FailurePolicy,
}

/// Result of one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PluginOutcome {
    /// Continue the request; header operations apply in order.
    Allow {
        /// Replace-or-append operations (`name`, `value`), lowercased names.
        set: Vec<(String, String)>,
        /// Header names to remove (lowercased).
        remove: Vec<String>,
    },
    /// Reject with this status (already validated to 400..=599).
    Deny(u16),
    /// The plugin could not decide: trap, fuel, deadline, memory or host
    /// validation. The listener's `on_error` policy decides what happens.
    Failed {
        /// Short, actionable reason (no guest stack trace).
        reason: String,
    },
}

impl PluginOutcome {
    /// True when the invocation produced an answer (allow or deny).
    #[must_use]
    pub fn answered(&self) -> bool {
        !matches!(self, Self::Failed { .. })
    }
}

/// Compiled plugin bound to one listener.
pub struct PluginHost {
    runtime: Arc<Runtime>,
    module: Module,
    linker: Linker<HostState>,
    settings: PluginSettings,
    path: PathBuf,
}

impl fmt::Debug for PluginHost {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PluginHost")
            .field("path", &self.path)
            .field("fuel", &self.settings.fuel)
            .field("timeout", &self.settings.timeout)
            .field("memory_bytes", &self.settings.memory_bytes)
            .field("on_error", &self.settings.on_error)
            .finish_non_exhaustive()
    }
}

/// Shared engine plus the epoch ticker thread. Dropping the last reference
/// stops the thread, so a refused configuration swap leaves no heartbeat.
struct Runtime {
    engine: Engine,
    stop: Arc<AtomicBool>,
    ticker: Option<JoinHandle<()>>,
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(ticker) = self.ticker.take()
            && ticker.join().is_err()
        {
            // The ticker only increments an atomic; a panic there is a bug,
            // but a listener being dropped cannot repair it. Report it once
            // instead of discarding the join result silently.
            eprintln!("WARN wasm plugin epoch ticker panicked");
        }
    }
}

fn new_runtime() -> Result<Arc<Runtime>, String> {
    let mut config = Config::new();
    config.consume_fuel(true);
    config.epoch_interruption(true);
    // A plugin gets the same stack a normal task would; a deep recursion must
    // trap, not abort the process (wasmtime's default guard pages still
    // apply).
    config.max_wasm_stack(512 * 1024);
    let engine = Engine::new(&config)
        .map_err(|error| format!("could not create the wasm engine: {error:#}"))?;
    let stop = Arc::new(AtomicBool::new(false));
    let ticker = {
        let engine = engine.clone();
        let stop = Arc::clone(&stop);
        std::thread::Builder::new()
            .name("eqproxy-plugin-epoch".to_owned())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    std::thread::sleep(EPOCH_TICK);
                    engine.increment_epoch();
                }
            })
            .map_err(|error| format!("could not start the epoch ticker: {error}"))?
    };
    Ok(Arc::new(Runtime {
        engine,
        stop,
        ticker: Some(ticker),
    }))
}

impl PluginHost {
    /// Loads and compiles a plugin. Every error is a configuration error: the
    /// caller rejects the snapshot instead of serving with a broken filter.
    pub fn load(settings: PluginSettings, base_dir: &Path) -> Result<Self, String> {
        let path = if settings.path.is_absolute() {
            settings.path.clone()
        } else {
            base_dir.join(&settings.path)
        };
        let metadata =
            std::fs::metadata(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        if !metadata.is_file() {
            return Err(format!("{}: not a regular file", path.display()));
        }
        if metadata.len() > MAX_MODULE_BYTES {
            return Err(format!(
                "{}: {} bytes exceeds the {MAX_MODULE_BYTES}-byte module limit",
                path.display(),
                metadata.len()
            ));
        }
        let bytes = std::fs::read(&path).map_err(|error| format!("{}: {error}", path.display()))?;
        let runtime = new_runtime()?;
        let module = Module::new(&runtime.engine, &bytes).map_err(|error| {
            format!(
                "{}: not a valid wasm module (ABI v{ABI_VERSION}): {error:#}",
                path.display()
            )
        })?;
        check_imports(&module)?;
        check_exports(&module, settings.memory_bytes)?;
        let mut linker = Linker::new(&runtime.engine);
        define_host_functions(&mut linker)?;
        Ok(Self {
            runtime,
            module,
            linker,
            settings,
            path,
        })
    }

    /// Failure policy configured for this listener.
    #[must_use]
    pub fn policy(&self) -> FailurePolicy {
        self.settings.on_error
    }

    /// Configured module path (for diagnostics/status).
    #[must_use]
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Runs the filter for one request head.
    ///
    /// This is synchronous and CPU-bound on purpose: the guest has no import
    /// that can block, and fuel/epoch interrupt a loop. See ADR-0031 §4.
    #[must_use]
    pub fn run(&self, head: &[u8]) -> PluginOutcome {
        if head.len() > MAX_PLUGIN_INPUT {
            return PluginOutcome::Failed {
                reason: format!(
                    "request head of {} bytes exceeds the {MAX_PLUGIN_INPUT}-byte plugin budget",
                    head.len()
                ),
            };
        }
        let limits = StoreLimitsBuilder::new()
            .memory_size(self.settings.memory_bytes)
            .memories(1)
            .tables(1)
            .instances(1)
            .trap_on_grow_failure(true)
            .build();
        let mut store = Store::new(
            &self.runtime.engine,
            HostState::new(limits, self.settings.max_header_ops),
        );
        store.limiter(|state| &mut state.limits);
        if let Err(error) = store.set_fuel(self.settings.fuel) {
            return PluginOutcome::Failed {
                reason: format!("could not set the fuel budget: {error:#}"),
            };
        }
        store.set_epoch_deadline(self.settings.timeout.as_millis().max(1) as u64);

        let instance = match self.linker.instantiate(&mut store, &self.module) {
            Ok(instance) => instance,
            Err(error) => {
                return PluginOutcome::Failed {
                    reason: host_error(&store, &error),
                };
            }
        };
        let alloc = match instance.get_typed_func::<i32, i32>(&mut store, "eqproxy_alloc") {
            Ok(func) => func,
            Err(error) => {
                return PluginOutcome::Failed {
                    reason: format!("missing export eqproxy_alloc: {error:#}"),
                };
            }
        };
        let call =
            match instance.get_typed_func::<(i32, i32), i32>(&mut store, "eqproxy_on_request") {
                Ok(func) => func,
                Err(error) => {
                    return PluginOutcome::Failed {
                        reason: format!("missing export eqproxy_on_request: {error:#}"),
                    };
                }
            };
        let pointer = match alloc.call(&mut store, head.len() as i32) {
            Ok(pointer) => pointer,
            Err(error) => {
                return PluginOutcome::Failed {
                    reason: host_error(&store, &error),
                };
            }
        };
        if pointer < 0 {
            return PluginOutcome::Failed {
                reason: format!("eqproxy_alloc returned a negative pointer ({pointer})"),
            };
        }
        let Some(memory) = instance.get_memory(&mut store, "memory") else {
            return PluginOutcome::Failed {
                reason: "the module has no exported memory".to_owned(),
            };
        };
        let start = pointer as usize;
        if start
            .checked_add(head.len())
            .is_none_or(|end| end > memory.data_size(&store))
        {
            return PluginOutcome::Failed {
                reason: format!(
                    "eqproxy_alloc returned out-of-bounds range at {start} for {} bytes",
                    head.len()
                ),
            };
        }
        if let Err(error) = memory.write(&mut store, start, head) {
            return PluginOutcome::Failed {
                reason: format!("could not write the request head into the plugin: {error:#}"),
            };
        }
        let status = match call.call(&mut store, (pointer, head.len() as i32)) {
            Ok(status) => status,
            Err(error) => {
                return PluginOutcome::Failed {
                    reason: host_error(&store, &error),
                };
            }
        };
        let state = store.data_mut();
        if let Some(reason) = state.error.take() {
            return PluginOutcome::Failed { reason };
        }
        let operations = std::mem::take(&mut state.operations);
        match status {
            0 => {
                let mut set = Vec::new();
                let mut remove = Vec::new();
                for operation in operations {
                    match operation {
                        HeaderOperation::Set(name, value) => set.push((name, value)),
                        HeaderOperation::Remove(name) => remove.push(name),
                    }
                }
                PluginOutcome::Allow { set, remove }
            }
            status if (400..=599).contains(&status) => PluginOutcome::Deny(status as u16),
            status => PluginOutcome::Failed {
                reason: format!(
                    "eqproxy_on_request returned {status}; expected 0 (continue) or 400..=599 (reject)"
                ),
            },
        }
    }
}

/// Guest-side header mutation collected during one invocation.
#[derive(Debug, Clone, PartialEq, Eq)]
enum HeaderOperation {
    Set(String, String),
    Remove(String),
}

struct HostState {
    limits: StoreLimits,
    max_ops: usize,
    operations: Vec<HeaderOperation>,
    operation_bytes: usize,
    error: Option<String>,
}

impl HostState {
    fn new(limits: StoreLimits, max_ops: usize) -> Self {
        Self {
            limits,
            max_ops: max_ops.clamp(1, MAX_OPS),
            operations: Vec::new(),
            operation_bytes: 0,
            error: None,
        }
    }

    fn push(&mut self, operation: HeaderOperation) -> Result<(), String> {
        if self.operations.len() >= self.max_ops {
            return Err(format!("plugin exceeded max_header_ops ({})", self.max_ops));
        }
        let bytes = match &operation {
            HeaderOperation::Set(name, value) => name.len() + value.len(),
            HeaderOperation::Remove(name) => name.len(),
        };
        self.operation_bytes = self
            .operation_bytes
            .checked_add(bytes)
            .ok_or_else(|| "plugin header mutation size overflowed".to_owned())?;
        if self.operation_bytes > MAX_OP_BYTES {
            return Err(format!(
                "plugin header mutations exceed {MAX_OP_BYTES} bytes"
            ));
        }
        self.operations.push(operation);
        Ok(())
    }
}

fn is_tchar(byte: u8) -> bool {
    byte.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&byte)
}

fn validate_name(name: &str) -> Result<(), String> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(format!("header name must be 1..={MAX_NAME_BYTES} bytes"));
    }
    if !name.bytes().all(is_tchar) {
        return Err("header name contains a byte outside the HTTP token set".to_owned());
    }
    if RESERVED_HEADERS.contains(&name) {
        return Err(format!(
            "header {name:?} is reserved: a plugin cannot change framing or connection headers"
        ));
    }
    Ok(())
}

fn validate_value(value: &str) -> Result<(), String> {
    if value.len() > MAX_VALUE_BYTES {
        return Err(format!("header value exceeds {MAX_VALUE_BYTES} bytes"));
    }
    if value.bytes().any(|byte| {
        byte == b'\r'
            || byte == b'\n'
            || byte == 0
            || (byte < 0x20 && byte != b'\t')
            || byte == 0x7f
    }) {
        return Err("header value contains a control character".to_owned());
    }
    Ok(())
}

fn guest_memory(caller: &mut Caller<'_, HostState>) -> Result<Memory, wasmtime::Error> {
    caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
        .ok_or_else(|| wasmtime::Error::msg("plugin has no exported memory"))
}

fn read_bytes(
    caller: &mut Caller<'_, HostState>,
    pointer: i32,
    length: i32,
    what: &str,
    maximum: usize,
) -> Result<Vec<u8>, wasmtime::Error> {
    if pointer < 0 || length < 0 {
        return Err(wasmtime::Error::msg(format!(
            "{what}: negative pointer or length"
        )));
    }
    let length = length as usize;
    if length > maximum {
        return Err(wasmtime::Error::msg(format!(
            "{what}: {length} bytes exceeds the {maximum}-byte limit"
        )));
    }
    let memory = guest_memory(caller)?;
    let start = pointer as usize;
    let end = start
        .checked_add(length)
        .ok_or_else(|| wasmtime::Error::msg(format!("{what}: pointer overflow")))?;
    let data = memory.data(&*caller);
    if end > data.len() {
        return Err(wasmtime::Error::msg(format!(
            "{what}: range {start}..{end} is outside the {} -byte memory",
            data.len()
        )));
    }
    Ok(data[start..end].to_vec())
}

fn read_text(
    caller: &mut Caller<'_, HostState>,
    pointer: i32,
    length: i32,
    what: &str,
    maximum: usize,
) -> Result<String, wasmtime::Error> {
    let bytes = read_bytes(caller, pointer, length, what, maximum)?;
    String::from_utf8(bytes).map_err(|_| wasmtime::Error::msg(format!("{what}: not valid UTF-8")))
}

fn define_host_functions(linker: &mut Linker<HostState>) -> Result<(), String> {
    linker
        .func_wrap(
            "eqproxy",
            "set_request_header",
            |mut caller: Caller<'_, HostState>,
             name_pointer: i32,
             name_length: i32,
             value_pointer: i32,
             value_length: i32|
             -> Result<(), wasmtime::Error> {
                let name = read_text(
                    &mut caller,
                    name_pointer,
                    name_length,
                    "set_request_header name",
                    MAX_NAME_BYTES,
                )?;
                let value = read_text(
                    &mut caller,
                    value_pointer,
                    value_length,
                    "set_request_header value",
                    MAX_VALUE_BYTES,
                )?;
                let name = name.to_ascii_lowercase();
                let outcome = validate_name(&name)
                    .and_then(|()| validate_value(&value))
                    .and_then(|()| caller.data_mut().push(HeaderOperation::Set(name, value)));
                record_or_trap(caller, outcome)
            },
        )
        .map_err(|error| format!("could not define set_request_header: {error:#}"))?;
    linker
        .func_wrap(
            "eqproxy",
            "remove_request_header",
            |mut caller: Caller<'_, HostState>,
             name_pointer: i32,
             name_length: i32|
             -> Result<(), wasmtime::Error> {
                let name = read_text(
                    &mut caller,
                    name_pointer,
                    name_length,
                    "remove_request_header name",
                    MAX_NAME_BYTES,
                )?;
                let name = name.to_ascii_lowercase();
                let outcome = validate_name(&name)
                    .and_then(|()| caller.data_mut().push(HeaderOperation::Remove(name)));
                record_or_trap(caller, outcome)
            },
        )
        .map_err(|error| format!("could not define remove_request_header: {error:#}"))?;
    Ok(())
}

/// A host validation error traps the guest (fail policy applies) and keeps the
/// clean reason in the store so the caller does not have to parse a wasm
/// backtrace.
fn record_or_trap(
    mut caller: Caller<'_, HostState>,
    outcome: Result<(), String>,
) -> Result<(), wasmtime::Error> {
    match outcome {
        Ok(()) => Ok(()),
        Err(reason) => {
            caller.data_mut().error = Some(reason.clone());
            Err(wasmtime::Error::msg(reason))
        }
    }
}

fn check_imports(module: &Module) -> Result<(), String> {
    for import in module.imports() {
        let module_name = import.module();
        let name = import.name();
        if module_name == "eqproxy"
            && matches!(name, "set_request_header" | "remove_request_header")
        {
            continue;
        }
        return Err(format!(
            "imports {module_name}.{name}: denied. Capabilities are deny-by-default: \
             ABI v{ABI_VERSION} exposes only eqproxy.set_request_header and \
             eqproxy.remove_request_header — no WASI, network or filesystem"
        ));
    }
    Ok(())
}

fn check_exports(module: &Module, memory_bytes: usize) -> Result<(), String> {
    match module.get_export("eqproxy_on_request") {
        Some(wasmtime::ExternType::Func(func))
            if matches!(
                func.params().collect::<Vec<_>>().as_slice(),
                [ValType::I32, ValType::I32]
            ) && matches!(
                func.results().collect::<Vec<_>>().as_slice(),
                [ValType::I32]
            ) => {}
        _ => {
            return Err(format!(
                "missing or wrong export eqproxy_on_request: expected (i32, i32) -> i32 (ABI v{ABI_VERSION})"
            ));
        }
    }
    match module.get_export("eqproxy_alloc") {
        Some(wasmtime::ExternType::Func(func))
            if matches!(func.params().collect::<Vec<_>>().as_slice(), [ValType::I32])
                && matches!(
                    func.results().collect::<Vec<_>>().as_slice(),
                    [ValType::I32]
                ) => {}
        _ => {
            return Err(format!(
                "missing or wrong export eqproxy_alloc: expected (i32) -> i32 (ABI v{ABI_VERSION})"
            ));
        }
    }
    match module.get_export("memory") {
        Some(wasmtime::ExternType::Memory(memory)) => {
            let minimum = memory.minimum().saturating_mul(65_536);
            if minimum > memory_bytes as u64 {
                return Err(format!(
                    "module needs at least {minimum} bytes of memory but memory_bytes = {memory_bytes}"
                ));
            }
        }
        _ => return Err("missing export memory".to_owned()),
    }
    Ok(())
}

/// Short reason for a failed call: the host's own validation when present,
/// otherwise the wasm trap class.
fn host_error(store: &Store<HostState>, error: &wasmtime::Error) -> String {
    if let Some(reason) = store.data().error.as_ref() {
        return reason.clone();
    }
    if let Some(trap) = error.downcast_ref::<Trap>() {
        return match trap {
            Trap::OutOfFuel => "fuel exhausted".to_owned(),
            Trap::Interrupt => "deadline exceeded".to_owned(),
            other => format!("wasm trap: {other}"),
        };
    }
    format!("{error:#}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Fixtures are real `.wasm` modules committed next to their `.wat`
    /// source; the test loads exactly the bytes the proxy loads at runtime.
    fn fixture(name: &str) -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("tests/fixtures/plugins")
            .join(name)
    }

    fn settings(name: &str) -> PluginSettings {
        PluginSettings {
            path: fixture(name),
            fuel: 10_000_000,
            timeout: Duration::from_millis(50),
            memory_bytes: 16 * 1024 * 1024,
            max_header_ops: 16,
            on_error: FailurePolicy::Closed,
        }
    }

    fn load(name: &str) -> PluginHost {
        PluginHost::load(settings(name), Path::new(".")).expect("fixture loads")
    }

    #[test]
    fn allow_reports_the_header_operations_the_guest_requested() {
        let host = load("add_header.wasm");
        assert_eq!(
            host.run(b"GET / HTTP/1.1\r\nhost: a\r\n"),
            PluginOutcome::Allow {
                set: vec![("x-plugin".to_owned(), "on".to_owned())],
                remove: Vec::new(),
            }
        );
    }

    #[test]
    fn a_verdict_of_403_is_a_denial_with_that_status() {
        let host = load("deny_403.wasm");
        assert_eq!(
            host.run(b"GET / HTTP/1.1\r\nhost: a\r\n"),
            PluginOutcome::Deny(403)
        );
    }

    #[test]
    fn fuel_exhaustion_interrupts_an_infinite_loop() {
        let mut resolved = settings("spin.wasm");
        resolved.fuel = 10_000;
        resolved.timeout = Duration::from_secs(5);
        let host = PluginHost::load(resolved, Path::new(".")).expect("loads");
        match host.run(b"GET / HTTP/1.1\r\nhost: a\r\n") {
            PluginOutcome::Failed { reason } => {
                assert!(reason.contains("fuel"), "unexpected reason: {reason}");
            }
            other => panic!("expected a fuel failure, got {other:?}"),
        }
    }

    #[test]
    fn the_epoch_deadline_interrupts_a_loop_with_plenty_of_fuel() {
        let mut resolved = settings("spin.wasm");
        resolved.fuel = 100_000_000;
        resolved.timeout = Duration::from_millis(5);
        let host = PluginHost::load(resolved, Path::new(".")).expect("loads");
        match host.run(b"GET / HTTP/1.1\r\nhost: a\r\n") {
            PluginOutcome::Failed { reason } => {
                assert!(reason.contains("deadline"), "unexpected reason: {reason}");
            }
            other => panic!("expected a deadline failure, got {other:?}"),
        }
    }

    #[test]
    fn wasi_imports_are_denied_at_load_and_named() {
        let error = PluginHost::load(settings("wasi_import.wasm"), Path::new("."))
            .expect_err("WASI must not be linked");
        assert!(
            error.contains("wasi_snapshot_preview1.fd_write"),
            "the denied import is named: {error}"
        );
        assert!(error.contains("deny-by-default"), "{error}");
    }

    #[test]
    fn a_reserved_framing_header_is_a_host_error() {
        let host = load("reserved_header.wasm");
        match host.run(b"GET / HTTP/1.1\r\nhost: a\r\n") {
            PluginOutcome::Failed { reason } => {
                assert!(reason.contains("reserved"), "unexpected reason: {reason}");
            }
            other => panic!("expected a reserved-header failure, got {other:?}"),
        }
    }

    #[test]
    fn a_memory_growth_over_the_bound_traps() {
        let mut resolved = settings("grow.wasm");
        resolved.memory_bytes = 1024 * 1024;
        let host = PluginHost::load(resolved, Path::new(".")).expect("loads");
        assert!(
            matches!(
                host.run(b"GET / HTTP/1.1\r\nhost: a\r\n"),
                PluginOutcome::Failed { .. }
            ),
            "growing past memory_bytes must interrupt the call"
        );
    }

    #[test]
    fn a_module_without_the_abi_exports_is_rejected_at_load() {
        let error = PluginHost::load(settings("no_abi_exports.wasm"), Path::new("."))
            .expect_err("eqproxy_on_request is required");
        assert!(error.contains("eqproxy_on_request"), "{error}");
    }

    #[test]
    fn a_module_whose_initial_memory_exceeds_the_bound_is_rejected_at_load() {
        let mut resolved = settings("huge_memory.wasm");
        resolved.memory_bytes = 1024 * 1024;
        let error =
            PluginHost::load(resolved, Path::new(".")).expect_err("64 pages do not fit in 1 MiB");
        assert!(error.contains("memory_bytes"), "{error}");
    }
}
