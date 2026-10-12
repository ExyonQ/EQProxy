# EQProxy

Proxy inverso TCP/HTTP de observabilidad mínima, escrito en Rust seguro
(`#![forbid(unsafe_code)]`).

## Estado

Fase 2a — proxy HTTP/1.1 real (framing estricto, timeouts por fase,
cancelación por señal). Consulta [SPEC.md](SPEC.md) para el comportamiento
especificado, [PARITY_MATRIX.md](PARITY_MATRIX.md) para la paridad con el
conversor de referencia y [ROADMAP.md](ROADMAP.md) para el plan.

## Compilar

```bash
cargo build --release --locked
```

Binario: `target/release/eqproxy`.

## Uso rápido

```bash
# Validar una configuración
eqproxy config check --config eqproxy.toml

# Convertir un config-de-referencia al formato canónico TOML
eqproxy config import ref --input config-de-referencia --output eqproxy.toml

# Arrancar el proxy
eqproxy serve --config eqproxy.toml
```

Formato canónico documentado en [docs/adr/0002-formato-configuracion.md](docs/adr/0002-formato-configuracion.md);
el ejemplo completo vive en [eqproxy.toml.example](eqproxy.toml.example).

## Contenedor

Multi-arquitectura (linux/amd64, linux/arm64) en
`ghcr.io/ExyonQ/eqproxy`:

```bash
docker run --rm ghcr.io/ExyonQ/eqproxy --help
```

## Limitaciones conocidas (documentadas, no ocultas)

### cargo-geiger: inventario incompleto de `unsafe` (INCONCLUSIVE)

`cargo geiger` termina con `error: Found N warnings` porque no alcanza
algunos ficheros de dependencias. **No es un pass** (criterio de Veyra
Proof). Causas raíz, todas upstream de cargo-geiger (probado en 0.13.0,
0.14.0 y git main `#118a9a28`; el pin de `signal-hook-registry` a 1.4.7
da el mismo fallo):

1. Su parser (syn) no traga la sintaxis de `signal-hook-registry`
   ([cargo-geiger#240](https://github.com/geiger-rs/cargo-geiger/issues/240)).
2. Declara «never scanned» ficheros que rustc lista en dep-info pero no
   son escaneables: markdown incluido con `include_str!` (clap) y
   `private.rs` generados por build-scripts e `include!`-ados
   (serde/serde_core/thiserror)
   ([#145](https://github.com/geiger-rs/cargo-geiger/issues/145),
   [#577](https://github.com/geiger-rs/cargo-geiger/issues/577)).

**Compensación verificada manualmente** (el hueco exacto del inventario):

| Fichero no escaneado | Construcciones `unsafe` |
|---|---|
| `signal-hook-registry-1.4.8/src/lib.rs` | 30 (FFI de señales unix de tokio) |
| `errno-0.3.14/src/unix.rs` | 4 |
| `errno-0.3.14/src/lib.rs` | 0 |
| `private.rs` generados (serde, serde_core, thiserror) | 0 |
| markdown de clap (no es código) | — |

El `unsafe` del workspace propio sigue prohibido por
`#![forbid(unsafe_code)]`; el hueco está en el FFI de señales de las
dependencias, inventariado arriba.

### Miri: 22 tests no ejecutados (20 imposibles + 2 de coste)

Miri **no emula red ni procesos**
([rust-lang/miri#3449](https://github.com/rust-lang/miri/issues/3449),
README de Miri): los 14 tests e2e de sockets y los 6 de procesos son
imposibles bajo cualquier flag. Otros 2 tests (aceptar config de 1 MiB
exacta) quedan excluidos por coste medido: >8 min de parse interpretado
por test, con la frontera cubierta por la suite normal y la CI. El resto
corre bajo miri, incluidos 4 tests de runtime tokio reescritos para usar
un runtime sin driver IO (mio/kqueue sí es FFI no emulado en macOS,
[#4007](https://github.com/rust-lang/miri/issues/4007)).

## Proceso de desarrollo

Cada funcionalidad sigue el proceso obligatorio de [AGENTS.md](AGENTS.md):
auditoría Veyra Proof con evidencia reproducible antes de cerrar.
