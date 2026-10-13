# ADR-0003: Multi-version reference and citation policy

Language: **English** · [Español](#español)

- State: **Accepted** (Phase 0, project lead's decision)
- Date: 2026-10-12
- Related: parity matrix (internal documentation), [BENCHMARK_PLAN.md](../../BENCHMARK_PLAN.md)

## Context

The brief requires pinning a specific stable version of the reference proxy and
recording version, date, edition, build options, platform and official
documentation. The installed base is heterogeneous: there are deployments on
old LTS branches (2.8, 3.0) alongside the most recent ones (3.2, 3.4). A single
reference would poorly cover legacy-branch users.

## Decision

**Multi-version matrix** (project lead's decision, 2026-10-12):

| Role | Pinned version | Release date | Branch state | Documentation used |
|---|---|---|---|---|
| Primary reference | **3.4.6 OSS** | 2026-09-28 | LTS, EOL expected 2031-Q2 | official 3.4 documentation |
| Legacy reference | **3.0.29 OSS** | 2026-09-28 | LTS, EOL expected 2029-Q2 | official 3.0 documentation |

- **Edition:** Community/OSS, **the only edition in parity scope** (user
  decision, 2026-10-12). The commercial editions of the reference proxy
  (Enterprise, the One platform, ALOHA, Fusion) are **excluded**: the exclusion
  is only documented in the parity matrix (internal documentation), with no
  equivalent goals.
- **Reference build options:** the Community Edition build
  (`TARGET=linux-glibc CPU=generic USE_PCRE2=1 USE_PCRE2_JIT=1 USE_TFO=1
  USE_LINUX_TPROXY=1 USE_LUA=1 USE_GETADDRINFO=1 USE_PROMEX=1 USE_SLZ=1
  USE_OPENSSL_AWSLC=1 USE_PTHREAD_EMULATION=1 USE_QUIC=1`) per the reference's
  official Dockerfile (3.4). For benchmarks the real `-vv` output of the binary
  used is **always** recorded (flags vary by distribution).
- **Reference platform:** Linux x86_64 glibc (matches ADR-0001).
- **Primary semantics source:** the official 3.4 and 3.0 configuration
  documentation (plus the official changelogs and the reference's source
  repository). The concrete URLs live in the project's internal documentation.

## Citation policy (mandatory across the project)

1. Every claim about the reference proxy's capabilities carries an official URL
   and the version it applies to.
2. If a capability differs between 3.0 and 3.4, the matrix records **both**
   semantics and EQProxy declares which one it preserves.
3. Anything not verified against official sources is marked **"unverified"**.
   A gap is never filled with assumptions.
4. Third-party sources (blogs, forums) only count for *user pain points*
   (internal documentation), never to assert product semantics.
5. Reference proxy version policy (verified fact): even-numbered branches are
   LTS with ~5 years of maintenance; odd ones, 12–18 months.

## Alternatives considered

1. **3.4.6 LTS only:** simpler, but it ignores the 3.0 installed base and
   loses the ability to detect semantics that changed between branches.
   Rejected by user decision.
2. **Matrix of all live branches (2.8, 3.0, 3.2, 3.3, 3.4):** disproportionate
   documentation cost. Branches 2.6/2.8 are in "critical fixes only" and 2.4
   is unmaintained; they create no parity commitment.

## Consequences

- The matrix's documentation cost partially doubles; it is mitigated with a
  "Ref. version" column per row and explicit "both" marks when semantics
  match.
- Comparative benchmarks pin 3.4.6 as the main opponent; 3.0.29 is used only
  for declared compatibility/regression scenarios.
- If the reference publishes a new LTS, an ADR is opened to decide whether to
  rotate the primary reference; it is never changed silently.

---

# Español

Idioma: [English](#adr-0003-multi-version-reference-and-citation-policy) · **Español**

- Estado: **Aceptado** (Fase 0, decisión del responsable del proyecto)
- Fecha: 2026-10-12
- Relacionado: matriz de paridad (documentación interna), [BENCHMARK_PLAN.md](../../BENCHMARK_PLAN.md)

## Contexto

El brief exige fijar una versión estable concreta del proxy de referencia y
registrar versión, fecha, edición, opciones de compilación, plataforma y
documentación oficial. La realidad de la base instalada es heterogénea: existen
despliegues en ramas LTS antiguas (2.8, 3.0) junto a los más recientes (3.2,
3.4). Una referencia única cubriría mal a los usuarios de ramas legacy.

## Decisión

**Matriz multi-versión** (decisión del responsable del proyecto, 2026-10-12):

| Rol | Versión fijada | Fecha de publicación | Estado rama | Documentación usada |
|---|---|---|---|---|
| Referencia primaria | **3.4.6 OSS** | 2026-09-28 | LTS, EOL previsto 2031-Q2 | documentación oficial 3.4 |
| Referencia legacy | **3.0.29 OSS** | 2026-09-28 | LTS, EOL previsto 2029-Q2 | documentación oficial 3.0 |

- **Edición:** Community/OSS, **única edición en alcance de paridad**
  (decisión del usuario, 2026-10-12). Las ediciones comerciales del proxy de
  referencia (Enterprise, plataforma One, ALOHA, Fusion) quedan **excluidas**:
  solo se documenta la exclusión en la matriz de paridad (documentación
  interna), sin objetivos equivalentes.
- **Opciones de compilación de referencia:** la build de Community Edition
  (`TARGET=linux-glibc CPU=generic USE_PCRE2=1 USE_PCRE2_JIT=1 USE_TFO=1
  USE_LINUX_TPROXY=1 USE_LUA=1 USE_GETADDRINFO=1 USE_PROMEX=1 USE_SLZ=1
  USE_OPENSSL_AWSLC=1 USE_PTHREAD_EMULATION=1 USE_QUIC=1`) según el Dockerfile
  oficial de la referencia (3.4). Para benchmarks se registrará **siempre** la
  salida real de `-vv` del binario usado (las flags varían por distribución).
- **Plataforma de la referencia:** Linux x86_64 glibc (coincide con ADR-0001).
- **Fuente principal de semántica:** la documentación oficial de configuración
  3.4 y 3.0 (más los changelogs oficiales y el repositorio de fuentes de la
  referencia). Las URLs concretas viven en la documentación interna del
  proyecto.

## Política de citas (obligatoria en todo el proyecto)

1. Toda afirmación sobre capacidades del proxy de referencia lleva URL oficial
   y versión a la que se aplica.
2. Si una capacidad difiere entre 3.0 y 3.4, la matriz registra **ambas**
   semánticas y EQProxy declara cuál preserva.
3. Lo no verificado contra fuentes oficiales se marca **"sin verificar"**.
   Nunca se rellena un hueco con suposiciones.
4. Las fuentes de terceros (blogs, foros) solo valen para *dolores de usuario*
   (documentación interna), nunca para afirmar semántica de producto.
5. Política de versiones del proxy de referencia (hecho verificado): las ramas
   pares son LTS con ~5 años de mantenimiento; las impares, 12–18 meses.

## Alternativas consideradas

1. **Solo 3.4.6 LTS:** más simple, pero ignora la base instalada en 3.0 y
   pierde la capacidad de detectar semántica que cambió entre ramas. Rechazada
   por decisión del usuario.
2. **Matriz de todas las ramas vivas (2.8, 3.0, 3.2, 3.3, 3.4):** coste
   documental desproporcionado. Las ramas 2.6/2.8 están en "solo arreglos
   críticos" y 2.4 sin mantenimiento; no generan compromiso de paridad.

## Consecuencias

- El coste documental de la matriz se duplica parcialmente; se mitiga con una
  columna "Versión ref." por fila y marcas explícitas de "ambas" cuando la
  semántica coincide.
- Los benchmarks comparativos fijan 3.4.6 como oponente principal; 3.0.29 se
  usa solo para escenarios de compatibilidad/regresión declarados.
- Si la referencia publica una nueva LTS, se abre un ADR que decida si se rota
  la referencia primaria; no se cambia en silencio.
