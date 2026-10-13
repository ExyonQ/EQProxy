# ADR-0003: Referencia multi-versión y política de citas

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
