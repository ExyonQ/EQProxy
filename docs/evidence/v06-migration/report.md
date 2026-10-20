# Migration report — real source configs vs the EQProxy translation

- date (UTC epoch): 1792502050
- eqproxy binary: /Volumes/Lexar/Cursor/EQProxy/target/debug/eqproxy (sha256 31ef7e1004810056745a481aa41de7552feeab846c3bfc332ced37e98f2b0ed3)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/haproxy.cfg (sha256 69a53bcad82b95f496c286ecb13e6cc9db66fbae7e5baa3d9daa453e42f773f9)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/nginx.conf (sha256 693cb35be47036717638424b8338bd1b5008d985e6002135d11efeae969d818b)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/envoy.yaml (sha256 c9bc949f1fc694bc2b6e7ba697895156abbf7a7ecccdbb7f1491d7033cd6de47)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/ingress.yaml (sha256 4c0f3dfab6cee3fe854583daa3d94a3450aa85ee2a02efe988042fc25026bf97)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/ingress-nginx-generated.conf (sha256 ad75c870fa0218b40a94478b7c3cbfe09fef47b4cb5bd7cdc2a73cdfd109218c)
- /Volumes/Lexar/Cursor/EQProxy/eqproxy-cli/../docs/migration/eqproxy.toml (sha256 f15aa9768d3aabdb9eecf19d526fd6d7ba8694b59f2fbff26c38bdfcf741dbde)
- haproxy: haproxy:3.4.6 (sha256:e273915691a8eab3f105bf3e39fd4c29a4ecf334e33421903b5589d25e14db26)
- nginx: nginx:alpine (sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2)
- ingress-nginx data plane: registry.k8s.io/ingress-nginx/controller:v1.13.0 (sha256:dc75a7baec7a3b827a5d7ab0acd10ab507904c7dad692365b3e3b596eca1afd2)
- envoy: envoyproxy/envoy:v1.34.2 (sha256:daca6a3f353ba289cc786d2162d13d4ec2b16d921c6c3f2fc57ce6f7900ab3d9)
- backends: nginx:alpine (sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2)
- substitutions on the EQProxy translation (declared): free local listen
  address, and the five pools reached through their published host ports
  instead of the fixed container addresses.

| case | semantics | eqproxy | haproxy | nginx | ingress-nginx | envoy |
|---|---|---|---|---|---|---|
| m1-root | storefront vhost reaches the web pool | OK 200 "web /" | OK 200 "web /" | OK 200 "web /" | OK 200 "web /" | OK 200 "web /" |
| m2-canary-cookie | canary-by-cookie marks the storefront canary | OK 200 "canary /api/x" | OK 200 "canary /api/x" | OK 200 "canary /api/x" | OK 200 "canary /api/x" | OK 200 "canary /api/x" |
| m3-canary-header | canary-by-header marks the storefront canary | OK 200 "canary /" | OK 200 "canary /" | OK 200 "canary /" | OK 200 "canary /" | OK 200 "canary /" |
| m4-api-post | API vhost reaches the api pool | OK 200 "api /api/x" | OK 200 "api /api/x" | OK 200 "api /api/x" | OK 200 "api /api/x" | OK 200 "api /api/x" |
| m5-admin-post | method-scoped routing sends POST /admin to the admin pool | OK 200 "admin /admin/x" | OK 200 "admin /admin/x" | OK 200 "admin /admin/x" | OK 200 "admin /admin/x" | OK 200 "admin /admin/x" |
| m6-admin-get | a non-POST /admin request stays on the storefront pool | OK 200 "web /admin/x" | OK 200 "web /admin/x" | OK 200 "web /admin/x" | OK 200 "web /admin/x" | OK 200 "web /admin/x" |
| m7-reports | the /reports prefix reaches the api pool on the shop vhost | OK 200 "api /reports/x" | OK 200 "api /reports/x" | OK 200 "api /reports/x" | OK 200 "api /reports/x" | OK 200 "api /reports/x" |
| m8-rewrite | rewrite-target /api/v1/<rest> -> /api/<rest> | OK 200 "api /api/users" | OK 200 "api /api/users" | OK 200 "api /api/users" | OK 200 "api /api/users" | OK 200 "api /api/users" |
| m9-json | regex routing of *.json under /api/ | OK 200 "api /api/a.json" | OK 200 "api /api/a.json" | OK 200 "api /api/a.json" | OK 200 "api /api/a.json" | OK 200 "api /api/a.json" |
| m10-redirect | the legacy path redirects to /blog | OK 301 -> /blog "" | OK 301 -> /blog "" | OK 301 -> /blog "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.31.6</center>\r\n</body>\r\n</html>\r\n" | OK 301 -> /blog "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.27.1</center>\r\n</body>\r\n</html>\r\n" | OK 301 -> /blog "" |
| m11-healthz | the health answer is local (no backend contacted) | OK 200 "ok" | OK 200 "ok" | OK 200 "ok" | OK 200 "ok" | OK 200 "ok" |
| m12-default-host | an unknown host reaches the default backend | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" |
| m13-api-fallback | the api vhost falls back for unmatched paths | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" | OK 200 "fallback /x" |

verdict: 13/13 cases route identically across the five implementations (65 checks).
