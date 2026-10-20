# Differential report — shared-semantics corpus (v0.6 gate)

- date (UTC epoch): 1792502095
- eqproxy binary: /Volumes/Lexar/Cursor/EQProxy/target/debug/eqproxy (sha256 31ef7e1004810056745a481aa41de7552feeab846c3bfc332ced37e98f2b0ed3)
- haproxy: haproxy:3.4.6 (sha256:e273915691a8eab3f105bf3e39fd4c29a4ecf334e33421903b5589d25e14db26)
- ingress-nginx data plane: registry.k8s.io/ingress-nginx/controller:v1.13.0 (sha256:dc75a7baec7a3b827a5d7ab0acd10ab507904c7dad692365b3e3b596eca1afd2)
- envoy: envoyproxy/envoy:v1.34.2 (sha256:daca6a3f353ba289cc786d2162d13d4ec2b16d921c6c3f2fc57ce6f7900ab3d9)
- backends: nginx:alpine (sha256:df221db836e1754089190208cee7eeda94f233197056426eda74a43ab1abeac2)
- normalization: status code only (reason phrase ignored); `Location` reduced to
  path + query when absolute; body compared only when the case declares one;
  comma-joined header values normalized to the `", "` separator; the client
  address of each implementation is calibrated at run time and substituted
  as `CLIENT`.

| case | shared semantics | eqproxy | haproxy | ingress-nginx | envoy |
|---|---|---|---|---|---|
| c1-prefix | path_prefix routes the request to its backend | OK 200 "api /c1/users" | OK 200 "api /c1/users" | OK 200 "api /c1/users" | OK 200 "api /c1/users" |
| c1-boundary | a literal prefix boundary: /c1/ must not swallow /c10 | OK 200 "fallback /c10/users" | OK 200 "fallback /c10/users" | OK 200 "fallback /c10/users" | OK 200 "fallback /c10/users" |
| c2-host | host match is case-insensitive | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" |
| c2-port | host match compares without the :port suffix | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" | OK 200 "mgmt /c2/x" |
| c2-near | a host near miss must not route | OK 200 "fallback /c2/x" | OK 200 "fallback /c2/x" | OK 200 "fallback /c2/x" | OK 200 "fallback /c2/x" |
| c3-method | method condition matches | OK 200 "mgmt /c3/x" | OK 200 "mgmt /c3/x" | OK 200 "mgmt /c3/x" | OK 200 "mgmt /c3/x" |
| c3-near | method near miss must not route | OK 200 "fallback /c3/x" | OK 200 "fallback /c3/x" | OK 200 "fallback /c3/x" | OK 200 "fallback /c3/x" |
| c4-header | header exact match routes | OK 200 "mgmt /c4/x" | OK 200 "mgmt /c4/x" | OK 200 "mgmt /c4/x" | OK 200 "mgmt /c4/x" |
| c4-near | missing header must not route | OK 200 "fallback /c4/x" | OK 200 "fallback /c4/x" | OK 200 "fallback /c4/x" | OK 200 "fallback /c4/x" |
| c5-first | ordered rules: the first matching rule wins over a later one | OK 200 "mgmt /c5/x" | OK 200 "mgmt /c5/x" | OK 200 "mgmt /c5/x" | OK 200 "mgmt /c5/x" |
| c5-second | ordered rules: the later rule catches what the first misses | OK 200 "api /c5/x" | OK 200 "api /c5/x" | OK 200 "api /c5/x" | OK 200 "api /c5/x" |
| c6-redirect | local 3xx with Location (body not compared: per-implementation) | OK 301 -> /c6/new "" | OK 301 -> /c6/new "" | OK 301 -> /c6/new "<html>\r\n<head><title>301 Moved Permanently</title></head>\r\n<body>\r\n<center><h1>301 Moved Permanently</h1></center>\r\n<hr><center>nginx/1.27.1</center>\r\n</body>\r\n</html>" | OK 301 -> /c6/new "" |
| c7-direct | local direct response (no backend contacted) | OK 200 "pong" | OK 200 "pong" | OK 200 "pong" | OK 200 "pong" |
| c8-rewrite | prefix rewrite: the backend sees the rewritten target | OK 200 "api /c8/api/users" | OK 200 "api /c8/api/users" | OK 200 "api /c8/api/users" | OK 200 "api /c8/api/users" |
| c11-regex | path regex routes .json paths (spelling per implementation, see corpus doc) | OK 200 "mgmt /c11/data.json" | OK 200 "mgmt /c11/data.json" | OK 200 "mgmt /c11/data.json" | OK 200 "mgmt /c11/data.json" |
| c11-boundary | regex near miss (.jsonx) must not route | OK 200 "fallback /c11/data.jsonx" | OK 200 "fallback /c11/data.jsonx" | OK 200 "fallback /c11/data.jsonx" | OK 200 "fallback /c11/data.jsonx" |
| h1-xff-append | XFF grows: client-sent hops are kept, the client is appended | OK 200 "api /h1/x xff=[10.9.9.9, CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h1/x xff=[10.9.9.9, CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h1/x xff=[10.9.9.9, CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h1/x xff=[10.9.9.9, CLIENT] real=[] beta=[] gone=[] added=[]" |
| h2-xff-xri-replace | anti-spoofing: XFF and X-Real-IP carry the real client only | OK 200 "api /h2/x xff=[CLIENT] real=[CLIENT] beta=[] gone=[] added=[]" | OK 200 "api /h2/x xff=[CLIENT] real=[CLIENT] beta=[] gone=[] added=[]" | OK 200 "api /h2/x xff=[CLIENT] real=[CLIENT] beta=[] gone=[] added=[]" | OK 200 "api /h2/x xff=[CLIENT] real=[CLIENT] beta=[] gone=[] added=[]" |
| h4-xfp | X-Forwarded-Proto carries the client scheme | OK 200 "api /h4/x xff=[CLIENT] real=[] proto=[http] beta=[] gone=[] added=[]" | OK 200 "api /h4/x xff=[CLIENT] real=[] proto=[http] beta=[] gone=[] added=[]" | OK 200 "api /h4/x xff=[CLIENT] real=[] proto=[http] beta=[] gone=[] added=[]" | OK 200 "api /h4/x xff=[CLIENT] real=[] proto=[http] beta=[] gone=[] added=[]" |
| h5-set-header | set-header replaces the client's value on the forwarded request | OK 200 "api /h5/x xff=[CLIENT] real=[] beta=[on] gone=[] added=[]" | OK 200 "api /h5/x xff=[CLIENT] real=[] beta=[on] gone=[] added=[]" | OK 200 "api /h5/x xff=[CLIENT] real=[] beta=[on] gone=[] added=[]" | OK 200 "api /h5/x xff=[CLIENT] real=[] beta=[on] gone=[] added=[]" |
| h6-del-header | del-header removes the client's header before forwarding | OK 200 "api /h6/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h6/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h6/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h6/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" |
| h7-add-header | add-header combines the added value with the client's | OK 200 "api /h7/x xff=[CLIENT] real=[] beta=[] gone=[] added=[base, extra]" | OK 200 "api /h7/x xff=[CLIENT] real=[] beta=[] gone=[] added=[base, extra]" | OK 200 "api /h7/x xff=[CLIENT] real=[] beta=[] gone=[] added=[base, extra]" | OK 200 "api /h7/x xff=[CLIENT] real=[] beta=[] gone=[] added=[base, extra]" |
| h8-response-marker | response headers can be set on the way back | OK 200 "api /h8/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h8/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h8/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" | OK 200 "api /h8/x xff=[CLIENT] real=[] beta=[] gone=[] added=[]" |

verdict: 23/23 cases agree across their applicable implementations (0 documented exclusion(s)).
