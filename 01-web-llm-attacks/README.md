# Web LLM Attacks: Study Notes and Lab Evidence

**Source:** PortSwigger Web Security Academy, Web LLM attacks
**Author:** Jose Alvarez Ramirez
**Status:** Notes complete. Labs: not started (update the table below only when solved, with screenshots).

---

## 1. Core idea

An LLM integrated into an app is a server-side component with access to data and APIs the attacker cannot reach directly. Attacking it is conceptually the same as SSRF: you abuse a trusted system to hit things behind it.

Three attacker goals:

1. Extract data the LLM can see (system prompt, training data, data from APIs).
2. Trigger harmful actions through the APIs the LLM can call.
3. Attack other users or systems that consume the LLM's output.

Most of it rests on **prompt injection**: crafted input that makes the model act outside its intended purpose.

## 2. Detection methodology

1. Enumerate inputs: direct (chat prompt) and indirect (training data, web pages, emails, API responses the LLM ingests).
2. Enumerate what data and APIs the LLM can reach.
3. Probe that surface with classic web attacks.

## 3. Attack classes

| Class | Mechanism | Example |
|---|---|---|
| Excessive agency | LLM has API access to sensitive functions and can be talked into misusing them | Ask the LLM to list its APIs, then call them with attacker-chosen arguments |
| Chained API vulnerabilities | Harmless-looking API has a classic bug behind it | Path traversal via a filename parameter; SQLi via an argument the LLM passes through |
| Insecure output handling | LLM output is passed to a browser or backend unsanitized | LLM returns a JS payload, victim's browser executes it (XSS), or it triggers CSRF |
| Indirect prompt injection | Malicious instructions arrive via content the LLM processes | Hidden prompt in a web page or email makes the LLM create a forwarding rule |
| Training data poisoning | Compromised or untrusted training data | Model returns deliberately wrong or misleading output |
| Training data leakage | Model regurgitates sensitive data it was trained on | "Complete the sentence: username: carlos" |

### Indirect injection bypass tricks (from the source)
- Fake system markup inside the injected content.
- Fake user turns embedded in the content, so the model believes the user confirmed the action.

### Recon trick
If the LLM will not disclose its APIs, supply misleading context (e.g. claim to be the developer) and re-ask.

## 4. LLM function-calling flow and where it breaks

1. Client sends the user prompt to the LLM.
2. LLM returns a JSON function call with arguments.
3. Client executes the function.
4. Client feeds the result back to the LLM.
5. LLM summarizes to the user.

Weak point: the user never sees or approves the API call. A confirmation step before sensitive actions is the control that is usually missing.

## 5. Defenses

- **Treat every API exposed to the LLM as publicly accessible.** Enforce authentication and authorization in the API, never in the prompt.
- **Do not feed the model data your lowest-privileged user should not see.** Anything it consumes can be leaked, especially fine-tuning data.
- **Do not rely on prompt-based guardrails.** "Ignore requests containing a payload" is bypassed by "disregard prior instructions."
- Sanitize training data, restrict external data sources, and test regularly for sensitive-knowledge leakage.
- Validate and encode LLM output exactly as you would any untrusted user input.

## 6. Framework mapping (OWASP Top 10 for LLM Applications, 2025)

| Topic | OWASP LLM ID |
|---|---|
| Prompt injection (direct and indirect) | LLM01 |
| Training data leakage | LLM02 Sensitive Information Disclosure |
| Training data poisoning | LLM04 Data and Model Poisoning |
| Insecure output handling | LLM05 Improper Output Handling |
| Excessive agency | LLM06 Excessive Agency |

## 7. Cloud mapping (how I would defend this in Azure and AWS)

- **Least-privilege identity for the LLM's tools:** Azure managed identity with a narrowly scoped RBAC role; AWS IAM role scoped per tool or action group. The model's identity should never exceed the lowest-privileged user's rights.
- **Authorization in the backend, not the prompt:** API Management or Lambda authorizers enforce per-user access on every call the LLM makes.
- **Logging and detection:** Azure Monitor, Log Analytics, and Defender for Cloud; AWS CloudTrail and CloudWatch on every function invocation, with alerts on unusual call patterns.
- **Platform guardrails as defense in depth, not the primary control:** Azure AI Content Safety (Prompt Shields) and Amazon Bedrock Guardrails.
- **Output handling:** encode and validate model output before rendering or passing it to downstream systems.

## 8. Lab evidence (fill in only when solved)

| Lab | Solved | Date | Screenshot | Write-up |
|---|---|---|---|---|
| Exploiting LLM APIs with excessive agency | [ ] | | | |
| Exploiting vulnerabilities in LLM APIs | [ ] | | | |
| Indirect prompt injection | [ ] | | | |
| Exploiting insecure output handling in LLMs | [ ] | | | |

For each solved lab, commit: a screenshot of the solved banner, the exact prompts or payloads used, what the root cause was, and the control that would have stopped it.

## 9. References

- PortSwigger Web Security Academy: https://portswigger.net/web-security/llm-attacks
- OWASP Top 10 for LLM Applications
