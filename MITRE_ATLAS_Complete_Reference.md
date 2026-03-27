# MITRE ATLAS Complete Tactics & Techniques Reference

**Framework:** MITRE ATLAS (Adversarial Threat Landscape for Artificial-Intelligence Systems)
**Current Version:** 5.4.0 (as of February 2026)
**Official Site:** https://atlas.mitre.org
**Data Repository:** https://github.com/mitre-atlas/atlas-data

**As of v5.4.0:** 16 tactics, 108+ techniques and sub-techniques

---

## Technique Maturity Levels (ATLAS Definition)
- **Feasible** — Shown to work in research/academic setting
- **Demonstrated** — Shown effective in red team exercise on a realistic AI system
- **Realized** — Used by a threat actor in a real-world incident

---

## Red Team Testability Legend
- **YES** — Can be fully emulated in a controlled red team exercise
- **PARTIAL** — Can be partially emulated with caveats noted
- **NO** — Cannot be practically emulated (reason noted)

---

## TACTICS OVERVIEW

| Tactic ID    | Tactic Name             | Description |
|--------------|-------------------------|-------------|
| AML.TA0002   | Reconnaissance          | Gathering information about the AI system to plan future operations |
| AML.TA0003   | Resource Development    | Establishing resources to support operations |
| AML.TA0004   | Initial Access          | Gaining access to the AI system |
| AML.TA0000   | ML Model Access         | Attempting to gain some level of access to an AI model |
| AML.TA0005   | Execution               | Running malicious code embedded in AI artifacts or software |
| AML.TA0006   | Persistence             | Maintaining foothold via AI artifacts or software |
| AML.TA0012   | Privilege Escalation    | Gaining higher-level permissions |
| AML.TA0007   | Defense Evasion         | Avoiding detection by AI-enabled security software |
| AML.TA0013   | Credential Access       | Stealing account names and passwords |
| AML.TA0008   | Discovery               | Figuring out the AI environment |
| AML.TA0015   | Lateral Movement        | Moving through the AI environment |
| AML.TA0009   | Collection              | Gathering AI artifacts and related information |
| AML.TA0001   | ML Attack Staging       | Leveraging knowledge and access to tailor the attack |
| AML.TA0014   | Command and Control     | Communicating with compromised AI systems to control them |
| AML.TA0010   | Exfiltration            | Stealing AI artifacts or other information |
| AML.TA0011   | Impact                  | Manipulating, interrupting, eroding confidence in, or destroying AI systems |

---

## TECHNIQUES BY TACTIC

---

### TACTIC: Reconnaissance (AML.TA0002)
*Adversaries gather information about the AI system they can use to plan future operations.*

---

#### AML.T0000 — Search for Victim's Publicly Available Research Materials
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated
- **Description:** Adversaries search publicly available research to learn how and where ML is used within a victim organization. Sources include conference proceedings, pre-print repositories, and technical blogs.
- **Red Team Testable:** YES — OSINT exercises can directly replicate this by searching arXiv, ACM, NeurIPS proceedings, and organizational tech blogs.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0000.000 | Journals and Conference Proceedings | Search premier ML conference publications (NeurIPS, ICML, CVPR) for details about victim's AI approaches | YES |
| AML.T0000.001 | Pre-Print Repositories | Search arXiv and similar platforms for unreviewed research revealing victim's current ML work | YES |
| AML.T0000.002 | Technical Blogs | Search research lab and employee blogs for ML implementation details, frameworks, and API info | YES |

---

#### AML.T0001 — Search for Publicly Available Adversarial Vulnerability Analysis
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated
- **Description:** Adversaries identify pre-existing work done for the class of models used by the target, including attack implementations and academic papers on vulnerabilities specific to those model types.
- **Red Team Testable:** YES — Can replicate by searching CVE databases, academic papers (e.g., on Clever Hans, TextFooler), and public exploit databases.

---

#### AML.T0003 — Search Victim-Owned Websites
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated
- **Description:** Adversaries search websites owned by the victim for information about their ML-enabled products, employee information, business relationships, and technical architecture.
- **Red Team Testable:** YES — Standard web OSINT; scrape product pages, job postings, and API documentation.

---

#### AML.T0004 — Search Application Repositories
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated
- **Description:** Adversaries search open application repositories (Google Play, App Store, GitHub) to identify AI-enabled applications and gather technical intelligence about their implementation.
- **Red Team Testable:** YES — Directly replicable by downloading and reverse-engineering apps or reviewing public GitHub repos.

---

#### AML.T0006 — Active Scanning
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Realized
- **Description:** Adversaries probe or scan the victim system to gather information, including scanning for open ports, AI DevOps tools (MLflow, Kubeflow, Jupyter), and public AI chat agent endpoints.
- **Red Team Testable:** YES — Standard network scanning with tools like nmap, plus AI-specific tool discovery.

---

#### AML.T0064 — Gather RAG-Indexed Targets
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated
- **Description:** Adversaries identify data sources used in retrieval-augmented generation (RAG) systems. This intelligence helps target specific documents or data stores for poisoning operations.
- **Red Team Testable:** YES — Can probe RAG-enabled systems by crafting queries to infer what documents are indexed.

---

#### AML.T0087 — Gather Victim Identity Information
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries gather identity information about individuals to support social engineering, deepfake creation, or targeted phishing attacks leveraging generative AI capabilities.
- **Red Team Testable:** YES — Standard OSINT collection of identity data (LinkedIn, social media, public records).

---

#### AML.T0095 — Search Open Websites/Domains
- **Tactic:** Reconnaissance (AML.TA0002)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries search open websites and domain registration data to gather intelligence about target AI systems, infrastructure, and personnel.
- **Red Team Testable:** YES — OSINT via WHOIS, Shodan, Censys, and standard web searching.

---

### TACTIC: Resource Development (AML.TA0003)
*Adversaries establish resources they can use to support operations — capabilities, infrastructure, and artifacts needed to execute AI attacks.*

---

#### AML.T0002 — Acquire Public ML Artifacts
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries search public sources including cloud storage, Hugging Face, GitHub, and model registries to acquire datasets, model architectures, pre-trained models, and configurations that aid attack development.
- **Red Team Testable:** YES — Directly replicable by downloading public models/datasets from Hugging Face, PyTorch Hub, etc.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0002.000 | Datasets | Collect public or victim-representative datasets from cloud storage or websites | YES |
| AML.T0002.001 | Models | Obtain model architectures and pre-trained weights in ONNX, HDF5, PyTorch, or TensorFlow formats | YES |

---

#### AML.T0008 — Acquire Infrastructure
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries buy, lease, or rent infrastructure (servers, GPU compute, domains, hardware) for staging and executing ML attack operations.
- **Red Team Testable:** YES — Red teams regularly set up cloud compute and infrastructure for testing.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0008.000 | ML Development Workspaces | Use free/paid GPU resources like Google Colab for developing attacks | YES |
| AML.T0008.001 | Consumer Hardware | Purchase consumer hardware (GPUs) providing full attack control | YES |
| AML.T0008.002 | Domains | Acquire domain names for use in dataset poisoning that distributes URLs | YES |
| AML.T0008.003 | Physical Countermeasures | Acquire physical items (stickers, lasers) disrupting physical-world AI models | PARTIAL — Requires physical environment access |
| AML.T0008.004 | Serverless | Use serverless computing infrastructure for attack staging | YES |

---

#### AML.T0016 — Obtain Capabilities
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries search for and obtain software capabilities for operations, both AI-specific attack tools and generic tools repurposed for ML attacks.
- **Red Team Testable:** YES — Downloading and deploying open-source adversarial ML libraries is straightforward.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0016.000 | Adversarial ML Attack Implementations | Obtain open-source ML attack libraries (CleverHans, FoolBox, ART, TextFooler) | YES |
| AML.T0016.001 | Software Tools | Obtain legitimate software repurposed for malicious ML attack support | YES |
| AML.T0016.002 | Generative AI | Obtain generative AI models including LLMs and uncensored model variants | YES |

---

#### AML.T0017 — Develop Capabilities
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries develop their own capabilities to support ML operations, including custom adversarial attack code, evasion tools, and poisoning pipelines.
- **Red Team Testable:** YES — Custom attack development is core red team activity.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0017.000 | Adversarial ML Attacks | Develop custom adversarial attacks leveraging existing libraries or academic research | YES |

---

#### AML.T0019 — Publish Poisoned Datasets
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Demonstrated
- **Description:** Adversaries poison training data and publish it to a public location (Hugging Face, GitHub, Kaggle) to be discovered and used by victim organizations. Datasets may be novel or presented as variants of popular existing ones.
- **Red Team Testable:** PARTIAL — Can demonstrate data poisoning in lab environment; publishing to real repositories would cause harm and is not appropriate for authorized testing.

---

#### AML.T0020 — Poison Training Data
- **Tactic:** Resource Development (AML.TA0003) and Persistence (AML.TA0006)
- **Maturity:** Realized
- **Description:** Adversaries modify training data or labels to embed vulnerabilities that cause the trained model to behave in adversary-defined ways, often activated by a backdoor trigger.
- **Red Team Testable:** YES — Can be fully demonstrated in an isolated lab environment with dedicated training datasets.

---

#### AML.T0021 — Establish Accounts
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries create accounts with various services (GitHub, Hugging Face, cloud providers, data labeling platforms) for use in targeting, gaining resource access, or victim impersonation.
- **Red Team Testable:** YES — Red teams can create test accounts on public platforms as part of authorized exercises.

---

#### AML.T0058 — Publish Poisoned Models
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries publish backdoored or maliciously modified models to public repositories (Hugging Face Hub, PyTorch Hub, GitHub) for distribution via supply chain compromise.
- **Red Team Testable:** PARTIAL — Poisoning a model and testing its backdoor can be demonstrated in a lab; publishing to real registries is outside authorized scope.

---

#### AML.T0060 — Publish Hallucinated Entities
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Demonstrated
- **Description:** Adversaries create and register entities (npm packages, domains, GitHub repos) matching hallucinations generated by LLMs, directing victims who act on those hallucinations to adversary-controlled resources.
- **Red Team Testable:** PARTIAL — Can demonstrate the hallucination discovery phase; actually registering and deploying malicious packages requires careful scoping.

---

#### AML.T0065 — LLM Prompt Crafting
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Realized
- **Description:** Adversaries use acquired knowledge of the target generative AI system to craft effective prompts that bypass defenses or elicit specific harmful outputs. This is a preparatory stage for prompt injection attacks.
- **Red Team Testable:** YES — Core LLM red team activity; craft and test prompts against authorized systems.

---

#### AML.T0066 — Retrieval Content Crafting
- **Tactic:** Resource Development (AML.TA0003)
- **Maturity:** Demonstrated
- **Description:** Adversaries write and position content specifically designed to be retrieved by user queries in RAG systems, enabling manipulation of users through the AI system's responses.
- **Red Team Testable:** YES — Can demonstrate by injecting crafted content into a RAG data source and querying the system.

---

### TACTIC: Initial Access (AML.TA0004)
*Adversaries attempt to gain access to the AI system through various entry points.*

---

#### AML.T0010 — AI Supply Chain Compromise
- **Tactic:** Initial Access (AML.TA0004)
- **Maturity:** Realized
- **Description:** Adversaries gain initial access by compromising the AI supply chain — hardware, data sources, software dependencies, or pre-trained models used by the victim.
- **Red Team Testable:** PARTIAL — Data and model sub-techniques are testable in lab; hardware compromise requires physical access.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0010.000 | Hardware | Disrupt or manipulate specialized AI hardware (GPUs, TPUs, embedded devices) in supply chain | NO — Requires hardware supply chain access |
| AML.T0010.001 | AI Software | Compromise ML frameworks, LLM integration tools, or inference engines via dependency chain | YES — Can demonstrate with test ML pipelines |
| AML.T0010.002 | Data | Compromise open-source datasets or poison private dataset labeling services | YES — Lab-demonstrable |
| AML.T0010.003 | Model | Compromise open-source models used for fine-tuning with malware or adversarial techniques | YES — Lab-demonstrable with test model repos |
| AML.T0010.004 | Container Registry | Push manipulated container images overwriting existing names/tags | YES — Testable against authorized registries |

---

#### AML.T0012 — Valid Accounts
- **Tactic:** Initial Access (AML.TA0004) and Privilege Escalation (AML.TA0012)
- **Maturity:** Realized
- **Description:** Adversaries obtain and abuse credentials of existing accounts (usernames/passwords or API keys) to access ML resources, data pipelines, or model serving infrastructure.
- **Red Team Testable:** YES — Standard credential testing; use authorized test accounts and captured credentials per rules of engagement.

---

#### AML.T0015 — Evade ML Model
- **Tactic:** Initial Access (AML.TA0004), Defense Evasion (AML.TA0007), Impact (AML.TA0011)
- **Maturity:** Realized
- **Description:** Adversaries craft adversarial inputs that prevent an ML model from correctly identifying contents — for example, evading malware classifiers, facial recognition, or spam filters. Includes generating deepfakes to evade identity verification.
- **Red Team Testable:** YES — Adversarial evasion testing against ML-based security controls is a core red team capability.

---

#### AML.T0049 — Exploit Public-Facing Application
- **Tactic:** Initial Access (AML.TA0004)
- **Maturity:** Realized
- **Description:** Adversaries exploit weaknesses in internet-accessible AI applications, APIs, or web interfaces hosting ML functionality. Includes traditional web app vulnerabilities targeting AI endpoints.
- **Red Team Testable:** YES — Standard web app pentesting against AI-enabled applications.

---

#### AML.T0052 — Phishing
- **Tactic:** Initial Access (AML.TA0004), Lateral Movement (AML.TA0015)
- **Maturity:** Realized
- **Description:** Adversaries send phishing messages to gain access to victim ML systems or credentials. AI/LLM capabilities can generate highly convincing, personalized phishing content at scale.
- **Red Team Testable:** YES — Phishing simulations are standard red team activity; can include AI-generated lures.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0052.000 | Spearphishing via Social Engineering LLM | Weaponize LLMs as targeted social engineers for credential harvesting | YES — Can demonstrate with authorized LLM-assisted phishing tests |

---

#### AML.T0078 — Drive-by Compromise
- **Tactic:** Initial Access (AML.TA0004)
- **Maturity:** Demonstrated (added v4.9.0, Apr 2025)
- **Description:** Adversaries gain access to victim systems when users visit a website hosting malicious content. AI-generated or AI-targeted malicious web content is used to exploit browsers or AI agents.
- **Red Team Testable:** YES — Can stage controlled drive-by scenarios against authorized test environments.

---

#### AML.T0093 — Prompt Infiltration via Public-Facing Application
- **Tactic:** Initial Access (AML.TA0004)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries exploit public-facing AI applications (chatbots, AI assistants) to inject prompts that establish persistent access or exfiltrate data through the AI's responses.
- **Red Team Testable:** YES — Can test against authorized AI-enabled public applications with proper scoping.

---

### TACTIC: ML Model Access (AML.TA0000)
*Adversaries attempt to gain some level of access to a target AI model — a precondition for many downstream attack techniques.*

---

#### AML.T0040 — AI Model Inference API Access
- **Tactic:** ML Model Access (AML.TA0000)
- **Maturity:** Demonstrated
- **Description:** Adversaries gain access to the model's inference API through legitimate means (free tier, paid access, or compromised credentials). This is the foundational access type for numerous ATLAS attack chains.
- **Red Team Testable:** YES — API access testing is fundamental to AI red teaming; use authorized accounts.

---

#### AML.T0041 — Physical Environment Access
- **Tactic:** ML Model Access (AML.TA0000)
- **Maturity:** Demonstrated
- **Description:** Adversaries exploit physical access to environments where AI systems operate (autonomous vehicles, surveillance cameras, medical imaging) to modify data collection, inject adversarial inputs, or physically disrupt sensors.
- **Red Team Testable:** PARTIAL — Requires physical access to the target environment. Testable if authorized physical red team access is granted.

---

#### AML.T0044 — Full ML Model Access
- **Tactic:** ML Model Access (AML.TA0000)
- **Maturity:** Demonstrated
- **Description:** Adversaries gain complete "white-box" access to a model — full knowledge of architecture, parameters, and class ontology. Enables offline attack development, adversarial example crafting, and model inversion.
- **Red Team Testable:** YES — When authorized to test against a specific model, white-box access can be granted to simulate this scenario.

---

#### AML.T0047 — ML-Enabled Product or Service
- **Tactic:** ML Model Access (AML.TA0000)
- **Maturity:** Realized
- **Description:** Adversaries use a product or service that incorporates AI under the hood to gain indirect access to the underlying model. Logs or metadata may reveal inference details useful for further attacks.
- **Red Team Testable:** YES — Accessing authorized AI-enabled products and analyzing their behavior/metadata is testable.

---

#### AML.T0096 — AI Service API
- **Tactic:** ML Model Access (AML.TA0000)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries exploit AI service APIs as part of broader attack chains, leveraging existing infrastructure to maintain stealth and persistent access while "living off the land" within AI service ecosystems.
- **Red Team Testable:** YES — Can test authorized AI service API endpoints for misconfigurations and abuse potential.

---

### TACTIC: Execution (AML.TA0005)
*Adversaries run malicious code embedded in AI artifacts or software.*

---

#### AML.T0011 — User Execution
- **Tactic:** Execution (AML.TA0005)
- **Maturity:** Realized
- **Description:** Adversaries rely on specific user actions to execute unsafe code, often introduced via ML supply chain compromise. Users inadvertently run malicious ML artifacts (model files that execute code when loaded).
- **Red Team Testable:** YES — Can demonstrate malicious model file execution in isolated lab environments.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0011.000 | Unsafe ML Artifacts | Develop malicious model files (HDF5, pickle) that execute arbitrary code when loaded | YES — Lab-demonstrable |
| AML.T0011.001 | Malicious Package | Create harmful ML software packages appearing legitimate while introducing harm | YES — Lab-demonstrable |
| AML.T0011.002 | Poisoned AI Agent Tool | Deploy poisoned AI agent tools that execute malicious actions when invoked | YES — Lab-demonstrable |
| AML.T0011.003 | Malicious Link | Deliver malicious links through AI-generated content leading to harmful code execution | YES |

---

#### AML.T0050 — Command and Scripting Interpreter
- **Tactic:** Execution (AML.TA0005)
- **Maturity:** Demonstrated
- **Description:** Adversaries abuse command and scripting interpreters (Unix shell, PowerShell, Python) to execute commands within AI infrastructure environments.
- **Red Team Testable:** YES — Standard post-access execution testing applies to AI infrastructure.

---

#### AML.T0051 — LLM Prompt Injection
- **Tactic:** Execution (AML.TA0005)
- **Maturity:** Realized
- **Description:** Adversaries craft malicious prompts as inputs to an LLM, causing the model to ignore prior instructions, bypass guardrails, or execute unintended operations including tool calls or code execution.
- **Red Team Testable:** YES — Core LLM red team technique; prompt injection testing is well-established.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0051.000 | Direct | Adversary directly provides malicious prompts as an LLM user | YES |
| AML.T0051.001 | Indirect | Inject prompts through external data channels (web pages, documents, emails) ingested by the LLM | YES — Requires system with RAG or web access |
| AML.T0051.002 | Triggered | Craft prompts that activate only when specific conditions are met | YES |

---

#### AML.T0053 — AI Agent Tool Invocation
- **Tactic:** Execution (AML.TA0005), Privilege Escalation (AML.TA0012)
- **Maturity:** Demonstrated
- **Description:** Adversaries use their access to an AI agent to invoke tools the agent has access to (web search, code execution, file system access, external APIs), potentially gaining access to resources beyond the intended scope.
- **Red Team Testable:** YES — Can test against authorized AI agent deployments with defined tool permissions.

---

#### AML.T0088 — Generate Deepfakes
- **Tactic:** Execution (AML.TA0005)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries generate synthetic media (audio, video, images) of real individuals using generative AI to impersonate targets, bypass biometric authentication, or conduct social engineering attacks at scale.
- **Red Team Testable:** YES — Deepfake generation for authorized authorized impersonation testing is demonstrable with consent.

---

#### AML.T0101 — Data Destruction via AI Agent Tool Invocation
- **Tactic:** Execution (AML.TA0005), Impact (AML.TA0011)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries leverage AI agent tool access to invoke destructive capabilities — deleting files, dropping databases, or disrupting infrastructure — using tools the agent legitimately has access to.
- **Red Team Testable:** YES — Demonstrable in authorized environments with appropriate safeguards; requires isolated test environment.

---

#### AML.T0102 — Generate Malicious Commands
- **Tactic:** Execution (AML.TA0005)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries use generative AI models to produce malicious commands, shellcode, exploit code, or attack scripts — lowering the technical barrier for malicious actors to execute sophisticated attacks.
- **Red Team Testable:** YES — Can demonstrate with authorized LLM testing to generate attack content in lab environment.

---

### TACTIC: Persistence (AML.TA0006)
*Adversaries maintain their foothold via AI artifacts or software, surviving reboots, credential changes, and system updates.*

---

#### AML.T0018 — Manipulate AI Model
- **Tactic:** Persistence (AML.TA0006), ML Attack Staging (AML.TA0001)
- **Maturity:** Realized
- **Description:** Adversaries directly manipulate an AI model to change its behavior persistently, introducing malicious functionality or degrading performance in ways that survive model redeployment.
- **Red Team Testable:** YES — Demonstrable in lab with authorized model manipulation.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0018.000 | Poison ML Model | Manipulate model weights to change behavior while maintaining plausible performance | YES — Lab-demonstrable |
| AML.T0018.001 | Modify AI Model Architecture | Add/remove/modify layers to redefine model behavior while maintaining functionality | YES — Lab-demonstrable |
| AML.T0018.002 | Embed Malware | Embed malicious executable code into model files (pickle files, HDF5) that runs upon loading | YES — Lab-demonstrable |

---

#### AML.T0061 — LLM Prompt Self-Replication
- **Tactic:** Persistence (AML.TA0006)
- **Maturity:** Demonstrated
- **Description:** Adversaries craft LLM prompt injections that cause prompts to self-replicate through LLM outputs — the model propagates the injection to subsequent interactions, users, or connected systems.
- **Red Team Testable:** YES — Can test self-replicating prompt chains in authorized multi-agent or chat system environments.

---

#### AML.T0070 — RAG Poisoning
- **Tactic:** Persistence (AML.TA0006)
- **Maturity:** Demonstrated
- **Description:** Adversaries inject malicious content into data indexed by a RAG system, causing the AI to persistently retrieve and act on adversary-controlled content when users query the system.
- **Red Team Testable:** YES — Can demonstrate by injecting content into authorized RAG data sources and querying the system.

---

#### AML.T0080 — AI Agent Context Poisoning
- **Tactic:** Persistence (AML.TA0006)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries manipulate the context used by an AI agent's LLM to persistently influence its responses and actions across future interactions.
- **Red Team Testable:** YES — Testable against authorized AI agent deployments.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0080.001 | Memory | Poison the long-term memory of an LLM so malicious content persists across future sessions | YES — Requires agent with memory capability |
| AML.T0080.002 | Thread | Inject malicious instructions into a specific chat thread affecting all interactions in that conversation | YES |

---

#### AML.T0081 — Modify AI Agent Configuration
- **Tactic:** Persistence (AML.TA0006)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries alter an AI agent's configuration files to create persistent malicious behavior affecting all agents sharing that configuration. Changes survive individual conversation resets.
- **Red Team Testable:** YES — Testable if authorized access to agent configuration is granted.

---

#### AML.T0092 — Manipulate User LLM Chat History
- **Tactic:** Persistence (AML.TA0006)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries modify a user's LLM chat history to inject false memories or context that persistently influence the model's future responses for that user.
- **Red Team Testable:** YES — Demonstrable if authorized access to chat history storage is granted.

---

### TACTIC: Privilege Escalation (AML.TA0012)
*Adversaries gain higher-level permissions within or via AI systems.*

---

#### AML.T0054 — LLM Jailbreak
- **Tactic:** Privilege Escalation (AML.TA0012), Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated
- **Description:** Adversaries use carefully crafted prompt injections to bypass an LLM's safety restrictions, content filters, and operational constraints, gaining the ability to elicit restricted outputs or behaviors.
- **Red Team Testable:** YES — Core LLM red team technique; jailbreak testing against authorized LLM systems.

---

#### AML.T0091 — Use Alternate Authentication Material
- **Tactic:** Privilege Escalation (AML.TA0012), Credential Access (AML.TA0013)
- **Maturity:** Realized (added v5.1.0, Nov 2025)
- **Description:** Adversaries use alternate authentication material (session tokens, API keys, OAuth tokens) rather than traditional credentials to access AI systems and bypass standard authentication controls.
- **Red Team Testable:** YES — Standard token-based authentication testing applies to AI service APIs.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0091.000 | Application Access Token | Use API keys, OAuth tokens, or JWT tokens to access AI services | YES |

---

### TACTIC: Defense Evasion (AML.TA0007)
*Adversaries avoid being detected by AI-enabled security software or monitoring systems.*

---

#### AML.T0067 — LLM Trusted Output Components Manipulation
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated
- **Description:** Adversaries craft prompts that manipulate an LLM to produce outputs that appear authoritative and trustworthy (citations, official-looking formatting, false attributions), increasing the likelihood victims act on malicious content.
- **Red Team Testable:** YES — Can demonstrate against authorized LLM systems.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0067.000 | Citations | Manipulate LLM to produce fake citations appearing legitimate or citing adversary-controlled sources | YES |

---

#### AML.T0068 — LLM Prompt Obfuscation
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated
- **Description:** Adversaries hide or obfuscate prompt injections using text steganography, encoding (Base64, ROT13), multi-modal embedding in images, or whitespace manipulation to evade content filters and prompt injection detection.
- **Red Team Testable:** YES — Can test obfuscation techniques against authorized LLM guardrails.

---

#### AML.T0071 — False RAG Entry Injection
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated
- **Description:** Adversaries introduce false or misleading entries into a victim's RAG database that bypass monitoring and detection tools, causing the AI to retrieve and use adversary-controlled information.
- **Red Team Testable:** YES — Can demonstrate in authorized RAG system environments.

---

#### AML.T0073 — Impersonation
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Realized (added v4.9.0, Apr 2025)
- **Description:** Adversaries impersonate trusted persons, organizations, or systems to persuade victims into taking actions, particularly targeting AI DevOps staff or ML pipeline maintainers.
- **Red Team Testable:** YES — Standard social engineering and impersonation testing.

---

#### AML.T0074 — Masquerading
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Realized (added v4.9.0, Apr 2025)
- **Description:** Adversaries manipulate features of their artifacts (ML models, packages, datasets) to appear legitimate, naming them to match trusted sources while concealing malicious functionality.
- **Red Team Testable:** YES — Can create masqueraded test artifacts in controlled environments.

---

#### AML.T0097 — Virtualization/Sandbox Evasion
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries detect and evade AI security sandboxes or virtualized analysis environments by identifying execution context cues before activating malicious behavior.
- **Red Team Testable:** YES — Standard sandbox evasion techniques applicable to AI model analysis environments.

---

#### AML.T0107 — Exploitation for Defense Evasion
- **Tactic:** Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated (added v5.4.0, Feb 2026)
- **Description:** Adversaries exploit vulnerabilities in AI security defenses, guardrails, or monitoring systems to evade detection while carrying out attacks.
- **Red Team Testable:** YES — Demonstrable against authorized AI security control implementations.

---

### TACTIC: Credential Access (AML.TA0013)
*Adversaries steal credentials to access AI systems, data, and infrastructure.*

---

#### AML.T0055 — Unsecured Credentials
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Realized
- **Description:** Adversaries search compromised AI systems and repositories for insecurely stored credentials — API keys in plaintext files, hardcoded credentials in ML notebooks, tokens in environment files, or keys committed to version control.
- **Red Team Testable:** YES — Standard credential hunting applicable to AI/ML repositories and environments.

---

#### AML.T0082 — RAG Credential Harvesting
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries use an LLM to search for and collect credentials that were inadvertently ingested into a RAG database along with other organizational documents.
- **Red Team Testable:** YES — Can demonstrate by seeding authorized RAG systems with test credential documents and querying for them.

---

#### AML.T0083 — Credentials from AI Agent Configuration
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries access AI agent configuration files that contain API keys or passwords for connected tools and services, harvesting these credentials for lateral movement.
- **Red Team Testable:** YES — Testable against authorized AI agent configuration files.

---

#### AML.T0090 — OS Credential Dumping
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Realized (added v5.1.0, Nov 2025)
- **Description:** Adversaries dump OS credentials from AI infrastructure hosts to enable lateral movement within the AI development or deployment environment.
- **Red Team Testable:** YES — Standard OS credential dumping techniques (Mimikatz, etc.) applicable to AI infrastructure hosts.

---

#### AML.T0098 — AI Agent Tool Credential Harvesting
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries use AI agent access to invoke tools and retrieve credentials, secrets, API keys, and other authentication material from the tools and data sources the agent connects to.
- **Red Team Testable:** YES — Can test against authorized AI agent deployments with tool access.

---

#### AML.T0106 — Exploitation for Credential Access
- **Tactic:** Credential Access (AML.TA0013)
- **Maturity:** Demonstrated (added v5.4.0, Feb 2026)
- **Description:** Adversaries exploit vulnerabilities in AI systems or agent infrastructure to obtain credentials through buffer overflows, injection flaws, or other exploitation techniques.
- **Red Team Testable:** YES — Standard exploitation-based credential access testing on authorized AI infrastructure.

---

### TACTIC: Discovery (AML.TA0008)
*Adversaries figure out the AI environment — its components, capabilities, and vulnerabilities.*

---

#### AML.T0007 — Discover ML Artifacts
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated
- **Description:** Adversaries enumerate internal ML resources — searching for model weights, training datasets, configuration files, and ML pipeline components in file shares, container registries, and data repositories.
- **Red Team Testable:** YES — Enumerate authorized ML environments for exposed artifacts.

---

#### AML.T0013 — Discover ML Model Ontology
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated
- **Description:** Adversaries discover the ontology of an AI model's output space (classes, labels, output format) through repeated queries or inspection of configuration files, informing more precise attack crafting.
- **Red Team Testable:** YES — Query authorized model APIs to enumerate output classes and structure.

---

#### AML.T0014 — Discover ML Model Family
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Feasible
- **Description:** Adversaries identify the general family of ML model used (ResNet, BERT, GPT-4, etc.) through documentation review, behavioral fingerprinting, or API response analysis, enabling targeted attack selection.
- **Red Team Testable:** YES — Model fingerprinting against authorized systems.

---

#### AML.T0062 — Discover LLM Hallucinations
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated
- **Description:** Adversaries systematically query LLMs to identify hallucinated entities (package names, domains, API endpoints) that the model fabricates. These hallucinations are then used as targets for publishing malicious content.
- **Red Team Testable:** YES — Can probe authorized LLMs for hallucination patterns.

---

#### AML.T0063 — Discover AI Model Outputs
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated
- **Description:** Adversaries discover model outputs (confidence scores, attention weights, intermediate representations) that are not required for normal system operation but that reveal exploitable model weaknesses.
- **Red Team Testable:** YES — Inspect authorized model API responses for verbose output.

---

#### AML.T0069 — Discover LLM System Information
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated
- **Description:** Adversaries probe LLMs to discover system-level information including special character sets, instruction keywords, and system prompt structure, enabling more effective prompt injection attacks.
- **Red Team Testable:** YES — Standard LLM probing against authorized systems.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0069.000 | Special Character Sets | Discover delimiters and special characters with semantic meaning to the LLM | YES |
| AML.T0069.001 | System Instruction Keywords | Discover keywords with special meaning (e.g., "Ignore previous instructions") | YES |
| AML.T0069.002 | System Prompt | Discover the content and structure of system instructions to circumvent guardrails | YES |

---

#### AML.T0075 — Cloud Service Discovery
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Feasible (added v4.9.0, Apr 2025)
- **Description:** Adversaries enumerate cloud services (IaaS, PaaS, SaaS, AIaaS) running in the victim's environment to identify AI infrastructure, model serving endpoints, and ML pipeline components.
- **Red Team Testable:** YES — Standard cloud enumeration applicable to AI cloud services.

---

#### AML.T0084 — Discover AI Agent Configuration
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries probe AI agents to discover their configuration — what tools they can access, what data sources they query, what activation triggers control their behavior.
- **Red Team Testable:** YES — Query authorized AI agent deployments to discover configuration.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0084.000 | Embedded Knowledge | Discover knowledge or data embedded in agent configuration or system prompts | YES |
| AML.T0084.001 | Tool Definitions | Identify what tools and capabilities the agent has access to | YES |
| AML.T0084.002 | Activation Triggers | Discover keywords or events that automatically trigger agent workflows | YES |

---

#### AML.T0089 — Process Discovery
- **Tactic:** Discovery (AML.TA0008)
- **Maturity:** Realized (added v5.1.0, Nov 2025)
- **Description:** Adversaries discover running processes on AI infrastructure hosts to identify ML workloads, model servers, training jobs, and pipeline orchestrators for targeting.
- **Red Team Testable:** YES — Standard process enumeration on authorized AI infrastructure hosts.

---

### TACTIC: Lateral Movement (AML.TA0015)
*Adversaries move through the AI environment to reach additional systems or resources.*

---

#### AML.T0052 — Phishing (also listed under Initial Access)
- **Tactic:** Lateral Movement (AML.TA0015), Initial Access (AML.TA0004)
- See entry under Initial Access above.

---

### TACTIC: Collection (AML.TA0009)
*Adversaries gather AI artifacts and other information of value for exfiltration or attack staging.*

---

#### AML.T0035 — ML Artifact Collection
- **Tactic:** Collection (AML.TA0009)
- **Maturity:** Realized
- **Description:** Adversaries collect ML artifacts — model weights, training datasets, evaluation data, telemetry logs, configuration files — for exfiltration or use in further attack staging (e.g., crafting adversarial examples).
- **Red Team Testable:** YES — Enumerate and collect accessible artifacts from authorized environments.

---

#### AML.T0036 — Data from Information Repositories
- **Tactic:** Collection (AML.TA0009)
- **Maturity:** Realized
- **Description:** Adversaries mine collaborative platforms (SharePoint, Confluence, Notion, internal wikis) where AI teams store documentation, model cards, training data specs, and system architecture information.
- **Red Team Testable:** YES — Standard collection from authorized internal repositories.

---

#### AML.T0037 — Data from Local System
- **Tactic:** Collection (AML.TA0009)
- **Maturity:** Realized
- **Description:** Adversaries search local file systems on AI workstations or servers for model files, training datasets, API keys, SSH keys, and configuration files.
- **Red Team Testable:** YES — Standard local file system enumeration on authorized hosts.

---

#### AML.T0085 — Data from AI Services
- **Tactic:** Collection (AML.TA0009)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries collect proprietary or sensitive information by querying AI services that have RAG access to internal documents or tool access to organizational systems.
- **Red Team Testable:** YES — Query authorized AI services to demonstrate data collection capability.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0085.000 | RAG Databases | Extract documents and data from RAG-indexed organizational knowledge bases | YES — Requires RAG-enabled system |
| AML.T0085.001 | AI Agent Tools | Use agent tool invocations to collect data from connected organizational systems | YES — Requires agent with tool access |

---

#### AML.T0099 — AI Agent Tool Data Poisoning
- **Tactic:** Collection (AML.TA0009), Persistence (AML.TA0006)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** Adversaries place malicious or inaccurate content in locations where AI agents will invoke and process it, poisoning agent behavior through tool interactions.
- **Red Team Testable:** YES — Can demonstrate by placing test content in authorized environments.

---

### TACTIC: ML Attack Staging (AML.TA0001)
*Adversaries leverage knowledge of and access to the target model to prepare and tailor attacks.*

---

#### AML.T0005 — Create Proxy ML Model
- **Tactic:** ML Attack Staging (AML.TA0001)
- **Maturity:** Demonstrated
- **Description:** Adversaries create substitute models that mimic the target model's behavior for offline attack development and testing, avoiding detection by the target system during attack refinement.
- **Red Team Testable:** YES — Building proxy models is standard ML red team preparation.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0005.000 | Train Proxy via Gathered ML Artifacts | Build proxy models from representative datasets and architectures gathered during recon | YES |
| AML.T0005.001 | Train Proxy via Replication | Replicate private models through repeated API queries (model extraction attack) | YES — Requires authorized API access |
| AML.T0005.002 | Use Pre-Trained Model | Leverage off-the-shelf pre-trained models as functional proxies for target systems | YES |

---

#### AML.T0042 — Verify Attack
- **Tactic:** ML Attack Staging (AML.TA0001)
- **Maturity:** Demonstrated
- **Description:** Adversaries validate attack effectiveness via the inference API or offline proxy model copies before deployment, gaining confidence the attack will succeed against the production target.
- **Red Team Testable:** YES — Attack verification is standard red team activity.

---

#### AML.T0043 — Craft Adversarial Data
- **Tactic:** ML Attack Staging (AML.TA0001)
- **Maturity:** Realized
- **Description:** Adversaries create modified inputs (adversarial examples) designed to cause the AI model to produce incorrect, harmful, or adversary-desired outputs. Effects range from misclassification to energy exhaustion.
- **Red Team Testable:** YES — Adversarial example crafting is well-established; tools like ART, CleverHans, Foolbox are available.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0043.000 | White-Box Optimization | Use full model access to directly optimize adversarial examples via gradient methods | YES — Requires white-box model access |
| AML.T0043.001 | Black-Box Optimization | Optimize adversarial examples using only API inference access (more queries required) | YES — Requires API access |
| AML.T0043.002 | Black-Box Transfer | Use proxy model attacks that generalize to target model via transferability | YES |
| AML.T0043.003 | Manual Modification | Manually craft adversarial inputs using domain knowledge and trial-and-error | YES |
| AML.T0043.004 | Insert Backdoor Trigger | Add imperceptible triggers (pixel patterns, audio tones) that activate backdoored model behavior | YES — Requires model training access |

---

#### AML.T0079 — Stage Capabilities
- **Tactic:** ML Attack Staging (AML.TA0001)
- **Maturity:** Demonstrated (added v4.9.0, Apr 2025)
- **Description:** Adversaries stage attack capabilities (poisoned datasets, malicious models, adversarial examples) in positions where they will be consumed by the victim's AI pipeline.
- **Red Team Testable:** YES — Can stage test artifacts in authorized environments to demonstrate the capability.

---

### TACTIC: Command and Control (AML.TA0014)
*Adversaries communicate with and control compromised AI systems.*

---

#### AML.T0072 — Reverse Shell
- **Tactic:** Command and Control (AML.TA0014)
- **Maturity:** Realized (added v4.9.0, Apr 2025)
- **Description:** Adversaries utilize a reverse shell on compromised AI infrastructure hosts (model servers, training clusters, MLOps platforms) to establish persistent command and control, with the victim's system initiating outbound connections.
- **Red Team Testable:** YES — Standard reverse shell establishment on authorized hosts; applies to AI infrastructure.

---

#### AML.T0108 — AI Agent
- **Tactic:** Command and Control (AML.TA0014)
- **Maturity:** Demonstrated (added v5.4.0, Feb 2026)
- **Description:** Adversaries leverage a compromised or maliciously deployed AI agent as a command and control channel, using the agent's outbound communications and tool invocations to issue commands and receive data from compromised systems while blending with legitimate AI traffic.
- **Red Team Testable:** YES — Can demonstrate with authorized AI agent deployment configured as a C2 channel.

---

### TACTIC: Exfiltration (AML.TA0010)
*Adversaries steal AI artifacts, model intellectual property, or sensitive data processed by AI systems.*

---

#### AML.T0024 — Exfiltration via ML Inference API
- **Tactic:** Exfiltration (AML.TA0010)
- **Maturity:** Feasible
- **Description:** Adversaries extract private information through targeted queries to the model's inference API, exploiting model leakage vulnerabilities to reconstruct training data or copy the model.
- **Red Team Testable:** PARTIAL — Membership inference and model extraction are demonstrable in lab settings; depends on target model architecture and output verbosity.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0024.000 | Infer Training Data Membership | Determine whether specific data samples were in the training set via confidence score analysis | PARTIAL — Requires verbose model outputs |
| AML.T0024.001 | Invert ML Model | Reconstruct training data using confidence scores from inference API | PARTIAL — Effectiveness depends on model type and output detail |
| AML.T0024.002 | Extract ML Model | Copy a functional model through repeated API queries (model stealing attack) | YES — Demonstrable with authorized API access |

---

#### AML.T0025 — Exfiltration via Cyber Means
- **Tactic:** Exfiltration (AML.TA0010)
- **Maturity:** Realized
- **Description:** Adversaries exfiltrate ML artifacts (models, datasets, training code, API keys) via traditional cybersecurity exfiltration techniques (encrypted channels, DNS tunneling, cloud storage uploads).
- **Red Team Testable:** YES — Standard exfiltration techniques applied to ML artifacts.

---

#### AML.T0056 — Extract LLM System Prompt
- **Tactic:** Exfiltration (AML.TA0010)
- **Maturity:** Feasible
- **Description:** Adversaries extract an LLM's system prompt (confidential instructions, persona definitions, tool configurations) through carefully crafted queries, stealing intellectual property and operational context.
- **Red Team Testable:** YES — Core LLM red team technique against authorized systems.

---

#### AML.T0057 — LLM Data Leakage
- **Tactic:** Exfiltration (AML.TA0010)
- **Maturity:** Demonstrated
- **Description:** Adversaries craft prompts that cause an LLM to leak sensitive information from its training data, in-context data, or connected data sources (RAG, conversation history, tool outputs).
- **Red Team Testable:** YES — Demonstrable against authorized LLM deployments.

---

#### AML.T0086 — Exfiltration via AI Agent Tool Invocation
- **Tactic:** Exfiltration (AML.TA0010)
- **Maturity:** Demonstrated (added v5.0.0, Sep 2025)
- **Description:** Adversaries use prompts to invoke AI agent tools (file upload, email, API calls) to exfiltrate data from the systems the agent has access to, leveraging the agent's legitimate permissions.
- **Red Team Testable:** YES — Can demonstrate with authorized AI agent and tool access.

---

### TACTIC: Impact (AML.TA0011)
*Adversaries manipulate, interrupt, erode confidence in, or destroy AI systems and the organizations that rely on them.*

---

#### AML.T0029 — Denial of ML Service
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Demonstrated
- **Description:** Adversaries flood ML systems with computationally expensive requests crafted to maximize resource consumption, degrading or shutting down the service for legitimate users.
- **Red Team Testable:** YES — Load testing and DoS simulation against authorized systems; requires careful scoping to avoid disruption.

---

#### AML.T0031 — Erode ML Model Integrity
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Realized
- **Description:** Adversaries repeatedly submit adversarial data to a deployed model, gradually degrading its performance over time and eroding organizational confidence in the system.
- **Red Team Testable:** YES — Can demonstrate incremental degradation in authorized test environments.

---

#### AML.T0034 — Cost Harvesting
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Feasible
- **Description:** Adversaries target AI services with computationally expensive "sponge" queries designed to maximize energy consumption and API costs, imposing financial harm on the victim organization.
- **Red Team Testable:** PARTIAL — Demonstrable in limited scope; full-scale testing requires authorization and budget impact controls.

---

#### AML.T0046 — Spamming ML System with Chaff Data
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Feasible
- **Description:** Adversaries spam AI systems (particularly human-in-the-loop systems) with large volumes of chaff data, overwhelming analyst capacity and causing genuine alerts to be missed.
- **Red Team Testable:** YES — Can simulate against authorized systems with appropriate safeguards.

---

#### AML.T0048 — External Harms
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Realized
- **Description:** Adversaries abuse access to AI systems to cause harms external to the system itself — financial, reputational, societal, or personal harms affecting organizations, individuals, or populations.
- **Red Team Testable:** PARTIAL — Can demonstrate the mechanism; actual harm realization is outside authorized scope.

##### Sub-techniques:
| ID | Name | Description | Testable |
|----|------|-------------|----------|
| AML.T0048.000 | Financial Harm | Generate monetary loss through AI-enabled theft, fraud, market manipulation, or coercion | PARTIAL — Mechanism demonstrable; actual harm not authorized |
| AML.T0048.001 | Reputational Harm | Damage organizational reputation through AI-generated disinformation or deepfakes | PARTIAL — Mechanism demonstrable |
| AML.T0048.002 | Societal Harm | Create harmful outcomes affecting general public via disinformation or biased AI outputs | NO — Requires production system and real-world impact |
| AML.T0048.003 | User Harm | Target individual victims with AI-enabled financial or reputational damage | PARTIAL — Mechanism demonstrable |
| AML.T0048.004 | ML Intellectual Property Theft | Steal proprietary training data and models for economic gain | YES — Demonstrable via model extraction techniques |

---

#### AML.T0059 — Erode Dataset Integrity
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Demonstrated
- **Description:** Adversaries poison or manipulate portions of a training or evaluation dataset over time, gradually reducing its usefulness, causing model degradation, and consuming organizational resources in retraining.
- **Red Team Testable:** YES — Can demonstrate in authorized lab environments with test datasets.

---

#### AML.T0076 — Corrupt AI Model
- **Tactic:** Impact (AML.TA0011)
- **Maturity:** Demonstrated (added v4.9.0, Apr 2025)
- **Description:** Adversaries directly corrupt AI model files or weights to degrade or destroy model functionality, potentially rendering the system inoperable or causing it to produce consistently incorrect outputs.
- **Red Team Testable:** YES — Demonstrable in authorized model file manipulation exercises.

---

#### AML.T0077 — LLM Response Rendering
- **Tactic:** Impact (AML.TA0011), Defense Evasion (AML.TA0007)
- **Maturity:** Demonstrated (added v4.9.0, Apr 2025)
- **Description:** Adversaries craft LLM outputs that, when rendered by downstream applications (browsers, terminals, chat UIs), execute code or display malicious content through markdown injection, HTML injection, or ANSI escape sequences.
- **Red Team Testable:** YES — Can test against authorized LLM-integrated applications with rendering capabilities.

---

#### AML.T0100 — AI Agent Clickbait
- **Tactic:** Impact (AML.TA0011), Execution (AML.TA0005)
- **Maturity:** Demonstrated (added v5.2.0, Dec 2025)
- **Description:** A novel attack class — adversaries lure AI agent browsers into unintended actions (clicks, navigation, code copying) by exploiting how agents interpret UI elements, visual cues, or embedded prompts on websites, potentially causing agents to execute malicious code directly in the user's OS.
- **Red Team Testable:** YES — Can demonstrate against authorized AI browser agent deployments; novel and highly relevant for agentic AI red teams.

---

#### AML.T0103 — Deploy AI Agent
- **Tactic:** Impact (AML.TA0011), Execution (AML.TA0005)
- **Maturity:** Demonstrated (added v5.3.0, Jan 2026)
- **Description:** Adversaries deploy malicious AI agents within victim environments or AI platforms, creating persistent autonomous entities that execute adversary-defined tasks using the victim's resources and credentials.
- **Red Team Testable:** YES — Can demonstrate unauthorized agent deployment in authorized test environments.

---

#### AML.T0104 — Publish Poisoned AI Agent Tool
- **Tactic:** Impact (AML.TA0011), Resource Development (AML.TA0003)
- **Maturity:** Demonstrated (added v5.4.0, Feb 2026)
- **Description:** Adversaries publish maliciously modified or backdoored AI agent tools (MCP servers, plugins, extensions) to public marketplaces, poisoning the supply chain for organizations that install and connect these tools to their AI agents.
- **Red Team Testable:** PARTIAL — Poisoning and testing a tool is lab-demonstrable; publishing to real marketplaces is outside authorized scope.

---

#### AML.T0105 — Escape to Host
- **Tactic:** Impact (AML.TA0011), Privilege Escalation (AML.TA0012)
- **Maturity:** Demonstrated (added v5.4.0, Feb 2026)
- **Description:** Adversaries exploit AI agent tool access (code execution sandboxes, container escapes) to break out of the AI system's intended execution environment and gain direct access to the underlying host system.
- **Red Team Testable:** YES — Container/sandbox escape testing applicable to AI code execution environments; requires authorized infrastructure.

---

#### AML.T0094 — Delay Execution of LLM Instructions
- **Tactic:** Impact (AML.TA0011), Persistence (AML.TA0006)
- **Maturity:** Demonstrated (added v5.1.0, Nov 2025)
- **Description:** Adversaries inject instructions into LLM context that are configured to execute only after a delay or upon a specific future condition, making detection harder and enabling time-shifted attacks.
- **Red Team Testable:** YES — Can demonstrate delayed instruction execution against authorized LLM systems.

---

## CROSS-TACTIC TECHNIQUE INDEX

Techniques that span multiple tactics (listed under all relevant tactics above):

| Technique ID | Name | Tactics |
|---|---|---|
| AML.T0012 | Valid Accounts | Initial Access, Privilege Escalation |
| AML.T0015 | Evade ML Model | Initial Access, Defense Evasion, Impact |
| AML.T0018 | Manipulate AI Model | Persistence, ML Attack Staging |
| AML.T0020 | Poison Training Data | Resource Development, Persistence |
| AML.T0048 | External Harms | Impact (multiple sub-harm types) |
| AML.T0051 | LLM Prompt Injection | Execution (and cascades to other tactics) |
| AML.T0052 | Phishing | Initial Access, Lateral Movement |
| AML.T0053 | AI Agent Tool Invocation | Execution, Privilege Escalation |
| AML.T0054 | LLM Jailbreak | Privilege Escalation, Defense Evasion |
| AML.T0077 | LLM Response Rendering | Impact, Defense Evasion |
| AML.T0091 | Use Alternate Authentication Material | Privilege Escalation, Credential Access |
| AML.T0099 | AI Agent Tool Data Poisoning | Collection, Persistence |
| AML.T0100 | AI Agent Clickbait | Impact, Execution |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | Execution, Impact |
| AML.T0103 | Deploy AI Agent | Impact, Execution |
| AML.T0104 | Publish Poisoned AI Agent Tool | Impact, Resource Development |
| AML.T0105 | Escape to Host | Impact, Privilege Escalation |

---

## COMPLETE TECHNIQUES QUICK-REFERENCE TABLE

| Technique ID | Name | Tactic(s) | Maturity | Red Team Testable |
|---|---|---|---|---|
| AML.T0000 | Search for Victim's Publicly Available Research Materials | Recon | Demonstrated | YES |
| AML.T0000.000 | Journals and Conference Proceedings | Recon | Feasible | YES |
| AML.T0000.001 | Pre-Print Repositories | Recon | Demonstrated | YES |
| AML.T0000.002 | Technical Blogs | Recon | Feasible | YES |
| AML.T0001 | Search for Publicly Available Adversarial Vulnerability Analysis | Recon | Demonstrated | YES |
| AML.T0002 | Acquire Public ML Artifacts | Resource Dev | Realized | YES |
| AML.T0002.000 | Datasets | Resource Dev | Demonstrated | YES |
| AML.T0002.001 | Models | Resource Dev | Demonstrated | YES |
| AML.T0003 | Search Victim-Owned Websites | Recon | Demonstrated | YES |
| AML.T0004 | Search Application Repositories | Recon | Demonstrated | YES |
| AML.T0005 | Create Proxy ML Model | ML Attack Staging | Demonstrated | YES |
| AML.T0005.000 | Train Proxy via Gathered ML Artifacts | ML Attack Staging | Demonstrated | YES |
| AML.T0005.001 | Train Proxy via Replication | ML Attack Staging | Demonstrated | YES |
| AML.T0005.002 | Use Pre-Trained Model | ML Attack Staging | Feasible | YES |
| AML.T0006 | Active Scanning | Recon | Realized | YES |
| AML.T0007 | Discover ML Artifacts | Discovery | Demonstrated | YES |
| AML.T0008 | Acquire Infrastructure | Resource Dev | Realized | YES |
| AML.T0008.000 | ML Development Workspaces | Resource Dev | Demonstrated | YES |
| AML.T0008.001 | Consumer Hardware | Resource Dev | Realized | YES |
| AML.T0008.002 | Domains | Resource Dev | Demonstrated | YES |
| AML.T0008.003 | Physical Countermeasures | Resource Dev | Demonstrated | PARTIAL |
| AML.T0008.004 | Serverless | Resource Dev | Demonstrated | YES |
| AML.T0010 | AI Supply Chain Compromise | Initial Access | Realized | PARTIAL |
| AML.T0010.000 | Hardware | Initial Access | Feasible | NO |
| AML.T0010.001 | AI Software | Initial Access | Realized | YES |
| AML.T0010.002 | Data | Initial Access | Realized | YES |
| AML.T0010.003 | Model | Initial Access | Realized | YES |
| AML.T0010.004 | Container Registry | Initial Access | Demonstrated | YES |
| AML.T0011 | User Execution | Execution | Realized | YES |
| AML.T0011.000 | Unsafe ML Artifacts | Execution | Realized | YES |
| AML.T0011.001 | Malicious Package | Execution | Realized | YES |
| AML.T0011.002 | Poisoned AI Agent Tool | Execution | Demonstrated | YES |
| AML.T0011.003 | Malicious Link | Execution | Realized | YES |
| AML.T0012 | Valid Accounts | Initial Access / Priv Esc | Realized | YES |
| AML.T0013 | Discover ML Model Ontology | Discovery | Demonstrated | YES |
| AML.T0014 | Discover ML Model Family | Discovery | Feasible | YES |
| AML.T0015 | Evade ML Model | Initial Access / Defense Evasion / Impact | Realized | YES |
| AML.T0016 | Obtain Capabilities | Resource Dev | Realized | YES |
| AML.T0016.000 | Adversarial ML Attack Implementations | Resource Dev | Realized | YES |
| AML.T0016.001 | Software Tools | Resource Dev | Realized | YES |
| AML.T0016.002 | Generative AI | Resource Dev | Realized | YES |
| AML.T0017 | Develop Capabilities | Resource Dev | Realized | YES |
| AML.T0017.000 | Adversarial ML Attacks | Resource Dev | Demonstrated | YES |
| AML.T0018 | Manipulate AI Model | Persistence / ML Attack Staging | Realized | YES |
| AML.T0018.000 | Poison ML Model | Persistence | Demonstrated | YES |
| AML.T0018.001 | Modify AI Model Architecture | Persistence | Demonstrated | YES |
| AML.T0018.002 | Embed Malware | Persistence | Realized | YES |
| AML.T0019 | Publish Poisoned Datasets | Resource Dev | Demonstrated | PARTIAL |
| AML.T0020 | Poison Training Data | Resource Dev / Persistence | Realized | YES |
| AML.T0021 | Establish Accounts | Resource Dev | Realized | YES |
| AML.T0024 | Exfiltration via ML Inference API | Exfiltration | Feasible | PARTIAL |
| AML.T0024.000 | Infer Training Data Membership | Exfiltration | Feasible | PARTIAL |
| AML.T0024.001 | Invert ML Model | Exfiltration | Feasible | PARTIAL |
| AML.T0024.002 | Extract ML Model | Exfiltration | Feasible | YES |
| AML.T0025 | Exfiltration via Cyber Means | Exfiltration | Realized | YES |
| AML.T0029 | Denial of ML Service | Impact | Demonstrated | YES |
| AML.T0031 | Erode ML Model Integrity | Impact | Realized | YES |
| AML.T0034 | Cost Harvesting | Impact | Feasible | PARTIAL |
| AML.T0035 | ML Artifact Collection | Collection | Realized | YES |
| AML.T0036 | Data from Information Repositories | Collection | Realized | YES |
| AML.T0037 | Data from Local System | Collection | Realized | YES |
| AML.T0040 | AI Model Inference API Access | ML Model Access | Demonstrated | YES |
| AML.T0041 | Physical Environment Access | ML Model Access | Demonstrated | PARTIAL |
| AML.T0042 | Verify Attack | ML Attack Staging | Demonstrated | YES |
| AML.T0043 | Craft Adversarial Data | ML Attack Staging | Realized | YES |
| AML.T0043.000 | White-Box Optimization | ML Attack Staging | Demonstrated | YES |
| AML.T0043.001 | Black-Box Optimization | ML Attack Staging | Demonstrated | YES |
| AML.T0043.002 | Black-Box Transfer | ML Attack Staging | Demonstrated | YES |
| AML.T0043.003 | Manual Modification | ML Attack Staging | Realized | YES |
| AML.T0043.004 | Insert Backdoor Trigger | ML Attack Staging | Demonstrated | YES |
| AML.T0044 | Full ML Model Access | ML Model Access | Demonstrated | YES |
| AML.T0046 | Spamming ML System with Chaff Data | Impact | Feasible | YES |
| AML.T0047 | ML-Enabled Product or Service | ML Model Access | Realized | YES |
| AML.T0048 | External Harms | Impact | Realized | PARTIAL |
| AML.T0048.000 | Financial Harm | Impact | Realized | PARTIAL |
| AML.T0048.001 | Reputational Harm | Impact | Demonstrated | PARTIAL |
| AML.T0048.002 | Societal Harm | Impact | Feasible | NO |
| AML.T0048.003 | User Harm | Impact | Realized | PARTIAL |
| AML.T0048.004 | ML Intellectual Property Theft | Impact | Demonstrated | YES |
| AML.T0049 | Exploit Public-Facing Application | Initial Access | Realized | YES |
| AML.T0050 | Command and Scripting Interpreter | Execution | Demonstrated | YES |
| AML.T0051 | LLM Prompt Injection | Execution | Realized | YES |
| AML.T0051.000 | Direct | Execution | Realized | YES |
| AML.T0051.001 | Indirect | Execution | Demonstrated | YES |
| AML.T0051.002 | Triggered | Execution | Demonstrated | YES |
| AML.T0052 | Phishing | Initial Access / Lateral Movement | Realized | YES |
| AML.T0052.000 | Spearphishing via Social Engineering LLM | Initial Access | Demonstrated | YES |
| AML.T0053 | AI Agent Tool Invocation | Execution / Priv Esc | Demonstrated | YES |
| AML.T0054 | LLM Jailbreak | Priv Esc / Defense Evasion | Demonstrated | YES |
| AML.T0055 | Unsecured Credentials | Credential Access | Realized | YES |
| AML.T0056 | Extract LLM System Prompt | Exfiltration | Feasible | YES |
| AML.T0057 | LLM Data Leakage | Exfiltration | Demonstrated | YES |
| AML.T0058 | Publish Poisoned Models | Resource Dev | Realized | PARTIAL |
| AML.T0059 | Erode Dataset Integrity | Impact | Demonstrated | YES |
| AML.T0060 | Publish Hallucinated Entities | Resource Dev | Demonstrated | PARTIAL |
| AML.T0061 | LLM Prompt Self-Replication | Persistence | Demonstrated | YES |
| AML.T0062 | Discover LLM Hallucinations | Discovery | Demonstrated | YES |
| AML.T0063 | Discover AI Model Outputs | Discovery | Demonstrated | YES |
| AML.T0064 | Gather RAG-Indexed Targets | Recon | Demonstrated | YES |
| AML.T0065 | LLM Prompt Crafting | Resource Dev | Realized | YES |
| AML.T0066 | Retrieval Content Crafting | Resource Dev | Demonstrated | YES |
| AML.T0067 | LLM Trusted Output Components Manipulation | Defense Evasion | Demonstrated | YES |
| AML.T0067.000 | Citations | Defense Evasion | Demonstrated | YES |
| AML.T0068 | LLM Prompt Obfuscation | Defense Evasion | Demonstrated | YES |
| AML.T0069 | Discover LLM System Information | Discovery | Demonstrated | YES |
| AML.T0069.000 | Special Character Sets | Discovery | Demonstrated | YES |
| AML.T0069.001 | System Instruction Keywords | Discovery | Demonstrated | YES |
| AML.T0069.002 | System Prompt | Discovery | Demonstrated | YES |
| AML.T0070 | RAG Poisoning | Persistence | Demonstrated | YES |
| AML.T0071 | False RAG Entry Injection | Defense Evasion | Demonstrated | YES |
| AML.T0072 | Reverse Shell | C2 | Realized | YES |
| AML.T0073 | Impersonation | Defense Evasion | Realized | YES |
| AML.T0074 | Masquerading | Defense Evasion | Realized | YES |
| AML.T0075 | Cloud Service Discovery | Discovery | Feasible | YES |
| AML.T0076 | Corrupt AI Model | Impact | Demonstrated | YES |
| AML.T0077 | LLM Response Rendering | Impact / Defense Evasion | Demonstrated | YES |
| AML.T0078 | Drive-by Compromise | Initial Access | Demonstrated | YES |
| AML.T0079 | Stage Capabilities | ML Attack Staging | Demonstrated | YES |
| AML.T0080 | AI Agent Context Poisoning | Persistence | Demonstrated | YES |
| AML.T0080.001 | Memory | Persistence | Demonstrated | YES |
| AML.T0080.002 | Thread | Persistence | Demonstrated | YES |
| AML.T0081 | Modify AI Agent Configuration | Persistence | Demonstrated | YES |
| AML.T0082 | RAG Credential Harvesting | Credential Access | Demonstrated | YES |
| AML.T0083 | Credentials from AI Agent Configuration | Credential Access | Demonstrated | YES |
| AML.T0084 | Discover AI Agent Configuration | Discovery | Demonstrated | YES |
| AML.T0084.000 | Embedded Knowledge | Discovery | Demonstrated | YES |
| AML.T0084.001 | Tool Definitions | Discovery | Demonstrated | YES |
| AML.T0084.002 | Activation Triggers | Discovery | Demonstrated | YES |
| AML.T0085 | Data from AI Services | Collection | Demonstrated | YES |
| AML.T0085.000 | RAG Databases | Collection | Demonstrated | YES |
| AML.T0085.001 | AI Agent Tools | Collection | Demonstrated | YES |
| AML.T0086 | Exfiltration via AI Agent Tool Invocation | Exfiltration | Demonstrated | YES |
| AML.T0087 | Gather Victim Identity Information | Recon | Demonstrated | YES |
| AML.T0088 | Generate Deepfakes | Execution | Demonstrated | YES |
| AML.T0089 | Process Discovery | Discovery | Realized | YES |
| AML.T0090 | OS Credential Dumping | Credential Access | Realized | YES |
| AML.T0091 | Use Alternate Authentication Material | Priv Esc / Credential Access | Realized | YES |
| AML.T0091.000 | Application Access Token | Priv Esc / Credential Access | Realized | YES |
| AML.T0092 | Manipulate User LLM Chat History | Persistence | Demonstrated | YES |
| AML.T0093 | Prompt Infiltration via Public-Facing Application | Initial Access | Demonstrated | YES |
| AML.T0094 | Delay Execution of LLM Instructions | Impact / Persistence | Demonstrated | YES |
| AML.T0095 | Search Open Websites/Domains | Recon | Demonstrated | YES |
| AML.T0096 | AI Service API | ML Model Access | Demonstrated | YES |
| AML.T0097 | Virtualization/Sandbox Evasion | Defense Evasion | Demonstrated | YES |
| AML.T0098 | AI Agent Tool Credential Harvesting | Credential Access | Demonstrated | YES |
| AML.T0099 | AI Agent Tool Data Poisoning | Collection / Persistence | Demonstrated | YES |
| AML.T0100 | AI Agent Clickbait | Impact / Execution | Demonstrated | YES |
| AML.T0101 | Data Destruction via AI Agent Tool Invocation | Execution / Impact | Demonstrated | YES |
| AML.T0102 | Generate Malicious Commands | Execution | Demonstrated | YES |
| AML.T0103 | Deploy AI Agent | Impact / Execution | Demonstrated | YES |
| AML.T0104 | Publish Poisoned AI Agent Tool | Impact / Resource Dev | Demonstrated | PARTIAL |
| AML.T0105 | Escape to Host | Impact / Priv Esc | Demonstrated | YES |
| AML.T0106 | Exploitation for Credential Access | Credential Access | Demonstrated | YES |
| AML.T0107 | Exploitation for Defense Evasion | Defense Evasion | Demonstrated | YES |
| AML.T0108 | AI Agent | C2 | Demonstrated | YES |

---

## RED TEAM TESTABILITY SUMMARY

| Category | Count |
|---|---|
| YES — Fully testable | ~89 |
| PARTIAL — Partially testable | ~15 |
| NO — Not practically testable | ~2 |

### Techniques marked PARTIAL — explanation of limitations:
- **AML.T0008.003** (Physical Countermeasures) — Requires physical access to environment where AI sensors operate
- **AML.T0010.000** (Hardware Supply Chain) — Requires access to hardware manufacturing/distribution chain
- **AML.T0019** (Publish Poisoned Datasets) — Publishing to live public registries is outside authorized scope; lab demonstrable
- **AML.T0024** and sub-techniques — Effectiveness heavily depends on target model's output verbosity and architecture; model inversion (T0024.001) is architecture-dependent
- **AML.T0034** (Cost Harvesting) — Full-scale testing would incur real costs; limited demonstration possible
- **AML.T0041** (Physical Environment Access) — Requires physical access to AI deployment environment
- **AML.T0048.000-.003** (External Harms sub-types) — Mechanism is demonstrable; causing actual harm is never authorized
- **AML.T0058** (Publish Poisoned Models) — Publishing to real Hugging Face/registries outside authorized scope
- **AML.T0060** (Publish Hallucinated Entities) — Discovery phase testable; deployment to live services requires scoping
- **AML.T0104** (Publish Poisoned AI Agent Tool) — Lab poisoning demonstrable; publishing to live marketplaces requires scoping

### Techniques marked NO:
- **AML.T0010.000** (Hardware) — Requires hardware supply chain access; not feasible in standard red team
- **AML.T0048.002** (Societal Harm) — Requires production system and actual societal impact; no authorized equivalent

---

## CHANGELOG — KEY FRAMEWORK VERSIONS

| Version | Date | Key Additions |
|---|---|---|
| v4.4.0 | Apr 2023 | 1 matrix, 12 tactics, 40 techniques, 27 sub-techniques (baseline) |
| v4.7.0 | Oct 2024 | Added LLM/GenAI techniques: T0058-T0063 (prompt self-replication, hallucinations, poisoned models) |
| v4.8.0 | Mar 2025 | Added RAG-focused techniques: T0064-T0071 (RAG poisoning, LLM prompt crafting, obfuscation) |
| v4.9.0 | Apr 2025 | Added T0072-T0079 (reverse shell, impersonation, masquerading, cloud discovery, corrupt model) |
| v5.0.0 | Sep 2025 | Added 14 AI agent techniques: T0080-T0086 (agent context poisoning, RAG cred harvesting, agent config) |
| v5.1.0 | Nov 2025 | Added T0087-T0095 (deepfakes, identity gathering, OS cred dump, chat history manipulation) |
| v5.2.0 | Dec 2025 | Added T0096-T0102 (AI service API, sandbox evasion, agent tool attacks, generate malicious commands) |
| v5.3.0 | Jan 2026 | Added T0103 (Deploy AI Agent) |
| v5.4.0 | Feb 2026 | Added T0104-T0108 (poisoned agent tools, escape to host, exploitation techniques, AI Agent C2) |

---

## SOURCES

- [MITRE ATLAS Official Site](https://atlas.mitre.org)
- [MITRE ATLAS Data Repository (GitHub)](https://github.com/mitre-atlas/atlas-data)
- [MITRE ATLAS CHANGELOG](https://github.com/mitre-atlas/atlas-data/blob/main/CHANGELOG.md)
- [MITRE ATLAS Navigator](https://mitre-atlas.github.io/atlas-navigator/)
- [MISP Galaxy — MITRE ATLAS Attack Patterns](https://misp-galaxy.org/mitre-atlas-attack-pattern/)
- [Zenity Labs — MITRE ATLAS AI Agent Techniques (Sep 2025)](https://zenity.io/blog/current-events/zenity-labs-and-mitre-atlas-collaborate-to-advances-ai-agent-security-with-the-first-release-of)
- [Zenity Labs — MITRE ATLAS 2026 Update](https://zenity.io/blog/current-events/zenitys-contributions-to-mitre-atlas-first-2026-update)
- [Practical DevSecOps — MITRE ATLAS Framework Guide](https://www.practical-devsecops.com/mitre-atlas-framework-guide-securing-ai-systems/)
- [Vectra AI — MITRE ATLAS Overview](https://www.vectra.ai/topics/mitre-atlas)
- [MITRE ATLAS Fact Sheet (PDF)](https://atlas.mitre.org/pdf-files/MITRE_ATLAS_Fact_Sheet.pdf)
- [CSRC NIST — MITRE ATLAS Overview Presentation](https://csrc.nist.gov/csrc/media/Presentations/2025/mitre-atlas/TuePM2.1-MITRE%20ATLAS%20Overview%20Sept%202025.pdf)
