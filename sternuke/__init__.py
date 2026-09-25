# -*- coding: utf-8 -*-
"""
sternuke
========

A local, AI-assisted vulnerability *assessment* framework.

sternuke is a high-speed, asynchronous scanner and autonomous agent that runs
entirely on infrastructure you control:

* **Web/API assessment** - async request manager with local signature (regex /
  word / status) matching and bounded parameter fuzzing.
* **Blockchain repo assessment** - static structural modelling of Solidity and
  Rust sources (contracts, functions, visibility, access controls) before any
  model sees the code.
* **Autonomous AI agent** - orchestrates a *local* Ollama / vLLM model over the
  standard OpenAI-compatible API to synthesise localized JSON/YAML detection
  rules; degrades to deterministic heuristics when offline.

No commercial APIs, license keys or paid cloud feeds are required or contacted.

This tool is for authorised security assessment only - use it exclusively on
systems and code you own or have explicit written permission to test.
"""

from .engine import (
    AsyncHttpClient, Finding, HttpResponse, Matcher, RepoCrawler, Rule,
    RuleEngine, ScanPolicy, SourceFile, WebScanner,
)
from .ai_agent import (
    AIAgent, ContractBlueprint, FunctionInfo, LocalModelClient, ModelConfig,
    RustAnalyzer, SolidityAnalyzer, StateVariable, WebContextBuilder,
)
from .state_engine import (
    ChainResult, DependencyGraph, Extractor, InteractionStep, SelfCorrectionLoop,
    SessionState, StatefulChainEngine, StepResult,
)
from .memory import (
    HashingEmbedder, MemoryRecord, Recall, VectorMemory, build_default_memory,
    cosine,
)
from .cognitive import (
    BusinessLogicMutator, CallGraphNode, CrossContractAnalyzer, ExternalCall,
)
from .fuzzing import (
    AbiFunction, BinaryFuzzer, ByteMutator, ContractFuzzer, Corpus, FuzzBudget,
    ScopeError, TypedMutator, WebFuzzer, encode_call, keccak256,
)
from .fuzzing.abi_advanced import (
    AbiType, decode as abi_decode, encode as abi_encode,
    encode_call as abi_encode_call, parse_type,
)
from .state_engine import (
    DependencyGraphEngine, ExtractionRule, RequestSpec, SessionStateManager,
    jsonpath_get,
)
from .intelligence import (
    AnomalyContext, Advisory, CVSSCalculator, CVSSVector, HackerOneReporter,
    IntelligenceEngine, NucleiTemplateWriter, SeverityMapper,
)
from .assets import Asset, AssetParser, AssetType
from .auth import AuthError, FormAuthenticator, LoginConfig
from .webgui import WebDashboard, serve as serve_dashboard

__version__ = "2.1.3"

__all__ = [
    # engine
    "AsyncHttpClient", "Finding", "HttpResponse", "Matcher", "RepoCrawler",
    "Rule", "RuleEngine", "ScanPolicy", "SourceFile", "WebScanner",
    # ai_agent
    "AIAgent", "ContractBlueprint", "FunctionInfo", "LocalModelClient",
    "ModelConfig", "RustAnalyzer", "SolidityAnalyzer", "StateVariable",
    "WebContextBuilder",
    # state_engine
    "ChainResult", "DependencyGraph", "Extractor", "InteractionStep",
    "SelfCorrectionLoop", "SessionState", "StatefulChainEngine", "StepResult",
    # memory
    "HashingEmbedder", "MemoryRecord", "Recall", "VectorMemory",
    "build_default_memory", "cosine",
    # cognitive
    "BusinessLogicMutator", "CallGraphNode", "CrossContractAnalyzer",
    "ExternalCall",
    # fuzzing
    "AbiFunction", "BinaryFuzzer", "ByteMutator", "ContractFuzzer", "Corpus",
    "FuzzBudget", "ScopeError", "TypedMutator", "WebFuzzer", "encode_call",
    "keccak256",
    # advanced ABI codec
    "AbiType", "abi_decode", "abi_encode", "abi_encode_call", "parse_type",
    # state engine (v2)
    "DependencyGraphEngine", "ExtractionRule", "RequestSpec",
    "SessionStateManager", "jsonpath_get",
    # intelligence
    "AnomalyContext", "Advisory", "CVSSCalculator", "CVSSVector",
    "HackerOneReporter", "IntelligenceEngine", "NucleiTemplateWriter",
    "SeverityMapper",
    # assets
    "Asset", "AssetParser", "AssetType",
    # auth
    "AuthError", "FormAuthenticator", "LoginConfig",
    # web dashboard
    "WebDashboard", "serve_dashboard",
    "__version__",
]
