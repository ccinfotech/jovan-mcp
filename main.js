/******/ (() => { // webpackBootstrap
/******/ 	"use strict";
/******/ 	var __webpack_modules__ = ([
/* 0 */,
/* 1 */
/***/ ((module) => {

module.exports = require("@modelcontextprotocol/sdk/server/stdio.js");

/***/ }),
/* 2 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.resolvePath = resolvePath;
exports.fetchBootstrap = fetchBootstrap;
exports.getBootstrap = getBootstrap;
exports.getToolMeta = getToolMeta;
exports.toolName = toolName;
exports.toolDesc = toolDesc;
exports.apiPath = apiPath;
const config_1 = __webpack_require__(3);
let _bootstrap = null;
function resolvePath(template, params = {}) {
    let resolved = template;
    for (const [key, value] of Object.entries(params)) {
        resolved = resolved.replace(`:${key}`, encodeURIComponent(value));
    }
    return resolved;
}
async function fetchBootstrap() {
    const url = `${config_1.config.apiBaseUrl}/mcp/bootstrap`;
    const response = await fetch(url, {
        method: 'GET',
        headers: { 'Content-Type': 'application/json' },
    });
    if (!response.ok) {
        const body = await response.text();
        throw new Error(`Bootstrap fetch failed (${response.status}): ${body}`);
    }
    const json = await response.json();
    const data = (json && typeof json === 'object' && 'data' in json && 'success' in json)
        ? json.data
        : json;
    _bootstrap = data;
    return _bootstrap;
}
function getBootstrap() {
    if (!_bootstrap) {
        throw new Error('Bootstrap not loaded. Call fetchBootstrap() at startup first.');
    }
    return _bootstrap;
}
function getToolMeta(toolId) {
    return getBootstrap().tools.find(t => t.id === toolId);
}
function toolName(toolId) {
    return getToolMeta(toolId)?.toolName ?? toolId;
}
function toolDesc(toolId) {
    return getToolMeta(toolId)?.description ?? '';
}
function apiPath(pathKey, params = {}) {
    const template = getBootstrap().paths[pathKey];
    if (!template)
        throw new Error(`Unknown API path key: ${pathKey}`);
    return resolvePath(template, params);
}


/***/ }),
/* 3 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.config = void 0;
function detectClientTool() {
    if (process.env.MCP_CLIENT_TOOL)
        return process.env.MCP_CLIENT_TOOL;
    if (process.env.CLAUDE_CODE_VERSION || process.env.CLAUDE_CODE_ENTRYPOINT)
        return 'claude-code';
    if (process.env.CURSOR_TRACE_ID)
        return 'cursor';
    if (process.env.CONTINUE_CORE_DIR)
        return 'continue';
    if (process.env.CODEIUM_API_KEY)
        return 'windsurf';
    return 'mcp-client';
}
exports.config = {
    apiBaseUrl: process.env.JOVAN_API_URL ?? 'http://localhost:3000/api/v1',
    defaultApiKey: process.env.JOVAN_API_KEY ?? '',
    defaultProjectId: process.env.JOVAN_PROJECT_ID ?? '',
    pollIntervalMs: parseInt(process.env.MCP_POLL_INTERVAL ?? '3000', 10),
    pollTimeoutMs: parseInt(process.env.MCP_POLL_TIMEOUT ?? '900000', 10),
    serverName: process.env.MCP_SERVER_NAME ?? 'jovan-mcp-server',
    serverVersion: process.env.MCP_SERVER_VERSION ?? '1.0.0',
    sessionHeader: process.env.MCP_SESSION_HEADER ?? 'X-MCP-Session',
    clientTool: detectClientTool(),
    requestTimeoutMs: parseInt(process.env.MCP_REQUEST_TIMEOUT ?? '15000', 10),
    maxConcurrentRequests: parseInt(process.env.MCP_MAX_CONCURRENT ?? '4', 10),
    keepAliveMs: parseInt(process.env.MCP_KEEP_ALIVE ?? '30000', 10),
    cacheEnabled: process.env.MCP_CACHE_ENABLED !== 'false',
    cacheTtlListMs: parseInt(process.env.MCP_CACHE_TTL_LIST ?? '30000', 10),
    cacheTtlDetailMs: parseInt(process.env.MCP_CACHE_TTL_DETAIL ?? '15000', 10),
    cacheTtlRefMs: parseInt(process.env.MCP_CACHE_TTL_REF ?? '300000', 10),
    cbFailureThreshold: parseInt(process.env.MCP_CB_FAILURES ?? '5', 10),
    cbResetTimeoutMs: parseInt(process.env.MCP_CB_RESET ?? '30000', 10),
    heartbeatIntervalMs: parseInt(process.env.MCP_HEARTBEAT_INTERVAL ?? '60000', 10),
    heartbeatEnabled: process.env.MCP_HEARTBEAT_ENABLED !== 'false',
    compressionThreshold: parseInt(process.env.MCP_COMPRESS_THRESHOLD ?? '1024', 10),
};


/***/ }),
/* 4 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.createMcpServer = createMcpServer;
const mcp_js_1 = __webpack_require__(5);
const zod_1 = __webpack_require__(6);
const config_1 = __webpack_require__(3);
const session_1 = __webpack_require__(7);
const connect_tool_1 = __webpack_require__(12);
const disconnect_tool_1 = __webpack_require__(21);
const assets_tool_1 = __webpack_require__(22);
const execute_tool_1 = __webpack_require__(23);
const approvals_tool_1 = __webpack_require__(25);
const context_tool_1 = __webpack_require__(26);
const artifacts_tool_1 = __webpack_require__(27);
const bugs_tool_1 = __webpack_require__(28);
const features_tool_1 = __webpack_require__(29);
const polling_tool_1 = __webpack_require__(30);
function logToolExecution(toolId, args, result, startedAt) {
    if (!session_1.sessionManager.isConnected())
        return;
    const session = session_1.sessionManager.get();
    if (!session)
        return;
    const completedAt = Date.now();
    const url = `${config_1.config.apiBaseUrl}/mcp/sessions/log`;
    fetch(url, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            [config_1.config.sessionHeader]: session.sessionToken,
        },
        body: JSON.stringify({
            tool: toolId,
            action: toolId,
            input: typeof args === 'object' && args !== null ? args : {},
            status: result.success ? 'COMPLETED' : 'FAILED',
            startedAt: new Date(startedAt).toISOString(),
            completedAt: new Date(completedAt).toISOString(),
            durationMs: completedAt - startedAt,
            error: result.error,
        }),
    }).catch(() => {
        process.stderr.write(`[MCP:log] Failed to log ${toolId} execution\n`);
    });
}
function withLogging(toolId, handler) {
    return async (args) => {
        const startedAt = Date.now();
        try {
            const result = await handler(args);
            logToolExecution(toolId, args, { success: true }, startedAt);
            return result;
        }
        catch (err) {
            const message = err instanceof Error ? err.message : 'Unknown error';
            logToolExecution(toolId, args, { success: false, error: message }, startedAt);
            throw err;
        }
    };
}
function createMcpServer(bootstrap) {
    const server = new mcp_js_1.McpServer({
        name: bootstrap.server.name,
        version: bootstrap.server.version,
    });
    const name = (id) => {
        const meta = bootstrap.tools.find(t => t.id === id);
        return meta?.toolName ?? id;
    };
    const desc = (id) => {
        const meta = bootstrap.tools.find(t => t.id === id);
        return meta?.description ?? '';
    };
    server.tool(name('AUTH_CONNECT'), desc('AUTH_CONNECT'), {
        apiKey: zod_1.z.string().optional().describe('JoVan API key. Omit if JOVAN_API_KEY env var is set.'),
        projectId: zod_1.z.string().optional().describe('JoVan Project ID. Omit if JOVAN_PROJECT_ID env var is set.'),
    }, async (args) => (0, connect_tool_1.handleConnect)(args));
    server.tool(name('AUTH_DISCONNECT'), desc('AUTH_DISCONNECT'), {}, async () => (0, disconnect_tool_1.handleDisconnect)());
    server.tool(name('ASSETS_LIST'), desc('ASSETS_LIST'), { sdlcPhaseId: zod_1.z.string().optional() }, withLogging('ASSETS_LIST', async (args) => (0, assets_tool_1.handleListAssets)(args)));
    server.tool(name('ASSETS_RETRIEVE'), desc('ASSETS_RETRIEVE'), { packId: zod_1.z.string() }, withLogging('ASSETS_RETRIEVE', async (args) => (0, assets_tool_1.handleRetrieveAsset)(args)));
    server.tool(name('ASSETS_COMPOSE'), desc('ASSETS_COMPOSE'), { sdlcPhaseId: zod_1.z.string(), payload: zod_1.z.record(zod_1.z.unknown()).optional(), justification: zod_1.z.string().optional() }, withLogging('ASSETS_COMPOSE', async (args) => (0, approvals_tool_1.handleCompose)(args)));
    server.tool(name('EXECUTE_PHASE'), desc('EXECUTE_PHASE'), { sdlcPhaseId: zod_1.z.string(), action: zod_1.z.string(), payload: zod_1.z.record(zod_1.z.unknown()).optional(), justification: zod_1.z.string().optional() }, withLogging('EXECUTE_PHASE', async (args) => (0, execute_tool_1.handleExecutePhase)(args)));
    server.tool(name('CHECK_STATUS'), desc('CHECK_STATUS'), { executionId: zod_1.z.string() }, withLogging('CHECK_STATUS', async (args) => (0, execute_tool_1.handleCheckStatus)(args)));
    server.tool(name('APPROVALS_LIST'), desc('APPROVALS_LIST'), {}, withLogging('APPROVALS_LIST', async () => (0, approvals_tool_1.handleListApprovals)()));
    server.tool(name('VIEW_PROGRESS'), desc('VIEW_PROGRESS'), {}, withLogging('VIEW_PROGRESS', async () => (0, execute_tool_1.handleViewProgress)()));
    server.tool(name('GET_KNOWLEDGE'), desc('GET_KNOWLEDGE'), {}, withLogging('GET_KNOWLEDGE', async () => (0, context_tool_1.handleRefreshContext)()));
    server.tool(name('AUTO_RUN'), desc('AUTO_RUN'), { action: zod_1.z.string().optional(), dryRun: zod_1.z.boolean().optional(), startFromPhaseId: zod_1.z.string().optional() }, withLogging('AUTO_RUN', async (args) => (0, execute_tool_1.handleAutoRun)(args)));
    server.tool(name('SUBMIT_ARTIFACT'), desc('SUBMIT_ARTIFACT'), {
        type: zod_1.z.string(),
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        content: zod_1.z.record(zod_1.z.unknown()),
        featureId: zod_1.z.string().optional(),
        milestoneId: zod_1.z.string().optional(),
        sdlcPhaseId: zod_1.z.string().optional(),
    }, withLogging('SUBMIT_ARTIFACT', async (args) => (0, artifacts_tool_1.handleSubmitArtifact)(args)));
    server.tool(name('UPDATE_ARTIFACT'), desc('UPDATE_ARTIFACT'), {
        assetId: zod_1.z.string(),
        type: zod_1.z.string().optional(),
        name: zod_1.z.string().optional(),
        content: zod_1.z.record(zod_1.z.unknown()).optional(),
        changeNote: zod_1.z.string().optional(),
    }, withLogging('UPDATE_ARTIFACT', async (args) => (0, artifacts_tool_1.handleUpdateArtifact)(args)));
    server.tool(name('SUBMIT_BRD'), desc('SUBMIT_BRD'), {
        brdSummary: zod_1.z.string(),
        totalFunctionalPoints: zod_1.z.number().optional(),
        complexityLevel: zod_1.z.string().optional(),
        estimatedTraditionalDays: zod_1.z.number().optional(),
        estimatedAiHours: zod_1.z.number().optional(),
        estimatedStartDate: zod_1.z.string().optional(),
        estimatedEndDate: zod_1.z.string().optional(),
    }, withLogging('SUBMIT_BRD', async (args) => (0, artifacts_tool_1.handleSubmitBrd)(args)));
    server.tool(name('SUBMIT_CHANGE_REQUEST'), desc('SUBMIT_CHANGE_REQUEST'), {
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        content: zod_1.z.record(zod_1.z.unknown()),
    }, withLogging('SUBMIT_CHANGE_REQUEST', async (args) => (0, artifacts_tool_1.handleSubmitChangeRequest)(args)));
    server.tool(name('LIST_CHANGE_REQUESTS'), desc('LIST_CHANGE_REQUESTS'), {}, withLogging('LIST_CHANGE_REQUESTS', async () => (0, artifacts_tool_1.handleListChangeRequests)()));
    server.tool(name('GET_CHANGE_REQUEST'), desc('GET_CHANGE_REQUEST'), { assetId: zod_1.z.string() }, withLogging('GET_CHANGE_REQUEST', async (args) => (0, artifacts_tool_1.handleGetChangeRequest)(args)));
    server.tool(name('SUBMIT_TEST_RESULTS'), desc('SUBMIT_TEST_RESULTS'), {
        name: zod_1.z.string(),
        content: zod_1.z.record(zod_1.z.unknown()),
        featureId: zod_1.z.string().optional(),
        sdlcPhaseId: zod_1.z.string().optional(),
    }, withLogging('SUBMIT_TEST_RESULTS', async (args) => (0, artifacts_tool_1.handleSubmitTestResults)(args)));
    server.tool(name('UPDATE_TEST_STATUS'), desc('UPDATE_TEST_STATUS'), {
        assetId: zod_1.z.string(),
        status: zod_1.z.string(),
    }, withLogging('UPDATE_TEST_STATUS', async (args) => (0, artifacts_tool_1.handleUpdateTestStatus)(args)));
    server.tool(name('CREATE_BUG'), desc('CREATE_BUG'), {
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        content: zod_1.z.record(zod_1.z.unknown()),
        featureId: zod_1.z.string().optional(),
        milestoneId: zod_1.z.string().optional(),
    }, withLogging('CREATE_BUG', async (args) => (0, bugs_tool_1.handleCreateBug)(args)));
    server.tool(name('UPDATE_BUG'), desc('UPDATE_BUG'), {
        assetId: zod_1.z.string(),
        status: zod_1.z.string(),
    }, withLogging('UPDATE_BUG', async (args) => (0, bugs_tool_1.handleUpdateBug)(args)));
    server.tool(name('LIST_BUGS'), desc('LIST_BUGS'), { status: zod_1.z.string().optional() }, withLogging('LIST_BUGS', async (args) => (0, bugs_tool_1.handleListBugs)(args)));
    server.tool(name('GET_BUG'), desc('GET_BUG'), { assetId: zod_1.z.string() }, withLogging('GET_BUG', async (args) => (0, bugs_tool_1.handleGetBug)(args)));
    server.tool(name('UPDATE_PROGRESS'), desc('UPDATE_PROGRESS'), {
        entityType: zod_1.z.string(),
        entityId: zod_1.z.string(),
        fields: zod_1.z.record(zod_1.z.unknown()),
    }, withLogging('UPDATE_PROGRESS', async (args) => (0, features_tool_1.handleUpdateProgress)(args)));
    server.tool(name('UPDATE_STATUS'), desc('UPDATE_STATUS'), {
        entityType: zod_1.z.string(),
        entityId: zod_1.z.string(),
        status: zod_1.z.string(),
    }, withLogging('UPDATE_STATUS', async (args) => (0, features_tool_1.handleUpdateStatus)(args)));
    server.tool(name('LIST_FEATURES'), desc('LIST_FEATURES'), {
        milestoneId: zod_1.z.string().optional(),
        status: zod_1.z.string().optional(),
    }, withLogging('LIST_FEATURES', async (args) => (0, features_tool_1.handleListFeatures)(args)));
    server.tool(name('GET_FEATURE_SPEC'), desc('GET_FEATURE_SPEC'), { featureId: zod_1.z.string() }, withLogging('GET_FEATURE_SPEC', async (args) => (0, features_tool_1.handleGetFeatureSpec)(args)));
    server.tool(name('CREATE_FEATURE'), desc('CREATE_FEATURE'), {
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        milestoneId: zod_1.z.string().optional(),
        priority: zod_1.z.string().optional(),
        complexity: zod_1.z.string().optional(),
        estimatedTraditionalDays: zod_1.z.number().optional(),
        estimatedAiHours: zod_1.z.number().optional(),
    }, withLogging('CREATE_FEATURE', async (args) => (0, features_tool_1.handleCreateFeature)(args)));
    server.tool(name('CREATE_MILESTONE'), desc('CREATE_MILESTONE'), {
        name: zod_1.z.string(),
        description: zod_1.z.string().optional(),
        order: zod_1.z.number().optional(),
        startDate: zod_1.z.string().optional(),
        dueDate: zod_1.z.string().optional(),
        functionalPoints: zod_1.z.number().optional(),
        estimatedTraditionalDays: zod_1.z.number().optional(),
        estimatedAiHours: zod_1.z.number().optional(),
    }, withLogging('CREATE_MILESTONE', async (args) => (0, features_tool_1.handleCreateMilestone)(args)));
    server.tool(name('DEPLOY_STATUS'), desc('DEPLOY_STATUS'), {
        name: zod_1.z.string(),
        content: zod_1.z.record(zod_1.z.unknown()),
        featureId: zod_1.z.string().optional(),
    }, withLogging('DEPLOY_STATUS', async (args) => (0, artifacts_tool_1.handleDeployStatus)(args)));
    server.tool(name('POLL_COMMANDS'), desc('POLL_COMMANDS'), {}, withLogging('POLL_COMMANDS', async () => (0, polling_tool_1.handlePollCommands)()));
    server.tool(name('GET_SOP'), desc('GET_SOP'), { category: zod_1.z.string().optional() }, withLogging('GET_SOP', async (args) => (0, polling_tool_1.handleGetSop)(args)));
    server.tool(name('GET_DIRECTIVES'), desc('GET_DIRECTIVES'), { category: zod_1.z.string().optional() }, withLogging('GET_DIRECTIVES', async (args) => (0, polling_tool_1.handleGetDirectives)(args)));
    server.tool(name('GIT_PUSH'), desc('GIT_PUSH'), {
        branch: zod_1.z.string(),
        commitHash: zod_1.z.string(),
        commitMessage: zod_1.z.string(),
        filesChanged: zod_1.z.number().optional(),
    }, withLogging('GIT_PUSH', async (args) => (0, polling_tool_1.handleGitPush)(args)));
    return server;
}


/***/ }),
/* 5 */
/***/ ((module) => {

module.exports = require("@modelcontextprotocol/sdk/server/mcp.js");

/***/ }),
/* 6 */
/***/ ((module) => {

module.exports = require("zod");

/***/ }),
/* 7 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.sessionManager = void 0;
const crypto_1 = __webpack_require__(8);
const config_1 = __webpack_require__(3);
const request_cache_1 = __webpack_require__(9);
const circuit_breaker_1 = __webpack_require__(10);
const request_signer_1 = __webpack_require__(11);
const ALGO = 'aes-256-gcm';
class SessionManager {
    session = null;
    autoRun = null;
    encryptionKey = null;
    encryptedToken = null;
    heartbeatTimer = null;
    setEncryptionKey(fingerprint) {
        this.encryptionKey = (0, crypto_1.createHash)('sha256').update(fingerprint).digest();
    }
    encrypt(plaintext) {
        if (!this.encryptionKey)
            return { iv: '', data: plaintext, tag: '' };
        const iv = (0, crypto_1.randomBytes)(12);
        const cipher = (0, crypto_1.createCipheriv)(ALGO, this.encryptionKey, iv);
        let encrypted = cipher.update(plaintext, 'utf8', 'hex');
        encrypted += cipher.final('hex');
        const tag = cipher.getAuthTag().toString('hex');
        return { iv: iv.toString('hex'), data: encrypted, tag };
    }
    decrypt(encrypted) {
        if (!this.encryptionKey || !encrypted.iv)
            return encrypted.data;
        const decipher = (0, crypto_1.createDecipheriv)(ALGO, this.encryptionKey, Buffer.from(encrypted.iv, 'hex'));
        decipher.setAuthTag(Buffer.from(encrypted.tag, 'hex'));
        let decrypted = decipher.update(encrypted.data, 'hex', 'utf8');
        decrypted += decipher.final('utf8');
        return decrypted;
    }
    set(state) {
        this.encryptedToken = this.encrypt(state.sessionToken);
        this.session = { ...state, sessionToken: '***' };
        this.startHeartbeat();
    }
    get() {
        if (!this.session)
            return null;
        return {
            ...this.session,
            sessionToken: this.encryptedToken ? this.decrypt(this.encryptedToken) : '',
        };
    }
    clear() {
        this.session = null;
        this.encryptedToken = null;
        this.autoRun = null;
        this.stopHeartbeat();
        request_cache_1.requestCache.clear();
        circuit_breaker_1.circuitBreaker.reset();
        request_signer_1.requestSigner.clearSecret();
    }
    isConnected() {
        return this.session !== null;
    }
    getToken() {
        if (!this.encryptedToken)
            return null;
        return this.decrypt(this.encryptedToken);
    }
    getAutoRunState() {
        return this.autoRun;
    }
    setAutoRunState(state) {
        this.autoRun = state;
    }
    clearAutoRunState() {
        this.autoRun = null;
    }
    isAutoRunActive() {
        return this.autoRun !== null && (this.autoRun.status === 'RUNNING' || this.autoRun.status === 'PAUSED_FOR_APPROVAL');
    }
    startHeartbeat() {
        if (!config_1.config.heartbeatEnabled)
            return;
        this.stopHeartbeat();
        this.heartbeatTimer = setInterval(async () => {
            try {
                const token = this.getToken();
                if (!token)
                    return;
                const url = `${config_1.config.apiBaseUrl}/mcp/sessions/heartbeat`;
                const response = await fetch(url, {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        [config_1.config.sessionHeader]: token,
                    },
                });
                if (response.status === 401 || response.status === 403) {
                    process.stderr.write('[MCP:heartbeat] Session revoked by portal. Disconnecting.\n');
                    this.clear();
                }
            }
            catch {
                process.stderr.write('[MCP:heartbeat] Portal unreachable\n');
            }
        }, config_1.config.heartbeatIntervalMs);
        if (this.heartbeatTimer.unref) {
            this.heartbeatTimer.unref();
        }
    }
    stopHeartbeat() {
        if (this.heartbeatTimer) {
            clearInterval(this.heartbeatTimer);
            this.heartbeatTimer = null;
        }
    }
}
exports.sessionManager = new SessionManager();


/***/ }),
/* 8 */
/***/ ((module) => {

module.exports = require("crypto");

/***/ }),
/* 9 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.requestCache = void 0;
const config_1 = __webpack_require__(3);
class RequestCache {
    cache = new Map();
    maxEntries = 100;
    get(key) {
        if (!config_1.config.cacheEnabled)
            return undefined;
        const entry = this.cache.get(key);
        if (!entry)
            return undefined;
        if (Date.now() > entry.expiresAt) {
            this.cache.delete(key);
            return undefined;
        }
        this.cache.delete(key);
        this.cache.set(key, entry);
        process.stderr.write(`[MCP:cache] HIT ${key}\n`);
        return entry.data;
    }
    set(key, data, ttlMs) {
        if (!config_1.config.cacheEnabled || ttlMs <= 0)
            return;
        if (this.cache.size >= this.maxEntries) {
            const oldest = this.cache.keys().next().value;
            if (oldest !== undefined) {
                this.cache.delete(oldest);
            }
        }
        this.cache.set(key, {
            data,
            expiresAt: Date.now() + ttlMs,
            key,
        });
    }
    invalidatePrefix(prefix) {
        const toDelete = [];
        for (const key of this.cache.keys()) {
            if (key.startsWith(prefix)) {
                toDelete.push(key);
            }
        }
        for (const key of toDelete) {
            this.cache.delete(key);
        }
        if (toDelete.length > 0) {
            process.stderr.write(`[MCP:cache] Invalidated ${toDelete.length} entries for prefix "${prefix}"\n`);
        }
    }
    clear() {
        const size = this.cache.size;
        this.cache.clear();
        if (size > 0) {
            process.stderr.write(`[MCP:cache] Cleared ${size} entries\n`);
        }
    }
    get size() {
        return this.cache.size;
    }
    getTtl(path) {
        if (path.includes('/mcp/execute/') && path.endsWith('/status')) {
            return 0;
        }
        if (path.includes('/reference/') || path.includes('/bootstrap')) {
            return config_1.config.cacheTtlRefMs;
        }
        const segments = path.split('/').filter(Boolean);
        const lastSeg = segments[segments.length - 1] ?? '';
        if (lastSeg.length >= 20 || /^[a-f0-9-]{20,}$/i.test(lastSeg)) {
            return config_1.config.cacheTtlDetailMs;
        }
        return config_1.config.cacheTtlListMs;
    }
}
exports.requestCache = new RequestCache();


/***/ }),
/* 10 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.circuitBreaker = void 0;
const config_1 = __webpack_require__(3);
class CircuitBreaker {
    state = 'CLOSED';
    failureCount = 0;
    successCount = 0;
    lastFailureAt = 0;
    successesToClose = 2;
    check() {
        if (this.state === 'CLOSED')
            return;
        if (this.state === 'OPEN') {
            const elapsed = Date.now() - this.lastFailureAt;
            if (elapsed >= config_1.config.cbResetTimeoutMs) {
                this.transition('HALF_OPEN');
                return;
            }
            throw new Error('Portal unreachable — circuit breaker is OPEN. Retrying automatically in a few seconds.');
        }
    }
    onSuccess() {
        if (this.state === 'CLOSED') {
            this.failureCount = 0;
            return;
        }
        if (this.state === 'HALF_OPEN') {
            this.successCount++;
            if (this.successCount >= this.successesToClose) {
                this.transition('CLOSED');
            }
        }
    }
    onFailure() {
        this.failureCount++;
        this.lastFailureAt = Date.now();
        if (this.state === 'HALF_OPEN') {
            this.transition('OPEN');
            return;
        }
        if (this.state === 'CLOSED' && this.failureCount >= config_1.config.cbFailureThreshold) {
            this.transition('OPEN');
        }
    }
    reset() {
        this.transition('CLOSED');
    }
    getState() {
        return this.state;
    }
    transition(newState) {
        const oldState = this.state;
        this.state = newState;
        this.failureCount = 0;
        this.successCount = 0;
        if (oldState !== newState) {
            process.stderr.write(`[MCP:circuit] ${oldState} -> ${newState}\n`);
        }
    }
}
exports.circuitBreaker = new CircuitBreaker();


/***/ }),
/* 11 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.requestSigner = void 0;
const crypto_1 = __webpack_require__(8);
class RequestSigner {
    signingSecret = null;
    setSecret(secret) {
        this.signingSecret = secret;
    }
    clearSecret() {
        this.signingSecret = null;
    }
    isEnabled() {
        return this.signingSecret !== null;
    }
    sign(method, path, body) {
        if (!this.signingSecret)
            return {};
        const timestamp = Math.floor(Date.now() / 1000).toString();
        const nonce = (0, crypto_1.randomBytes)(16).toString('hex');
        const bodyHash = body
            ? (0, crypto_1.createHash)('sha256').update(body).digest('hex')
            : (0, crypto_1.createHash)('sha256').update('').digest('hex');
        const payload = `${method.toUpperCase()}\n${path}\n${bodyHash}\n${nonce}\n${timestamp}`;
        const signature = (0, crypto_1.createHmac)('sha256', this.signingSecret)
            .update(payload)
            .digest('hex');
        return {
            'X-MCP-Signature': signature,
            'X-MCP-Nonce': nonce,
            'X-MCP-Timestamp': timestamp,
        };
    }
}
exports.requestSigner = new RequestSigner();


/***/ }),
/* 12 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleConnect = handleConnect;
const bootstrap_1 = __webpack_require__(2);
const config_1 = __webpack_require__(3);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const request_signer_1 = __webpack_require__(11);
const fingerprint_1 = __webpack_require__(16);
const result_formatter_1 = __webpack_require__(19);
const agent_guide_1 = __webpack_require__(20);
function buildCompactSummary(ctx, agentPrompt) {
    const lines = [];
    lines.push('## SDLC Phases');
    lines.push('');
    for (const domain of ctx.workflow) {
        for (const phase of domain.phases) {
            const gated = phase.gated ? ' **[GATED]**' : '';
            lines.push(`- \`${phase.id}\` — **${phase.name}** (${phase.agentRole})${gated}`);
        }
    }
    if (ctx.agentConstraints.length > 0) {
        lines.push('');
        lines.push('## Constraints');
        for (const c of ctx.agentConstraints) {
            lines.push(`- ${c}`);
        }
    }
    if (agentPrompt) {
        const techMatch = agentPrompt.match(/## Tech Stack\n([\s\S]*?)(?=\n##|\n---|\n$)/);
        if (techMatch) {
            lines.push('');
            lines.push('## Tech Stack');
            lines.push(techMatch[1].trim());
        }
        const bugMatch = agentPrompt.match(/## Bug Fix Mode: (\w+)/);
        if (bugMatch) {
            lines.push('');
            lines.push(`## Bug Fix Mode: ${bugMatch[1]}`);
        }
    }
    return lines.join('\n');
}
async function handleConnect(args) {
    if (session_1.sessionManager.isConnected()) {
        return (0, result_formatter_1.text)('Already connected. Use jovan_disconnect first.');
    }
    const apiKey = args.apiKey || config_1.config.defaultApiKey;
    const projectId = args.projectId || config_1.config.defaultProjectId;
    if (!apiKey || !projectId) {
        return (0, result_formatter_1.text)('Connection failed: apiKey and projectId are required.\n' +
            'Pass them as arguments to jovan_connect, or set JOVAN_API_KEY and JOVAN_PROJECT_ID ' +
            'environment variables in your MCP server configuration.');
    }
    const { fingerprint, machineName } = await (0, fingerprint_1.getMachineFingerprint)();
    session_1.sessionManager.setEncryptionKey(fingerprint);
    const result = await api_client_1.apiClient.post((0, bootstrap_1.apiPath)('connect'), {
        apiKey,
        machineFingerprint: fingerprint,
        projectId,
        clientInfo: { machineName, aiEngine: config_1.config.clientTool, tool: config_1.config.clientTool },
    }, false);
    if (result.signingSecret) {
        request_signer_1.requestSigner.setSecret(result.signingSecret);
    }
    session_1.sessionManager.set({
        sessionId: result.sessionId,
        sessionToken: result.sessionToken,
        projectId: result.projectId,
        projectName: result.projectName,
        context: result.context,
    });
    const parts = [
        `Connected to project "${result.projectName}" (${result.projectId})`,
        `Session: ${result.sessionId}`,
    ];
    if (result.context) {
        parts.push(`Status: ${result.context.projectStatus} | ${result.context.totalPhases} phases (${result.context.gatedPhaseCount} gated)`);
        parts.push('');
        parts.push(buildCompactSummary(result.context, result.agentPrompt));
    }
    parts.push('');
    parts.push(agent_guide_1.AGENT_GUIDE);
    return (0, result_formatter_1.text)(parts.join('\n'));
}


/***/ }),
/* 13 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.apiClient = void 0;
const config_1 = __webpack_require__(3);
const session_1 = __webpack_require__(7);
const request_cache_1 = __webpack_require__(9);
const circuit_breaker_1 = __webpack_require__(10);
const request_signer_1 = __webpack_require__(11);
const http_1 = __webpack_require__(14);
const keepAliveAgent = new http_1.Agent({
    keepAlive: true,
    keepAliveMsecs: config_1.config.keepAliveMs,
    maxSockets: 6,
    maxFreeSockets: 4,
});
class Semaphore {
    max;
    current = 0;
    queue = [];
    constructor(max) {
        this.max = max;
    }
    async acquire() {
        if (this.current < this.max) {
            this.current++;
            return;
        }
        return new Promise((resolve) => {
            this.queue.push(() => {
                this.current++;
                resolve();
            });
        });
    }
    release() {
        this.current--;
        const next = this.queue.shift();
        if (next)
            next();
    }
}
const semaphore = new Semaphore(config_1.config.maxConcurrentRequests);
const inflight = new Map();
function sanitizeError(status, method, path, rawMessage) {
    process.stderr.write(`[MCP:api] ${method} ${path} failed (${status}): ${rawMessage}\n`);
    if (status === 401)
        return 'Session expired. Please reconnect.';
    if (status === 403)
        return rawMessage ? `Access denied: ${rawMessage}` : 'Access denied.';
    if (status === 404)
        return 'Resource not found.';
    if (status === 400)
        return `Validation error: ${rawMessage}`;
    if (status === 409)
        return 'Conflict — resource was modified. Please retry.';
    if (status === 422)
        return 'Invalid input. Check your parameters.';
    if (status === 429)
        return 'Rate limited. Please wait before retrying.';
    if (status >= 500)
        return 'Server error. The portal may be temporarily unavailable.';
    return 'Request failed. Please try again.';
}
function isServerError(status) {
    return status >= 500;
}
async function request(method, path, body, useSession = true) {
    const isGet = method === 'GET';
    const cacheKey = `GET:${path}`;
    if (isGet) {
        const existing = inflight.get(cacheKey);
        if (existing) {
            process.stderr.write(`[MCP:dedup] Reusing in-flight request for ${path}\n`);
            return existing;
        }
    }
    if (isGet) {
        const cached = request_cache_1.requestCache.get(cacheKey);
        if (cached !== undefined) {
            return cached;
        }
    }
    const doRequest = async () => {
        await semaphore.acquire();
        try {
            circuit_breaker_1.circuitBreaker.check();
            const url = `${config_1.config.apiBaseUrl}${path}`;
            const headers = {
                'Content-Type': 'application/json',
                'Accept-Encoding': 'gzip, deflate',
            };
            if (useSession) {
                const token = session_1.sessionManager.getToken();
                if (token) {
                    headers[config_1.config.sessionHeader] = token;
                }
            }
            let bodyStr;
            let bodyPayload;
            if (body !== undefined) {
                bodyStr = JSON.stringify(body);
                bodyPayload = bodyStr;
            }
            const urlPath = new URL(url).pathname;
            const sigHeaders = request_signer_1.requestSigner.sign(method, urlPath, bodyStr);
            Object.assign(headers, sigHeaders);
            const controller = new AbortController();
            const timeout = setTimeout(() => controller.abort(), config_1.config.requestTimeoutMs);
            let response;
            try {
                response = await fetch(url, {
                    method,
                    headers,
                    body: bodyPayload,
                    signal: controller.signal,
                });
            }
            catch (fetchErr) {
                circuit_breaker_1.circuitBreaker.onFailure();
                const msg = fetchErr instanceof Error ? fetchErr.message : 'Network error';
                if (msg.includes('abort')) {
                    throw new Error('Request timed out. The portal may be slow or unreachable.');
                }
                throw new Error('Portal unreachable. Check your network connection.');
            }
            finally {
                clearTimeout(timeout);
            }
            if (!response.ok) {
                const errorBody = await response.text();
                let rawMessage;
                try {
                    const parsed = JSON.parse(errorBody);
                    rawMessage = parsed.message ?? parsed.error ?? errorBody;
                }
                catch {
                    rawMessage = errorBody;
                }
                const debugInfo = {
                    timestamp: new Date().toISOString(),
                    method,
                    path,
                    url: `${config_1.config.apiBaseUrl}${path}`,
                    status: response.status,
                    rawMessage,
                    errorBody,
                    hasSessionToken: !!headers[config_1.config.sessionHeader],
                    sessionTokenLength: headers[config_1.config.sessionHeader]?.length ?? 0,
                };
                process.stderr.write(`[MCP:debug] ${JSON.stringify(debugInfo)}\n`);
                try {
                    const fs = await Promise.resolve().then(() => __importStar(__webpack_require__(15)));
                    fs.writeFileSync('D:/Workspace/jovan/mcp-debug.json', JSON.stringify(debugInfo, null, 2));
                }
                catch { }
                if (isServerError(response.status)) {
                    circuit_breaker_1.circuitBreaker.onFailure();
                }
                throw new Error(sanitizeError(response.status, method, path, rawMessage));
            }
            circuit_breaker_1.circuitBreaker.onSuccess();
            const json = await response.json();
            const data = (json && typeof json === 'object' && 'data' in json && 'success' in json)
                ? json.data
                : json;
            if (isGet) {
                const ttl = request_cache_1.requestCache.getTtl(path);
                request_cache_1.requestCache.set(cacheKey, data, ttl);
            }
            if (!isGet) {
                const prefixMatch = path.match(/^(\/[^?]+)/);
                if (prefixMatch) {
                    const basePath = prefixMatch[1];
                    const segments = basePath.split('/').filter(Boolean);
                    if (segments.length >= 2) {
                        const parentPath = '/' + segments.slice(0, -1).join('/');
                        request_cache_1.requestCache.invalidatePrefix(`GET:${parentPath}`);
                    }
                    request_cache_1.requestCache.invalidatePrefix(`GET:${basePath}`);
                }
            }
            return data;
        }
        finally {
            semaphore.release();
        }
    };
    if (isGet) {
        const promise = doRequest().finally(() => {
            inflight.delete(cacheKey);
        });
        inflight.set(cacheKey, promise);
        return promise;
    }
    return doRequest();
}
exports.apiClient = {
    get: (path, useSession = true) => request('GET', path, undefined, useSession),
    post: (path, body, useSession = true) => request('POST', path, body, useSession),
    put: (path, body, useSession = true) => request('PUT', path, body, useSession),
    patch: (path, body, useSession = true) => request('PATCH', path, body, useSession),
    delete: (path, useSession = true) => request('DELETE', path, undefined, useSession),
};


/***/ }),
/* 14 */
/***/ ((module) => {

module.exports = require("http");

/***/ }),
/* 15 */
/***/ ((module) => {

module.exports = require("fs");

/***/ }),
/* 16 */
/***/ (function(__unused_webpack_module, exports, __webpack_require__) {


var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.getMachineFingerprint = getMachineFingerprint;
const crypto_1 = __webpack_require__(8);
const os_1 = __webpack_require__(17);
async function getMachineFingerprint() {
    let machineId = 'unknown';
    try {
        const { machineIdSync } = await Promise.resolve().then(() => __importStar(__webpack_require__(18)));
        machineId = machineIdSync(true);
    }
    catch {
        machineId = `${(0, os_1.hostname)()}-${(0, os_1.platform)()}-fallback`;
    }
    const cpuModel = (0, os_1.cpus)()[0]?.model ?? 'unknown';
    const components = [(0, os_1.hostname)(), (0, os_1.platform)(), (0, os_1.arch)(), cpuModel, machineId];
    const fingerprint = (0, crypto_1.createHash)('sha256').update(components.join('|')).digest('hex');
    const machineName = `${(0, os_1.hostname)()} (${(0, os_1.platform)()} ${(0, os_1.arch)()})`;
    return { fingerprint, machineName };
}


/***/ }),
/* 17 */
/***/ ((module) => {

module.exports = require("os");

/***/ }),
/* 18 */
/***/ ((module) => {

module.exports = require("node-machine-id");

/***/ }),
/* 19 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.ok = ok;
exports.err = err;
exports.text = text;
const isProd = process.env.NODE_ENV === 'production';
function stringify(data) {
    return isProd ? JSON.stringify(data) : JSON.stringify(data, null, 2);
}
function ok(data) {
    return {
        content: [{ type: 'text', text: stringify(data) }],
    };
}
function err(message) {
    return {
        content: [{ type: 'text', text: message }],
        isError: true,
    };
}
function text(message) {
    return {
        content: [{ type: 'text', text: message }],
    };
}


/***/ }),
/* 20 */
/***/ ((__unused_webpack_module, exports) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.AGENT_GUIDE = void 0;
exports.AGENT_GUIDE = `
# JoVan Agent Guide

You are the **JoVan Virtual Development Team** connected via MCP. The portal is your control plane — it stores governance, tracks progress, manages approvals. You execute locally; the portal governs.

## After Connecting

1. Call \`jovan_view_progress\` to see what's done.
2. Call \`jovan_poll_commands\` for pending human actions.
3. If starting fresh: wait for a BRD, then \`jovan_submit_brd\`, \`jovan_create_milestone\`, \`jovan_create_feature\`.
4. If resuming: pick up from the current feature status.

## Development Workflow

For each feature, call \`jovan_execute_phase({ sdlcPhaseId, action: "execute", payload: { featureId } })\`.
This returns **phase-specific instructions**: your role, SOPs to follow, expected artifact types with content shapes, and tech stack.

**Feature status flow**: PLANNED → REQUIREMENTS → DESIGNING → DEVELOPING → DEPLOYED_DEV → TESTING → SECURITY_REVIEW → DOCUMENTING → DONE

Gated phases block until human approval. Non-gated phases proceed immediately.

## Key Tools

| Action | Tool |
|--------|------|
| Submit artifact | \`jovan_submit_artifact({ type, name, content, featureId })\` |
| Update artifact | \`jovan_update_artifact({ assetId, content, changeNote })\` |
| Create bug | \`jovan_create_bug({ name, content, featureId })\` — triggers bug fix mode |
| Submit tests | \`jovan_submit_test_results({ name, content, featureId })\` |
| Deploy status | \`jovan_deploy_status({ name, content })\` |
| Git push | \`jovan_git_push({ branch, commitHash, commitMessage })\` |
| Change request | \`jovan_submit_change_request({ name, content })\` |
| Update status | \`jovan_update_status({ entityType, entityId, status })\` |
| View SOPs | \`jovan_get_sop({ category })\` — returns full SOP prompts |
| Refresh context | \`jovan_refresh_context()\` — reload full agent prompt |
| Auto-run | \`jovan_auto_run({ dryRun: true })\` — preview all phases |

## Rules

1. **Use predefined JSON structures** from phase context for artifact content shapes.
2. **Follow SOPs** — they are governance requirements, not suggestions.
3. **Never skip approval gates.**
4. **Submit artifacts frequently** — don't batch at the end.
5. **Link artifacts to features** for traceability.
6. **Create bugs for test failures** — the portal needs the audit trail.
7. **Predefined structures stay in memory only** — never write to disk.
`.trimEnd();


/***/ }),
/* 21 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleDisconnect = handleDisconnect;
const config_1 = __webpack_require__(3);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
async function handleDisconnect() {
    if (!session_1.sessionManager.isConnected()) {
        return (0, result_formatter_1.text)('No active session to disconnect.');
    }
    const session = session_1.sessionManager.get();
    try {
        const url = `${config_1.config.apiBaseUrl}/mcp/sessions/disconnect`;
        await fetch(url, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                [config_1.config.sessionHeader]: session.sessionToken,
            },
        });
    }
    catch {
        process.stderr.write('[MCP:disconnect] Failed to notify portal\n');
    }
    session_1.sessionManager.clear();
    return (0, result_formatter_1.text)(`Disconnected from project "${session.projectName}". Session cleared.`);
}


/***/ }),
/* 22 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleListAssets = handleListAssets;
exports.handleRetrieveAsset = handleRetrieveAsset;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
const fs_1 = __webpack_require__(15);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleListAssets(args) {
    const session = requireSession();
    const token = session_1.sessionManager.getToken();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const params = args.sdlcPhaseId ? `?type=${encodeURIComponent(args.sdlcPhaseId)}` : '';
    try {
        (0, fs_1.writeFileSync)('D:/Workspace/jovan/mcp-debug-assets.json', JSON.stringify({
            timestamp: new Date().toISOString(),
            connected: session_1.sessionManager.isConnected(),
            sessionId: session.sessionId,
            projectId: session.projectId,
            tokenLength: token?.length ?? 0,
            tokenFirst10: token?.substring(0, 10) ?? 'null',
            path: path + params,
        }, null, 2));
    }
    catch { }
    const assets = await api_client_1.apiClient.get(`${path}${params}`);
    return (0, result_formatter_1.ok)(assets);
}
async function handleRetrieveAsset(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAsset', { projectId: session.projectId, assetId: args.packId });
    const asset = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(asset);
}


/***/ }),
/* 23 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleExecutePhase = handleExecutePhase;
exports.handleCheckStatus = handleCheckStatus;
exports.handleViewProgress = handleViewProgress;
exports.handleAutoRun = handleAutoRun;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const approval_poller_1 = __webpack_require__(24);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function fetchPhaseContext(projectId, phaseId) {
    try {
        const path = (0, bootstrap_1.apiPath)('phaseContext', { projectId, phaseId });
        return await api_client_1.apiClient.get(path);
    }
    catch (err) {
        process.stderr.write(`[MCP] Failed to fetch phase context: ${err instanceof Error ? err.message : 'unknown'}\n`);
        return null;
    }
}
function formatPhaseInstructions(ctx) {
    const lines = [];
    lines.push(`## Phase Instructions: ${ctx.phase.name}`);
    lines.push(`**You are now acting as: ${ctx.virtualTeamMember.agentRole || ctx.phase.agentRole}**`);
    lines.push(`**Set features to: ${ctx.featureStatusMapping}**`);
    if (ctx.phase.description) {
        lines.push(`**Objective**: ${ctx.phase.description}`);
    }
    lines.push('');
    if (ctx.sops.length > 0) {
        lines.push('### SOPs to Follow:');
        for (const sop of ctx.sops) {
            lines.push(`#### ${sop.name} (${sop.category})`);
            if (sop.prompt)
                lines.push(sop.prompt);
            if (sop.constraints.length > 0) {
                lines.push('Constraints:');
                for (const c of sop.constraints)
                    lines.push(`- ${c}`);
            }
        }
        lines.push('');
    }
    if (ctx.expectedOutputs.length > 0) {
        lines.push('### Expected Outputs:');
        for (const out of ctx.expectedOutputs) {
            const req = out.required ? '[REQUIRED]' : '[optional]';
            lines.push(`- ${req} **${out.assetType}** — submit via \`${out.mcpTool}\``);
            if (out.contentShape)
                lines.push(`  Shape: \`${out.contentShape}\``);
            if (out.jsonSchema)
                lines.push(`  Schema: \`${JSON.stringify(out.jsonSchema)}\``);
        }
        lines.push('');
    }
    if (ctx.techStack.length > 0) {
        const stackStr = ctx.techStack.map((t) => `${t.name} (${t.category})`).join(', ');
        lines.push(`### Tech Stack: ${stackStr}`);
        lines.push('');
    }
    if (ctx.agentConstraints.length > 0) {
        lines.push('### Constraints:');
        for (const c of ctx.agentConstraints)
            lines.push(`- ${c}`);
        lines.push('');
    }
    lines.push(`### Bug Fix Mode: ${ctx.bugFixMode}`);
    return lines.join('\n');
}
async function handleExecutePhase(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectExecute', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        sdlcPhaseId: args.sdlcPhaseId,
        action: args.action,
        payload: args.payload,
        justification: args.justification,
    });
    if (result.status === 'PENDING_APPROVAL' && result.executionId) {
        process.stderr.write(`[MCP] Phase "${result.phaseName}" requires approval. Polling for approval...\n`);
        const finalResult = await (0, approval_poller_1.pollForApproval)(result.executionId);
        if (finalResult.status === 'RUNNING') {
            const phaseContext = await fetchPhaseContext(session.projectId, args.sdlcPhaseId);
            const instructions = phaseContext ? formatPhaseInstructions(phaseContext) : '';
            return (0, result_formatter_1.ok)({
                ...finalResult,
                phaseName: result.phaseName,
                message: `Phase "${result.phaseName}" APPROVED. You may proceed.`,
                phaseContext: phaseContext ?? undefined,
                instructions,
            });
        }
        else if (finalResult.status === 'CANCELLED') {
            const reason = finalResult.error ?? 'Rejected or expired';
            return (0, result_formatter_1.ok)({
                ...finalResult,
                phaseName: result.phaseName,
                message: `Phase "${result.phaseName}" was REJECTED or EXPIRED: ${reason}. Do NOT proceed with this phase.`,
            });
        }
        else {
            return (0, result_formatter_1.ok)({
                ...finalResult,
                phaseName: result.phaseName,
                message: `Phase "${result.phaseName}" approval status: ${finalResult.status}. Check with the user before proceeding.`,
            });
        }
    }
    if (result.status === 'RUNNING' || result.status === 'COMPLETED') {
        const phaseContext = await fetchPhaseContext(session.projectId, args.sdlcPhaseId);
        const instructions = phaseContext ? formatPhaseInstructions(phaseContext) : '';
        return (0, result_formatter_1.ok)({
            ...result,
            phaseContext: phaseContext ?? undefined,
            instructions,
        });
    }
    return (0, result_formatter_1.ok)(result);
}
async function handleCheckStatus(args) {
    requireSession();
    const path = (0, bootstrap_1.apiPath)('executionStatus', { executionId: args.executionId });
    const result = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(result);
}
async function handleViewProgress() {
    const session = requireSession();
    const [milestones, features, stats] = await Promise.all([
        api_client_1.apiClient.get((0, bootstrap_1.apiPath)('projectMilestones', { projectId: session.projectId })),
        api_client_1.apiClient.get(`${(0, bootstrap_1.apiPath)('projectFeatures', { projectId: session.projectId })}?compact=true`),
        api_client_1.apiClient.get((0, bootstrap_1.apiPath)('dashboardStats')),
    ]);
    const featuresByStatus = {};
    const blockedFeatures = [];
    let doneCount = 0;
    let inProgressCount = 0;
    for (const f of features) {
        const s = f.status ?? 'UNKNOWN';
        featuresByStatus[s] = (featuresByStatus[s] ?? 0) + 1;
        if (s === 'BLOCKED') {
            blockedFeatures.push({ id: f.id, name: f.name });
        }
        if (s === 'DONE')
            doneCount++;
        if (s !== 'DONE' && s !== 'PLANNED' && s !== 'BLOCKED')
            inProgressCount++;
    }
    const completionPercent = features.length > 0
        ? Math.round((doneCount / features.length) * 100)
        : 0;
    const nextActions = [];
    if (blockedFeatures.length > 0) {
        nextActions.push(`Resolve ${blockedFeatures.length} blocked feature(s): ${blockedFeatures.map((f) => f.name).join(', ')}`);
    }
    const plannedCount = featuresByStatus['PLANNED'] ?? 0;
    if (plannedCount > 0 && inProgressCount === 0) {
        nextActions.push(`Start work on ${plannedCount} planned feature(s)`);
    }
    if (completionPercent === 100) {
        nextActions.push('All features done — consider final deployment');
    }
    const progress = {
        project: session.projectName,
        completionPercent,
        milestones: milestones.map((m) => ({
            name: m.name,
            status: m.status,
            progress: m.progress ?? 0,
            features: m._count?.features ?? 0,
        })),
        featureSummary: {
            total: features.length,
            done: doneCount,
            inProgress: inProgressCount,
            blocked: blockedFeatures.length,
            byStatus: featuresByStatus,
        },
        blockedFeatures: blockedFeatures.length > 0 ? blockedFeatures : undefined,
        nextActions: nextActions.length > 0 ? nextActions : undefined,
        stats,
    };
    return (0, result_formatter_1.ok)(progress);
}
async function handleAutoRun(args) {
    const session = requireSession();
    if (!session.context) {
        return (0, result_formatter_1.text)('No workflow context loaded. Reconnect to load phases.');
    }
    const phases = session.context.workflow.flatMap((d) => d.phases.map((p) => ({ ...p, domainName: d.name })));
    const startIdx = args.startFromPhaseId ? phases.findIndex((p) => p.id === args.startFromPhaseId) : 0;
    const phasesToRun = phases.slice(startIdx >= 0 ? startIdx : 0);
    if (args.dryRun) {
        const planItems = [];
        for (let i = 0; i < phasesToRun.length; i++) {
            const p = phasesToRun[i];
            let detail = `${i + 1}. **${p.name}** (${p.agentRole})`;
            if (p.gated)
                detail += ' [GATED — requires approval]';
            const ctx = await fetchPhaseContext(session.projectId, p.id);
            if (ctx) {
                detail += `\n   Feature status: → ${ctx.featureStatusMapping}`;
                if (ctx.expectedOutputs.length > 0) {
                    const outputs = ctx.expectedOutputs
                        .map((o) => `${o.required ? '[REQ]' : '[opt]'} ${o.assetType}`)
                        .join(', ');
                    detail += `\n   Expected outputs: ${outputs}`;
                }
                if (ctx.sops.length > 0) {
                    detail += `\n   SOPs: ${ctx.sops.map((s) => s.name).join(', ')}`;
                }
            }
            planItems.push(detail);
        }
        return (0, result_formatter_1.text)(`Auto-run plan (${phasesToRun.length} phases):\n\n${planItems.join('\n\n')}`);
    }
    const autoRunState = {
        status: 'RUNNING',
        totalPhases: phasesToRun.length,
        currentPhaseIndex: 0,
        results: [],
        startedAt: Date.now(),
    };
    session_1.sessionManager.setAutoRunState(autoRunState);
    const action = args.action ?? 'execute';
    for (let i = 0; i < phasesToRun.length; i++) {
        const phase = phasesToRun[i];
        autoRunState.currentPhaseIndex = i;
        session_1.sessionManager.setAutoRunState(autoRunState);
        process.stderr.write(`[MCP:auto-run] Phase ${i + 1}/${phasesToRun.length}: ${phase.name}\n`);
        const phaseResult = {
            phaseId: phase.id,
            phaseName: phase.name,
            domainName: phase.domainName,
            agentRole: phase.agentRole,
            status: 'COMPLETED',
        };
        try {
            const execPath = (0, bootstrap_1.apiPath)('projectExecute', { projectId: session.projectId });
            const execResult = await api_client_1.apiClient.post(execPath, {
                sdlcPhaseId: phase.id,
                action,
            });
            phaseResult.executionId = execResult.executionId;
            if (execResult.status === 'PENDING_APPROVAL' && execResult.executionId) {
                phaseResult.approvalId = execResult.approvalRequestId;
                autoRunState.status = 'PAUSED_FOR_APPROVAL';
                session_1.sessionManager.setAutoRunState(autoRunState);
                process.stderr.write(`[MCP:auto-run] Phase "${phase.name}" is gated. Waiting for approval...\n`);
                const approvalResult = await (0, approval_poller_1.pollForApproval)(execResult.executionId);
                if (approvalResult.status === 'RUNNING') {
                    phaseResult.status = 'COMPLETED';
                    autoRunState.status = 'RUNNING';
                }
                else if (approvalResult.status === 'CANCELLED') {
                    phaseResult.status = 'REJECTED';
                    phaseResult.error = approvalResult.error ?? 'Rejected or expired';
                    autoRunState.status = 'HALTED';
                    autoRunState.results.push(phaseResult);
                    session_1.sessionManager.setAutoRunState(autoRunState);
                    break;
                }
                else {
                    phaseResult.status = 'FAILED';
                    phaseResult.error = `Unexpected status: ${approvalResult.status}`;
                    autoRunState.status = 'HALTED';
                    autoRunState.results.push(phaseResult);
                    session_1.sessionManager.setAutoRunState(autoRunState);
                    break;
                }
            }
            else if (execResult.status === 'FAILED') {
                phaseResult.status = 'FAILED';
                phaseResult.error = execResult.error ?? 'Phase execution failed';
                autoRunState.status = 'FAILED';
                autoRunState.results.push(phaseResult);
                session_1.sessionManager.setAutoRunState(autoRunState);
                break;
            }
            const ctx = await fetchPhaseContext(session.projectId, phase.id);
            if (ctx) {
                phaseResult.phaseContext = ctx;
            }
        }
        catch (err) {
            phaseResult.status = 'FAILED';
            phaseResult.error = err instanceof Error ? err.message : 'Unknown error';
            autoRunState.status = 'FAILED';
            autoRunState.results.push(phaseResult);
            session_1.sessionManager.setAutoRunState(autoRunState);
            break;
        }
        autoRunState.results.push(phaseResult);
        session_1.sessionManager.setAutoRunState(autoRunState);
    }
    if (autoRunState.status === 'RUNNING') {
        autoRunState.status = 'COMPLETED';
    }
    autoRunState.completedAt = Date.now();
    session_1.sessionManager.setAutoRunState(autoRunState);
    const summary = autoRunState.results.map((r, i) => `${i + 1}. ${r.phaseName} — ${r.status}${r.error ? ` (${r.error})` : ''}`);
    return (0, result_formatter_1.ok)({
        status: autoRunState.status,
        totalPhases: autoRunState.totalPhases,
        completedPhases: autoRunState.results.filter((r) => r.status === 'COMPLETED').length,
        results: autoRunState.results,
        summary: summary.join('\n'),
        durationMs: (autoRunState.completedAt ?? Date.now()) - autoRunState.startedAt,
    });
}


/***/ }),
/* 24 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.pollForApproval = pollForApproval;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const config_1 = __webpack_require__(3);
async function pollForApproval(executionId) {
    const startTime = Date.now();
    while (Date.now() - startTime < config_1.config.pollTimeoutMs) {
        const result = await api_client_1.apiClient.get((0, bootstrap_1.apiPath)('executionStatus', { executionId }));
        if (result.status !== 'PENDING') {
            return result;
        }
        await new Promise((resolve) => setTimeout(resolve, config_1.config.pollIntervalMs));
    }
    return {
        executionId,
        status: 'CANCELLED',
        error: 'Polling timed out waiting for approval',
    };
}


/***/ }),
/* 25 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleListApprovals = handleListApprovals;
exports.handleCompose = handleCompose;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleListApprovals() {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('approvalsList', { projectId: session.projectId });
    const approvals = await api_client_1.apiClient.get(`${path}&status=PENDING`);
    return (0, result_formatter_1.ok)(approvals);
}
async function handleCompose(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        sdlcPhaseId: args.sdlcPhaseId,
        payload: args.payload,
        justification: args.justification,
        type: 'GOVERNANCE_BUNDLE',
    });
    return (0, result_formatter_1.ok)(result);
}


/***/ }),
/* 26 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleRefreshContext = handleRefreshContext;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleRefreshContext() {
    const session = requireSession();
    const [promptData, features, milestones] = await Promise.all([
        api_client_1.apiClient.get((0, bootstrap_1.apiPath)('agentPrompt', { projectId: session.projectId })),
        api_client_1.apiClient.get(`${(0, bootstrap_1.apiPath)('projectFeatures', { projectId: session.projectId })}?compact=true`),
        api_client_1.apiClient.get((0, bootstrap_1.apiPath)('projectMilestones', { projectId: session.projectId })),
    ]);
    if (promptData?.context && session.context) {
        const updated = { ...session, context: { ...session.context, ...promptData.context } };
        session_1.sessionManager.set(updated);
    }
    const featuresByStatus = {};
    for (const f of features ?? []) {
        const s = f.status ?? 'UNKNOWN';
        featuresByStatus[s] = (featuresByStatus[s] ?? 0) + 1;
    }
    return (0, result_formatter_1.ok)({
        project: session.projectName,
        projectId: session.projectId,
        agentPrompt: promptData?.agentPrompt ?? '',
        progress: {
            features: {
                total: features?.length ?? 0,
                byStatus: featuresByStatus,
            },
            milestones: (milestones ?? []).map((m) => ({
                name: m.name,
                status: m.status,
                progress: m.progress ?? 0,
                features: m._count?.features ?? 0,
            })),
        },
        workflowPhases: session.context?.totalPhases ?? 0,
        message: 'Context refreshed with latest agent prompt and progress data.',
    });
}


/***/ }),
/* 27 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleSubmitArtifact = handleSubmitArtifact;
exports.handleUpdateArtifact = handleUpdateArtifact;
exports.handleSubmitBrd = handleSubmitBrd;
exports.handleSubmitChangeRequest = handleSubmitChangeRequest;
exports.handleListChangeRequests = handleListChangeRequests;
exports.handleGetChangeRequest = handleGetChangeRequest;
exports.handleSubmitTestResults = handleSubmitTestResults;
exports.handleUpdateTestStatus = handleUpdateTestStatus;
exports.handleDeployStatus = handleDeployStatus;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleSubmitArtifact(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        type: args.type,
        name: args.name,
        description: args.description,
        content: args.content,
        featureId: args.featureId,
        milestoneId: args.milestoneId,
        sdlcPhaseId: args.sdlcPhaseId,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleUpdateArtifact(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAsset', { projectId: session.projectId, assetId: args.assetId });
    const result = await api_client_1.apiClient.put(path, {
        type: args.type,
        name: args.name,
        content: args.content,
        changeNote: args.changeNote,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleSubmitBrd(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectPlan', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        brdSummary: args.brdSummary,
        totalFunctionalPoints: args.totalFunctionalPoints,
        complexityLevel: args.complexityLevel,
        estimatedTraditionalDays: args.estimatedTraditionalDays,
        estimatedAiHours: args.estimatedAiHours,
        estimatedStartDate: args.estimatedStartDate,
        estimatedEndDate: args.estimatedEndDate,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleSubmitChangeRequest(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        type: 'CHANGE_REQUEST',
        name: args.name,
        description: args.description,
        content: args.content,
        status: 'SUBMITTED',
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleListChangeRequests() {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.get(`${path}?type=CHANGE_REQUEST`);
    return (0, result_formatter_1.ok)(result);
}
async function handleGetChangeRequest(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAsset', { projectId: session.projectId, assetId: args.assetId });
    const result = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(result);
}
async function handleSubmitTestResults(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        type: 'TEST_RUN',
        name: args.name,
        content: args.content,
        featureId: args.featureId,
        sdlcPhaseId: args.sdlcPhaseId,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleUpdateTestStatus(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssetStatus', { projectId: session.projectId, assetId: args.assetId });
    const result = await api_client_1.apiClient.patch(path, { status: args.status });
    return (0, result_formatter_1.ok)(result);
}
async function handleDeployStatus(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        type: 'DEPLOYMENT_PLAN',
        name: args.name,
        content: args.content,
        featureId: args.featureId,
    });
    return (0, result_formatter_1.ok)(result);
}


/***/ }),
/* 28 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleCreateBug = handleCreateBug;
exports.handleUpdateBug = handleUpdateBug;
exports.handleListBugs = handleListBugs;
exports.handleGetBug = handleGetBug;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleCreateBug(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssets', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        type: 'BUG',
        name: args.name,
        description: args.description,
        content: args.content,
        featureId: args.featureId,
        milestoneId: args.milestoneId,
        status: 'NEW',
    });
    const bugId = result?.id;
    if (bugId) {
        try {
            const bugCreatedPath = (0, bootstrap_1.apiPath)('bugCreated', { projectId: session.projectId, bugId });
            const enforcement = await api_client_1.apiClient.post(bugCreatedPath);
            return (0, result_formatter_1.ok)({
                ...result,
                bugFixMode: enforcement?.bugFixMode,
                approvalRequired: enforcement?.approvalRequired ?? false,
                approvalRequestId: enforcement?.approvalRequestId,
                bugFixMessage: enforcement?.message,
            });
        }
        catch (err) {
            process.stderr.write(`[MCP] Warning: bugCreated callback failed: ${err instanceof Error ? err.message : 'unknown'}\n`);
        }
    }
    return (0, result_formatter_1.ok)(result);
}
async function handleUpdateBug(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAssetStatus', { projectId: session.projectId, assetId: args.assetId });
    const result = await api_client_1.apiClient.patch(path, { status: args.status });
    return (0, result_formatter_1.ok)(result);
}
async function handleListBugs(args) {
    const session = requireSession();
    const basePath = (0, bootstrap_1.apiPath)('projectBugs', { projectId: session.projectId });
    const path = args.status ? `${basePath}&status=${encodeURIComponent(args.status)}` : basePath;
    const result = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(result);
}
async function handleGetBug(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectAsset', { projectId: session.projectId, assetId: args.assetId });
    const result = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(result);
}


/***/ }),
/* 29 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handleListFeatures = handleListFeatures;
exports.handleGetFeatureSpec = handleGetFeatureSpec;
exports.handleCreateFeature = handleCreateFeature;
exports.handleCreateMilestone = handleCreateMilestone;
exports.handleUpdateStatus = handleUpdateStatus;
exports.handleUpdateProgress = handleUpdateProgress;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handleListFeatures(args) {
    const session = requireSession();
    const basePath = (0, bootstrap_1.apiPath)('projectFeatures', { projectId: session.projectId });
    const params = ['compact=true'];
    if (args.milestoneId)
        params.push(`milestoneId=${encodeURIComponent(args.milestoneId)}`);
    if (args.status)
        params.push(`status=${encodeURIComponent(args.status)}`);
    const qs = `?${params.join('&')}`;
    const result = await api_client_1.apiClient.get(`${basePath}${qs}`);
    return (0, result_formatter_1.ok)(result);
}
async function handleGetFeatureSpec(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectFeature', { projectId: session.projectId, featureId: args.featureId });
    const result = await api_client_1.apiClient.get(path);
    return (0, result_formatter_1.ok)(result);
}
async function handleCreateFeature(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectFeatures', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        name: args.name,
        description: args.description,
        milestoneId: args.milestoneId,
        priority: args.priority,
        complexity: args.complexity,
        estimatedTraditionalDays: args.estimatedTraditionalDays,
        estimatedAiHours: args.estimatedAiHours,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleCreateMilestone(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('projectMilestones', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        name: args.name,
        description: args.description,
        order: args.order,
        startDate: args.startDate,
        dueDate: args.dueDate,
        functionalPoints: args.functionalPoints,
        estimatedTraditionalDays: args.estimatedTraditionalDays,
        estimatedAiHours: args.estimatedAiHours,
    });
    return (0, result_formatter_1.ok)(result);
}
async function handleUpdateStatus(args) {
    const session = requireSession();
    let path;
    switch (args.entityType) {
        case 'feature':
            path = (0, bootstrap_1.apiPath)('projectFeatureStatus', { projectId: session.projectId, featureId: args.entityId });
            break;
        case 'milestone':
            path = (0, bootstrap_1.apiPath)('projectMilestone', { projectId: session.projectId, milestoneId: args.entityId });
            break;
        case 'asset':
            path = (0, bootstrap_1.apiPath)('projectAssetStatus', { projectId: session.projectId, assetId: args.entityId });
            break;
        default:
            throw new Error(`Unknown entity type: ${args.entityType}. Use "feature", "milestone", or "asset".`);
    }
    const result = await api_client_1.apiClient.patch(path, { status: args.status });
    return (0, result_formatter_1.ok)(result);
}
async function handleUpdateProgress(args) {
    const session = requireSession();
    let path;
    let method = 'put';
    switch (args.entityType) {
        case 'feature':
            path = (0, bootstrap_1.apiPath)('projectFeature', { projectId: session.projectId, featureId: args.entityId });
            break;
        case 'milestone':
            path = (0, bootstrap_1.apiPath)('projectMilestone', { projectId: session.projectId, milestoneId: args.entityId });
            break;
        case 'project':
            path = `/projects/${encodeURIComponent(session.projectId)}`;
            method = 'put';
            break;
        case 'project_plan':
            path = (0, bootstrap_1.apiPath)('projectPlan', { projectId: session.projectId });
            method = 'patch';
            break;
        default:
            throw new Error(`Unknown entity type: ${args.entityType}. Use "feature", "milestone", "project", or "project_plan".`);
    }
    const result = method === 'patch'
        ? await api_client_1.apiClient.patch(path, args.fields)
        : await api_client_1.apiClient.put(path, args.fields);
    return (0, result_formatter_1.ok)(result);
}


/***/ }),
/* 30 */
/***/ ((__unused_webpack_module, exports, __webpack_require__) => {


Object.defineProperty(exports, "__esModule", ({ value: true }));
exports.handlePollCommands = handlePollCommands;
exports.handleGetSop = handleGetSop;
exports.handleGetDirectives = handleGetDirectives;
exports.handleGitPush = handleGitPush;
const bootstrap_1 = __webpack_require__(2);
const api_client_1 = __webpack_require__(13);
const session_1 = __webpack_require__(7);
const result_formatter_1 = __webpack_require__(19);
const context_tool_1 = __webpack_require__(26);
function requireSession() {
    if (!session_1.sessionManager.isConnected())
        throw new Error('Not connected. Call jovan_connect first.');
    return session_1.sessionManager.get();
}
async function handlePollCommands() {
    requireSession();
    const result = await api_client_1.apiClient.get((0, bootstrap_1.apiPath)('sessionPoll'));
    const commands = result?.commands ?? [];
    const refreshCmd = commands.find((c) => c.type === 'REFRESH_CONTEXT');
    if (refreshCmd) {
        try {
            await (0, context_tool_1.handleRefreshContext)();
        }
        catch {
        }
        return (0, result_formatter_1.ok)({
            projectId: result?.projectId,
            pendingApprovals: result?.pendingApprovals ?? [],
            commands,
            contextRefreshed: true,
            message: `Context auto-refreshed: ${refreshCmd.reason}. Blueprint directives updated. Resume with latest governance rules.`,
        });
    }
    return (0, result_formatter_1.ok)({
        projectId: result?.projectId,
        pendingApprovals: result?.pendingApprovals ?? [],
        commands,
        contextRefreshed: false,
        message: result?.message ?? 'No pending commands or approvals.',
    });
}
async function handleGetSop(args) {
    const session = requireSession();
    const basePath = (0, bootstrap_1.apiPath)('sopsResolve', { projectId: session.projectId });
    const path = args.category
        ? `${basePath}&category=${encodeURIComponent(args.category)}`
        : basePath;
    const result = await api_client_1.apiClient.get(path);
    const detailed = (result ?? []).map((s) => {
        const content = s.content;
        return {
            id: s.id,
            name: s.name,
            category: s.category,
            scope: s.scope,
            sdlcPhaseIds: s.sdlcPhaseIds,
            requiresApproval: s.requiresApproval,
            prompt: s.prompt ?? content?.prompt ?? '',
            constraints: s.constraints ?? [],
            skills: s.skills ?? [],
            agentRoles: s.agentRoles ?? [],
            phaseOutcomes: content?.phaseOutcomes ?? [],
        };
    });
    return (0, result_formatter_1.ok)(detailed);
}
async function handleGetDirectives(args) {
    const session = requireSession();
    const basePath = (0, bootstrap_1.apiPath)('directivesResolve', { projectId: session.projectId });
    const path = args.category
        ? `${basePath}?category=${encodeURIComponent(args.category)}`
        : basePath;
    const result = await api_client_1.apiClient.get(path);
    const detailed = (result ?? []).map((d) => {
        const content = d.content;
        return {
            id: d.id,
            name: d.name,
            category: d.category,
            sdlcPhaseIds: d.sdlcPhaseIds,
            requiresApproval: d.requiresApproval,
            prompt: d.prompt ?? content?.prompt ?? '',
            constraints: d.constraints ?? [],
            skills: d.skills ?? [],
            agentRoles: d.agentRoles ?? [],
            phaseOutcomes: content?.phaseOutcomes ?? [],
        };
    });
    return (0, result_formatter_1.ok)(detailed);
}
async function handleGitPush(args) {
    const session = requireSession();
    const path = (0, bootstrap_1.apiPath)('gitCommits', { projectId: session.projectId });
    const result = await api_client_1.apiClient.post(path, {
        branch: args.branch,
        commitHash: args.commitHash,
        commitMessage: args.commitMessage,
        filesChanged: args.filesChanged,
    });
    return (0, result_formatter_1.ok)(result);
}


/***/ })
/******/ 	]);
/************************************************************************/
/******/ 	// The module cache
/******/ 	var __webpack_module_cache__ = {};
/******/ 	
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/ 		// Check if module is in cache
/******/ 		var cachedModule = __webpack_module_cache__[moduleId];
/******/ 		if (cachedModule !== undefined) {
/******/ 			return cachedModule.exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = __webpack_module_cache__[moduleId] = {
/******/ 			// no module.id needed
/******/ 			// no module.loaded needed
/******/ 			exports: {}
/******/ 		};
/******/ 	
/******/ 		// Execute the module function
/******/ 		__webpack_modules__[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/ 	
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/ 	
/************************************************************************/
var __webpack_exports__ = {};
// This entry needs to be wrapped in an IIFE because it needs to be isolated against other modules in the chunk.
(() => {
var exports = __webpack_exports__;

Object.defineProperty(exports, "__esModule", ({ value: true }));
const stdio_js_1 = __webpack_require__(1);
const bootstrap_1 = __webpack_require__(2);
const server_1 = __webpack_require__(4);
const config_1 = __webpack_require__(3);
async function main() {
    const bootstrap = await (0, bootstrap_1.fetchBootstrap)();
    process.stderr.write(`[MCP] Bootstrap loaded: ${bootstrap.tools.length} tools, ` +
        `server=${bootstrap.server.name} v${bootstrap.server.version}\n`);
    const server = (0, server_1.createMcpServer)(bootstrap);
    const transport = new stdio_js_1.StdioServerTransport();
    await server.connect(transport);
    process.stderr.write(`[MCP] Server running (portal: ${config_1.config.apiBaseUrl})\n`);
    process.on('SIGINT', async () => {
        await server.close();
        process.exit(0);
    });
    process.on('SIGTERM', async () => {
        await server.close();
        process.exit(0);
    });
}
main().catch((err) => {
    process.stderr.write(`MCP server failed to start: ${err}\n`);
    process.exit(1);
});

})();

/******/ })()
;
//# sourceMappingURL=main.js.map