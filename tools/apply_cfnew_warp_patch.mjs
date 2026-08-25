import fs from 'node:fs';

const path = process.argv[2] || '_worker_core.js';
let source = fs.readFileSync(path, 'utf8');

function replaceExact(oldText, newText, expectedCount = 1) {
  const parts = source.split(oldText);
  const count = parts.length - 1;
  if (count !== expectedCount) {
    throw new Error(`Expected ${expectedCount} occurrence(s), found ${count}: ${oldText.slice(0, 100)}`);
  }
  source = parts.join(newText);
}

if (source.includes('const CFNEW官方直连地址 = [')) {
  console.log('cfnew WARP patch already present; no changes needed.');
  process.exit(0);
}

const dialMarker = 'let TCP并发拨号数 = 2, 反代并发拨号数 = 1, 预加载竞速拨号 = false;';
replaceExact(dialMarker, `${dialMarker}\nconst CFNEW官方直连地址 = [\n\t'172.71.218.190', '162.158.228.87', '162.158.189.134', '162.158.26.63', '162.158.25.86',\n\t'162.158.29.216', '162.158.218.160', '162.158.227.214', '172.69.118.198', '172.69.119.150'\n];\nconst WARP_TLS端口 = new Set([443, 2053, 2083, 2087, 2096, 8443]);\nconst WARP默认首字节超时 = 1200;\nfunction WARP配置启用(value) {\n\tif (value === undefined || value === null || String(value).trim() === '') return true;\n\treturn !/^(?:0|false|off|no|direct)$/i.test(String(value).trim());\n}\nfunction WARP种子哈希(seed) {\n\tlet hash = 2166136261 >>> 0;\n\tfor (const char of String(seed || 'CF')) {\n\t\thash ^= char.charCodeAt(0);\n\t\thash = Math.imul(hash, 16777619) >>> 0;\n\t}\n\treturn hash >>> 0;\n}\nfunction 获取WARP候选地址(反代上下文 = {}) {\n\tconst fixed = String(反代上下文.WARP固定地址 || '').trim();\n\tif (fixed && CFNEW官方直连地址.includes(fixed)) {\n\t\treturn [fixed, ...CFNEW官方直连地址.filter(ip => ip !== fixed)];\n\t}\n\tconst start = WARP种子哈希(反代上下文.WARP种子 || 'CF') % CFNEW官方直连地址.length;\n\treturn CFNEW官方直连地址.map((_, i) => CFNEW官方直连地址[(start + i) % CFNEW官方直连地址.length]);\n}\nfunction 附加WARP配置(反代上下文, env = {}, request = null) {\n\tconst rawTimeout = Number(env.WARP_TIMEOUT ?? env.warp_timeout ?? WARP默认首字节超时);\n\tconst timeout = Number.isFinite(rawTimeout)\n\t\t? Math.min(5000, Math.max(250, Math.round(rawTimeout)))\n\t\t: WARP默认首字节超时;\n\tconst fixed = String(env.WARP_IP ?? env.warp_ip ?? '').trim();\n\t反代上下文.WARP启用 = WARP配置启用(env.WARP ?? env.warp);\n\t反代上下文.WARP首字节超时 = timeout;\n\t反代上下文.WARP固定地址 = CFNEW官方直连地址.includes(fixed) ? fixed : '';\n\t反代上下文.WARP种子 = String(request?.cf?.colo || 'CF');\n\treturn 反代上下文;\n}`);

const contextLine = 'const 反代上下文 = await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底);';
const contextPatched = 'const 反代上下文 = 附加WARP配置(await 反代参数获取(url, userID, 默认反代IP, 默认反代兜底), env, request);';
replaceExact(contextLine, contextPatched, 2);

const horseLine = '\tconst 使用木马反代 = 允许木马反代 && (反代上下文.木马反代地址 || null);';
replaceExact(horseLine, `${horseLine}\n\tconst ctxWARP首字节超时 = Number(反代上下文.WARP首字节超时) || WARP默认首字节超时;\n\tconst ctxWARP可用 = 反代上下文.WARP启用 !== false && ctx反代兜底 !== false && !ctx代理类型 && !使用木马反代 && WARP_TLS端口.has(Number(portNum));`);

replaceExact(
  '\tconst 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null) => {',
  '\tconst 安装当前连接 = async (socket, generation, downlinkDrain, retryFunc = null, firstByteTimeoutMs = 0) => {'
);
replaceExact(
  '\t\tconnectStreams(socket, ws, 取出响应头, retryFunc, 连接仍有效, remoteConnWrapper).catch(err => {',
  '\t\tconnectStreams(socket, ws, 取出响应头, retryFunc, 连接仍有效, remoteConnWrapper, firstByteTimeoutMs).catch(err => {'
);

const directFunction = `\tasync function connectDirect(address, port, data = null, 启用预加载 = false) {\n\t\tconst 预加载候选列表 = 启用预加载 ? await 构建预加载竞速候选列表(address, port) : null;\n\t\tconst 候选列表 = 预加载候选列表 || Array.from({ length: TCP并发拨号数 }, (_, attempt) => ({ hostname: address, port, attempt }));\n\t\tlog(预加载候选列表\n\t\t\t? \`[TCP直连] 并发尝试 \${候选列表.length} 路: \${候选列表.map(候选 => \`\${候选.hostname}:\${候选.port}\`).join(', ')}\`\n\t\t\t: \`[TCP直连] 并发尝试 \${候选列表.length} 路: \${address}:\${port}\`);\n\t\tlet socket = null;\n\t\ttry {\n\t\t\tconst 连接结果 = await 并发打开候选连接(候选列表);\n\t\t\tsocket = 连接结果.socket;\n\t\t\tif (预加载候选列表) {\n\t\t\t\tconst winner = 连接结果.candidate;\n\t\t\t\tlog(\`[TCP直连] 预加载竞速结果: \${winner.hostname}:\${winner.port} 胜出，源域名: \${winner.resolvedFrom || address}\`);\n\t\t\t}\n\t\t\tawait 写入首包(socket, data);\n\t\t\treturn socket;\n\t\t} catch (err) {\n\t\t\ttry { socket?.close?.() } catch (e) { }\n\t\t\tif (预加载候选列表) log(\`[TCP直连] 预加载竞速失败: \${err.message || err}\`);\n\t\t\tthrow err;\n\t\t}\n\t}`;
const directWithWarp = `${directFunction}\n\n\tasync function connectWARPDirect(data = null) {\n\t\tconst 候选地址 = 获取WARP候选地址(反代上下文).slice(0, 2);\n\t\tlet lastError = null;\n\t\tfor (const address of 候选地址) {\n\t\t\tlet socket = null;\n\t\t\ttry {\n\t\t\t\tlog(\`[WARP回退] 尝试 Cloudflare anycast \${address}:443\`);\n\t\t\t\tsocket = await 打开TCP连接(address, 443);\n\t\t\t\tawait 写入首包(socket, data);\n\t\t\t\treturn socket;\n\t\t\t} catch (err) {\n\t\t\t\tlastError = err;\n\t\t\t\ttry { socket?.close?.() } catch (e) { }\n\t\t\t\tlog(\`[WARP回退] \${address}:443 失败: \${err?.message || err}\`);\n\t\t\t}\n\t\t}\n\t\tthrow lastError || new Error('WARP Cloudflare anycast fallback failed');\n\t}`;
replaceExact(directFunction, directWithWarp);

const beforeConnectProxy = '\tasync function connectProxyIP(address, port, data = null, 所有反代数组 = null, 启用反代失败兜底 = true) {';
replaceExact(beforeConnectProxy, `\tlet WARP已尝试 = false;\n\n\tasync function connecttoWARP() {\n\t\tif (!ctxWARP可用 || WARP已尝试) return connecttoPry(!已通过代理发送首包);\n\t\tif (remoteConnWrapper.connectingPromise) {\n\t\t\tawait remoteConnWrapper.connectingPromise;\n\t\t\treturn;\n\t\t}\n\t\tWARP已尝试 = true;\n\t\tconst { generation: WARP世代, downlinkDrain } = 开始TCP连接世代(remoteConnWrapper);\n\t\tlet WARPsocket = null;\n\t\tconst task = (async () => {\n\t\t\ttry {\n\t\t\t\tWARPsocket = await connectWARPDirect(rawData);\n\t\t\t\tawait 安装当前连接(WARPsocket, WARP世代, downlinkDrain, async () => {\n\t\t\t\t\tif (remoteConnWrapper.generation !== WARP世代 || remoteConnWrapper.socket !== WARPsocket) return;\n\t\t\t\t\tawait connecttoPry(!已通过代理发送首包);\n\t\t\t\t}, ctxWARP首字节超时);\n\t\t\t} catch (err) {\n\t\t\t\ttry { WARPsocket?.close?.() } catch (e) { }\n\t\t\t\tif (remoteConnWrapper.generation === WARP世代) remoteConnWrapper.socket = null;\n\t\t\t\tthrow err;\n\t\t\t}\n\t\t})();\n\t\tremoteConnWrapper.connectingPromise = task;\n\t\ttry {\n\t\t\tawait task;\n\t\t} finally {\n\t\t\tif (remoteConnWrapper.connectingPromise === task) remoteConnWrapper.connectingPromise = null;\n\t\t}\n\t}\n\n${beforeConnectProxy}`);

const retryAssignment = '\tremoteConnWrapper.retryConnect = async () => connecttoPry(!已通过代理发送首包);';
replaceExact(retryAssignment, `\tremoteConnWrapper.retryConnect = async () => {\n\t\tif (ctxWARP可用 && !WARP已尝试) {\n\t\t\ttry {\n\t\t\t\tawait connecttoWARP();\n\t\t\t\treturn;\n\t\t\t} catch (err) {\n\t\t\t\tlog(\`[WARP回退] Cloudflare anycast 失败，继续原 EdgeTunnel 反代: \${err?.message || err}\`);\n\t\t\t\tif (ws.readyState !== WebSocket.OPEN) throw err;\n\t\t\t}\n\t\t}\n\t\tawait connecttoPry(!已通过代理发送首包);\n\t};`);

const initialInstall = `\t\t\tawait 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {\n\t\t\t\tif (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;\n\t\t\t\tawait connecttoPry();\n\t\t\t});`;
const initialInstallPatched = `\t\t\tawait 安装当前连接(initialSocket, 直连世代, 世代连接.downlinkDrain, async () => {\n\t\t\t\tif (remoteConnWrapper.generation !== 直连世代 || remoteConnWrapper.socket !== initialSocket) return;\n\t\t\t\tawait remoteConnWrapper.retryConnect();\n\t\t\t}, ctxWARP可用 ? ctxWARP首字节超时 : 0);`;
replaceExact(initialInstall, initialInstallPatched);

const directCatch = `\t\t\tif (ws.readyState !== WebSocket.OPEN) throw err;\n\t\t\tawait connecttoPry();\n\t\t\tif (仅建立连接) return remoteConnWrapper.socket;`;
const directCatchPatched = `\t\t\tif (ws.readyState !== WebSocket.OPEN) throw err;\n\t\t\tawait remoteConnWrapper.retryConnect();\n\t\t\tif (仅建立连接) return remoteConnWrapper.socket;`;
replaceExact(directCatch, directCatchPatched);

const streamSignature = 'async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null) {';
replaceExact(streamSignature, 'async function connectStreams(remoteSocket, webSocket, headerData, retryFunc, isCurrentSocket = null, remoteConnWrapper = null, firstByteTimeoutMs = 0) {');

const readerSetup = `\ttry { reader = remoteSocket.readable.getReader({ mode: 'byob' }); useBYOB = true }\n\tcatch (e) { reader = remoteSocket.readable.getReader() }`;
replaceExact(readerSetup, `${readerSetup}\n\n\tlet 首字节定时器 = null;\n\tconst 清理首字节定时器 = () => {\n\t\tif (首字节定时器) clearTimeout(首字节定时器);\n\t\t首字节定时器 = null;\n\t};\n\tif (retryFunc && Number(firstByteTimeoutMs) > 0) {\n\t\t首字节定时器 = setTimeout(() => {\n\t\t\tif (hasData || !当前连接仍有效()) return;\n\t\t\tlog(\`[TCP下行] \${firstByteTimeoutMs}ms 未收到首字节，关闭当前 socket 并触发重试\`);\n\t\t\ttry { remoteSocket.close() } catch (e) { }\n\t\t}, Number(firstByteTimeoutMs));\n\t}`);

replaceExact('\t\t\t\thasData = true;', '\t\t\t\tif (!hasData) { hasData = true; 清理首字节定时器(); }', 2);
replaceExact('\tfinally {\n\t\tif (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {', '\tfinally {\n\t\t清理首字节定时器();\n\t\tif (当前连接仍有效() && webSocket.readyState === WebSocket.OPEN) {');

fs.writeFileSync(path, source, 'utf8');
console.log('Applied cfnew-style native WARP retry patch.');
