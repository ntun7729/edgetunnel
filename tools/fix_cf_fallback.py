from pathlib import Path

p = Path('worker.js')
s = p.read_text()

old_pool = "const CF_FALLBACK_IPS = ['104.16.0.1', '104.17.0.1', '104.18.0.1'];\n"
new_pool = """const CF_FALLBACK_IPS = [
  '172.71.218.190', '162.158.228.87', '162.158.189.134', '162.158.26.63',
  '162.158.25.86', '162.158.29.216', '162.158.218.160', '162.158.227.214',
  '172.69.118.198', '172.69.119.150',
];
"""
if old_pool not in s:
    raise SystemExit('old CF fallback pool not found')
s = s.replace(old_pool, new_pool, 1)

old_state = "  let fallbackAttempted = false;\n  let switching = false;\n"
new_state = "  let fallbackAttempted = false;\n  let fallbackAttempt = -1;\n  let switching = false;\n"
if old_state not in s:
    raise SystemExit('fallback state anchor not found')
s = s.replace(old_state, new_state, 1)

old_timer = """  const clearFirstByteTimer = () => {
    if (firstByteTimer) clearTimeout(firstByteTimer);
    firstByteTimer = null;
  };
"""
new_timer = old_timer + """
  const armFirstByteTimer = (isFallback) => {
    clearFirstByteTimer();
    if (!canCfFallback || firstByteSeen || closed) return;
    firstByteTimer = setTimeout(() => {
      if (closed || firstByteSeen) return;
      if (isFallback) {
        triggerCfFallback(`${config.cfFirstByteMs}ms without first byte on CF fallback`, true).catch(() => {});
      } else if (!fallbackAttempted) {
        triggerCfFallback(`${config.cfFirstByteMs}ms without first byte`, false).catch(() => {});
      }
    }, config.cfFirstByteMs);
  };
"""
if old_timer not in s:
    raise SystemExit('timer anchor not found')
s = s.replace(old_timer, new_timer, 1)

old_downlink = """  const startDownlink = (myGeneration, isFallback) => {
    const myReader = reader;
    (async () => {
      try {
        while (!closed && myGeneration === generation) {
          const { value, done: streamDone } = await myReader.read();
          if (streamDone) {
            if (!firstByteSeen && !isFallback && canCfFallback) {
              await triggerCfFallback('direct EOF before first byte');
            } else if (myGeneration === generation) {
              closeAll(1000, 'remote closed');
            }
            return;
          }
          if (!value?.byteLength) continue;
          if (myGeneration !== generation || closed) return;
          markFirstByte();
          idle.arm();
          await waitForWsBackpressure(ws);
          sendWs(ws, value);
        }
      } catch (error) {
        if (closed || myGeneration !== generation) return;
        if (!firstByteSeen && !isFallback && canCfFallback) {
          try {
            await triggerCfFallback(`direct read failed: ${error?.message || error}`);
            return;
          } catch {}
        }
        log('downlink failed', error?.message || error);
        closeAll(1011, 'downlink failed');
      } finally {
        try { myReader.releaseLock(); } catch {}
      }
    })();
  };
"""
new_downlink = """  const startDownlink = (myGeneration, isFallback) => {
    const myReader = reader;
    (async () => {
      try {
        while (!closed && myGeneration === generation) {
          const { value, done: streamDone } = await myReader.read();
          if (myGeneration !== generation || closed) return;
          if (streamDone) {
            if (!firstByteSeen && canCfFallback) {
              await triggerCfFallback(isFallback ? 'CF fallback EOF before first byte' : 'direct EOF before first byte', isFallback);
            } else {
              closeAll(1000, 'remote closed');
            }
            return;
          }
          if (!value?.byteLength) continue;
          markFirstByte();
          idle.arm();
          await waitForWsBackpressure(ws);
          sendWs(ws, value);
        }
      } catch (error) {
        if (closed || myGeneration !== generation) return;
        if (!firstByteSeen && canCfFallback) {
          try {
            await triggerCfFallback(`${isFallback ? 'CF fallback' : 'direct'} read failed: ${error?.message || error}`, isFallback);
            return;
          } catch {}
        }
        log('downlink failed', error?.message || error);
        closeAll(1011, 'downlink failed');
      } finally {
        try { myReader.releaseLock(); } catch {}
      }
    })();
  };
"""
if old_downlink not in s:
    raise SystemExit('downlink block not found')
s = s.replace(old_downlink, new_downlink, 1)

old_open = """  const openTarget = async (targetHost, label, isFallback) => {
    const myGeneration = ++generation;
    const newSocket = await connectWithTimeout(connector, targetHost, port, config.connectTimeoutMs);
    if (closed || myGeneration !== generation) {
      try { newSocket.close(); } catch {}
      throw new Error('connection superseded');
    }
    socket = newSocket;
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost);
    startDownlink(myGeneration, isFallback);
  };

  const writeReplay = async () => {
    let i = 0;
    while (!closed && i < replay.length) {
      const item = replay[i++];
      await writer.write(item.bytes);
      replayedThroughId = Math.max(replayedThroughId, item.id);
    }
  };
"""
new_open = """  const openTarget = async (targetHost, label, isFallback, timeoutMs = config.connectTimeoutMs) => {
    const myGeneration = ++generation;
    const newSocket = await connectWithTimeout(connector, targetHost, port, timeoutMs);
    if (closed || myGeneration !== generation) {
      try { newSocket.close(); } catch {}
      throw new Error('connection superseded');
    }
    socket = newSocket;
    writer = socket.writable.getWriter();
    reader = socket.readable.getReader();
    replayedThroughId = -1;
    log('TCP connected', `${host}:${port}`, requestMeta.connectorName, label, targetHost);
    startDownlink(myGeneration, isFallback);
  };

  const writeReplay = async () => {
    let i = 0;
    while (!closed && i < replay.length) {
      const item = replay[i++];
      if (item.id <= replayedThroughId) continue;
      await writer.write(item.bytes);
      replayedThroughId = item.id;
    }
  };
"""
if old_open not in s:
    raise SystemExit('open/replay block not found')
s = s.replace(old_open, new_open, 1)

old_fallback = """  async function triggerCfFallback(reason) {
    if (!canCfFallback || fallbackAttempted || firstByteSeen || closed) {
      throw new Error('Cloudflare fallback unavailable');
    }
    fallbackAttempted = true;
    switching = true;
    clearFirstByteTimer();
    generation++;
    closeCurrent();
    const fallbackIp = selectCfFallback(host, 0);
    log('CF fallback', reason, `${host}:${port}`, 'via', fallbackIp);
    switchPromise = (async () => {
      await openTarget(fallbackIp, 'cf-anycast', true);
      await writeReplay();
      switching = false;
      idle.arm();
    })().catch((error) => {
      switching = false;
      log('CF fallback failed', error?.message || error);
      closeAll(1011, 'Cloudflare fallback failed');
      throw error;
    });
    return switchPromise;
  }
"""
new_fallback = """  async function triggerCfFallback(reason, advance = false) {
    if (!canCfFallback || firstByteSeen || closed) {
      throw new Error('Cloudflare fallback unavailable');
    }
    if (!fallbackAttempted) {
      fallbackAttempted = true;
      fallbackAttempt = 0;
    } else if (advance) {
      fallbackAttempt += 1;
    }

    switching = true;
    clearFirstByteTimer();
    generation++;
    closeCurrent();

    switchPromise = (async () => {
      let lastError = null;
      const fallbackConnectMs = Math.max(500, Math.min(config.connectTimeoutMs, config.cfFirstByteMs));
      while (!closed && !firstByteSeen && fallbackAttempt < CF_FALLBACK_IPS.length) {
        const fallbackIp = selectCfFallback(host, fallbackAttempt);
        log('CF fallback', reason, `${host}:${port}`, `candidate=${fallbackAttempt + 1}/${CF_FALLBACK_IPS.length}`, 'via', fallbackIp);
        try {
          await openTarget(fallbackIp, 'cf-anycast', true, fallbackConnectMs);
          await writeReplay();
          switching = false;
          idle.arm();
          armFirstByteTimer(true);
          return;
        } catch (error) {
          lastError = error;
          log('CF fallback candidate failed', fallbackIp, error?.message || error);
          fallbackAttempt += 1;
          generation++;
          closeCurrent();
        }
      }
      switching = false;
      const message = lastError?.message || 'all Cloudflare fallback candidates exhausted';
      closeAll(1011, 'Cloudflare fallback failed');
      throw new Error(message);
    })();
    return switchPromise;
  }
"""
if old_fallback not in s:
    raise SystemExit('fallback function not found')
s = s.replace(old_fallback, new_fallback, 1)

old_force = """    if (forceCfFallback) {
      fallbackAttempted = true;
      await openTarget(selectCfFallback(host, 0), 'cf-anycast-force', true);
    } else {
"""
new_force = """    if (forceCfFallback) {
      await triggerCfFallback('forced CF fallback', false);
    } else {
"""
if old_force not in s:
    raise SystemExit('force block not found')
s = s.replace(old_force, new_force, 1)

old_connect_fail = """        if (!canCfFallback) throw error;
        fallbackAttempted = false;
        await triggerCfFallback(`direct connect failed: ${error?.message || error}`);
"""
new_connect_fail = """        if (!canCfFallback) throw error;
        await triggerCfFallback(`direct connect failed: ${error?.message || error}`, false);
"""
if old_connect_fail not in s:
    raise SystemExit('direct connect failure block not found')
s = s.replace(old_connect_fail, new_connect_fail, 1)

old_final_timer = """    if (!firstByteSeen && canCfFallback && !forceCfFallback && !fallbackAttempted) {
      firstByteTimer = setTimeout(() => {
        if (!closed && !firstByteSeen && !fallbackAttempted) {
          triggerCfFallback(`${config.cfFirstByteMs}ms without first byte`).catch(() => {});
        }
      }, config.cfFirstByteMs);
    }
"""
new_final_timer = """    if (!firstByteSeen && canCfFallback) {
      armFirstByteTimer(fallbackAttempted);
    }
"""
if old_final_timer not in s:
    raise SystemExit('final first-byte timer block not found')
s = s.replace(old_final_timer, new_final_timer, 1)

p.write_text(s)
print('patched worker.js')
