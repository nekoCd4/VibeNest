// Console Bridge - sends browser console logs to server terminal
(function() {
  const originalLog = console.log;
  const originalWarn = console.warn;
  const originalError = console.error;
  const originalInfo = console.info;
  const originalDebug = console.debug;
  
  const sendLog = (level, args) => {
    try {
      const messages = Array.from(args).map(arg => {
        if (typeof arg === 'string' || typeof arg === 'number' || typeof arg === 'boolean') {
          return String(arg);
        } else if (arg instanceof Error) {
          return `${arg.name}: ${arg.message}\n${arg.stack}`;
        } else if (typeof arg === 'object') {
          try { return JSON.stringify(arg); } catch (e) { return String(arg); }
        }
        return String(arg);
      });
      
      fetch('/api/client-log', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          level: level,
          messages: messages,
          url: window.location.href,
          timestamp: new Date().toISOString()
        })
      }).catch(err => {
        // Fail silently - don't create infinite loops
      });
    } catch (e) {
      // Fail silently
    }
  };
  
  console.log = function(...args) {
    originalLog.apply(console, args);
    sendLog('log', args);
  };
  
  console.warn = function(...args) {
    originalWarn.apply(console, args);
    sendLog('warn', args);
  };
  
  console.error = function(...args) {
    originalError.apply(console, args);
    sendLog('error', args);
  };
  
  console.info = function(...args) {
    originalInfo.apply(console, args);
    sendLog('info', args);
  };
  
  console.debug = function(...args) {
    originalDebug.apply(console, args);
    sendLog('debug', args);
  };
  
  console.log('[CONSOLE-BRIDGE] Client console logging to server initialized');
})();
