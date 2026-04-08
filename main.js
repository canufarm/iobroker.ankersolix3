'use strict';

/**
 * ioBroker Adapter: ankersolix3
 * Anker Solix 3 / Solarbank 3 → ioBroker via Cloud MQTT
 * Basiert auf bridge.js (ronny130286/ioBroker.ankersolix2 Auth-Methode)
 */

const utils  = require('@iobroker/adapter-core');
const { decodeAnkerMessage } = require('./lib/decoder');
const axios  = require('axios');
const mqtt   = require('mqtt');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const SERVER_PUBLIC_KEY =
  '04c5c00c4f8d1197cc7c3167c52bf7acb054d722f0ef08dcd7e0883236e0d72a3' +
  '868d9750cb47fa4619248f3d83f0f662671dadc6e2d31c2f41db0161651c7c076';

// ─── Feldtypen für ioBroker-Objekte ──────────────────────────────────────────
// Felder die als String gespeichert werden (alle anderen → number)
const STRING_FIELDS = new Set(['sw_version', 'device_sn', 'timestamp']);

class AnkerSolix3 extends utils.Adapter {
  constructor(options) {
    super({ ...options, name: 'ankersolix3' });

    this.session      = null;
    this.ankerClient  = null;
    this.refreshTimer = null;
    this.triggerInterval = null;
    this.msgSeq       = 1;
    this.devicePower  = {};   // { sn: { pv, ac, lastActive, lastSeen } }
    this.knownObjects = new Set();  // bereits angelegte State-IDs

    this.on('ready',  this.onReady.bind(this));
    this.on('unload', this.onUnload.bind(this));
  }

  // ─── Hilfsfunktionen ───────────────────────────────────────────────────────

  md5(s) {
    return crypto.createHash('md5').update(Buffer.from(s)).digest('hex');
  }

  getTimezoneGMT() {
    const tzo = -new Date().getTimezoneOffset(), dif = tzo >= 0 ? '+' : '-';
    const pad = n => String(Math.floor(Math.abs(n))).padStart(2, '0');
    return `GMT${dif}${pad(tzo / 60)}:${pad(tzo % 60)}`;
  }

  encryptAPIData(data, key) {
    const cipher = crypto.createCipheriv('aes-256-cbc', key, key.slice(0, 16));
    return cipher.update(data, 'utf8', 'base64') + cipher.final('base64');
  }

  buildHeaders(authToken, userId) {
    const h = {
      'Content-Type': 'application/json',
      'Country':      (this.config.ankerCountry || 'DE').toUpperCase(),
      'Timezone':     this.getTimezoneGMT(),
      'Model-Type':   'DESKTOP',
      'App-Name':     'anker_power',
      'Os-Type':      'android',
    };
    if (authToken) {
      h['X-Auth-Token'] = authToken;
      h['gtoken']       = this.md5(userId);
    }
    return h;
  }

  // ─── Session-Cache ─────────────────────────────────────────────────────────

  getSessionCachePath() {
    // Datenpfad: <iobroker-data>/ankersolix3.<instanz-nr>/session.json
    const dir = path.join(
      utils.getAbsoluteDefaultDataDir(),
      `${this.namespace.replace('.', '_')}`,
    );
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    return path.join(dir, 'session.json');
  }

  saveSession(s) {
    try { fs.writeFileSync(this.getSessionCachePath(), JSON.stringify(s, null, 2)); } catch (_) {}
  }

  loadCachedSession() {
    try {
      const s = JSON.parse(fs.readFileSync(this.getSessionCachePath(), 'utf8'));
      if (s?.auth_token && s?.token_expires_at) {
        const expiresIn = s.token_expires_at - Math.floor(Date.now() / 1000);
        if (expiresIn > 3600) {
          this.log.info(`Cached Session: user=${s.email} | läuft ab in ${Math.round(expiresIn / 3600)}h`);
          return s;
        }
      }
    } catch (_) {}
    return null;
  }

  // ─── 1. Login ──────────────────────────────────────────────────────────────

  async ankerLogin() {
    this.log.info(`Einloggen: ${this.config.ankerUser}`);
    const server = this.config.ankerServer || 'https://ankerpower-api-eu.anker.com';

    const ecdh = crypto.createECDH('prime256v1');
    ecdh.generateKeys();
    const sharedSecret = ecdh.computeSecret(Buffer.from(SERVER_PUBLIC_KEY, 'hex'));

    const body = {
      ab:                 (this.config.ankerCountry || 'DE').toUpperCase(),
      client_secret_info: { public_key: ecdh.getPublicKey('hex') },
      enc:                0,
      email:              this.config.ankerUser,
      password:           this.encryptAPIData(this.config.ankerPass, sharedSecret),
      time_zone:          new Date().getTimezoneOffset() !== 0
                            ? -new Date().getTimezoneOffset() * 60 * 1000
                            : 0,
      transaction:        `${Date.now()}`,
    };

    let res;
    try {
      res = await axios.post(`${server}/passport/login`, body,
        { headers: this.buildHeaders(), timeout: 15000 });
    } catch (err) {
      const msg = err.response
        ? `Login ${err.response.status}: ${JSON.stringify(err.response.data)}`
        : err.message;
      this.log.error(msg);
      throw err;
    }

    if (res.data?.code !== 0) {
      throw new Error(`Login fehlgeschlagen (${res.data?.code}): ${JSON.stringify(res.data)}`);
    }

    this.session = res.data.data;
    this.log.info(`Login OK – user=${this.session.email}`);
    this.saveSession(this.session);
    return this.session;
  }

  // ─── 2. MQTT-Credentials ───────────────────────────────────────────────────

  async getMqttCredentials() {
    this.log.info('Hole MQTT-Credentials...');
    const server = this.config.ankerServer || 'https://ankerpower-api-eu.anker.com';
    let res;
    try {
      res = await axios.post(
        `${server}/app/devicemanage/get_user_mqtt_info`, {},
        { headers: this.buildHeaders(this.session.auth_token, this.session.user_id), timeout: 15000 },
      );
    } catch (err) {
      const msg = err.response
        ? `${err.response.status}: ${JSON.stringify(err.response.data)}`
        : err.message;
      this.log.error(msg);
      throw err;
    }
    if (res.data?.code !== 0) throw new Error(`MQTT-Creds (${res.data?.code}): ${JSON.stringify(res.data)}`);
    const d = res.data.data;
    this.log.info(`Broker: ${d.endpoint_addr}:8883`);
    return {
      brokerUrl: d.endpoint_addr, port: 8883, clientId: d.thing_name,
      cert: d.certificate_pem, key: d.private_key, ca: d.aws_root_ca1_pem,
      appName: d.app_name || 'anker_power',
      certId: d.certificate_id || '',
    };
  }

  // ─── 3. Geräteliste ────────────────────────────────────────────────────────

  async getDevices() {
    const deviceSns = (this.config.deviceSns || '').split(',').map(s => s.trim()).filter(Boolean);
    const devicePn  = this.config.devicePn || '+';

    if (deviceSns.length > 0) {
      this.log.info(`Konfigurierte SNs: ${deviceSns.join(', ')}`);
      return deviceSns.map(sn => ({ sn, pn: devicePn }));
    }
    const server = this.config.ankerServer || 'https://ankerpower-api-eu.anker.com';
    try {
      const res = await axios.post(
        `${server}/power_service/v1/app/get_relate_and_bind_devices`, {},
        { headers: this.buildHeaders(this.session.auth_token, this.session.user_id), timeout: 15000 },
      );
      const raw = res.data?.data?.data || res.data?.data || [];
      const devices = (Array.isArray(raw) ? raw : Object.values(raw))
        .map(d => ({ sn: d.device_sn || d.sn || '', pn: d.device_pn || d.product_code || devicePn }))
        .filter(d => d.sn);
      devices.forEach(d => this.log.info(`Gerät: sn=${d.sn} pn=${d.pn}`));
      return devices.length > 0 ? devices : [{ sn: '*', pn: devicePn }];
    } catch (err) {
      this.log.warn(`Geräteliste: ${err.message}`);
      return [];
    }
  }

  // ─── ioBroker State-Verwaltung ─────────────────────────────────────────────

  async ensureStateObject(sn, key) {
    const id = `${sn}.${key}`;
    if (this.knownObjects.has(id)) return;

    const isString = STRING_FIELDS.has(key);
    await this.setObjectNotExistsAsync(id, {
      type: 'state',
      common: {
        name:  key,
        type:  isString ? 'string' : 'number',
        role:  isString ? 'text'   : 'value',
        read:  true,
        write: false,
        unit:  this._guessUnit(key),
      },
      native: {},
    });
    this.knownObjects.add(id);
  }

  _guessUnit(key) {
    if (key.includes('power') || key === 'max_load' || key === 'pv_limit') return 'W';
    if (key.includes('energy') || key.includes('yield'))                   return 'Wh';
    if (key === 'temperature')                                              return '°C';
    if (key.includes('soc') || key.includes('soh') || key === 'min_soc')  return '%';
    return '';
  }

  async publishValue(sn, key, rawValue) {
    try {
      await this.ensureStateObject(sn, key);
      const isString = STRING_FIELDS.has(key);
      const num = parseFloat(rawValue);
      const val = (!isString && !isNaN(num)) ? num : rawValue;
      await this.setStateAsync(`${sn}.${key}`, { val, ack: true });
    } catch (err) {
      this.log.debug(`publishValue ${sn}.${key}: ${err.message}`);
    }
  }

  // ─── Idle-Erkennung ────────────────────────────────────────────────────────

  updateDevicePower(sn, fields) {
    if (!this.devicePower[sn])
      this.devicePower[sn] = { pv: 0, ac: 0, lastActive: Date.now(), lastSeen: Date.now() };
    this.devicePower[sn].lastSeen = Date.now();
    const threshold = parseFloat(this.config.idleThresholdW) || 0;
    for (const { key, value } of fields) {
      if (key === 'photovoltaic_power')     this.devicePower[sn].pv = parseFloat(value) || 0;
      if (key === 'ac_output_power_signed') this.devicePower[sn].ac = parseFloat(value) || 0;
    }
    if (this.devicePower[sn].pv > threshold)
      this.devicePower[sn].lastActive = Date.now();
  }

  isDeviceIdle(sn) {
    const d = this.devicePower[sn];
    if (!d) return true;

    const staleMs   = Date.now() - d.lastSeen;
    const staleTimeout = (parseInt(this.config.staleTimeoutS) || 180) * 1000;
    if (staleMs > staleTimeout) return true;

    const threshold   = parseFloat(this.config.idleThresholdW) || 0;
    const idleTimeout = (parseInt(this.config.idleTimeoutS) || 120) * 1000;
    const pvZero = d.pv <= threshold;
    const acZero = Math.abs(d.ac) <= threshold;
    const idleMs = Date.now() - d.lastActive;
    return pvZero && acZero && idleMs > idleTimeout;
  }

  // ─── Nachtruhe ─────────────────────────────────────────────────────────────

  parseHHMM(s) {
    if (!s || !/^\d{3,4}$/.test(s)) return null;
    const p = s.padStart(4, '0');
    const h = parseInt(p.slice(0, 2), 10);
    const m = parseInt(p.slice(2, 4), 10);
    if (h > 23 || m > 59) return null;
    return h * 60 + m;
  }

  isNightSleepTime() {
    const startMin = this.parseHHMM(this.config.nightSleepStart || '');
    if (startMin === null) return false;
    const endMin = this.parseHHMM(this.config.nightSleepEnd || '');
    if (endMin === null) return false;
    const now = new Date();
    const cur = now.getHours() * 60 + now.getMinutes();
    return startMin < endMin
      ? (cur >= startMin && cur < endMin)
      : (cur >= startMin || cur < endMin);
  }

  // ─── Realtime Trigger ──────────────────────────────────────────────────────

  buildRealtimeTriggerPayload(creds, device) {
    const ts      = Math.floor(Date.now() / 1000);
    const timeout = 60;
    const tsBuf   = Buffer.allocUnsafe(4); tsBuf.writeUInt32LE(ts, 0);
    const toBuf   = Buffer.allocUnsafe(4); toBuf.writeUInt32LE(timeout, 0);

    const fields = Buffer.concat([
      Buffer.from([0xa1, 0x01, 0x22]),
      Buffer.from([0xa2, 0x02, 0x01, 0x01]),
      Buffer.from([0xa3, 0x05, 0x03]), toBuf,
      Buffer.from([0xfe, 0x05, 0x03]), tsBuf,
    ]);

    const totalLen = 9 + fields.length + 1;
    const header = Buffer.from([
      0xff, 0x09,
      totalLen & 0xff, (totalLen >> 8) & 0xff,
      0x03, 0x00, 0x0f, 0x00, 0x57,
    ]);
    const msgBody = Buffer.concat([header, fields]);
    let xor = 0;
    for (const b of msgBody) xor ^= b;
    const hexData = Buffer.concat([msgBody, Buffer.from([xor])]);

    const envelope = {
      head: {
        version:   '1.0.0.1',
        client_id: `android-${creds.appName}-${this.session.user_id}-${creds.certId}`,
        sess_id:   '1234-5678',
        msg_seq:   this.msgSeq++,
        cmd_status: 2,
        cmd:        17,
        sign_code:  1,
        device_pn:  device.pn,
        device_sn:  device.sn,
        seed:       1,
        timestamp:  ts,
      },
      payload: JSON.stringify({
        device_sn:  device.sn,
        account_id: this.session.user_id,
        data:       hexData.toString('base64'),
      }, null, 0),
    };
    return {
      topic:   `cmd/${creds.appName}/${device.pn}/${device.sn}/req`,
      message: JSON.stringify(envelope),
    };
  }

  startRealtimeTrigger(creds, devices) {
    if (this.triggerInterval) clearInterval(this.triggerInterval);

    const sendTriggers = () => {
      if (!this.ankerClient?.connected) return;
      devices.forEach(device => {
        if (device.pn === '+' || !device.pn) return;

        if (this.isNightSleepTime()) {
          // this.log.debug(`Trigger pausiert (Nachtruhe ${this.config.nightSleepStart}–${this.config.nightSleepEnd})`);
          return;
        }
        if (this.isDeviceIdle(device.sn)) {
          // this.log.debug(`Trigger pausiert (${device.sn} idle)`);
          return;
        }
        try {
          const { topic, message } = this.buildRealtimeTriggerPayload(creds, device);
          this.ankerClient.publish(topic, message, { qos: 0 }, (err) => {
            if (err) this.log.warn(`Trigger fehlgeschlagen (${device.sn}): ${err.message}`);
          });
        } catch (err) {
          this.log.warn(`Trigger-Build-Fehler: ${err.message}`);
        }
      });
    };

    sendTriggers();
    this.triggerInterval = setInterval(sendTriggers, 50 * 1000);
    this.log.info(`Realtime-Trigger aktiv (alle 50s) für: ${devices.map(d => d.sn).join(', ')}`);
  }

  // ─── 5. Anker Cloud MQTT ───────────────────────────────────────────────────

  connectAnkerMqtt(creds, devices) {
    return new Promise((resolve, reject) => {
      this.log.info(`Verbinde Anker MQTT: ${creds.brokerUrl}:${creds.port}`);
      this.ankerClient = mqtt.connect({
        host: creds.brokerUrl, port: creds.port, protocol: 'mqtts',
        cert: creds.cert, key: creds.key, ca: creds.ca,
        clientId: creds.clientId, keepalive: 60,
        reconnectPeriod: 10000, connectTimeout: 20000, rejectUnauthorized: true,
      });

      this.ankerClient.once('connect', () => {
        this.log.info('Anker Cloud MQTT verbunden ✓');
        this.setState('info.connection', true, true);

        const topics = devices.map(({ sn, pn }) => `dt/${creds.appName}/${pn}/${sn}/#`);
        if (topics.length === 0) topics.push(`dt/${creds.appName}/#`);

        topics.forEach(topic => {
          this.ankerClient.subscribe(topic, { qos: 0 }, (err) => {
            if (err) this.log.error(`Subscribe ${topic}: ${err.message}`);
            else     this.log.info(`Abonniert ✓: ${topic}`);
          });
        });
        resolve();
        this.startRealtimeTrigger(creds, devices);
      });

      this.ankerClient.on('message', (topic, payload) => {
        try {
          const parts = topic.split('/');
          const sn = parts[3] || 'unknown';
          const fields = decodeAnkerMessage(topic, payload);
          this.updateDevicePower(sn, fields);
          fields.forEach(({ key, value }) => {
            this.publishValue(sn, key, value);
          });
        } catch (err) {
          this.log.debug('Decoder-Fehler: ' + err.message);
        }
      });

      this.ankerClient.on('error',     e  => this.log.error('Anker MQTT: ' + e.message));
      this.ankerClient.on('reconnect', () => this.log.warn('Anker MQTT: reconnect...'));
      this.ankerClient.on('close',     () => {
        this.log.warn('Anker MQTT: getrennt');
        this.setState('info.connection', false, true);
      });
      setTimeout(() => reject(new Error('Anker MQTT Timeout')), 25000);
    });
  }

  // ─── 6. Session-Refresh ────────────────────────────────────────────────────

  scheduleRefresh(creds) {
    if (this.refreshTimer) clearTimeout(this.refreshTimer);
    this.refreshTimer = setTimeout(async () => {
      try {
        await this.ankerLogin();
        const [newCreds, devices] = await Promise.all([this.getMqttCredentials(), this.getDevices()]);
        if (this.ankerClient) { this.ankerClient.removeAllListeners(); this.ankerClient.end(true); }
        if (this.triggerInterval) { clearInterval(this.triggerInterval); this.triggerInterval = null; }
        await this.connectAnkerMqtt(newCreds, devices);
        this.scheduleRefresh(newCreds);
      } catch (err) {
        this.log.error('Refresh: ' + err.message);
        setTimeout(() => this.scheduleRefresh(creds), 5 * 60 * 1000);
      }
    }, 22 * 60 * 60 * 1000);
  }

  // ─── Adapter-Lifecycle ─────────────────────────────────────────────────────

  async onReady() {
    this.log.info('=== Anker Solix 3 Adapter startet ===');

    if (!this.config.ankerUser || !this.config.ankerPass) {
      this.log.error('Anker E-Mail und Passwort müssen in der Instanz-Konfiguration gesetzt sein!');
      return;
    }
    await this.start();
  }

  async start() {
    try {
      this.session = this.loadCachedSession() || await this.ankerLogin();
      const [creds, devices] = await Promise.all([this.getMqttCredentials(), this.getDevices()]);
      await this.connectAnkerMqtt(creds, devices);
      this.scheduleRefresh(creds);
      this.log.info('=== Bridge läuft ===');
    } catch (err) {
      this.log.error('Start: ' + err.message);
      this._restartTimeout = setTimeout(() => this.start(), 30000);
    }
  }

  onUnload(callback) {
    try {
      if (this.triggerInterval)  clearInterval(this.triggerInterval);
      if (this.refreshTimer)     clearTimeout(this.refreshTimer);
      if (this._restartTimeout)  clearTimeout(this._restartTimeout);
      if (this.ankerClient) {
        this.ankerClient.removeAllListeners();
        this.ankerClient.end(true);
      }
    } catch (_) {}
    callback();
  }
}

// Entry point
if (require.main !== module) {
  module.exports = (options) => new AnkerSolix3(options);
} else {
  new AnkerSolix3();
}
