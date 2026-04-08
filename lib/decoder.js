/**
 * Anker Solix MQTT Payload Decoder – A17C5 (Solarbank 3 E2700)
 * Feldnamen: thomluther/anker-solix-api mqttmap.py
 * Numeric types: uint8/16/32 (type 01), sint (type 02), var (type 03), float32 (type 04/catch-all)
 */

'use strict';

// ─── Feldkarten ───────────────────────────────────────────────────────────────

// Vorzeichenbehaftete Felder (signed int oder signed float)
const SIGNED_FIELDS = new Set(['ac','ae','c4','b6','bd','cc','battery_power_signed',
  'ac_output_power_signed','grid_power_signed','battery_power_signed?','grid_power_signed?']);

// msg type 0405 – param_info – kommt alle 3-5s mit Realtime-Trigger
const MAP_0405 = {
  a2: 'device_sn',
  a3: 'main_battery_soc',       // %
  a5: 'temperature',            // °C (signed)
  a6: 'battery_soc',            // %
  a7: 'sw_version',
  ab: 'photovoltaic_power',     // W Solar-Leistung
  ac: 'battery_power_signed',   // W (+ = Laden, – = Entladen)
  ad: 'output_power',           // W Ausgangsleistung
  ae: 'ac_output_power_signed', // W AC-Ausgang
  b0: 'pv_yield',               // Wh Solar-Ertrag heute
  b1: 'charged_energy',         // Wh geladen heute
  b2: 'discharged_energy',      // Wh entladen heute
  b3: 'output_energy',          // Wh Ausgang heute
  b4: 'consumed_energy',        // Wh verbraucht heute
  b5: 'min_soc',                // % Mindest-SOC
  b8: 'usage_mode',             // 0=Manuell, 1=Automatik
  b9: 'home_load_preset',       // W Haus-Preset
  bb: 'heating_power',          // W
  bc: 'grid_to_battery_power',  // W Netz→Batterie
  bd: 'max_load',               // W
  c2: 'photovoltaic_power2',
  c4: 'grid_power_signed',      // W (+ = Einspeisung, – = Bezug)
  c5: 'home_demand',            // W Hausverbrauch
  c6: 'pv_1_power',             // W Eingang 1
  c7: 'pv_2_power',             // W Eingang 2
  c8: 'pv_3_power',             // W Eingang 3
  c9: 'pv_4_power',             // W Eingang 4
  d4: 'device_timeout_min',     // Minuten (×30)
  d5: 'pv_limit',               // W
  d6: 'ac_input_limit',         // W
  fe: 'msg_timestamp',
};

// msg type 0408 – state_info – kommt alle ~300s
const MAP_0408 = {
  a2: 'device_sn',
  a3: 'local_timestamp',
  a4: 'utc_timestamp',
  a5: 'battery_soc_calc',       // % (×0.1)
  a6: 'battery_soh',            // % (×0.1)
  a7: 'battery_soc',
  a9: 'usage_mode',
  ab: 'photovoltaic_power',
  ac: 'pv_yield',
  b1: 'home_demand',
  b2: 'home_consumption',
  b6: 'battery_power_signed',
  b7: 'charged_energy',
  b8: 'discharged_energy',
  bd: 'grid_power_signed',
  be: 'grid_import_energy',
  bf: 'grid_export_energy',
  c7: 'pv_1_power',
  c8: 'pv_2_power',
  c9: 'pv_3_power',
  ca: 'pv_4_power',
  d3: 'ac_output_power',
  d5: 'grid_to_home_power',
  dc: 'max_load',
  dd: 'ac_input_limit',
  e0: 'min_soc',
  e6: 'pv_limit',
  cc: 'temperature',
  fe: 'msg_timestamp',
};

// msg type 040a – expansion data
const MAP_040A = {
  a1: 'pattern',
  a2: 'charge_priority',
  a3: 'battery_reserve_pct',
  fe: 'msg_timestamp',
};

const MSG_MAPS = { '0405': MAP_0405, '0408': MAP_0408, '040a': MAP_040A };

// ─── TLV-Parser ───────────────────────────────────────────────────────────────

function readValue(raw, code) {
  const flen = raw.length;

  // 1-Byte-Felder: kein Type-Byte
  if (flen === 1) {
    const v = raw[0];
    return SIGNED_FIELDS.has(code) && v > 127 ? v - 256 : v;
  }

  const type = raw[0];
  const data = raw.slice(1);
  const dlen = data.length;

  switch (type) {
    case 0x01:
      // 1 Byte unsigned int (fix)
      return dlen >= 1 ? data[0] : 0;

    case 0x02:
      // 2 Byte signed int LE (fix)
      return dlen >= 2 ? data.readInt16LE(0) : (dlen === 1 ? data.readInt8(0) : 0);

    case 0x03:
      // 4 Byte uint oder sint LE
      if (dlen >= 4) {
        return SIGNED_FIELDS.has(code)
          ? data.readInt32LE(0)
          : data.readUInt32LE(0);
      }
      return dlen > 0 ? data.readUIntLE(0, dlen) : 0;

    case 0x04:
      // Bitmask-Felder (Schalter wie ac_socket, light_mode etc.) → als hex
      return data.toString('hex');

    case 0x05:
      // 4 Byte signed float LE (Energie in Wh, Leistung in W)
      return dlen >= 4 ? Math.round(data.readFloatLE(0) * 10) / 10 : 0;

    case 0x06:
      // Mixed bytes/string
      return data.toString('utf8').replace(/\0/g, '').trim();

    default:
      // Unbekannter Typ: als hex
      return data.toString('hex');
  }
}

function parseAnkerTLV(buf) {
  if (!buf || buf.length < 9) return null;
  if (buf[0] !== 0xff || buf[1] !== 0x09) return null;

  const msgType = ((buf[7] << 8) | buf[8]).toString(16).padStart(4, '0');
  const fields  = {};
  let i = 9;

  while (i + 1 < buf.length) {
    const code = buf[i].toString(16).padStart(2, '0');
    const flen = buf[i + 1];
    i += 2;
    if (flen === 0 || i + flen > buf.length) break;
    fields[code] = readValue(buf.slice(i, i + flen), code);
    i += flen;
  }

  return { msgType, fields };
}

// ─── Hauptfunktion ────────────────────────────────────────────────────────────

function decodeAnkerMessage(topic, payload) {
  const results = [];

  let outer;
  try { outer = JSON.parse(payload.toString('utf8')); } catch { return results; }

  const head  = outer.head || {};
  const inner = (() => { try { return JSON.parse(outer.payload || '{}'); } catch { return {}; } })();
  const dataB64 = inner?.data || inner?.trans;

  if (head.timestamp) results.push({ key: 'timestamp', value: String(head.timestamp) });

  if (!dataB64 || typeof dataB64 !== 'string') return results;

  const buf    = Buffer.from(dataB64, 'base64');
  const parsed = parseAnkerTLV(buf);
  if (!parsed) return results;

  const { msgType, fields } = parsed;
  const map = MSG_MAPS[msgType];
  if (!map) return results;  // Unbekannter Message-Type: ignorieren

  for (const [code, value] of Object.entries(fields)) {
    if (value === undefined || value === null) continue;
    const name = map[code];
    if (!name || name === 'device_sn') continue;

    // Sonderbehandlung für 0408: SOC × 0.1
    let finalValue = value;
    if (msgType === '0408' && (code === 'a5' || code === 'a6') && typeof value === 'number') {
      finalValue = Math.round(value * 0.1 * 10) / 10;
    }
    if (code === 'd4' && typeof value === 'number') {
      finalValue = value * 30;
    }

    results.push({ key: name, value: String(finalValue) });
  }

  return results;
}

module.exports = { decodeAnkerMessage };
