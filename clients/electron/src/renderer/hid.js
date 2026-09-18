// Browser KeyboardEvent.code -> USB HID Usage ID (Usage Page 0x07), plus
// tracking of the 8-bit HID modifier byte.
//
// The KVM keyboard packet is a standard USB HID boot-keyboard report:
//   [modifier, reserved(0), k0..k5]
// which is exactly what the vendor client sends (PackData.keyData, 8 bytes).

const CODES = {
  KeyA: 0x04, KeyB: 0x05, KeyC: 0x06, KeyD: 0x07, KeyE: 0x08, KeyF: 0x09,
  KeyG: 0x0a, KeyH: 0x0b, KeyI: 0x0c, KeyJ: 0x0d, KeyK: 0x0e, KeyL: 0x0f,
  KeyM: 0x10, KeyN: 0x11, KeyO: 0x12, KeyP: 0x13, KeyQ: 0x14, KeyR: 0x15,
  KeyS: 0x16, KeyT: 0x17, KeyU: 0x18, KeyV: 0x19, KeyW: 0x1a, KeyX: 0x1b,
  KeyY: 0x1c, KeyZ: 0x1d,
  Digit1: 0x1e, Digit2: 0x1f, Digit3: 0x20, Digit4: 0x21, Digit5: 0x22,
  Digit6: 0x23, Digit7: 0x24, Digit8: 0x25, Digit9: 0x26, Digit0: 0x27,
  Enter: 0x28, Escape: 0x29, Backspace: 0x2a, Tab: 0x2b, Space: 0x2c,
  Minus: 0x2d, Equal: 0x2e, BracketLeft: 0x2f, BracketRight: 0x30, Backslash: 0x31,
  Semicolon: 0x33, Quote: 0x34, Backquote: 0x35, Comma: 0x36, Period: 0x37,
  Slash: 0x38, CapsLock: 0x39,
  F1: 0x3a, F2: 0x3b, F3: 0x3c, F4: 0x3d, F5: 0x3e, F6: 0x3f,
  F7: 0x40, F8: 0x41, F9: 0x42, F10: 0x43, F11: 0x44, F12: 0x45,
  PrintScreen: 0x46, ScrollLock: 0x47, Pause: 0x48,
  Insert: 0x49, Home: 0x4a, PageUp: 0x4b, Delete: 0x4c, End: 0x4d, PageDown: 0x4e,
  ArrowRight: 0x4f, ArrowLeft: 0x50, ArrowDown: 0x51, ArrowUp: 0x52,
  NumLock: 0x53, NumpadDivide: 0x54, NumpadMultiply: 0x55, NumpadSubtract: 0x56,
  NumpadAdd: 0x57, NumpadEnter: 0x58,
  Numpad1: 0x59, Numpad2: 0x5a, Numpad3: 0x5b, Numpad4: 0x5c, Numpad5: 0x5d,
  Numpad6: 0x5e, Numpad7: 0x5f, Numpad8: 0x60, Numpad9: 0x61, Numpad0: 0x62,
  NumpadDecimal: 0x63, NumpadComma: 0x85, NumpadEqual: 0x67,
  IntlBackslash: 0x64, ContextMenu: 0x65,
  IntlRo: 0x87, KanaMode: 0x88, IntlYen: 0x89,
  Convert: 0x8a, NonConvert: 0x8b,
};

// modifier keys map to bits in the report's first byte, not to keycode slots
const MODIFIERS = {
  ControlLeft: 0x01, ShiftLeft: 0x02, AltLeft: 0x04, MetaLeft: 0x08,
  ControlRight: 0x10, ShiftRight: 0x20, AltRight: 0x40, MetaRight: 0x80,
};

export class KeyboardState {
  constructor() {
    this.held = new Map();        // code -> usage id (non-modifier)
    this.mods = new Set();        // held modifier codes
  }

  /** @returns {Uint8Array|null} an 8-byte HID report, or null if the key is unknown */
  keydown(code) {
    if (MODIFIERS[code]) { this.mods.add(code); return this.report(); }
    const usage = CODES[code];
    if (usage === undefined) return null;
    if (!this.held.has(code)) {
      if (this.held.size >= 6) return null;     // boot protocol reports hold at most 6 keys
      this.held.set(code, usage);
    }
    return this.report();
  }

  keyup(code) {
    if (MODIFIERS[code]) { this.mods.delete(code); return this.report(); }
    if (!this.held.has(code)) return null;
    this.held.delete(code);
    return this.report();
  }

  releaseAll() {
    this.held.clear();
    this.mods.clear();
    return this.report();
  }

  report() {
    let mod = 0;
    for (const c of this.mods) mod |= MODIFIERS[c];
    const out = new Uint8Array(8);
    out[0] = mod;
    let i = 2;
    for (const usage of this.held.values()) { if (i > 7) break; out[i++] = usage; }
    return out;
  }
}

export const HID = { CODES, MODIFIERS };
