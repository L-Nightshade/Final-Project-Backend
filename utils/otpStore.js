// Simple in-memory OTP store. Not persistent. Suitable for dev/testing.
// API: save(key, code, ttlSeconds), verify(key, code), get(key), delete(key)

const store = new Map();

const now = () => Math.floor(Date.now() / 1000);

export default {
  save(key, code, ttlSeconds = 300) {
    const expiresAt = now() + ttlSeconds;
    store.set(key, { code: String(code), expiresAt });
  },

  get(key) {
    const data = store.get(key);
    if (!data) return null;
    if (data.expiresAt < now()) {
      store.delete(key);
      return null;
    }
    return data.code;
  },

  verify(key, code) {
    const real = this.get(key);
    if (!real) return false;
    return String(code) === String(real);
  },

  delete(key) {
    store.delete(key);
  },

  // (optional) debug helper
  _all() {
    return Array.from(store.entries());
  },
};
