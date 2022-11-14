const partial =
  (fn, ...partials) =>
  (...args) =>
    fn(...partials.concat(args))

export default partial
