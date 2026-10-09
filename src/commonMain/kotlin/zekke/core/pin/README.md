# `zekke.core.pin` — the PIN format rules

The rules a PIN must pass before it is registered:

- exactly 6 ASCII digits (`0`–`9`; other scripts' digits are refused);
- not one repeated digit (`111111`);
- not an ascending or descending run (`123456`, `654321`).

```kotlin
validatePin(pin)    // PinValidation.Valid or PinValidation.Invalid(reason)
assertValidPin(pin) // throws InvalidPinException(reason)
```

`PinRejection` carries the reason; each app turns it into its own sentence. The PIN is a
`CharArray`, so the caller can zero it. How a PIN is used is [`oprf`](../oprf/README.md).

## Tests

`PinRulesTest`: valid PINs, and each rejection with its reason.
