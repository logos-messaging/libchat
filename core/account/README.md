# λAccount

Logos(λ) Accounts are used to represent users across multiple services. 

An Account is a grouping of different entities used to describe a single User or entity in the Logos Ecosystem. 


## Services Supported

|Service | Supported |
|--------|-----------|
| [λChat](https://github.com/logos-messaging/logos-chat) | 🟢 |

### `LogosAccount`

Not Implemented

### `TestLogosAccount` (`feature = "dev"`)

A minimal implementation intended for development, testing, and CLI tooling. It accepts any string as the account ID and generates a fresh Ed25519 key pair on construction. State is not persisted — identity is lost on drop.

**Do not use in production.**

