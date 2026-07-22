<p align="center">
  <img src="assets/banner.png" alt="Guard" width="180">
</p>

<h1 align="center">Guard</h1>

<p align="center">
  <b>Enterprise-grade authorization and API security platform for Go.</b>
</p>

<p align="center">
  <a href="#installation">Install</a> ·
  <a href="#quick-start">Quick Start</a> ·
  <a href="#core-components">Components</a> ·
  <a href="#roadmap">Roadmap</a>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/Go-1.21%2B-00ADD8?logo=go&logoColor=white" alt="Go">
  <img src="https://img.shields.io/badge/license-MIT-green" alt="License">
  <img src="https://img.shields.io/badge/status-alpha-orange" alt="Status">
</p>

---

Guard is a Go-native security toolkit that simplifies authentication, authorization, and API protection for modern applications and microservices. It provides session management, RBAC, ABAC, API key authentication, rate limiting, audit logging, and security middleware with a developer-friendly API.

## Features

| | |
|---|---|
| 🔐 Session management | 👥 Role-Based Access Control (RBAC) |
| 🏷️ Attribute-Based Access Control (ABAC) | 🔑 API key authentication |
| ⚡ Configurable rate limiting | 📋 Audit logs |
| 🛡️ Security middleware | 🌐 Service-to-service authentication |
| 📊 Security analytics support | 🔄 Automatic permission sync |
| 🚀 Gin, Echo, Fiber, Chi, net/http | 💾 PostgreSQL, MySQL, Redis |
| 🔌 Extensible plugin architecture | |

## Installation

```bash
go get github.com/bakhod1r/guard
```

## Quick Start

```go
package main

import "github.com/bakhod1r/guard"

func main() {
    g := guard.New()

    g.UseSession()
    g.UseRBAC()
    g.UseABAC()
    g.UseAPIKeys()
    g.UseRateLimiter()

    // Register middleware
    // router.Use(g.Middleware())
}
```

## Core Components

| Component | Description |
|---|---|
| **Sessions** | Secure, stateful session management. |
| **Authorization** | RBAC and ABAC policy enforcement. |
| **API Keys** | Secure API key generation, rotation, and validation. |
| **Rate Limiting** | Route, user, session, or API key-based throttling. |
| **Audit** | Track authentication and authorization events. |
| **Service Identity** | Secure service-to-service authentication. |
| **Middleware** | Plug-and-play security for Go web frameworks. |

## Why Guard?

Most Go applications combine multiple libraries for sessions, authorization, API keys, rate limiting, and auditing. Guard brings these capabilities together in a single, cohesive platform with a consistent developer experience.

## Roadmap

- [ ] Session management
- [ ] RBAC & ABAC
- [ ] API keys
- [ ] Rate limiting
- [ ] Audit logging
- [ ] Service-to-service authentication
- [ ] Admin dashboard
- [ ] Security analytics
- [ ] Policy engine
- [ ] Plugin ecosystem

## License

MIT License. See [LICENSE](LICENSE).
