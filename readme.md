# 🍽️ UberEats Lite — Backend  
**Repositorio:** `ubereaats-backend`  
**Stack:** Node.js · Express · TypeScript · Postgres · Prisma · Redis · JWT · OAuth · Socket.io · BullMQ · Docker

---

## 📌 Descripción General
Este backend implementa toda la lógica de negocio para un sistema tipo **UberEats / Rappi**, incluyendo:

- API REST completa
- Autenticación moderna (JWT + Refresh Tokens + Redis)
- OAuth (Google & Apple)
- Restaurantes, productos, carrito, pedidos
- Tracking en tiempo real vía WebSockets
- Asignación automática de repartidores (BullMQ)
- Cache + sesiones + geolocalización en Redis
- Preparado para deploy gratuito en Railway / Render

Produce la API utilizada tanto por la **app Flutter móvil + web + PWA**, como por un panel de administración opcional.

---

## 🚀 Tecnologías Principales
| Área | Tecnología |
|------|------------|
| Lenguaje | Node.js + TypeScript |
| Framework | Express |
| Base de datos | Postgres (via Prisma ORM) |
| Cache / Sessions / Queues | Redis |
| Realtime | Socket.io |
| Auth | JWT · Refresh Tokens · OAuth Google · OAuth Apple |
| Colas | BullMQ |
| Validaciones | Zod |
| Infra | Docker + Docker Compose |

---

## 🔐 Autenticación y Sesiones
El backend utiliza un sistema moderno basado en:

### ✔ Access Token (JWT)
- Expira cada 15 minutos  
- Stateless (no se guarda en Redis)

### ✔ Refresh Token (Redis)
- Expira en 30 días (TTL automático)
- Rotación automática
- Se revoca con un simple `DEL`

**Esquema en Redis:**
refresh:<userId>:<sessionId> = <refresh_token> (TTL 30d)
blacklist:<jti> = true (TTL = exp original)


### ✔ OAuth Compatible
Funciona con:
- Google OAuth2
- Apple Sign-In

---
## 🗂️ Estructura del Proyecto
/src
/config
/modules
/auth
/users
/restaurants
/products
/cart
/orders
/delivery
/tracking
/middlewares
/utils
app.ts
server.ts

/prisma
schema.prisma

/docker
.env.example

## 📡 Endpoints Principales

### 🔹 Auth
POST /auth/register
POST /auth/login
POST /auth/oauth/google
POST /auth/oauth/apple
POST /auth/refresh
POST /auth/logout

### 🔹 Restaurantes / Productos
GET /restaurants
GET /restaurants/:id
POST /restaurants
PUT /restaurants/:id
DELETE /restaurants/:id

GET /restaurants/:id/products
POST /restaurants/:id/products
PUT /products/:id
DELETE /products/:id

### 🔹 Carrito (Redis)
GET /cart
POST /cart/add
POST /cart/remove
DELETE /cart/clear

shell
Copiar código

### 🔹 Pedidos / Tracking
POST /orders
GET /orders/:id
PUT /orders/:id/status

WS: /tracking/:orderId

---

## 🚴‍♂️ Asignación de Repartidores (BullMQ)
- Cola: `orders:pending`
- Asigna el repartidor más cercano
- Reintentos automáticos
- Fallback si nadie acepta
- Integración con WebSockets

---

## 📍 Tracking en Tiempo Real
Redis almacena:

location:<orderId> = { lat, lng } (TTL 60s)

yaml
Copiar código

El cliente escucha eventos via Socket.io:
- `location:update`
- `order:status`

---

## 🐳 Docker / Entorno Local

### 1. Copiar variables de entorno
cp .env.example .env

shell
Copiar código

### 2. Levantar infraestructura (Postgres + Redis)
docker compose up -d

shell
Copiar código

### 3. Ejecutar migraciones
npx prisma migrate dev

shell
Copiar código

### 4. Iniciar API
pnpm dev

yaml
Copiar código

---

## 🚀 Deploy (Railway / Render)
- Base de datos → Neon / Supabase / Railway
- Redis → Upstash (free)
- API → Railway / Render
- Variables de entorno desde el panel
- Soporte para Socket.io en modo serverless-friendly

---

## 📘 Documentación
- Swagger (opcional)
- Postman Collection incluida en `/docs`

---

## 🏁 Estado del Proyecto
✔ Arquitectura definida  
✔ Autenticación moderna  
✔ WebSockets listos  
✔ Manejo completo de Redis  

---

## 📄 Licencia
MIT — Libre para usar y modificar.