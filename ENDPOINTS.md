# Endpoints do Microserviço de Autenticação

## POST /api/register
Registra um novo usuário.
- Body: `{ "login": "string", "password": "string" }`
- Response: `{ id, login }`

## POST /api/login
Realiza login do usuário.
- Body: `{ "login": "string", "password": "string" }`
- Response: `{ perfil: { id, login } }`
- Cookie: `token` (JWT)

## POST /api/check
Valida o token do usuário e retorna o perfil completo.
- Cookie: `token` (JWT)
- Response: `{ perfil: { id, login, ... } }`
- Erro 401: `{ "error": "CREDENCIAIS_INVALIDAS", "message": "Login ou senha inválidos." }`
