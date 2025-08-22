const request = require('supertest');
const mongoose = require('mongoose');
const express = require('express');
const authRoutes = require('../routes/auth');
const User = require('../models/User');
require('dotenv').config({ path: '.env.test' });

const app = express();
app.use(express.json());
app.use('/api', authRoutes);

beforeAll(async () => {
  await mongoose.connect(process.env.MONGO_URI);
  await User.deleteMany({});
});

afterAll(async () => {
  await mongoose.disconnect();
});

describe('Auth API', () => {
  const userData = { login: 'testuser', password: 'testpass' };

  // Testa o registro de um novo usuário:
  // 1. Envia uma requisição POST para /api/register com login e senha.
  // 2. Espera status 201 (criado).
  // 3. Verifica se o corpo da resposta contém o id e o login do usuário.
  it('should register a new user', async () => {
    const res = await request(app)
      .post('/api/register')
      .send(userData);
    expect(res.statusCode).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('login', userData.login);
  });

  // Testa o registro duplicado de usuário:
  // 1. Tenta registrar o mesmo usuário novamente.
  // 2. Espera status 400 (erro de usuário já existente).
  it('should not register duplicate user', async () => {
    const res = await request(app)
      .post('/api/register')
      .send(userData);
    expect(res.statusCode).toBe(400);
  });

  // Testa o login e o envio do cookie:
  // 1. Envia uma requisição POST para /api/login com login e senha válidos.
  // 2. Espera status 200 (sucesso).
  // 3. Verifica se o cookie de autenticação foi enviado na resposta.
  // 4. Verifica se o corpo da resposta contém o perfil do usuário.
  it('should login and set cookie', async () => {
    const res = await request(app)
      .post('/api/login')
      .send(userData);
    expect(res.statusCode).toBe(200);
    expect(res.headers['set-cookie']).toBeDefined();
    expect(res.body).toHaveProperty('perfil');
    expect(res.body.perfil).toHaveProperty('login', userData.login);
  });

  // Testa o login com senha incorreta:
  // 1. Envia uma requisição POST para /api/login com login correto e senha errada.
  // 2. Espera status 401 (não autorizado).
  // 3. Verifica se o corpo da resposta contém o erro esperado.
  it('should fail login with wrong password', async () => {
    const res = await request(app)
      .post('/api/login')
      .send({ login: userData.login, password: 'wrongpass' });
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('error', 'CREDENCIAIS_INVALIDAS');
  });

  // Testa a validação do token e retorno do perfil:
  // 1. Realiza login para obter o cookie de autenticação.
  // 2. Envia uma requisição POST para /api/check com o cookie.
  // 3. Espera status 200 (sucesso).
  // 4. Verifica se o corpo da resposta contém o perfil do usuário.
  it('should validate token and return perfil', async () => {
    const loginRes = await request(app)
      .post('/api/login')
      .send(userData);
    const cookie = loginRes.headers['set-cookie'];
    const checkRes = await request(app)
      .post('/api/check')
      .set('Cookie', cookie)
      .send();
    expect(checkRes.statusCode).toBe(200);
    expect(checkRes.body).toHaveProperty('perfil');
    expect(checkRes.body.perfil).toHaveProperty('login', userData.login);
  });

  // Testa a validação sem token:
  // 1. Envia uma requisição POST para /api/check sem cookie de autenticação.
  // 2. Espera status 401 (não autorizado).
  // 3. Verifica se o corpo da resposta contém o erro esperado.
  it('should fail check with no token', async () => {
    const res = await request(app)
      .post('/api/check')
      .send();
    expect(res.statusCode).toBe(401);
    expect(res.body).toHaveProperty('error', 'CREDENCIAIS_INVALIDAS');
  });
});
