const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const User = require('../models/User');
const logger = require('../config/logger');

const router = express.Router();
router.use(cookieParser());

function signToken(user) {
  return jwt.sign(
    { id: user._id, login: user.login },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

router.post('/register', async (req, res) => {
  console.log('teste')
  const { login, password } = req.body;
  if (!login || !password) {
    logger.warn(`Tentativa de registro sem login ou senha.`);
    return res.status(400).json({ message: 'login e password são obrigatórios' });
  }
  try {
    const exists = await User.findOne({ login });
    if (exists) {
      logger.warn(`Tentativa de registro duplicado para login: ${login}`);
      return res.status(400).json({ message: 'Usuário já existe' });
    }
    const hashed = await bcrypt.hash(password, 10);
  const user = await User.create({ login, password: hashed });
  logger.info(`Usuário registrado com sucesso: ${login}`);
  return res.status(201).json({ id: user._id, login: user.login });
  } catch {
    return res.status(500).json({ message: 'Erro no servidor' });
  }
});

router.post('/login', async (req, res) => {
  const { login, password } = req.body;
  try {
    const user = await User.findOne({ login });
  if (!user) {
    logger.warn(`Tentativa de login com login inexistente: ${login}`);
    return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS', message: 'Login ou senha inválidos.' });
  }
  const ok = await bcrypt.compare(password, user.password);
  if (!ok) {
    logger.warn(`Tentativa de login com senha incorreta para login: ${login}`);
    return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS', message: 'Login ou senha inválidos.' });
  }
    const token = signToken(user);
    res.cookie('token', token, {
      httpOnly: true,
      secure: true,
      sameSite: 'strict',
      maxAge: 3600000 // 1 HORA 
    });
  logger.info(`Login realizado com sucesso para login: ${login}`);
  return res.json({ perfil: { id: user._id, login: user.login } });
  } catch {
    return res.status(500).json({ message: 'Erro no servidor' });
  }
});

router.post('/check', async (req, res) => {
  const token = req.cookies.token;
  if (!token) {
    logger.warn(`Tentativa de validação de token sem cookie.`);
    return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS', message: 'Login ou senha inválidos.' });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const user = await User.findById(decoded.id).select('-password');
    if (!user) {
      logger.warn(`Token válido, mas usuário não encontrado no banco. ID: ${decoded.id}`);
      return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS', message: 'Login ou senha inválidos.' });
    }
    logger.info(`Token validado e perfil retornado para login: ${user.login}`);
    return res.json({ perfil: user });
  } catch {
    return res.status(401).json({ error: 'CREDENCIAIS_INVALIDAS', message: 'Login ou senha inválidos.' });
  }
});

module.exports = router;