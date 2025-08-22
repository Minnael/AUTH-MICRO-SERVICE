const express = require('express');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const User = require('../models/User');

const router = express.Router();

function signToken(user) {
  return jwt.sign(
    { id: user._id, username: user.username },
    process.env.JWT_SECRET,
    { expiresIn: '1h' }
  );
}

router.post('/register', async (req, res) => {
  const { username, password } = req.body;
  if (!username || !password) return res.status(400).json({ message: 'username e password são obrigatórios' });
  try {
    const exists = await User.findOne({ username });
    if (exists) return res.status(400).json({ message: 'Usuário já existe' });
    const hashed = await bcrypt.hash(password, 10);
    const user = await User.create({ username, password: hashed });
    return res.status(201).json({ id: user._id, username: user.username });
  } catch {
    return res.status(500).json({ message: 'Erro no servidor' });
  }
});

router.post('/login', async (req, res) => {
  const { username, password } = req.body;
  try {
    const user = await User.findOne({ username });
    if (!user) return res.status(400).json({ message: 'Usuário não encontrado' });
    const ok = await bcrypt.compare(password, user.password);
    if (!ok) return res.status(401).json({ message: 'Senha incorreta' });
    const token = signToken(user);
    return res.json({ token });
  } catch {
    return res.status(500).json({ message: 'Erro no servidor' });
  }
});

router.get('/validate', (req, res) => {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  if (!token) return res.status(401).json({ message: 'Token não fornecido' });
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    return res.json({ user: decoded });
  } catch {
    return res.status(401).json({ message: 'Token inválido ou expirado' });
  }
});

module.exports = router;