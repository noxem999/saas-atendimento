const express = require('express');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const path = require('path');
const fs = require('fs');
const QRCode = require('qrcode');
const pino = require('pino');
const {
  default: makeWASocket,
  useMultiFileAuthState,
  DisconnectReason,
  fetchLatestBaileysVersion,
} = require('@whiskeysockets/baileys');

const app = express();
const PORT = process.env.PORT || 3000;

// O segredo do JWT vem da variável de ambiente JWT_SECRET.
// O fallback existe só para desenvolvimento local: em produção o servidor se recusa a subir sem ele.
const EM_PRODUCAO = process.env.NODE_ENV === 'production';
if (EM_PRODUCAO && !process.env.JWT_SECRET) {
  console.error('ERRO: defina a variável de ambiente JWT_SECRET antes de subir em produção.');
  process.exit(1);
}
const JWT_SECRET = process.env.JWT_SECRET || 'segredo-apenas-para-desenvolvimento';
const SALT_ROUNDS = 10;

app.use(express.json());

// "Banco de dados" simulado em memória (zera quando o servidor reinicia)
const usuarios = [];
let proximoId = 1;

const emailValido = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
const normalizarEmail = (email) => String(email).trim().toLowerCase();

// ---------- Middleware de autenticação ----------
function autenticar(req, res, next) {
  const header = req.headers.authorization || '';
  const [tipo, token] = header.split(' ');

  if (tipo !== 'Bearer' || !token) {
    return res.status(401).json({ erro: 'Token não informado.' });
  }

  try {
    req.auth = jwt.verify(token, JWT_SECRET);
    next();
  } catch (err) {
    const mensagem =
      err.name === 'TokenExpiredError' ? 'Sessão expirada. Entre novamente.' : 'Token inválido.';
    return res.status(401).json({ erro: mensagem });
  }
}

// ---------- Rotas ----------
// Health check (use em Settings > Health Check Path no Render)
app.get('/health', (req, res) => res.json({ status: 'ok' }));

app.post('/api/registrar', async (req, res) => {
  try {
    const { nome, email, senha } = req.body || {};

    if (!nome || !email || !senha) {
      return res.status(400).json({ erro: 'Preencha nome, e-mail e senha.' });
    }
    if (!emailValido(String(email).trim())) {
      return res.status(400).json({ erro: 'Informe um e-mail válido.' });
    }
    if (String(senha).length < 6) {
      return res.status(400).json({ erro: 'A senha precisa ter pelo menos 6 caracteres.' });
    }

    const emailNormalizado = normalizarEmail(email);
    if (usuarios.some((u) => u.email === emailNormalizado)) {
      return res.status(409).json({ erro: 'Este e-mail já está cadastrado.' });
    }

    const senhaHash = await bcrypt.hash(String(senha), SALT_ROUNDS);
    const usuario = {
      id: proximoId++,
      nome: String(nome).trim(),
      email: emailNormalizado,
      senhaHash,
      criadoEm: new Date().toISOString(),
    };
    usuarios.push(usuario);

    return res.status(201).json({ mensagem: 'Conta criada com sucesso.' });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao registrar.' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { email, senha } = req.body || {};

    if (!email || !senha) {
      return res.status(400).json({ erro: 'Informe e-mail e senha.' });
    }

    const usuario = usuarios.find((u) => u.email === normalizarEmail(email));
    // Mesma mensagem para e-mail inexistente e senha errada (evita revelar quais e-mails existem)
    const senhaCorreta = usuario ? await bcrypt.compare(String(senha), usuario.senhaHash) : false;

    if (!usuario || !senhaCorreta) {
      return res.status(401).json({ erro: 'E-mail ou senha incorretos.' });
    }

    const token = jwt.sign({ sub: usuario.id, email: usuario.email }, JWT_SECRET, {
      expiresIn: '1h',
    });

    return res.json({ token, nome: usuario.nome });
  } catch (err) {
    console.error(err);
    return res.status(500).json({ erro: 'Erro interno ao entrar.' });
  }
});

app.get('/api/painel', autenticar, (req, res) => {
  const usuario = usuarios.find((u) => u.id === req.auth.sub);
  if (!usuario) {
    return res.status(401).json({ erro: 'Usuário não encontrado. Entre novamente.' });
  }

  return res.json({
    id: usuario.id,
    nome: usuario.nome,
    email: usuario.email,
    criadoEm: usuario.criadoEm,
  });
});

// ---------- Agendamentos (dados simulados em memória) ----------
const agendamentos = [
  { id: 1, cliente: 'João', servico: 'Corte', horario: '14:00' },
  { id: 2, cliente: 'Maria', servico: 'Escova', horario: '15:30' },
  { id: 3, cliente: 'Carlos', servico: 'Barba', horario: '16:45' },
];

app.get('/api/agendamentos', autenticar, (req, res) => {
  res.json(agendamentos);
});

// ---------- WhatsApp (Baileys) ----------
// Sessão do WhatsApp (não versionar!). No Render, aponte WHATSAPP_AUTH_DIR para um disco persistente
// (ex.: /data/auth_whatsapp); sem isso a sessão se perde a cada deploy/reinício.
const AUTH_DIR = process.env.WHATSAPP_AUTH_DIR || path.join(__dirname, 'auth_whatsapp');

let qrCodeAtual = null; // QR Code atual em Base64 (PNG, sem o prefixo "data:...")
let whatsappConectado = false;
let iniciandoWhatsApp = false;

async function iniciarWhatsApp() {
  if (iniciandoWhatsApp) return; // evita abrir duas conexões ao mesmo tempo
  iniciandoWhatsApp = true;

  try {
    const { state, saveCreds } = await useMultiFileAuthState(AUTH_DIR);
    const { version } = await fetchLatestBaileysVersion();

    const sock = makeWASocket({
      version,
      auth: state,
      logger: pino({ level: 'silent' }),
      browser: ['Painel SaaS', 'Chrome', '1.0.0'],
    });

    sock.ev.on('creds.update', saveCreds);

    sock.ev.on('connection.update', async (update) => {
      const { connection, lastDisconnect, qr } = update;

      // Novo QR Code: converte para imagem e guarda na variável global
      if (qr) {
        try {
          const dataUrl = await QRCode.toDataURL(qr, { width: 300, margin: 2 });
          qrCodeAtual = dataUrl.split(',')[1]; // só o Base64
        } catch (err) {
          console.error('Erro ao gerar QR Code:', err.message);
        }
      }

      if (connection === 'open') {
        whatsappConectado = true;
        qrCodeAtual = null;
        console.log('WhatsApp conectado.');
      }

      if (connection === 'close') {
        whatsappConectado = false;
        qrCodeAtual = null;

        const status = lastDisconnect?.error?.output?.statusCode;
        if (status === DisconnectReason.loggedOut) {
          // Aparelho desconectado pelo celular: apaga a sessão para gerar um QR novo
          fs.rmSync(AUTH_DIR, { recursive: true, force: true });
          console.log('WhatsApp desconectado pelo aparelho. Gerando novo QR Code...');
        } else {
          console.log(`Conexão do WhatsApp fechada (código ${status}). Reconectando...`);
        }

        iniciandoWhatsApp = false;
        setTimeout(iniciarWhatsApp, 3000);
      }
    });
  } catch (err) {
    console.error('Erro ao iniciar o WhatsApp:', err.message);
    iniciandoWhatsApp = false;
    setTimeout(iniciarWhatsApp, 5000);
  }
}

app.get('/api/whatsapp/qrcode', autenticar, (req, res) => {
  if (whatsappConectado) {
    return res.json({ conectado: true });
  }
  return res.json({ qrcode: qrCodeAtual, conectado: false });
});

// ---------- Front-end ----------
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});

app.listen(PORT, () => {
  console.log(`Servidor rodando em http://localhost:${PORT}`);
  iniciarWhatsApp();
});